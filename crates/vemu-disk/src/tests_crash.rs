//! Crash-consistency test: power loss at every step of the write/flush
//! ordering.
//!
//! The overlay file is a [`CrashStorage`]: writes land in a volatile cache
//! and become durable only at `sync`. Operation number `crash_at` (counting
//! writes and syncs) and everything after it fail, as if the host lost
//! power. What survives is the durable image plus any subset of the
//! unsynced writes, each kept whole, dropped, or torn at 512-byte sector
//! granularity, in any combination (a disk may reorder writes between
//! barriers).
//!
//! For every crash point and several survivor patterns, the overlay is
//! reopened and every sector must hold either its contents as of the last
//! acknowledged flush, or the data of a write issued after it (acknowledged
//! or the one that failed). In particular never a hole (zeros, garbage) and
//! never the golden image's data for a sector whose write a completed flush
//! covered. The test then checks the reopened overlay still works.
//!
//! A second test models a transient sync failure with Linux writeback
//! error semantics: one sync fails and the writes pending at that point
//! are dropped for good, while later syncs succeed. The guest carries on
//! (retries its flush, then exits cleanly); the same invariants must hold
//! after a power loss.

use std::io;
use std::sync::{Arc, Mutex};

use crate::BlockBackend;
use crate::buf::{ReadBuf, WriteBuf};
use crate::format::{Fingerprint, Header};
use crate::io::Storage;
use crate::overlay::Overlay;
use crate::testutil::{MemStorage, Prng, base_pattern};

const SECTOR: u64 = 512;

#[derive(Clone)]
struct CrashStorage(Arc<Mutex<CrashState>>);

struct CrashState {
    durable: Vec<u8>,
    cache: Vec<u8>,
    /// Writes since the last sync, in order.
    pending: Vec<(u64, Vec<u8>)>,
    ops: u64,
    crash_at: u64,
    syncs: u64,
    /// The sync with this number (0 first) fails once, dropping the
    /// pending writes (they never become durable); later syncs work.
    fail_sync: Option<u64>,
}

impl CrashStorage {
    fn new(initial: Vec<u8>, crash_at: u64) -> CrashStorage {
        CrashStorage(Arc::new(Mutex::new(CrashState {
            durable: initial.clone(),
            cache: initial,
            pending: Vec::new(),
            ops: 0,
            crash_at,
            syncs: 0,
            fail_sync: None,
        })))
    }

    /// No crash, but sync number `n` fails once (see `fail_sync`).
    fn transient(initial: Vec<u8>, n: u64) -> CrashStorage {
        let s = CrashStorage::new(initial, u64::MAX);
        s.0.lock().unwrap().fail_sync = Some(n);
        s
    }

    fn ops(&self) -> u64 {
        self.0.lock().unwrap().ops
    }

    fn syncs(&self) -> u64 {
        self.0.lock().unwrap().syncs
    }

    /// The file after the power loss: the durable bytes plus survivors of
    /// the pending writes chosen by `pattern` (0: none, 1: all, else random
    /// from `rng`, with tearing).
    fn after_crash(&self, pattern: u32, rng: &mut Prng) -> Vec<u8> {
        let s = self.0.lock().unwrap();
        let mut out = s.durable.clone();
        for (off, data) in &s.pending {
            let keep = match pattern {
                0 => 0,
                1 => 1,
                _ => rng.below(3),
            };
            let off = *off as usize;
            match keep {
                0 => {}
                1 => out[off..off + data.len()].copy_from_slice(data),
                _ => {
                    // Torn: each sector of the write independently.
                    let mut pos = 0;
                    while pos < data.len() {
                        let abs = off + pos;
                        let n = (SECTOR as usize - abs % SECTOR as usize).min(data.len() - pos);
                        if rng.chance(50) {
                            out[abs..abs + n].copy_from_slice(&data[pos..pos + n]);
                        }
                        pos += n;
                    }
                }
            }
        }
        out
    }
}

impl CrashState {
    /// Count a durability-relevant operation; fails from `crash_at` on.
    fn step(&mut self) -> io::Result<()> {
        if self.ops >= self.crash_at {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        self.ops += 1;
        Ok(())
    }
}

impl Storage for CrashStorage {
    fn read_at(&self, mut buf: ReadBuf<'_>, off: u64) -> io::Result<()> {
        let s = self.0.lock().unwrap();
        let off = off as usize;
        buf.copy_from(&s.cache[off..off + buf.len()]);
        Ok(())
    }

    fn write_at(&self, buf: WriteBuf<'_>, off: u64) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.step()?;
        let data = buf.to_vec();
        let o = off as usize;
        s.cache[o..o + data.len()].copy_from_slice(&data);
        s.pending.push((off, data));
        Ok(())
    }

    fn sync(&self) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.step()?;
        let n = s.syncs;
        s.syncs += 1;
        let pending = std::mem::take(&mut s.pending);
        if s.fail_sync == Some(n) {
            // Writeback failed: those writes are gone from the disk's
            // point of view (the cache still shows them to reads), and the
            // error is reported only this once.
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        for (off, data) in pending {
            let o = off as usize;
            s.durable[o..o + data.len()].copy_from_slice(&data);
        }
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        Ok(self.0.lock().unwrap().cache.len() as u64)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Version {
    Base,
    /// Written by the write with this tag (its sectors hold the tag byte).
    Tag(u8),
}

#[derive(Clone, Copy, Debug)]
enum Op {
    /// Sector-aligned write: (sector, sectors, tag).
    Write(u64, u64, u8),
    Flush,
}

/// A deterministic guest workload: sector-aligned writes (partial blocks,
/// whole blocks, spans), flushes, and rewrites of blocks written before
/// (also after a flush, without another one).
fn workload(seed: u64, sectors: u64, bs: u64) -> Vec<Op> {
    let mut rng = Prng::new(seed);
    let per_block = bs / SECTOR;
    let mut ops = Vec::new();
    let mut written: Vec<u64> = Vec::new();
    let mut tag = 0u8;
    while ops.len() < 36 {
        if rng.chance(22) {
            ops.push(Op::Flush);
            continue;
        }
        tag += 1;
        let start = if !written.is_empty() && rng.chance(35) {
            written[rng.below(written.len() as u64) as usize]
        } else if rng.chance(50) {
            rng.below(sectors.div_ceil(per_block)) * per_block
        } else {
            rng.below(sectors)
        };
        let n = (1 + rng.below(2 * per_block + 2)).min(sectors - start);
        written.push(start);
        ops.push(Op::Write(start, n, tag));
    }
    ops.push(Op::Flush);
    ops
}

struct Run {
    /// Allowed versions of each sector after a crash.
    allowed: Vec<Vec<Version>>,
    /// The workload ran to the end (and the final flush was acknowledged).
    completed: bool,
}

/// Run `ops` on a fresh overlay whose storage fails from `crash_at` on.
fn run_until_crash(file: &CrashStorage, base: &MemStorage, ops: &[Op], sectors: u64) -> Run {
    let ov = Overlay::from_storage(Box::new(file.clone()), Box::new(base.clone()), false)
        .expect("open before the crash");
    let mut current = vec![Version::Base; sectors as usize];
    let mut allowed: Vec<Vec<Version>> = vec![vec![Version::Base]; sectors as usize];
    for op in ops {
        match *op {
            Op::Write(start, n, tag) => {
                for s in start..start + n {
                    allowed[s as usize].push(Version::Tag(tag));
                }
                let data = vec![tag; (n * SECTOR) as usize];
                if ov.write_at(WriteBuf::new(&data), start * SECTOR).is_err() {
                    return Run {
                        allowed,
                        completed: false,
                    };
                }
                for s in start..start + n {
                    current[s as usize] = Version::Tag(tag);
                }
            }
            Op::Flush => {
                if ov.flush().is_err() {
                    return Run {
                        allowed,
                        completed: false,
                    };
                }
                for (a, c) in allowed.iter_mut().zip(&current) {
                    *a = vec![*c];
                }
            }
        }
    }
    // The power fails right after the last flush; nothing calls shutdown.
    Run {
        allowed,
        completed: true,
    }
}

fn version_of(sector: &[u8], base: &[u8]) -> Option<Version> {
    if sector == base {
        return Some(Version::Base);
    }
    let t = sector[0];
    (t != 0 && t < 0x80 && sector.iter().all(|&b| b == t)).then_some(Version::Tag(t))
}

fn check_scenario(seed: u64, bs: u32, size: u64) {
    let sectors = size / SECTOR;
    let base = MemStorage::new(base_pattern(size));
    let fp = Fingerprint {
        size,
        mtime_ns: 0,
        digest: 0,
    };
    let header = Header::new(bs, fp, "golden".into()).unwrap();
    let mut fresh = vec![0u8; header.file_len() as usize];
    fresh[..header.header_len()].copy_from_slice(&header.encode());
    let ops = workload(seed, sectors, u64::from(bs));

    // How many operations a full run takes.
    let probe = CrashStorage::new(fresh.clone(), u64::MAX);
    assert!(run_until_crash(&probe, &base, &ops, sectors).completed);
    let total = probe.ops();
    assert!(total > 20, "workload too small ({total} ops)");

    let mut rng = Prng::new(seed ^ 0xc0ffee);
    for crash_at in 0..=total {
        let file = CrashStorage::new(fresh.clone(), crash_at);
        let run = run_until_crash(&file, &base, &ops, sectors);
        assert_eq!(run.completed, crash_at == total);
        let what = format!("seed {seed} bs {bs} crash at {crash_at}/{total}");
        check_after_crash(&file, &base, &run.allowed, &mut rng, &what);
    }
}

/// Power loss now: for several survivor patterns, reopen the overlay and
/// check every sector against `allowed`, then that it still works.
fn check_after_crash(
    file: &CrashStorage,
    base: &MemStorage,
    allowed: &[Vec<Version>],
    rng: &mut Prng,
    what: &str,
) {
    let base_bytes = base.contents();
    let size = base_bytes.len() as u64;
    for pattern in 0..8 {
        let bytes = file.after_crash(pattern, rng);
        let survivor = MemStorage::new(bytes);
        let ov = Overlay::from_storage(Box::new(survivor.clone()), Box::new(base.clone()), false)
            .unwrap_or_else(|e| panic!("{what} pattern {pattern}: reopen failed: {e}"));
        let mut disk = vec![0u8; size as usize];
        ov.read_at(ReadBuf::new(&mut disk), 0).unwrap();
        let sectors = disk
            .chunks(SECTOR as usize)
            .zip(base_bytes.chunks(SECTOR as usize));
        for (s, ((got, base), allowed)) in sectors.zip(allowed).enumerate() {
            let v = version_of(got, base);
            assert!(
                v.is_some_and(|v| allowed.contains(&v)),
                "{what} pattern {pattern}: sector {s} is {v:?} (first bytes {:02x?}), allowed \
                 {allowed:?}",
                &got[..8]
            );
        }
        // The survivor is a working overlay: write, flush, reopen.
        if pattern == 2 {
            let tag = [0x7f; SECTOR as usize];
            ov.write_at(WriteBuf::new(&tag), size - SECTOR).unwrap();
            ov.flush().unwrap();
            drop(ov);
            let ov =
                Overlay::from_storage(Box::new(survivor), Box::new(base.clone()), false).unwrap();
            let mut last = [0u8; SECTOR as usize];
            ov.read_at(ReadBuf::new(&mut last), size - SECTOR).unwrap();
            assert_eq!(last, tag);
        }
    }
}

/// One sync fails transiently (Linux writeback-error semantics: the
/// pending writes are dropped and later syncs succeed). The guest ignores
/// the error and carries on, retrying flushes, then exits cleanly
/// (`shutdown`). No later flush may persist a bit for data that the failed
/// sync dropped: after a power loss, no sector reads as zeros.
fn check_transient_sync_failure(seed: u64, bs: u32, size: u64) {
    let sectors = size / SECTOR;
    let base = MemStorage::new(base_pattern(size));
    let fp = Fingerprint {
        size,
        mtime_ns: 0,
        digest: 0,
    };
    let header = Header::new(bs, fp, "golden".into()).unwrap();
    let mut fresh = vec![0u8; header.file_len() as usize];
    fresh[..header.header_len()].copy_from_slice(&header.encode());
    let ops = workload(seed, sectors, u64::from(bs));
    let probe = CrashStorage::new(fresh.clone(), u64::MAX);
    assert!(run_until_crash(&probe, &base, &ops, sectors).completed);
    let total_syncs = probe.syncs();
    assert!(total_syncs > 4, "workload too small ({total_syncs} syncs)");

    let mut rng = Prng::new(seed ^ 0xbad5ec);
    for fail in 0..total_syncs {
        let file = CrashStorage::transient(fresh.clone(), fail);
        let ov =
            Overlay::from_storage(Box::new(file.clone()), Box::new(base.clone()), false).unwrap();
        let mut current = vec![Version::Base; sectors as usize];
        let mut allowed: Vec<Vec<Version>> = vec![vec![Version::Base]; sectors as usize];
        let mut failures = 0;
        let acknowledge = |allowed: &mut Vec<Vec<Version>>, current: &[Version]| {
            for (a, c) in allowed.iter_mut().zip(current) {
                *a = vec![*c];
            }
        };
        for op in &ops {
            match *op {
                Op::Write(start, n, tag) => {
                    for s in start..start + n {
                        allowed[s as usize].push(Version::Tag(tag));
                    }
                    let data = vec![tag; (n * SECTOR) as usize];
                    if ov.write_at(WriteBuf::new(&data), start * SECTOR).is_ok() {
                        for s in start..start + n {
                            current[s as usize] = Version::Tag(tag);
                        }
                    }
                }
                Op::Flush => match ov.flush() {
                    Ok(()) => acknowledge(&mut allowed, &current),
                    Err(_) => failures += 1,
                },
            }
        }
        match ov.shutdown() {
            Ok(()) => acknowledge(&mut allowed, &current),
            Err(_) => failures += 1,
        }
        assert!(failures > 0, "seed {seed}: sync {fail} was never reached");
        let latched = ov.has_failed();
        drop(ov);
        let what = format!("seed {seed} bs {bs} transient failure of sync {fail}/{total_syncs}");
        check_after_crash(&file, &base, &allowed, &mut rng, &what);
        assert!(latched, "{what}: the failure was forgotten");
    }
}

#[test]
fn transient_sync_failure_never_persists_bits_for_lost_data() {
    for seed in 1..=6 {
        check_transient_sync_failure(seed, 4096, 12 * 4096 + 3 * SECTOR);
        check_transient_sync_failure(seed + 100, 1024, 40 * 1024);
    }
}

#[test]
fn crash_at_every_step_keeps_the_overlay_consistent() {
    for seed in 1..=6 {
        // A partial last block (3 sectors) at 4 KiB blocks.
        check_scenario(seed, 4096, 12 * 4096 + 3 * SECTOR);
        check_scenario(seed + 100, 1024, 40 * 1024);
    }
}
