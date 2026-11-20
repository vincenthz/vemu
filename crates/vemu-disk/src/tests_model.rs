//! Model-based randomized test: an overlay against a plain byte vector.
//!
//! Random writes (byte-granular and sector-aligned, inside one block or
//! across several, at the edges of the disk), reads, flushes and reopens,
//! from a seeded PRNG. After every read the overlay must equal the model,
//! and the allocated blocks must be exactly the blocks written.

use crate::BlockBackend;
use crate::buf::{ReadBuf, WriteBuf};
use crate::format::{Fingerprint, Header};
use crate::overlay::Overlay;
use crate::testutil::{MemStorage, Prng, base_pattern};

const SENTINEL: u8 = 0xee;

fn new_overlay(size: u64, bs: u32) -> (MemStorage, MemStorage) {
    let base = MemStorage::new(base_pattern(size));
    let fp = Fingerprint {
        size,
        mtime_ns: 0,
        digest: 0,
    };
    let h = Header::new(bs, fp, "golden".into()).unwrap();
    // The data region starts as a sentinel, so blocks the overlay writes
    // are visible: it must write exactly the blocks the guest wrote.
    let mut bytes = vec![0; h.file_len() as usize];
    bytes[h.data_offset as usize..].fill(SENTINEL);
    let file = MemStorage::new(bytes);
    file.poke(0, &h.encode());
    (file, base)
}

fn open(file: &MemStorage, base: &MemStorage) -> Overlay {
    Overlay::from_storage(Box::new(file.clone()), Box::new(base.clone()), false).unwrap()
}

fn run(seed: u64, bs: u32, size: u64, steps: usize) {
    let mut rng = Prng::new(seed);
    let (file, base) = new_overlay(size, bs);
    let bs64 = u64::from(bs);
    let blocks = size.div_ceil(bs64);
    let mut model = base.contents();
    let mut touched = vec![false; blocks as usize];
    let mut ov = open(&file, &base);
    let ctx =
        |step: usize, what: &str| format!("seed {seed} bs {bs} size {size} step {step}: {what}");

    for step in 0..steps {
        match rng.below(100) {
            0..=44 => {
                // Mostly near block boundaries, sometimes anywhere.
                let mut off = if rng.chance(60) {
                    let edge = rng.below(blocks + 1) * bs64;
                    edge.saturating_sub(rng.below(3)) + rng.below(3)
                } else {
                    rng.below(size)
                };
                off = off.min(size - 1);
                let max = (size - off).min(3 * bs64 + 700);
                let mut len = 1 + rng.below(max);
                if rng.chance(40) {
                    // A virtio-like request: whole sectors.
                    off &= !511;
                    len = (len.div_ceil(512) * 512).min((size - off) & !511);
                    if len == 0 {
                        continue;
                    }
                }
                let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                ov.write_at(WriteBuf::new(&data), off)
                    .unwrap_or_else(|e| panic!("{}", ctx(step, &e.to_string())));
                model[off as usize..(off + len) as usize].copy_from_slice(&data);
                for b in off / bs64..=(off + len - 1) / bs64 {
                    touched[b as usize] = true;
                }
            }
            45..=79 => {
                let off = rng.below(size);
                let len = 1 + rng.below((size - off).min(4 * bs64));
                let mut got = vec![0; len as usize];
                ov.read_at(ReadBuf::new(&mut got), off).unwrap();
                assert!(
                    got == model[off as usize..(off + len) as usize],
                    "{}",
                    ctx(step, &format!("read {len} at {off} differs"))
                );
            }
            80..=87 => ov.flush().unwrap(),
            88..=93 => {
                // A clean exit and a new run on the same overlay.
                ov.shutdown().unwrap();
                drop(ov);
                ov = open(&file, &base);
            }
            _ => {
                let mut got = vec![0; size as usize];
                ov.read_at(ReadBuf::new(&mut got), 0).unwrap();
                assert!(got == model, "{}", ctx(step, "full read differs"));
                for b in 0..blocks {
                    assert_eq!(
                        ov.is_allocated(b),
                        touched[b as usize],
                        "{}",
                        ctx(step, &format!("block {b} allocation"))
                    );
                }
            }
        }
    }
    ov.shutdown().unwrap();
    drop(ov);
    let ov = open(&file, &base);
    let mut got = vec![0; size as usize];
    ov.read_at(ReadBuf::new(&mut got), 0).unwrap();
    assert!(got == model, "{}", ctx(steps, "after the final reopen"));
    assert_eq!(base.contents(), base_pattern(size), "the base was written");
    // Unallocated blocks were never written in the file (it stays sparse);
    // allocated ones were written whole.
    let c = file.contents();
    let data_off = ov.header().data_offset as usize;
    for b in 0..blocks {
        let s = data_off + (b * bs64) as usize;
        let e = (s + bs as usize).min(c.len());
        if !touched[b as usize] {
            let untouched = c[s..e].iter().all(|&x| x == SENTINEL);
            assert!(
                untouched,
                "{}",
                ctx(steps, &format!("unwritten block {b} was written"))
            );
        } else {
            // Written whole: a sentinel byte left is one the guest wrote.
            let m = &model[(b * bs64) as usize..];
            let whole = c[s..e]
                .iter()
                .zip(m)
                .all(|(&x, &y)| x != SENTINEL || y == SENTINEL);
            assert!(
                whole,
                "{}",
                ctx(steps, &format!("block {b} was not written whole"))
            );
        }
    }
}

#[test]
fn overlay_matches_model() {
    for (seed, bs, size, steps) in [
        (1, 512, 37 * 512 + 100, 3000),
        (2, 4096, 20 * 4096, 3000),
        (3, 4096, 9 * 4096 + 1, 3000),
        (4, 64 << 10, 3 * (64 << 10) + 3 * 4096, 2000),
        (5, 512, 4096, 2000),
        (6, 1024, 1, 200),
        // More than one bitmap page (32768 blocks per page).
        (7, 512, 40_000 * 512 + 512, 400),
    ] {
        run(seed, bs, size, steps);
    }
}
