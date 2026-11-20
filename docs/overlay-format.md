# vemu overlay format, version 1

A vemu overlay is a file that holds a VM's writes on top of a read-only
**golden image** (the base: a raw disk image). The VM sees a virtual disk
the size of the golden image. Blocks the VM has written come from the
overlay; every other block comes from the golden image, which is never
written. Any number of overlays, and so any number of VMs, can share one
golden image.

This document specifies the file format and the rules an implementation
must follow to keep an overlay consistent across crashes. The
implementation is `crates/vemu-disk` (`format.rs` for the layout,
`overlay.rs` for I/O, flushes and concurrency, `image.rs` for files, locks
and fingerprints).

There is no commit-back to the golden image and no chaining: the golden
image of an overlay is always a raw image.

## Layout

All integers are little-endian. Offsets are in bytes from the start of the
file.

```
0                header: fixed fields (88 bytes), then the base path
bitmap_offset    allocation bitmap, one bit per block
data_offset      the virtual disk: guest byte X is stored at data_offset + X
data_offset + virtual_size    end of file
```

The file is created with its full length (`data_offset + virtual_size`) and
stays **sparse**: the bitmap and the data region start as holes, and only
blocks the guest writes are ever written. An implementation must never
write zeros (or anything) for a block it does not allocate.

### Header

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 8 | `magic` | `"VEMUOVL\0"` (`56 45 4d 55 4f 56 4c 00`) |
| 8 | 4 | `version` | 1 |
| 12 | 4 | `header_len` | 88 + `path_len`: the bytes the checksum covers |
| 16 | 4 | `block_size` | allocation unit in bytes: a power of two, 512 to 2 MiB |
| 20 | 4 | `flags` | 0. Readers refuse any other value (reserved for incompatible features) |
| 24 | 8 | `virtual_size` | size of the virtual disk; equals `base_size` |
| 32 | 8 | `bitmap_offset` | start of the bitmap; a multiple of 4096, at least `header_len` |
| 40 | 8 | `bitmap_len` | ceil(ceil(`virtual_size` / `block_size`) / 8) bytes |
| 48 | 8 | `data_offset` | start of the data region; a multiple of `block_size`, at least `bitmap_offset + bitmap_len` |
| 56 | 8 | `base_size` | golden image fingerprint: size in bytes |
| 64 | 8 | `base_mtime_ns` | fingerprint: modification time, signed nanoseconds since the Unix epoch |
| 72 | 8 | `base_digest` | fingerprint: sampled content digest (below) |
| 80 | 2 | `path_len` | length of the base path, 1 to 4096 |
| 82 | 2 | reserved | 0 |
| 84 | 4 | `checksum` | CRC-32C of bytes `[0, header_len)` with this field set to 0 |
| 88 | `path_len` | `base_path` | the golden image's path, raw bytes, no terminator |

Version 1 writers lay the file out as follows (readers accept any layout
that satisfies the constraints in the table):

- `bitmap_offset` = `header_len` rounded up to 4096 (so 4096 for any path
  shorter than 4008 bytes);
- `data_offset` = `bitmap_offset + bitmap_len` rounded up to
  max(`block_size`, 4096).

CRC-32C is the Castagnoli CRC (reflected polynomial `0x82F63B78`, initial
value and final XOR `0xFFFFFFFF`; `"123456789"` gives `0xE3069283`).

The header is written once, when the overlay is created, and never again.

### Base path

`base_path` names the golden image. It is stored **relative to the
directory that contains the overlay** when the canonical paths of that
directory and of the golden image share more than the root directory (for
example `golden.raw`, or `../../images/golden.raw`), so a directory tree
holding both can be moved or copied as a whole. Otherwise (they only share
`/`, typically on different volumes) it is stored absolute. A relative
path is resolved against the directory of the overlay's canonical path
(symbolic links to the overlay are followed first).

Throwaway snapshot overlays store the golden image's absolute canonical
path.

### Fingerprint

A golden image that changes after an overlay was made on it silently
corrupts the overlay: its blocks were copied from, and assume, the old
contents. So an overlay records the golden image's fingerprint and is
refused, with a message naming what differs, unless all three fields match
when it is opened:

- `base_size`: the size;
- `base_mtime_ns`: the modification time (`stat` `st_mtime` with
  nanoseconds), which catches any write through the filesystem;
- `base_digest`: FNV-1a 64 (offset basis `0xcbf29ce484222325`, prime
  `0x100000001b3`) over, in order: `base_size` as 8 little-endian bytes,
  then for each sampled window its offset as 8 little-endian bytes followed
  by its bytes. Windows are 64 KiB. An image of at most 16 windows (1 MiB)
  is hashed completely, window by window from offset 0 (the last one may be
  shorter). A larger image is sampled with 16 windows at offsets
  `floor((size - 65536) * i / 15)` for `i` = 0..15 (the first and the last
  64 KiB included).

The digest costs at most 1 MiB of reads, whatever the size of the golden
image, and catches a replaced image whose modification time was preserved
or restored (`cp -p`, `rsync -t`, `touch -r`, a restored backup). Nothing
cheap catches every change: a modification outside the sampled windows with
the modification time forged back is not detected. Copying a golden image
without preserving its modification time makes overlays refuse it, which
is the safe failure.

### Allocation bitmap

Bit `b` of the bitmap is bit `b mod 8` (least significant first) of byte
`b / 8`, at `bitmap_offset + b / 8`. Bit `b` set means that block `b`, the
virtual bytes `[b * block_size, min((b + 1) * block_size, virtual_size))`,
is held by the overlay at `data_offset + b * block_size`. A clear bit means
the block reads from the golden image at the same offset. Bits past the
last block are written as 0 and ignored when read.

Bits only ever go from 0 to 1 (there is no discard and no commit), which is
what makes a torn bitmap write harmless (see below).

Implementations keep the bitmap in memory and write it in 4096-byte pages
(the last page is shorter if `bitmap_len` is not a multiple of 4096). With
4 KiB blocks one page covers 128 MiB of virtual disk.

## Reading and writing

- **Read**: split the request into runs of blocks with the same bit; read
  allocated runs from the data region and the others from the golden
  image. An allocated block is never read from the golden image.
- **Write to allocated blocks**: write in place in the data region.
- **Write that covers whole unallocated blocks**: write them in place, then
  set their bits.
- **Partial write to an unallocated block (copy-up)**: read the block from
  the golden image, merge the new bytes, write the whole block to the data
  region, then set its bit. A write that spans several blocks does this for
  at most its first and last block.

Data for a newly allocated block is always written before its bit is set
in memory, and the bit in memory before it is persisted (next section).

## Durability and crash consistency

The bitmap is persisted at a guest `FLUSH` and at a clean exit, in this
order, with one flush at a time:

1. take a copy of the bitmap pages that changed since the last flush; every
   bit in the copy belongs to a block whose data write has completed;
2. sync the overlay file (`fcntl(F_FULLFSYNC)` on macOS, `fdatasync` on
   Linux): the data of those blocks, and every completed overwrite, is
   durable;
3. write the copied pages;
4. sync again.

The guest's flush completes after step 4. Taking the copy before step 2 is
essential: a block allocated by a write that completes during step 2 must
not have its bit persisted by this flush. Flushes must not overlap: an older
copy written after a newer one would clear bits the newer one made durable.

What a crash (power loss, `SIGKILL`, a host panic) can do:

- Writes not covered by a completed flush may be lost, as virtio allows. A
  block allocated since the last flush has no bit on disk, so it reads from
  the golden image again; the stale data left in its place in the data
  region is never read, and the next write to it copies it up again,
  overwriting it whole.
- An allocated block rewritten since the last flush reads as its old or its
  new contents (torn at sector granularity at worst, like a raw disk).
- A torn bitmap page write leaves each byte old or new; both are valid,
  because bits only go from 0 to 1 and every new bit's data was durable
  before the page was written.
- The header is never rewritten, so it cannot be torn after creation.

So after any crash the overlay opens, and a block whose write completed
before a completed flush never reads as zeros, garbage, or the golden
image's data. No journal and no clean-shutdown flag are needed: a flag
could only report that unflushed writes may have been lost, which is true
of every crash and allowed. The randomized crash test in
`crates/vemu-disk/src/tests_crash.rs` cuts the power at every write and
sync of the overlay file, keeps any subset of the unsynced writes (whole,
dropped or torn per sector) and checks these guarantees.

A failed flush is final. If any step fails (a sync reporting `EIO`, or
`ENOSPC`/`EDQUOT` at writeback on thin or network storage; a bitmap page
write), the overlay takes no more writes or flushes for as long as it is
open: every later write, guest `FLUSH` and the exit-time flush fail with an
I/O error and touch nothing, and vemu exits with an error saying the writes
since the last completed flush are lost. A failed sync cannot be retried:
Linux reports a writeback error once and marks the failed pages clean, so
the next `fdatasync` returns 0 although that data never reached the disk
(the PostgreSQL "fsyncgate" behaviour), and macOS promises nothing better.
A retried flush would persist bits for blocks whose data region is still a
hole, and those blocks would read as zeros. Failing instead keeps the
on-disk bitmap at the last completed flush, which is consistent; the next
run of the overlay starts from it. `tests_crash.rs` also checks this: one
sync fails and drops the pending writes, later syncs succeed, and the guest
retries its flushes and exits cleanly.

Throwaway snapshots are never synced: their file is discarded at exit, so a
guest `FLUSH` on a snapshot does nothing. They use 4 KiB blocks (larger ones
only for golden images above 4 TiB, to fit the bitmap limit). Their file is
in the temporary directory: `$TMPDIR` if it is set and not empty (a
relative one is taken from the current directory), else the system's
(`confstr(_CS_DARWIN_USER_TEMP_DIR)` on macOS, `/tmp` elsewhere). It never has a name on Linux (`O_TMPFILE`, on filesystems that
support it: tmpfs, ext4, XFS, btrfs). Elsewhere it is created with a
unique name and unlinked by the next system call, so only a `SIGKILL` in
the microseconds between the two leaves a `vemu-snapshot-*.vov` file
behind, empty (0 bytes, mode 0600, no guest or golden data).

## Locking

Every file is locked with `flock` without waiting, for as long as the disk
is open:

| File | Lock |
|---|---|
| overlay, read-write | `LOCK_EX` |
| overlay, read-only (`,ro`) | `LOCK_SH` |
| golden image of an overlay or snapshot | `LOCK_SH` |
| raw disk, read-write | `LOCK_EX` |
| raw disk, read-only | `LOCK_SH` |

Any number of VMs share a golden image, while none can open it read-write
(a conflict is refused, and the message says whether readers, such as
overlays, or a writer hold it). `flock` cannot name the holder, so when
two disks of one VM conflict (the same overlay twice, or an overlay and
its golden image read-write), vemu finds the earlier `--disk` that uses
the same file (by device and inode) and names it. `vemu overlay info`
takes `LOCK_SH` only as a probe, released at once, to learn whether a VM
writes the overlay; it then reads without a lock, so a VM can start while
it runs.

## Block size

The default block size is **4 KiB**, chosen against 64 KiB as follows.

- Write amplification: Linux guests write in 4 KiB pages and filesystem
  blocks, which are whole blocks at 4 KiB, so they never copy up. At 64 KiB
  the first 4 KiB write into each 64 KiB region reads 64 KiB from the
  golden image and writes 64 KiB, and the overlay grows by 64 KiB: 16 times
  the I/O and the space for scattered writes.
- Host space: 4 KiB is the allocation unit of APFS, ext4 and XFS, so the
  overlay's holes line up with the host's.
- Bitmap: one bit per block is 32 KiB of bitmap (memory and file) per GiB at
  4 KiB, 2 KiB per GiB at 64 KiB: 3.2 MiB for a 100 GiB golden image at
  4 KiB. Bitmaps are limited to 128 MiB (4 TiB at 4 KiB blocks); larger
  images need a larger block size.
- Reads: runs of differently allocated blocks cost one `pread` each, so
  very fragmented overlays read in smaller pieces at 4 KiB. This matters
  less than the write side.

`vemu overlay create --block-size` accepts 512 bytes to 2 MiB. A larger
block size suits huge images and sequential workloads.

## Format detection

`--disk PATH` opens `PATH` as an overlay when its first 8 bytes are the
magic, whatever its name; anything else is a raw image. A file with the
magic whose header is invalid (bad checksum, unknown version, unsupported
flags, impossible layout, truncated file) is refused, with a hint to give
it as `format=raw` if it really is a raw image that happens to start with
the magic. Such an image cannot be the golden image of an overlay or a
snapshot: a golden image that starts with the magic is refused as a chain.

Detection is a classic hole (QEMU's CVE-2008-2004): a guest writing to its
raw disk could plant an overlay header naming any file the host user can
read as its "golden image", and read that file after the next boot. So when
the format of a read-write raw disk was detected (not given as
`format=raw`), vemu refuses guest writes that would make the image's first
8 bytes equal the magic (the guest sees an I/O error, and vemu logs it
once). `format=raw` turns detection and the guard off; `format=overlay`
requires an overlay.

## Compatibility

A reader refuses a bad magic, a `version` other than 1, a bad checksum and
nonzero `flags`. Future versions that keep this layout readable by version 1
readers keep `version` 1 and must not set flags; anything else bumps the
version.

## Host filesystems

The format never writes a block the guest did not write. How much host space
the holes cost is up to the filesystem: ext4 and XFS keep them exactly
(`overlay_file_stays_sparse` checks this bound on Linux). APFS fills holes
of up to about 16 MiB ahead of a file's last allocated extent when the file
is written forward, so on macOS an overlay can take more space than the
blocks it holds (in the e2e test, 24 MiB on disk for 16 MiB of blocks), as
much as a raw image receiving the same writes would. `vemu overlay info`
shows both.
