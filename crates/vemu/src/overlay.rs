//! `vemu overlay create|info`: golden images and their overlays (the format
//! and the backend are in vemu-disk).

use std::fmt::Write as _;
use std::path::Path;

use vemu_disk::{BaseStatus, OverlayInfo};

use crate::cli::{OverlayCommand, overlay_usage};

/// Run the subcommand; returns the process exit status.
pub fn run(cmd: &OverlayCommand) -> i32 {
    match cmd {
        OverlayCommand::Help => {
            print!("{}", overlay_usage());
            0
        }
        OverlayCommand::Create {
            base,
            overlay,
            block_size,
        } => match vemu_disk::create(base, overlay, *block_size) {
            Ok(h) => {
                println!(
                    "created {}: an overlay on {} ({}, {} blocks)",
                    overlay.display(),
                    h.base_path.display(),
                    size(h.virtual_size),
                    size(u64::from(h.block_size)),
                );
                0
            }
            Err(e) => {
                eprintln!("vemu: overlay create: {e}");
                1
            }
        },
        OverlayCommand::Info { overlay } => match vemu_disk::info(overlay) {
            Ok(info) => {
                print!("{}", describe(overlay, &info));
                i32::from(info.base_status != BaseStatus::Ok)
            }
            Err(e) => {
                eprintln!("vemu: overlay info: {}: {e}", overlay.display());
                1
            }
        },
    }
}

/// The `info` report.
pub fn describe(path: &Path, i: &OverlayInfo) -> String {
    let h = &i.header;
    let mut s = String::new();
    let _ = writeln!(s, "overlay:        {}", path.display());
    let _ = writeln!(
        s,
        "format:         vemu overlay, version {}",
        vemu_disk::VERSION
    );
    let _ = writeln!(
        s,
        "virtual size:   {} ({} bytes)",
        size(h.virtual_size),
        h.virtual_size
    );
    let _ = writeln!(s, "block size:     {}", size(u64::from(h.block_size)));
    let stored = if h.base_path.is_absolute() {
        "absolute"
    } else {
        "relative to the overlay's directory"
    };
    let _ = writeln!(
        s,
        "golden image:   {} (stored {stored}: {})",
        i.base_path.display(),
        h.base_path.display()
    );
    let _ = writeln!(
        s,
        "fingerprint:    size {}, modified {}, sample digest {:016x}",
        h.base.size,
        timestamp(h.base.mtime_ns),
        h.base.digest
    );
    match &i.base_status {
        BaseStatus::Ok => {
            let _ = writeln!(s, "golden status:  ok (unchanged)");
        }
        BaseStatus::Unusable(why) => {
            let _ = writeln!(s, "golden status:  UNUSABLE: {why}");
        }
    }
    let blocks = h.blocks();
    let _ = writeln!(
        s,
        "allocated:      {} of {} blocks, {} ({:.1}%)",
        i.allocated_blocks,
        blocks,
        size(i.allocated_bytes),
        i.allocated_bytes as f64 * 100.0 / h.virtual_size as f64
    );
    let _ = writeln!(
        s,
        "file:           {} on disk ({} apparent, sparse)",
        size(i.disk_usage),
        size(i.file_size)
    );
    if i.in_use {
        let _ = writeln!(
            s,
            "in use:         a running VM has it open read-write; blocks it has not \
             flushed yet are not counted"
        );
    }
    s
}

/// Seconds since the epoch, with nanoseconds.
fn timestamp(ns: i64) -> String {
    format!(
        "{}.{:09}",
        ns.div_euclid(1_000_000_000),
        ns.rem_euclid(1_000_000_000)
    )
}

/// `bytes` in binary units: "512 B", "4 KiB", "1.5 GiB".
pub fn size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut unit = 0;
    let mut v = bytes as f64;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 || v.fract() == 0.0 {
        format!("{v:.0} {}", UNITS[unit])
    } else {
        format!("{v:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(512), "512 B");
        assert_eq!(size(4096), "4 KiB");
        assert_eq!(size(64 << 20), "64 MiB");
        assert_eq!(size(3 << 29), "1.5 GiB");
    }

    #[test]
    fn create_and_info() {
        let dir = std::env::temp_dir().join(format!("vemu-overlay-cmd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let golden = dir.join("golden.raw");
        std::fs::write(&golden, vec![7u8; 1 << 20]).unwrap();
        let ov = dir.join("vm.vov");
        let create = OverlayCommand::Create {
            base: golden.clone(),
            overlay: ov.clone(),
            block_size: 64 << 10,
        };
        assert_eq!(run(&create), 0);
        assert_eq!(run(&create), 1, "an existing overlay is not overwritten");
        let info = vemu_disk::info(&ov).unwrap();
        let text = describe(&ov, &info);
        assert!(
            text.contains("virtual size:   1 MiB (1048576 bytes)"),
            "{text}"
        );
        assert!(text.contains("block size:     64 KiB"), "{text}");
        assert!(
            text.contains("relative to the overlay's directory: golden.raw"),
            "{text}"
        );
        assert!(text.contains("golden status:  ok"), "{text}");
        assert!(
            text.contains("allocated:      0 of 16 blocks, 0 B (0.0%)"),
            "{text}"
        );
        assert_eq!(
            run(&OverlayCommand::Info {
                overlay: ov.clone()
            }),
            0
        );
        // A changed golden image: reported, exit status 1.
        std::fs::write(&golden, vec![8u8; 1 << 20]).unwrap();
        let info = vemu_disk::info(&ov).unwrap();
        assert!(describe(&ov, &info).contains("UNUSABLE: changed"));
        assert_eq!(
            run(&OverlayCommand::Info {
                overlay: ov.clone()
            }),
            1
        );
        assert_eq!(
            run(&OverlayCommand::Info { overlay: golden }),
            1,
            "not an overlay"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
