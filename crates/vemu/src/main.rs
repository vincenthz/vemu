//! vemu: boot a Linux guest on the host's hypervisor (Hypervisor.framework
//! on macOS/aarch64, KVM on Linux), with no CPU emulation. The guest
//! architecture is the host's.
//!
//! See DESIGN.md and docs/kvm-design.md for the machine models. Modules:
//!
//! - [`cli`]: command line;
//! - [`machine`]: assembling and running the machine (common to all
//!   architectures);
//! - [`arch`]: the guest-architecture machine models behind
//!   [`arch::ArchMachine`] (aarch64: layout, `Image` loader, device tree,
//!   PL011; x86_64: placeholder);
//! - [`bootfile`]: kernel/initrd file checks and initrd loading;
//! - [`overlay`]: the `vemu overlay` subcommand (golden images);
//! - [`build`]: the `vemu build` subcommand (Alpine images made by a
//!   builder VM; the host side is the vemu-build crate);
//! - [`vcpu`], [`power`]: vCPU threads, machine shutdown;
//! - [`bus`], [`irq`]: MMIO and port-I/O dispatch, interrupt lines;
//! - [`serial`], [`terminal`]: the console's host side and raw terminal
//!   mode.

/// Log a VMM message on stderr (`vemu: ...`), terminal-mode aware.
macro_rules! log {
    ($($arg:tt)*) => {
        $crate::terminal::log_line(format_args!($($arg)*))
    };
}
pub(crate) use log;

mod arch;
mod bootfile;
mod build;
mod bus;
mod cli;
mod irq;
mod machine;
mod overlay;
mod power;
mod serial;
mod terminal;
mod vcpu;

use std::process::ExitCode;

use power::Exit;

fn main() -> ExitCode {
    // A panic anywhere (a vCPU or device thread included) leaves the machine
    // in an unknown state: restore the terminal, report, and exit. exit()
    // runs no destructors, so a build's temporary files and OUT.partial are
    // removed here (vemu_build::cleanup).
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        terminal::restore();
        vemu_build::cleanup::run_now();
        default_hook(info);
        std::process::exit(101);
    }));

    let cfg = match cli::parse(std::env::args_os().skip(1)) {
        Ok(cli::Command::Run(cfg)) => cfg,
        Ok(cli::Command::Help) => {
            print!("{}", cli::usage());
            return ExitCode::SUCCESS;
        }
        Ok(cli::Command::Version) => {
            println!("vemu {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Ok(cli::Command::Overlay(cmd)) => return ExitCode::from(overlay::run(&cmd) as u8),
        Ok(cli::Command::BuildHelp) => {
            print!("{}", cli::build_usage());
            return ExitCode::SUCCESS;
        }
        Ok(cli::Command::Build(opts)) => {
            let status = build::run(&opts);
            terminal::restore();
            std::process::exit(status);
        }
        Err(e) => {
            let first = std::env::args_os().nth(1);
            let usage = if first.as_ref().is_some_and(|a| a == "overlay") {
                cli::overlay_usage()
            } else if first.as_ref().is_some_and(|a| a == "build") {
                cli::build_usage()
            } else {
                cli::usage()
            };
            eprintln!("vemu: {e}\n\n{usage}");
            return ExitCode::from(2);
        }
    };

    let result = machine::run(&cfg);
    terminal::restore();
    let status = match result {
        Ok(Exit::Error(e)) => {
            log!("error: {e}");
            1
        }
        Ok(Exit::Reset) => {
            log!("guest requested a reset; exiting (reboot is not supported)");
            0
        }
        Ok(Exit::Timeout(t)) => {
            log!("timed out after {} s", t.as_secs());
            1
        }
        Ok(exit) => exit.status(),
        Err(e) => {
            log!("{e}");
            1
        }
    };
    // Exit right away: vCPU threads that did not wind down in time (or the
    // console input thread blocked in read) must not keep the process alive.
    std::process::exit(status)
}

#[cfg(test)]
mod test_support {
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Held by tests while they spawn a child process, and by tests that
    /// need a closed fd to be really gone (a dead socket, a released
    /// `flock`): between fork and exec the child holds a copy of every fd.
    static FORK_LOCK: Mutex<()> = Mutex::new(());

    pub fn fork_lock() -> MutexGuard<'static, ()> {
        FORK_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
