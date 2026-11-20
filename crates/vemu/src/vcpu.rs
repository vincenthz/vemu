//! vCPU threads.
//!
//! A vCPU belongs to the thread that creates it (HVF requirement; KVM runs
//! it there too), so each vCPU gets a dedicated thread for its whole life:
//!
//! 1. create the vCPU and report success or failure to the main thread,
//!    which starts the threads one at a time, in index order (KVM numbers
//!    vCPUs in creation order, see `machine::start_vcpus`), and waits until
//!    *all* vCPUs exist and the VM is finalized (so the interrupt
//!    controller's topology is final before the guest looks at it) before
//!    releasing the threads;
//! 2. the boot vCPU gets its entry state (`Vcpu::set_boot_state`);
//! 3. run the guest, handling MMIO and port I/O via the buses, until the
//!    guest powers off or resets the machine, or the machine exits.
//!
//! Secondary vCPUs need nothing from the VMM to start: their `run()` blocks
//! inside the backend until the guest brings them up (PSCI `CPU_ON`,
//! INIT/SIPI), and blocks again after `CPU_OFF`.
//!
//! Shutdown: whoever ends the machine calls [`Control::request_exit`]; the
//! main thread then kicks every vCPU, whose `run()` returns `Kicked` and
//! whose loop sees the exit flag.

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread::{self, JoinHandle};

use vemu_hv::{BootState, SystemEvent, Vcpu, VcpuExit, Vm};

use crate::bus::{MmioBus, PortIoBus};
use crate::power::{Control, Exit};

/// What a vCPU thread needs.
pub struct VcpuContext {
    pub index: usize,
    pub vm: Arc<dyn Vm>,
    pub mmio: Arc<MmioBus>,
    pub pio: Arc<PortIoBus>,
    pub control: Arc<Control>,
    /// Entry state, for the boot vCPU only.
    pub boot: Option<BootState>,
}

/// Start the thread for vCPU `ctx.index`. It sends the result of creating
/// its vCPU on `created`, then waits for `start` before running it (and
/// exits without running if `start` is closed instead).
pub fn spawn(
    ctx: VcpuContext,
    created: Sender<Result<(), String>>,
    start: Receiver<()>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name(format!("vcpu{}", ctx.index))
        .spawn(move || thread_main(ctx, created, start))
}

fn thread_main(ctx: VcpuContext, created: Sender<Result<(), String>>, start: Receiver<()>) {
    let i = ctx.index;
    let mut vcpu = match ctx.vm.create_vcpu(i) {
        Ok(v) => {
            let _ = created.send(Ok(()));
            v
        }
        Err(e) => {
            let _ = created.send(Err(format!("cannot create vCPU {i}: {e}")));
            return;
        }
    };
    drop(created);
    if start.recv().is_err() {
        return;
    }
    let result = match &ctx.boot {
        Some(boot) => vcpu.set_boot_state(boot),
        None => Ok(()),
    }
    .and_then(|()| run(&ctx, vcpu.as_mut()));
    if let Err(e) = result {
        ctx.control
            .request_exit(Exit::Error(format!("vCPU {i}: {e}")));
    }
}

fn run(ctx: &VcpuContext, vcpu: &mut dyn Vcpu) -> vemu_hv::Result<()> {
    loop {
        if ctx.control.is_exiting() {
            return Ok(());
        }
        match vcpu.run()? {
            VcpuExit::MmioRead { addr, len } => {
                let v = ctx.mmio.read(addr, len);
                vcpu.complete_mmio_read(v)?;
            }
            VcpuExit::MmioWrite { addr, len, data } => ctx.mmio.write(addr, len, data),
            VcpuExit::IoIn { port, len } => {
                let v = ctx.pio.read(port, len);
                vcpu.complete_io_in(v)?;
            }
            VcpuExit::IoOut { port, len, data } => ctx.pio.write(port, len, data),
            VcpuExit::SystemEvent(event) => {
                ctx.control.request_exit(match event {
                    SystemEvent::Shutdown => Exit::PowerOff,
                    SystemEvent::Reset => Exit::Reset,
                });
                return Ok(());
            }
            // Not an SMCCC call: the backend already answered NOT_SUPPORTED.
            VcpuExit::Hvc { .. } => {}
            // The loop head checks why we were kicked.
            VcpuExit::Kicked => {}
        }
    }
}
