//! Machine assembly and lifetime, common to every guest architecture: VM,
//! RAM, devices and buses, vCPU threads, then waiting for the guest to
//! finish. What differs per architecture (boot images, guest-physical map,
//! firmware tables, architecture devices, boot vCPU state) comes from
//! [`crate::arch::Machine`].

use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vemu_core::GuestMemory;
use vemu_disk::BlockBackend;
use vemu_net::{UserNet, UserNetConfig};
use vemu_virtio::block::Block;
use vemu_virtio::console::Console;
use vemu_virtio::net::Net;
use vemu_virtio::{MmioTransport, VirtioDevice};

use crate::arch::{ArchMachine, BuildCtx, Machine};
use crate::bus::{MmioBus, PortIoBus};
use crate::cli::{Config, NetConfig};
use crate::irq::VmIrqLine;
use crate::power::{Control, Exit};
use crate::serial::Serial;
use crate::vcpu::{self, VcpuContext};

/// How long to wait for vCPU threads to wind down after the machine stops.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);
/// MAC address of the guest's virtio-net interface (qemu's default).
const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Build the machine described by `cfg`, run it until it stops and return
/// why. Errors are setup failures (bad files, hypervisor errors, ...).
pub fn run(cfg: &Config) -> Result<Exit, String> {
    // Everything that can fail on user input is checked before the VM exists.
    let arch = Machine::prepare(cfg)?;
    let cmdline = cfg.cmdline();
    if cmdline.len() >= Machine::CMDLINE_MAX {
        return Err(format!(
            "kernel command line is {} bytes; Linux accepts at most {}",
            cmdline.len(),
            Machine::CMDLINE_MAX - 1
        ));
    }
    let disks = open_disks(cfg)?;
    let net = start_network(&cfg.net)?;
    let mut serial = Serial::open(&cfg.serial).map_err(|e| format!("--serial: {e}"))?;

    let vm = vemu_hv::create_vm(&arch.vm_config(cfg))
        .map_err(|e| format!("cannot create the VM: {e}"))?;
    let info = vm.arch_info();

    // All of RAM is one GuestMemory (one region per range, holes between
    // them), so virtio DMA reaches every page. The VM maps it; it lives
    // until the process exits (devices hold references too).
    let ranges = arch
        .ram_regions(cfg)
        .iter()
        .map(|r| {
            usize::try_from(r.size)
                .map(|size| (r.gpa, size))
                .map_err(|_| format!("{} MiB of guest memory is too much", r.size >> 20))
        })
        .collect::<Result<Vec<_>, String>>()?;
    if ranges.is_empty() {
        return Err("the machine has no RAM".into());
    }
    let ram = GuestMemory::with_regions(&ranges).map_err(|e| {
        format!(
            "cannot allocate {} MiB of guest memory: {e}",
            cfg.memory >> 20
        )
    })?;
    vm.map_memory(&ram)
        .map_err(|e| format!("cannot map guest memory: {e}"))?;

    // Devices: virtio slots in DESIGN order (console, disks, net).
    let (console, console_input) = Console::new(serial.output());
    let mut devices: Vec<Box<dyn VirtioDevice>> = vec![Box::new(console)];
    devices.extend(
        disks
            .iter()
            .map(|d| Box::new(Block::with_backend(d.clone())) as Box<dyn VirtioDevice>),
    );
    if let Some(backend) = &net {
        devices.push(Box::new(Net::new(GUEST_MAC, backend.clone())));
    }
    if devices.len() > Machine::VIRTIO_SLOTS {
        return Err(format!(
            "too many devices: {} virtio devices, {} slots",
            devices.len(),
            Machine::VIRTIO_SLOTS
        ));
    }

    let mut mmio = MmioBus::new();
    let mut pio = PortIoBus::new();
    let mut slots = Vec::with_capacity(devices.len());
    for (n, dev) in devices.into_iter().enumerate() {
        let slot = arch.virtio_slot(&info, n)?;
        let name = format!("virtio{n} (type {})", dev.device_type());
        let irq = Arc::new(VmIrqLine::new(vm.clone(), slot.irq));
        let transport = MmioTransport::new(dev, ram.clone(), irq);
        mmio.insert(name, slot.base, slot.size, Arc::new(Mutex::new(transport)))?;
        slots.push(slot);
    }

    let control = Arc::new(Control::new());
    let setup = arch.build(BuildCtx {
        cfg,
        cmdline: &cmdline,
        vm: &vm,
        info: &info,
        ram: &ram,
        virtio: &slots,
        mmio: &mut mmio,
        pio: &mut pio,
        control: &control,
    })?;

    // vCPU threads: create all vCPUs, finalize the VM, then run them.
    let (mmio, pio) = (Arc::new(mmio), Arc::new(pio));
    let (threads, starts): (Vec<_>, Vec<_>) = start_vcpus(cfg.cpus, |index| VcpuContext {
        index,
        vm: vm.clone(),
        mmio: mmio.clone(),
        pio: pio.clone(),
        control: control.clone(),
        boot: (index == 0).then_some(setup.boot),
    })?
    .into_iter()
    .unzip();
    vm.finalize()
        .map_err(|e| format!("cannot finalize the VM: {e}"))?;

    serial
        .start_input(console_input, control.clone())
        .map_err(|e| format!("console input: {e}"))?;

    for start in starts {
        // Every thread is waiting for this (none ends before it).
        let _ = start.send(());
    }
    let mut exit = control.wait_for_exit_or(cfg.timeout);

    for i in 0..cfg.cpus {
        vm.kick(i);
    }
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while threads.iter().any(|t| !t.is_finished()) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    for t in threads.into_iter().filter(|t| t.is_finished()) {
        // A panicking vCPU thread has already ended the process (panic hook).
        let _ = t.join();
    }
    // Persist what a clean exit keeps (overlay bitmaps). Safe even if a
    // vCPU thread did not stop and is still in a disk request.
    for (d, backend) in cfg.disks.iter().zip(&disks) {
        if let Err(e) = backend.shutdown() {
            let msg = format!(
                "disk {}: cannot save the overlay at exit (writes since the guest's last \
                 flush may be lost): {e}",
                d.path.display()
            );
            if matches!(exit, Exit::Error(_)) {
                log!("{msg}");
            } else {
                exit = Exit::Error(msg);
            }
        }
    }
    // Let data the guest already sent reach host sockets, then close them.
    if let Some(net) = net {
        net.shutdown();
    }
    Ok(exit)
}

/// A started vCPU thread and the sender that releases it into the guest.
type VcpuThread = (JoinHandle<()>, mpsc::Sender<()>);

/// Start the threads of vCPUs `0..cpus` (contexts from `ctx`) and wait
/// until each has created its vCPU, one at a time: thread `i + 1` starts
/// only once vCPU `i` exists, because KVM numbers vCPUs in creation order
/// and that number must match the index (the vGICv2 routes interrupts by
/// it). Returns each thread with the sender that releases it into the
/// guest. Never waits for a thread that is not running: on the first
/// failure no further thread starts, and dropping the senders makes the
/// threads already started exit.
fn start_vcpus(
    cpus: usize,
    mut ctx: impl FnMut(usize) -> VcpuContext,
) -> Result<Vec<VcpuThread>, String> {
    let mut started = Vec::with_capacity(cpus);
    for index in 0..cpus {
        let (created_tx, created_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let thread = vcpu::spawn(ctx(index), created_tx, start_rx)
            .map_err(|e| format!("cannot start vCPU thread {index}: {e}"))?;
        // The thread sends exactly one result, or dies (dropping the
        // sender, which ends the wait too).
        match created_rx.recv() {
            Ok(Ok(())) => started.push((thread, start_tx)),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(format!("vCPU thread {index} died during setup")),
        }
    }
    Ok(started)
}

/// Start the user-mode network backend (binding the host forwards), if any.
fn start_network(net: &NetConfig) -> Result<Option<Arc<UserNet>>, String> {
    match net {
        NetConfig::None => Ok(None),
        NetConfig::User { hostfwd } => {
            let cfg = UserNetConfig {
                guest_mac: GUEST_MAC,
                hostfwd: hostfwd.clone(),
                ..UserNetConfig::default()
            };
            UserNet::new(cfg)
                .map(Some)
                .map_err(|e| format!("--net user: {e}"))
        }
    }
}

/// Open every `--disk` (raw image, overlay or snapshot, see
/// [`vemu_disk::open`]), taking its locks. A lock conflict with a disk
/// given earlier on the command line says so, instead of blaming another
/// process ([`vemu_disk::conflict_within`]).
fn open_disks(cfg: &Config) -> Result<Vec<Arc<dyn BlockBackend>>, String> {
    let mut disks = Vec::with_capacity(cfg.disks.len());
    for (i, d) in cfg.disks.iter().enumerate() {
        match vemu_disk::open(&d.path, d.options()) {
            Ok(b) => disks.push(b),
            Err(e) => {
                let within = (e.kind() == std::io::ErrorKind::WouldBlock)
                    .then(|| {
                        let earlier: Vec<_> = cfg.disks[..i]
                            .iter()
                            .map(|d| (d.path.as_path(), d.options()))
                            .collect();
                        vemu_disk::conflict_within(&earlier, &d.path, d.options())
                    })
                    .flatten();
                let msg = within.unwrap_or_else(|| e.to_string());
                return Err(format!("disk {}: {msg}", d.path.display()));
            }
        }
    }
    Ok(disks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    fn temp_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("vemu-machine-{name}-{}", std::process::id()))
    }

    fn config(args: &[&str]) -> Config {
        match crate::cli::parse(args.iter().map(Into::into)) {
            Ok(crate::cli::Command::Run(cfg)) => cfg,
            _ => panic!("bad test command line {args:?}"),
        }
    }

    /// A [`vemu_hv::Vm`] whose `create_vcpu` records the calls and fails
    /// (`Err`, or a panic) for one index.
    struct FakeVm {
        fail: Option<(usize, bool)>,
        /// (index, calling thread, vCPUs alive at the call).
        calls: Mutex<Vec<(usize, std::thread::ThreadId, usize)>>,
        live: Arc<AtomicUsize>,
    }

    struct FakeVcpu {
        index: usize,
        live: Arc<AtomicUsize>,
    }

    impl Drop for FakeVcpu {
        fn drop(&mut self) {
            self.live.fetch_sub(1, SeqCst);
        }
    }

    impl vemu_hv::Vm for FakeVm {
        fn arch_info(&self) -> vemu_hv::ArchVmInfo {
            unreachable!("not used")
        }
        fn map_memory(&self, _: &Arc<GuestMemory>) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn set_irq_line(&self, _: u32, _: bool) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn create_vcpu(&self, index: usize) -> vemu_hv::Result<Box<dyn vemu_hv::Vcpu>> {
            let live = self.live.load(SeqCst);
            self.calls
                .lock()
                .unwrap()
                .push((index, std::thread::current().id(), live));
            match self.fail {
                Some((i, false)) if i == index => {
                    return Err(vemu_hv::Error::invalid("create_vcpu", "fake failure"));
                }
                Some((i, true)) if i == index => panic!("fake vCPU {index} panics"),
                _ => {}
            }
            self.live.fetch_add(1, SeqCst);
            Ok(Box::new(FakeVcpu {
                index,
                live: self.live.clone(),
            }))
        }
        fn finalize(&self) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn kick(&self, _: usize) {}
    }

    impl vemu_hv::Vcpu for FakeVcpu {
        fn index(&self) -> usize {
            self.index
        }
        fn set_boot_state(&mut self, _: &vemu_hv::BootState) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn run(&mut self) -> vemu_hv::Result<vemu_hv::VcpuExit> {
            Ok(vemu_hv::VcpuExit::Kicked)
        }
        fn complete_mmio_read(&mut self, _: u64) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn complete_io_in(&mut self, _: u32) -> vemu_hv::Result<()> {
            Ok(())
        }
        fn get_reg(&self, _: vemu_hv::Reg) -> vemu_hv::Result<u64> {
            Ok(0)
        }
        fn set_reg(&mut self, _: vemu_hv::Reg, _: u64) -> vemu_hv::Result<()> {
            Ok(())
        }
    }

    type Started = Result<Vec<VcpuThread>, String>;

    /// `start_vcpus(cpus)` on a fake VM, on another thread so that a hang
    /// fails the test instead of blocking it.
    fn start_fake(cpus: usize, fail: Option<(usize, bool)>) -> (Arc<FakeVm>, Started) {
        let vm = Arc::new(FakeVm {
            fail,
            calls: Mutex::new(Vec::new()),
            live: Arc::new(AtomicUsize::new(0)),
        });
        let (tx, rx) = mpsc::channel();
        let fake = vm.clone();
        std::thread::spawn(move || {
            let (mmio, pio) = (Arc::new(MmioBus::new()), Arc::new(PortIoBus::new()));
            let control = Arc::new(Control::new());
            let started = start_vcpus(cpus, |index| VcpuContext {
                index,
                vm: fake.clone(),
                mmio: mmio.clone(),
                pio: pio.clone(),
                control: control.clone(),
                boot: None,
            });
            let _ = tx.send(started);
        });
        let started = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("start_vcpus hung");
        (vm, started)
    }

    /// Wait (bounded) until no fake vCPU is alive, i.e. their threads ended.
    fn wait_all_dropped(vm: &FakeVm) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while vm.live.load(SeqCst) != 0 {
            assert!(Instant::now() < deadline, "vCPU threads did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// vCPUs are created one at a time in index order (KVM numbers them in
    /// creation order), each on its own thread.
    #[test]
    fn vcpus_are_created_in_index_order() {
        let (vm, started) = start_fake(4, None);
        let started = started.unwrap();
        let calls = vm.calls.lock().unwrap().clone();
        assert_eq!(
            calls
                .iter()
                .map(|&(i, _, live)| (i, live))
                .collect::<Vec<_>>(),
            [(0, 0), (1, 1), (2, 2), (3, 3)],
            "vCPU i is created once vCPUs 0..i exist"
        );
        let mut threads: Vec<_> = calls.iter().map(|c| c.1).collect();
        threads.sort_unstable_by_key(|t| format!("{t:?}"));
        threads.dedup();
        assert_eq!(threads.len(), 4, "one thread per vCPU");
        assert!(!threads.contains(&std::thread::current().id()));
        // Dropping the start senders makes every thread exit unrun.
        for (t, start) in started {
            drop(start);
            t.join().unwrap();
        }
        assert_eq!(vm.live.load(SeqCst), 0);
    }

    /// A vCPU that cannot be created (error or dead thread) stops the
    /// setup without a hang: later vCPUs are not attempted and the threads
    /// already started exit.
    #[test]
    fn failed_vcpu_creation_does_not_hang() {
        for panics in [false, true] {
            let (vm, started) = start_fake(4, Some((1, panics)));
            let e = started.expect_err("vCPU 1 failed");
            if panics {
                assert!(e.contains("vCPU thread 1 died"), "{e}");
            } else {
                assert!(
                    e.contains("cannot create vCPU 1") && e.contains("fake failure"),
                    "{e}"
                );
            }
            let indices: Vec<_> = vm.calls.lock().unwrap().iter().map(|c| c.0).collect();
            assert_eq!(indices, [0, 1], "nothing after the failure");
            wait_all_dropped(&vm);
        }
    }

    #[test]
    fn disk_in_use_is_refused_with_its_path() {
        // A child spawned meanwhile would hold the locks of dropped disks.
        let _fork_guard = crate::test_support::fork_lock();
        let path = temp_file("disk");
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        let p = path.to_str().unwrap();
        // Read-write twice (as if by two VMs): the second open is refused.
        // Twice in one VM: named as such, not blamed on another process.
        let e = open_disks(&config(&["--kernel", "k", "--disk", p, "--disk", p]))
            .err()
            .expect("the same image opened read-write twice");
        assert!(e.starts_with(&format!("disk {p}: ")), "{e}");
        assert!(e.contains(&format!("already disk 1 ({p})")), "{e}");
        // While one VM has it read-write, not even read-only.
        let rw = open_disks(&config(&["--kernel", "k", "--disk", p])).unwrap();
        let ro = format!("{p},ro");
        let e = open_disks(&config(&["--kernel", "k", "--disk", &ro]))
            .err()
            .expect("in use by another VM");
        assert!(e.contains("in use") && e.contains("another vemu"), "{e}");
        drop(rw);
        // Read-only users share it.
        let ro = open_disks(&config(&["--kernel", "k", "--disk", &ro, "--disk", &ro])).unwrap();
        assert_eq!(ro.len(), 2);
        drop(ro);
        std::fs::remove_file(&path).unwrap();
    }
}
