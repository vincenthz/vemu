/*
 * x86_64-only KVM ABI checks (owned by the kvm x86_64 work): one
 * VEMU_CHECK(C expression, value) per struct size / offset / ioctl number /
 * constant that vemu-hv defines for x86 -- the structs and constants in
 * crates/vemu-hv/src/x86_64/kvm.rs, the ioctl numbers and capabilities in
 * crates/vemu-hv/src/kvm/x86_64.rs -- with the same literals pinned on the
 * Rust side by const asserts there.
 */

/* struct kvm_regs */
VEMU_CHECK(sizeof(struct kvm_regs), 144)
VEMU_CHECK(offsetof(struct kvm_regs, rax), 0)
VEMU_CHECK(offsetof(struct kvm_regs, rsi), 32)
VEMU_CHECK(offsetof(struct kvm_regs, r8), 64)
VEMU_CHECK(offsetof(struct kvm_regs, rip), 128)
VEMU_CHECK(offsetof(struct kvm_regs, rflags), 136)

/* struct kvm_segment */
VEMU_CHECK(sizeof(struct kvm_segment), 24)
VEMU_CHECK(offsetof(struct kvm_segment, base), 0)
VEMU_CHECK(offsetof(struct kvm_segment, limit), 8)
VEMU_CHECK(offsetof(struct kvm_segment, selector), 12)
VEMU_CHECK(offsetof(struct kvm_segment, type), 14)
VEMU_CHECK(offsetof(struct kvm_segment, present), 15)
VEMU_CHECK(offsetof(struct kvm_segment, dpl), 16)
VEMU_CHECK(offsetof(struct kvm_segment, db), 17)
VEMU_CHECK(offsetof(struct kvm_segment, s), 18)
VEMU_CHECK(offsetof(struct kvm_segment, l), 19)
VEMU_CHECK(offsetof(struct kvm_segment, g), 20)
VEMU_CHECK(offsetof(struct kvm_segment, avl), 21)
VEMU_CHECK(offsetof(struct kvm_segment, unusable), 22)
VEMU_CHECK(offsetof(struct kvm_segment, padding), 23)

/* struct kvm_dtable */
VEMU_CHECK(sizeof(struct kvm_dtable), 16)
VEMU_CHECK(offsetof(struct kvm_dtable, limit), 8)
VEMU_CHECK(offsetof(struct kvm_dtable, padding), 10)

/* struct kvm_sregs */
VEMU_CHECK(sizeof(struct kvm_sregs), 312)
VEMU_CHECK(offsetof(struct kvm_sregs, cs), 0)
VEMU_CHECK(offsetof(struct kvm_sregs, ds), 24)
VEMU_CHECK(offsetof(struct kvm_sregs, es), 48)
VEMU_CHECK(offsetof(struct kvm_sregs, fs), 72)
VEMU_CHECK(offsetof(struct kvm_sregs, gs), 96)
VEMU_CHECK(offsetof(struct kvm_sregs, ss), 120)
VEMU_CHECK(offsetof(struct kvm_sregs, tr), 144)
VEMU_CHECK(offsetof(struct kvm_sregs, ldt), 168)
VEMU_CHECK(offsetof(struct kvm_sregs, gdt), 192)
VEMU_CHECK(offsetof(struct kvm_sregs, idt), 208)
VEMU_CHECK(offsetof(struct kvm_sregs, cr0), 224)
VEMU_CHECK(offsetof(struct kvm_sregs, cr2), 232)
VEMU_CHECK(offsetof(struct kvm_sregs, cr3), 240)
VEMU_CHECK(offsetof(struct kvm_sregs, cr4), 248)
VEMU_CHECK(offsetof(struct kvm_sregs, cr8), 256)
VEMU_CHECK(offsetof(struct kvm_sregs, efer), 264)
VEMU_CHECK(offsetof(struct kvm_sregs, apic_base), 272)
VEMU_CHECK(offsetof(struct kvm_sregs, interrupt_bitmap), 280)
VEMU_CHECK(sizeof(((struct kvm_sregs *)0)->interrupt_bitmap), 32)
VEMU_CHECK(KVM_NR_INTERRUPTS, 256)

/* struct kvm_fpu */
VEMU_CHECK(sizeof(struct kvm_fpu), 416)
VEMU_CHECK(offsetof(struct kvm_fpu, fpr), 0)
VEMU_CHECK(offsetof(struct kvm_fpu, fcw), 128)
VEMU_CHECK(offsetof(struct kvm_fpu, fsw), 130)
VEMU_CHECK(offsetof(struct kvm_fpu, ftwx), 132)
VEMU_CHECK(offsetof(struct kvm_fpu, pad1), 133)
VEMU_CHECK(offsetof(struct kvm_fpu, last_opcode), 134)
VEMU_CHECK(offsetof(struct kvm_fpu, last_ip), 136)
VEMU_CHECK(offsetof(struct kvm_fpu, last_dp), 144)
VEMU_CHECK(offsetof(struct kvm_fpu, xmm), 152)
VEMU_CHECK(offsetof(struct kvm_fpu, mxcsr), 408)
VEMU_CHECK(offsetof(struct kvm_fpu, pad2), 412)

/* struct kvm_msr_entry / kvm_msrs */
VEMU_CHECK(sizeof(struct kvm_msr_entry), 16)
VEMU_CHECK(offsetof(struct kvm_msr_entry, index), 0)
VEMU_CHECK(offsetof(struct kvm_msr_entry, reserved), 4)
VEMU_CHECK(offsetof(struct kvm_msr_entry, data), 8)
VEMU_CHECK(sizeof(struct kvm_msrs), 8)
VEMU_CHECK(offsetof(struct kvm_msrs, nmsrs), 0)
VEMU_CHECK(offsetof(struct kvm_msrs, pad), 4)
VEMU_CHECK(offsetof(struct kvm_msrs, entries), 8)

/* struct kvm_cpuid_entry2 / kvm_cpuid2 */
VEMU_CHECK(sizeof(struct kvm_cpuid_entry2), 40)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, function), 0)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, index), 4)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, flags), 8)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, eax), 12)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, ebx), 16)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, ecx), 20)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, edx), 24)
VEMU_CHECK(offsetof(struct kvm_cpuid_entry2, padding), 28)
VEMU_CHECK(sizeof(struct kvm_cpuid2), 8)
VEMU_CHECK(offsetof(struct kvm_cpuid2, nent), 0)
VEMU_CHECK(offsetof(struct kvm_cpuid2, padding), 4)
VEMU_CHECK(offsetof(struct kvm_cpuid2, entries), 8)
VEMU_CHECK(KVM_CPUID_FLAG_SIGNIFCANT_INDEX, 1)

/* struct kvm_lapic_state */
VEMU_CHECK(sizeof(struct kvm_lapic_state), 1024)
VEMU_CHECK(KVM_APIC_REG_SIZE, 0x400)

/* struct kvm_pit_config */
VEMU_CHECK(sizeof(struct kvm_pit_config), 64)
VEMU_CHECK(offsetof(struct kvm_pit_config, flags), 0)
VEMU_CHECK(offsetof(struct kvm_pit_config, pad), 4)
VEMU_CHECK(KVM_PIT_SPEAKER_DUMMY, 1)

/* struct kvm_irq_routing_entry / kvm_irq_routing */
VEMU_CHECK(sizeof(struct kvm_irq_routing_entry), 48)
VEMU_CHECK(_Alignof(struct kvm_irq_routing_entry), 8)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, gsi), 0)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, type), 4)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, flags), 8)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, pad), 12)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, u), 16)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, u.irqchip.irqchip), 16)
VEMU_CHECK(offsetof(struct kvm_irq_routing_entry, u.irqchip.pin), 20)
VEMU_CHECK(sizeof(((struct kvm_irq_routing_entry *)0)->u), 32)
VEMU_CHECK(sizeof(struct kvm_irq_routing), 8)
VEMU_CHECK(offsetof(struct kvm_irq_routing, nr), 0)
VEMU_CHECK(offsetof(struct kvm_irq_routing, flags), 4)
VEMU_CHECK(offsetof(struct kvm_irq_routing, entries), 8)
VEMU_CHECK(KVM_IRQ_ROUTING_IRQCHIP, 1)
VEMU_CHECK(KVM_IRQCHIP_PIC_MASTER, 0)
VEMU_CHECK(KVM_IRQCHIP_PIC_SLAVE, 1)
VEMU_CHECK(KVM_IRQCHIP_IOAPIC, 2)
VEMU_CHECK(KVM_IOAPIC_NUM_PINS, 24)

/* ioctl numbers */
VEMU_CHECK(KVM_GET_SUPPORTED_CPUID, 0xc008ae05)
VEMU_CHECK(KVM_SET_GSI_ROUTING, 0x4008ae6a)
VEMU_CHECK(KVM_CREATE_PIT, 0xae64)
VEMU_CHECK(KVM_CREATE_PIT2, 0x4040ae77)
VEMU_CHECK(KVM_GET_REGS, 0x8090ae81)
VEMU_CHECK(KVM_SET_REGS, 0x4090ae82)
VEMU_CHECK(KVM_GET_SREGS, 0x8138ae83)
VEMU_CHECK(KVM_SET_SREGS, 0x4138ae84)
VEMU_CHECK(KVM_GET_MSRS, 0xc008ae88)
VEMU_CHECK(KVM_SET_MSRS, 0x4008ae89)
VEMU_CHECK(KVM_GET_FPU, 0x81a0ae8c)
VEMU_CHECK(KVM_SET_FPU, 0x41a0ae8d)
VEMU_CHECK(KVM_GET_LAPIC, 0x8400ae8e)
VEMU_CHECK(KVM_SET_LAPIC, 0x4400ae8f)
VEMU_CHECK(KVM_SET_CPUID2, 0x4008ae90)

/* capabilities */
VEMU_CHECK(KVM_CAP_SET_TSS_ADDR, 4)
VEMU_CHECK(KVM_CAP_EXT_CPUID, 7)
VEMU_CHECK(KVM_CAP_MP_STATE, 14)
VEMU_CHECK(KVM_CAP_IRQ_ROUTING, 25)
VEMU_CHECK(KVM_CAP_PIT2, 33)
VEMU_CHECK(KVM_CAP_SET_IDENTITY_MAP_ADDR, 37)
VEMU_CHECK(KVM_CAP_TSC_DEADLINE_TIMER, 72)
