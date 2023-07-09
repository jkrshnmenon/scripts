kvm_api_values = {
	"KVM_GET_API_VERSION": 0xae00,
	"KVM_CREATE_VM": 0xae01,
	"KVM_GET_MSR_INDEX_LIST": 0xc004ae02,
	"KVM_S390_ENABLE_SIE": 0xae06,
	"KVM_CHECK_EXTENSION": 0xae03,
	"KVM_GET_VCPU_MMAP_SIZE": 0xae04,
	"KVM_GET_SUPPORTED_CPUID": 0xc008ae05,
	"KVM_GET_EMULATED_CPUID": 0xc008ae09,
	"KVM_GET_MSR_FEATURE_INDEX_LIST": 0xc004ae0a,
	"KVM_SET_MEMORY_REGION": 0x4018ae40,
	"KVM_CREATE_VCPU": 0xae41,
	"KVM_GET_DIRTY_LOG": 0x4010ae42,
	"KVM_SET_MEMORY_ALIAS": 0x4020ae43,
	"KVM_SET_NR_MMU_PAGES": 0xae44,
	"KVM_GET_NR_MMU_PAGES": 0xae45,
	"KVM_SET_USER_MEMORY_REGION": 0x4020ae46,
	"KVM_SET_TSS_ADDR": 0xae47,
	"KVM_SET_IDENTITY_MAP_ADDR": 0x4008ae48,
	"KVM_S390_UCAS_MAP": 0x4018ae50,
	"KVM_S390_UCAS_UNMAP": 0x4018ae51,
	"KVM_S390_VCPU_FAULT": 0x4008ae52,
	"KVM_CREATE_IRQCHIP": 0xae60,
	"KVM_IRQ_LINE": 0x4008ae61,
	"KVM_GET_IRQCHIP": 0xc208ae62,
	"KVM_SET_IRQCHIP": 0x8208ae63,
	"KVM_CREATE_PIT": 0xae64,
	"KVM_GET_PIT": 0xc048ae65,
	"KVM_SET_PIT": 0x8048ae66,
	"KVM_IRQ_LINE_STATUS": 0xc008ae67,
	"KVM_ASSIGN_PCI_DEVICE": 0x8040ae69,
	"KVM_SET_GSI_ROUTING": 0x4008ae6a,
	"KVM_ASSIGN_DEV_IRQ": 0x4040ae70,
	"KVM_REINJECT_CONTROL": 0xae71,
	"KVM_DEASSIGN_PCI_DEVICE": 0x4040ae72,
	"KVM_ASSIGN_SET_MSIX_NR": 0x4008ae73,
	"KVM_ASSIGN_SET_MSIX_ENTRY": 0x4010ae74,
	"KVM_DEASSIGN_DEV_IRQ": 0x4040ae75,
	"KVM_IRQFD": 0x4020ae76,
	"KVM_CREATE_PIT2": 0x4040ae77,
	"KVM_SET_BOOT_CPU_ID": 0xae78,
	"KVM_IOEVENTFD": 0x4040ae79,
	"KVM_XEN_HVM_CONFIG": 0x4038ae7a,
	"KVM_SET_CLOCK": 0x4030ae7b,
	"KVM_GET_CLOCK": 0x8030ae7c,
	"KVM_GET_PIT2": 0x8070ae9f,
	"KVM_SET_PIT2": 0x4070aea0,
	"KVM_PPC_GET_PVINFO": 0x4080aea1,
	"KVM_SET_TSC_KHZ": 0xaea2,
	"KVM_GET_TSC_KHZ": 0xaea3,
	"KVM_ASSIGN_SET_INTX_MASK": 0x4040aea4,
	"KVM_SIGNAL_MSI": 0x4020aea5,
	"KVM_PPC_GET_SMMU_INFO": 0x8250aea6,
	"KVM_PPC_ALLOCATE_HTAB": 0xc004aea7,
	"KVM_ARM_SET_DEVICE_ADDR": 0x4010aeab,
	"KVM_PPC_RESIZE_HPT_PREPARE": 0x8010aead,
	"KVM_PPC_RESIZE_HPT_COMMIT": 0x8010aeae,
	"KVM_SET_PMU_EVENT_FILTER": 0x4020aeb2,
	"KVM_PPC_SVM_OFF": 0xaeb3,
	"KVM_CREATE_DEVICE": 0xc00caee0,
	"KVM_SET_DEVICE_ATTR": 0x4018aee1,
	"KVM_GET_DEVICE_ATTR": 0x4018aee2,
	"KVM_HAS_DEVICE_ATTR": 0x4018aee3,
	"KVM_RUN": 0xae80,
	"KVM_GET_REGS": 0x8090ae81,
	"KVM_SET_REGS": 0x4090ae82,
	"KVM_GET_SREGS": 0x8138ae83,
	"KVM_SET_SREGS": 0x4138ae84,
	"KVM_TRANSLATE": 0xc018ae85,
	"KVM_INTERRUPT": 0x4004ae86,
	"KVM_GET_MSRS": 0xc008ae88,
	"KVM_SET_MSRS": 0x4008ae89,
	"KVM_SET_CPUID": 0x4008ae8a,
	"KVM_SET_SIGNAL_MASK": 0x4004ae8b,
	"KVM_GET_FPU": 0x81a0ae8c,
	"KVM_SET_FPU": 0x41a0ae8d,
	"KVM_GET_LAPIC": 0x8400ae8e,
	"KVM_SET_LAPIC": 0x4400ae8f,
	"KVM_SET_CPUID2": 0x4008ae90,
	"KVM_GET_CPUID2": 0xc008ae91,
	"KVM_TPR_ACCESS_REPORTING": 0xc028ae92,
	"KVM_SET_VAPIC_ADDR": 0x4008ae93,
	"KVM_S390_INTERRUPT": 0x4010ae94,
	"KVM_S390_STORE_STATUS": 0x4008ae95,
	"KVM_S390_SET_INITIAL_PSW": 0x4010ae96,
	"KVM_S390_INITIAL_RESET": 0xae97,
	"KVM_GET_MP_STATE": 0x8004ae98,
	"KVM_SET_MP_STATE": 0x4004ae99,
	"KVM_NMI": 0xae9a,
	"KVM_SET_GUEST_DEBUG": 0x4048ae9b,
	"KVM_X86_SETUP_MCE": 0x4008ae9c,
	"KVM_X86_GET_MCE_CAP_SUPPORTED": 0x8008ae9d,
	"KVM_X86_SET_MCE": 0x4040ae9e,
	"KVM_GET_VCPU_EVENTS": 0x8040ae9f,
	"KVM_SET_VCPU_EVENTS": 0x4040aea0,
	"KVM_GET_DEBUGREGS": 0x8080aea1,
	"KVM_SET_DEBUGREGS": 0x4080aea2,
	"KVM_ENABLE_CAP": 0x4068aea3,
	"KVM_GET_XSAVE": 0x9000aea4,
	"KVM_SET_XSAVE": 0x5000aea5,
	"KVM_GET_XCRS": 0x8188aea6,
	"KVM_SET_XCRS": 0x4188aea7,
	"KVM_DIRTY_TLB": 0x4010aeaa,
	"KVM_GET_ONE_REG": 0x4010aeab,
	"KVM_SET_ONE_REG": 0x4010aeac,
	"KVM_KVMCLOCK_CTRL": 0xaead,
	"KVM_GET_REG_LIST": 0xc008aeb0,
	"KVM_S390_MEM_OP": 0x4040aeb1,
	"KVM_S390_GET_SKEYS": 0x4040aeb2,
	"KVM_S390_SET_SKEYS": 0x4040aeb3,
	"KVM_S390_IRQ": 0x4048aeb4,
	"KVM_S390_SET_IRQ_STATE": 0x4020aeb5,
	"KVM_S390_GET_IRQ_STATE": 0x4020aeb6,
	"KVM_SMI": 0xaeb7,
	"KVM_S390_GET_CMMA_BITS": 0xc020aeb8,
	"KVM_S390_SET_CMMA_BITS": 0x4020aeb9,
	"KVM_MEMORY_ENCRYPT_OP": 0xc008aeba,
	"KVM_MEMORY_ENCRYPT_REG_REGION": 0x8010aebb,
	"KVM_MEMORY_ENCRYPT_UNREG_REGION": 0x8010aebc,
	"KVM_HYPERV_EVENTFD": 0x4018aebd,
	"KVM_GET_NESTED_STATE": 0xc080aebe,
	"KVM_SET_NESTED_STATE": 0x4080aebf,
	"KVM_CLEAR_DIRTY_LOG": 0xc018aec0,
	"KVM_GET_SUPPORTED_HV_CPUID": 0xc008aec1,
	"KVM_ARM_VCPU_FINALIZE": 0x4004aec2,
	"KVM_S390_NORMAL_RESET": 0xaec3,
	"KVM_S390_CLEAR_RESET": 0xaec4,
	"KVM_S390_PV_COMMAND": 0xc020aec5,
	"KVM_X86_SET_MSR_FILTER": 0x4188aec6,
	"KVM_RESET_DIRTY_RINGS": 0xaec7,
	"KVM_XEN_HVM_GET_ATTR": 0xc048aec8,
	"KVM_XEN_HVM_SET_ATTR": 0x4048aec9,
	"KVM_XEN_VCPU_GET_ATTR": 0xc048aeca,
	"KVM_XEN_VCPU_SET_ATTR": 0x4048aecb,
	"KVM_GET_SREGS2": 0x8140aecc,
	"KVM_SET_SREGS2": 0x4140aecd,
	"KVM_GET_STATS_FD": 0xaece
}
