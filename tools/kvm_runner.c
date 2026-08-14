/*
 * Direct KVM Harness for Intel TDX / Bare-Metal TDREPORT Kernel Payload
 *
 * Exclusively targets Intel TDX (KVM_X86_TDX_VM = 5).
 * Boots bare-metal TDX payload directly using Linux /dev/kvm ioctls.
 */

#include <asm/kvm_para.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define LOW_MEM_SIZE (2ULL * 1024 * 1024 * 1024)
#define FW_BASE 0xff000000ULL
#define FW_SIZE 0x01000000ULL
#define TDVF_METADATA_OFFSET 0x20
#define TDVF_SIGNATURE 0x46564454U
#define TDVF_SECTION_HOB 2

// Upstream Linux Kernel KVM VM Type for Intel TDX (linux/kvm.h)
#ifndef KVM_X86_TDX_VM
#define KVM_X86_TDX_VM 5
#endif

// KVM Memory Encryption IOCTL
#ifndef KVM_MEMORY_ENCRYPT_OP
#define KVM_MEMORY_ENCRYPT_OP _IOWR(KVMIO, 0xba, struct kvm_tdx_cmd)
#endif

// TDX requires bus frequency 25MHz (40ns per cycle)
#define TDX_APIC_BUS_CYCLES_NS 40

#ifndef KVM_CAP_X86_APIC_BUS_CYCLES_NS
#define KVM_CAP_X86_APIC_BUS_CYCLES_NS 237
#endif

#ifndef KVM_CAP_SPLIT_IRQCHIP
#define KVM_CAP_SPLIT_IRQCHIP 121
#endif

#ifndef KVM_CREATE_IRQCHIP
#define KVM_CREATE_IRQCHIP _IO(KVMIO, 0x60)
#endif

// Linux 6.12+ guest_memfd and memory attributes
#ifndef KVM_SET_MEMORY_ATTRIBUTES
#define KVM_SET_MEMORY_ATTRIBUTES _IOW(KVMIO, 0xd2, struct kvm_memory_attributes)
#endif

#ifndef KVM_CREATE_GUEST_MEMFD
#define KVM_CREATE_GUEST_MEMFD _IOWR(KVMIO, 0xd4, struct kvm_create_guest_memfd)
#endif

#ifndef KVM_SET_USER_MEMORY_REGION2
#define KVM_SET_USER_MEMORY_REGION2 _IOW(KVMIO, 0x49, struct kvm_userspace_memory_region2)
#endif

#ifndef KVM_MEMORY_ATTRIBUTE_PRIVATE
#define KVM_MEMORY_ATTRIBUTE_PRIVATE (1ULL << 3)
#endif
#ifndef KVM_MEM_GUEST_MEMFD
#define KVM_MEM_GUEST_MEMFD (1UL << 2)
#endif

#define TDX_TD_ATTRIBUTES_DEBUG (1ULL << 0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE (1ULL << 28)
#define TDX_TD_ATTRIBUTES_PKS (1ULL << 30)
#define TDX_TD_ATTRIBUTES_PERFMON (1ULL << 63)

#define KVM_TDX_MEASURE_MEMORY_REGION (1ULL << 0)

// TDX Sub-command IDs for KVM_MEMORY_ENCRYPT_OP
enum kvm_tdx_cmd_id {
    KVM_TDX_CAPABILITIES = 0,
    KVM_TDX_INIT_VM = 1,
    KVM_TDX_INIT_VCPU = 2,
    KVM_TDX_INIT_MEM_REGION = 3,
    KVM_TDX_FINALIZE_VM = 4,
};

struct kvm_tdx_cmd {
    uint32_t id;
    uint32_t flags;
    uint64_t data;
    uint64_t hw_error;
};

// struct kvm_tdx_capabilities from linux-headers/asm-x86/kvm.h
struct kvm_tdx_capabilities {
    uint64_t supported_attrs;
    uint64_t supported_xfam;

    uint64_t kernel_tdvmcallinfo_1_r11;
    uint64_t user_tdvmcallinfo_1_r11;
    uint64_t kernel_tdvmcallinfo_1_r12;
    uint64_t user_tdvmcallinfo_1_r12;

    uint64_t reserved[250];

    /* Configurable CPUID bits for userspace */
    struct kvm_cpuid2 cpuid;
};

// struct kvm_tdx_init_vm from linux-headers/asm-x86/kvm.h
struct kvm_tdx_init_vm {
    uint64_t attributes;
    uint64_t xfam;
    uint64_t mrconfigid[6]; // 48 bytes SHA384
    uint64_t mrowner[6]; // 48 bytes SHA384
    uint64_t mrownerconfig[6]; // 48 bytes SHA384

    uint64_t reserved[12]; // 96 bytes padding (total 256 bytes before CPUID)

    struct kvm_cpuid2 cpuid; // Filtered CPUID entries
};

struct kvm_tdx_init_mem_region {
    uint64_t source_addr;
    uint64_t gpa;
    uint64_t nr_pages;
};

struct tdvf_metadata {
    uint32_t signature, length, version, nr_sections;
};

struct tdvf_section {
    uint32_t data_offset, raw_data_size;
    uint64_t memory_address, memory_data_size;
    uint32_t type, attributes;
};

struct tdvf_image {
    uint8_t* data;
    long size;
    struct tdvf_metadata* metadata;
    struct tdvf_section* sections;
    uint8_t* low_mem;
    uint8_t* fw_mem;
    uint64_t hob_gpa;
    int low_gmem;
    int fw_gmem;
};

struct efi_hob_header {
    uint16_t type, length;
    uint32_t reserved;
} __attribute__((packed));

struct efi_hob_handoff {
    struct efi_hob_header header;
    uint32_t version, boot_mode;
    uint64_t memory_top, memory_bottom, free_memory_top, free_memory_bottom, end_of_hob_list;
} __attribute__((packed));

struct efi_hob_resource {
    struct efi_hob_header header;
    uint8_t owner[16];
    uint32_t resource_type, resource_attributes;
    uint64_t physical_start, resource_length;
} __attribute__((packed));

static struct kvm_tdx_capabilities* tdx_caps = NULL;
static volatile sig_atomic_t watchdog_fired;
static void watchdog_handler(int signo)
{
    (void)signo;
    watchdog_fired = 1;
}

static int set_private(int vm_fd, uint64_t gpa, uint64_t size, int private)
{
    struct kvm_memory_attributes attr = {
        .address = gpa,
        .size = size,
        .attributes = private ? KVM_MEMORY_ATTRIBUTE_PRIVATE : 0
    };
    return ioctl(vm_fd, KVM_SET_MEMORY_ATTRIBUTES, &attr);
}

static int register_gmem_slot(int vm_fd, uint32_t slot, uint64_t gpa, uint64_t size, void* host, int* gmem_fd)
{
    struct kvm_create_guest_memfd create = { .size = size };
    *gmem_fd = ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &create);
    if (*gmem_fd < 0)
        return -1;
    struct kvm_userspace_memory_region2 region = {
        .slot = slot,
        .flags = KVM_MEM_GUEST_MEMFD,
        .guest_phys_addr = gpa,
        .memory_size = size,
        .userspace_addr = (uint64_t)(uintptr_t)host,
        .guest_memfd = (uint32_t)*gmem_fd,
    };
    return ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region);
}

static int build_hob(void* buffer, size_t size, uint64_t hob_gpa)
{
    uint8_t* p = buffer;
    size_t need = sizeof(struct efi_hob_handoff) + 2 * sizeof(struct efi_hob_resource) + sizeof(struct efi_hob_header);
    if (size < need)
        return -1;
    struct efi_hob_handoff* hit = (void*)p;
    *hit = (struct efi_hob_handoff) { .header = { .type = 1, .length = sizeof(*hit) }, .version = 9 };
    p += sizeof(*hit);
    const uint64_t starts[] = { 0, 0x100000 }, lengths[] = { 0xa0000, LOW_MEM_SIZE - 0x100000 };
    for (unsigned i = 0; i < 2; i++) {
        struct efi_hob_resource* r = (void*)p;
        *r = (struct efi_hob_resource) { .header = { .type = 3, .length = sizeof(*r) },
            .resource_type = 7,
            .resource_attributes = 7,
            .physical_start = starts[i],
            .resource_length = lengths[i] };
        p += sizeof(*r);
    }
    struct efi_hob_header* last = (void*)p;
    *last = (struct efi_hob_header) { .type = 0xffff, .length = sizeof(*last) };
    p += sizeof(*last);
    hit->end_of_hob_list = hob_gpa + (uint64_t)(p - (uint8_t*)buffer);
    return 0;
}

static int load_tdvf_image(int vm_fd, const char* path, struct tdvf_image* tdvf)
{
    FILE* file;
    uint32_t metadata_offset;

    memset(tdvf, 0, sizeof(*tdvf));
    tdvf->low_gmem = -1;
    tdvf->fw_gmem = -1;

    file = fopen(path, "rb");
    if (!file) {
        perror("[-] Open TDVF image");
        return -1;
    }
    if (fseek(file, 0, SEEK_END) || (tdvf->size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET)) {
        perror("[-] Determine TDVF image size");
        fclose(file);
        return -1;
    }

    tdvf->data = malloc((size_t)tdvf->size);
    if (!tdvf->data || fread(tdvf->data, 1, (size_t)tdvf->size, file) != (size_t)tdvf->size) {
        perror("[-] Read TDVF image");
        fclose(file);
        return -1;
    }
    fclose(file);

    if (tdvf->size < TDVF_METADATA_OFFSET + 4) {
        fprintf(stderr, "[-] TDVF image too small\n");
        return -1;
    }
    memcpy(&metadata_offset, tdvf->data + tdvf->size - TDVF_METADATA_OFFSET,
        sizeof(metadata_offset));
    if ((uint64_t)metadata_offset + sizeof(struct tdvf_metadata) > (uint64_t)tdvf->size) {
        fprintf(stderr, "[-] Invalid TDVF metadata offset\n");
        return -1;
    }

    tdvf->metadata = (void*)(tdvf->data + metadata_offset);
    if (tdvf->metadata->signature != TDVF_SIGNATURE || tdvf->metadata->version != 1 || tdvf->metadata->length != sizeof(*tdvf->metadata) + tdvf->metadata->nr_sections * sizeof(struct tdvf_section) || (uint64_t)metadata_offset + tdvf->metadata->length > (uint64_t)tdvf->size) {
        fprintf(stderr, "[-] Invalid TDVF metadata\n");
        return -1;
    }
    tdvf->sections = (void*)(tdvf->metadata + 1);
    printf("[+] Loaded TDVF %s (%ld bytes, %u sections)\n", path,
        tdvf->size, tdvf->metadata->nr_sections);

    tdvf->low_mem = mmap(NULL, LOW_MEM_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    tdvf->fw_mem = mmap(NULL, FW_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tdvf->low_mem == MAP_FAILED || tdvf->fw_mem == MAP_FAILED) {
        perror("[-] mmap guest memory");
        return -1;
    }

    for (uint32_t i = 0; i < tdvf->metadata->nr_sections; i++) {
        struct tdvf_section* section = &tdvf->sections[i];
        uint8_t* destination;

        if ((section->memory_address | section->memory_data_size) & 0xfff || section->raw_data_size > section->memory_data_size || (uint64_t)section->data_offset + section->raw_data_size > (uint64_t)tdvf->size) {
            fprintf(stderr, "[-] Invalid TDVF section %u\n", i);
            return -1;
        }
        if (section->memory_address + section->memory_data_size <= LOW_MEM_SIZE) {
            destination = tdvf->low_mem + section->memory_address;
        } else if (section->memory_address >= FW_BASE && section->memory_address + section->memory_data_size <= FW_BASE + FW_SIZE) {
            destination = tdvf->fw_mem + section->memory_address - FW_BASE;
        } else {
            fprintf(stderr, "[-] TDVF section %u outside guest slots\n", i);
            return -1;
        }
        if (section->raw_data_size) {
            memcpy(destination, tdvf->data + section->data_offset,
                section->raw_data_size);
        }
        if (section->type == TDVF_SECTION_HOB) {
            tdvf->hob_gpa = section->memory_address;
            if (build_hob(destination, section->memory_data_size,
                    tdvf->hob_gpa)) {
                fprintf(stderr, "[-] Failed to build TDVF HOB\n");
                return -1;
            }
        }
    }
    if (!tdvf->hob_gpa) {
        fprintf(stderr, "[-] TDVF has no TD_HOB section\n");
        return -1;
    }

    if (register_gmem_slot(vm_fd, 0, 0, LOW_MEM_SIZE, tdvf->low_mem,
            &tdvf->low_gmem)
        || register_gmem_slot(vm_fd, 1, FW_BASE, FW_SIZE, tdvf->fw_mem,
            &tdvf->fw_gmem)) {
        perror("[-] Register guest memory");
        return -1;
    }
    if (set_private(vm_fd, 0, LOW_MEM_SIZE, 1) || set_private(vm_fd, FW_BASE, FW_SIZE, 1)) {
        perror("[-] Set private memory");
        return -1;
    }
    printf("[+] Registered 2 GiB low RAM and 16 MiB TDVF firmware as private memory.\n");
    return 0;
}

// Helper to call KVM_MEMORY_ENCRYPT_OP with struct kvm_tdx_cmd
static int tdx_cmd(int fd, uint32_t cmd_id, uint32_t flags, void* data)
{
    struct kvm_tdx_cmd cmd;
    memset(&cmd, 0, sizeof(cmd));
    cmd.id = cmd_id;
    cmd.flags = flags;
    cmd.data = (uint64_t)(uintptr_t)data;

    int ret = ioctl(fd, KVM_MEMORY_ENCRYPT_OP, &cmd);
    if (ret < 0 && cmd.hw_error != 0) {
        printf("    [TDX SEAMCALL Error] cmd_id=%u hw_error=0x%llx\n", cmd_id, (unsigned long long)cmd.hw_error);
    }
    return ret;
}

/*
 * Implementation of get_tdx_capabilities matching QEMU (target/i386/kvm/tdx.c lines 133-170)
 */
static int get_tdx_capabilities(int vm_fd)
{
    struct kvm_tdx_capabilities* caps;
    int nr_cpuid_configs = 6;
    size_t size;
    int r;

    do {
        size = sizeof(struct kvm_tdx_capabilities) + nr_cpuid_configs * sizeof(struct kvm_cpuid_entry2);
        caps = (struct kvm_tdx_capabilities*)calloc(1, size);
        if (!caps) {
            return -ENOMEM;
        }
        caps->cpuid.nent = nr_cpuid_configs;

        r = tdx_cmd(vm_fd, KVM_TDX_CAPABILITIES, 0, caps);
        if (r < 0 && errno == E2BIG) {
            free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > 512) {
                fprintf(stderr, "[-] KVM TDX CPUID entries exceeds limit: 512\n");
                return -E2BIG;
            }
        } else if (r < 0) {
            int err = errno;
            free(caps);
            fprintf(stderr, "[-] KVM_TDX_CAPABILITIES failed: %s (errno=%d)\n", strerror(err), err);
            return -err;
        }
    } while (r < 0 && errno == E2BIG);

    tdx_caps = caps;

    printf("[+] get_tdx_capabilities succeeded! (cpuid nent=%u)\n", tdx_caps->cpuid.nent);
    printf("    supported_attrs = 0x%llx, supported_xfam = 0x%llx\n",
        (unsigned long long)tdx_caps->supported_attrs,
        (unsigned long long)tdx_caps->supported_xfam);

    return 0;
}

/* Find matching entry for function/index on kvm_cpuid2 struct */
static struct kvm_cpuid_entry2* cpuid_find_entry(struct kvm_cpuid2* cpuid,
    uint32_t function,
    uint32_t index)
{
    uint32_t i;
    for (i = 0; i < cpuid->nent; ++i) {
        if (cpuid->entries[i].function == function && cpuid->entries[i].index == index) {
            return &cpuid->entries[i];
        }
    }
    return NULL;
}

/* Filter guest CPUID entries against tdx_caps->cpuid */
static void tdx_filter_cpuid(struct kvm_cpuid2* cpuids)
{
    int i, dest_cnt = 0;
    struct kvm_cpuid_entry2 *src, *dest, *conf;

    for (i = 0; i < (int)cpuids->nent; i++) {
        src = cpuids->entries + i;
        conf = cpuid_find_entry(&tdx_caps->cpuid, src->function, src->index);
        if (!conf) {
            continue;
        }
        dest = cpuids->entries + dest_cnt;

        dest->function = src->function;
        dest->index = src->index;
        dest->flags = src->flags;
        dest->eax = src->eax & conf->eax;
        dest->ebx = src->ebx & conf->ebx;
        dest->ecx = src->ecx & conf->ecx;
        dest->edx = src->edx & conf->edx;

        dest_cnt++;
    }
    cpuids->nent = dest_cnt;
}

static int configure_vcpu(int kvm_fd, int vm_fd, uint64_t hob_gpa)
{
    size_t cpuid_size = sizeof(struct kvm_cpuid2) + 512 * sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2* cpuid;
    struct kvm_cpuid_entry2* leaf1;
    int vcpu_fd;

    printf("[+] Creating TDX vCPU (KVM_CREATE_VCPU)...\n");
    vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
    if (vcpu_fd < 0) {
        perror("[-] KVM_CREATE_VCPU failed");
        return -1;
    }
    printf("[+] TDX vCPU created successfully! (fd=%d)\n", vcpu_fd);

    cpuid = calloc(1, cpuid_size);
    if (!cpuid) {
        perror("[-] Allocate vCPU CPUID");
        close(vcpu_fd);
        return -1;
    }
    cpuid->nent = 512;
    if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid) < 0) {
        perror("[-] KVM_GET_SUPPORTED_CPUID for vCPU");
        free(cpuid);
        close(vcpu_fd);
        return -1;
    }

    leaf1 = cpuid_find_entry(cpuid, 1, 0);
    if (!leaf1) {
        fprintf(stderr, "[-] Host CPUID has no leaf 1\n");
        free(cpuid);
        close(vcpu_fd);
        return -1;
    }
    leaf1->ecx |= 1U << 21; /* TDX vCPUs require x2APIC. */
    printf("[+] Installing full vCPU CPUID (%u entries, x2APIC=%u).\n",
        cpuid->nent, !!(leaf1->ecx & (1U << 21)));
    if (ioctl(vcpu_fd, KVM_SET_CPUID2, cpuid) < 0) {
        perror("[-] KVM_SET_CPUID2");
        free(cpuid);
        close(vcpu_fd);
        return -1;
    }
    free(cpuid);

    if (tdx_cmd(vcpu_fd, KVM_TDX_INIT_VCPU, 0,
            (void*)(uintptr_t)hob_gpa)
        < 0) {
        perror("[-] KVM_TDX_INIT_VCPU");
        close(vcpu_fd);
        return -1;
    }
    printf("[+] KVM_TDX_INIT_VCPU succeeded (HOB GPA 0x%llx).\n",
        (unsigned long long)hob_gpa);
    return vcpu_fd;
}

static int initialize_tdvf_memory(int vcpu_fd, const struct tdvf_image* tdvf)
{
    for (uint32_t i = 0; i < tdvf->metadata->nr_sections; i++) {
        const struct tdvf_section* section = &tdvf->sections[i];
        uint8_t* source = section->memory_address < LOW_MEM_SIZE
            ? tdvf->low_mem + section->memory_address
            : tdvf->fw_mem + section->memory_address - FW_BASE;
        struct kvm_tdx_init_mem_region region = {
            .source_addr = (uint64_t)(uintptr_t)source,
            .gpa = section->memory_address,
            .nr_pages = section->memory_data_size >> 12,
        };
        uint32_t flags = (section->attributes & 1) ? KVM_TDX_MEASURE_MEMORY_REGION : 0;
        int result;

        do {
            result = tdx_cmd(vcpu_fd, KVM_TDX_INIT_MEM_REGION, flags, &region);
        } while (result < 0 && (errno == EAGAIN || errno == EINTR));

        if (result < 0) {
            fprintf(stderr,
                "[-] KVM_TDX_INIT_MEM_REGION section %u failed: %s\n",
                i, strerror(errno));
            return -1;
        }
        printf("[+] Initialized TDVF section %u at GPA 0x%llx (%llu pages).\n",
            i, (unsigned long long)section->memory_address,
            (unsigned long long)(section->memory_data_size >> 12));
    }
    return 0;
}

int main(int argc, char** argv)
{
    const char* payload_path = "td-shim-tdreport.bin";
    if (argc > 1) {
        payload_path = argv[1];
    }

    printf("============================================================\n");
    printf("     Direct KVM Runner for Intel TDX Bare-Metal Payload     \n");
    printf("============================================================\n");

    // Open /dev/kvm
    int kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) {
        perror("[-] Failed to open /dev/kvm");
        return 1;
    }

    // Check KVM API Version
    int api_ver = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    if (api_ver != 12) {
        fprintf(stderr, "[-] Unexpected KVM API version: %d (expected 12)\n", api_ver);
        close(kvm_fd);
        return 1;
    }

    // Create Intel TDX VM instance (type = 5: KVM_X86_TDX_VM)
    printf("[+] Attempting KVM_CREATE_VM (type=%d: KVM_X86_TDX_VM)...\n", KVM_X86_TDX_VM);
    int vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, KVM_X86_TDX_VM);
    if (vm_fd < 0) {
        fprintf(stderr, "[-] KVM_CREATE_VM(KVM_X86_TDX_VM) failed: %s (errno=%d)\n", strerror(errno), errno);
        close(kvm_fd);
        return 1;
    }
    printf("[+] Successfully created KVM_X86_TDX_VM instance! (fd=%d)\n", vm_fd);

    // Load and parse the td-shim TDVF image.
    struct tdvf_image tdvf;
    if (load_tdvf_image(vm_fd, payload_path, &tdvf) < 0) {
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    // Configure TDX Prerequisites & Initialize TDX VM
    // Enable in-kernel Local APIC
    struct kvm_enable_cap split_irqchip = {
        .cap = KVM_CAP_SPLIT_IRQCHIP,
        .args = { 24 }, // 24 GSIs
    };
    if (ioctl(vm_fd, KVM_ENABLE_CAP, &split_irqchip) == 0) {
        printf("[+] Enabled KVM_CAP_SPLIT_IRQCHIP (in-kernel Local APIC).\n");
    } else if (ioctl(vm_fd, KVM_CREATE_IRQCHIP, 0) == 0) {
        printf("[+] Created in-kernel IRQCHIP (KVM_CREATE_IRQCHIP).\n");
    }
    // Enable KVM_CAP_X86_APIC_BUS_CYCLES_NS (25MHz = 40ns)
    int apic_ext = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_X86_APIC_BUS_CYCLES_NS);
    if (apic_ext > 0) {
        struct kvm_enable_cap apic_cap = {
            .cap = KVM_CAP_X86_APIC_BUS_CYCLES_NS,
            .args = { TDX_APIC_BUS_CYCLES_NS },
        };
        if (ioctl(vm_fd, KVM_ENABLE_CAP, &apic_cap) == 0) {
            printf("[+] Set APIC bus frequency to 25MHz (KVM_CAP_X86_APIC_BUS_CYCLES_NS = 40ns).\n");
        }
    }

    struct kvm_enable_cap hypercall_cap = { .cap = KVM_CAP_EXIT_HYPERCALL, .args = { 1ULL << KVM_HC_MAP_GPA_RANGE } };
    if (ioctl(vm_fd, KVM_ENABLE_CAP, &hypercall_cap) < 0) {
        perror("[-] Enable KVM_HC_MAP_GPA_RANGE exits");
        return 1;
    }

    // Fetch TDX capabilities
    printf("[+] Fetching hardware TDX capabilities (get_tdx_capabilities)...\n");
    if (get_tdx_capabilities(vm_fd) < 0) {
        fprintf(stderr, "[-] get_tdx_capabilities failed\n");
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    // Initialize TDX VM
    printf("[+] Initializing TDX VM (KVM_TDX_INIT_VM)...\n");
    size_t init_sz = sizeof(struct kvm_tdx_init_vm) + 512 * sizeof(struct kvm_cpuid_entry2);
    struct kvm_tdx_init_vm* init_vm = (struct kvm_tdx_init_vm*)calloc(1, init_sz);

    if (tdx_caps) {
        init_vm->attributes = 0;
        if (tdx_caps->supported_attrs & TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE) {
            init_vm->attributes |= TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
        }
        init_vm->xfam = tdx_caps->supported_xfam;

        init_vm->cpuid.nent = 512;
        if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &init_vm->cpuid) >= 0) {
            tdx_filter_cpuid(&init_vm->cpuid);
            printf("[+] Filtered CPUID entries for TDX: %u entries\n", init_vm->cpuid.nent);
        }
    }

    int retry = 10000;
    int res;
    do {
        res = tdx_cmd(vm_fd, KVM_TDX_INIT_VM, 0, init_vm);
    } while (res < 0 && errno == EAGAIN && --retry > 0);

    if (res == 0) {
        printf("[+] KVM_TDX_INIT_VM succeeded! (attributes=0x%llx, xfam=0x%llx, cpuid nent=%u)\n",
            (unsigned long long)init_vm->attributes,
            (unsigned long long)init_vm->xfam,
            init_vm->cpuid.nent);
    } else {
        fprintf(stderr, "[-] KVM_TDX_INIT_VM failed: %s (errno=%d)\n", strerror(errno), errno);
        free(init_vm);
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }
    free(init_vm);

    // Create and configure the TDX vCPU.
    int vcpu_fd = configure_vcpu(kvm_fd, vm_fd, tdvf.hob_gpa);
    if (vcpu_fd < 0) {
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    // Populate every TDVF section via the vCPU fd, as required by the ABI.
    if (initialize_tdvf_memory(vcpu_fd, &tdvf) < 0) {
        close(vcpu_fd);
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    // Finalize TDX VM state (KVM_TDX_FINALIZE_VM)
    printf("[+] Finalizing TDX VM state (KVM_TDX_FINALIZE_VM)...\n");
    int fin_res = tdx_cmd(vm_fd, KVM_TDX_FINALIZE_VM, 0, NULL);
    if (fin_res == 0) {
        printf("[+] KVM_TDX_FINALIZE_VM finalized VM to RUNNABLE state!\n");
    } else {
        fprintf(stderr, "[-] KVM_TDX_FINALIZE_VM failed: %s (errno=%d)\n", strerror(errno), errno);
        int __attribute__((unused)) unused_ret = system("dmesg | grep -i tdx | tail -n 8");
        close(vcpu_fd);
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    // Map KVM Run buffer
    int mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (mmap_size < 0) {
        perror("[-] KVM_GET_VCPU_MMAP_SIZE failed");
        close(vcpu_fd);
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }
    struct kvm_run* run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
    if (run == MAP_FAILED) {
        perror("[-] mmap kvm_run failed");
        close(vcpu_fd);
        close(vm_fd);
        close(kvm_fd);
        return 1;
    }

    printf("[+] TDX vCPU ready for execution!\n");
    printf("[+] Executing guest CPU run loop (capturing COM1 UART 0x3F8 I/O exits)...\n");
    printf("------------------------------------------------------------\n");

    // Run Loop. A halted in-kernel LAPIC vCPU can otherwise block forever.
    struct sigaction watchdog_action = { .sa_handler = watchdog_handler };
    sigemptyset(&watchdog_action.sa_mask);
    sigaction(SIGALRM, &watchdog_action, NULL);
    while (1) {
        watchdog_fired = 0;
        alarm(60);
        int ret = ioctl(vcpu_fd, KVM_RUN, 0);
        alarm(0);
        if (ret < 0) {
            if (errno == EINTR && watchdog_fired) {
                fprintf(stderr, "[-] Guest made no userspace-visible progress for 60 seconds; guest execution is likely halted.\n");
                break;
            }
            if (errno == EINTR || errno == EAGAIN)
                continue;
            perror("[-] KVM_RUN execution failed");
            break;
        }

        switch (run->exit_reason) {
        case KVM_EXIT_HYPERCALL:
            if (run->hypercall.nr != KVM_HC_MAP_GPA_RANGE) {
                fprintf(stderr, "[-] Unexpected hypercall %llu\n", (unsigned long long)run->hypercall.nr);
                goto done;
            }
            {
                uint64_t gpa = run->hypercall.args[0];
                uint64_t size = run->hypercall.args[1] << 12;
                int private = !!(run->hypercall.args[2] & KVM_MAP_GPA_RANGE_ENCRYPTED);
                run->hypercall.ret = set_private(vm_fd, gpa, size, private) ? -errno : 0;
            }
            break;
#ifdef KVM_EXIT_MEMORY_FAULT
        case KVM_EXIT_MEMORY_FAULT:
            if (set_private(vm_fd, run->memory_fault.gpa, run->memory_fault.size,
                    !!(run->memory_fault.flags & KVM_MEMORY_EXIT_FLAG_PRIVATE))) {
                perror("[-] Resolve KVM_EXIT_MEMORY_FAULT");
                goto done;
            }
            break;
#endif
        case KVM_EXIT_IO:
            // Intercept COM1 serial output and payload completion.
            if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0x3f8) {
                char* p = (char*)run + run->io.data_offset;
                for (uint32_t i = 0; i < run->io.count; i++) {
                    putchar(p[i]);
                }
                fflush(stdout);
            } else if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0xf4 && run->io.size == 1 && run->io.count >= 1) {
                uint8_t status = *((uint8_t*)run + run->io.data_offset);
                printf("\n------------------------------------------------------------\n");
                if (status == 0)
                    printf("[+] Guest payload completed successfully.\n");
                else
                    printf("[-] Guest payload reported failure (status=%u).\n", status);
                goto done;
            }
            break;
        case KVM_EXIT_SHUTDOWN:
            printf("\n------------------------------------------------------------\n");
            printf("[+] KVM Intercepted Guest Shutdown / Triple Fault (KVM_EXIT_SHUTDOWN).\n");
            goto done;
        case KVM_EXIT_EXCEPTION:
            printf("\n------------------------------------------------------------\n");
            printf("[+] KVM Intercepted Guest Exception (vector=%u, error_code=%u).\n",
                run->ex.exception, run->ex.error_code);
            goto done;
        case KVM_EXIT_HLT:
            printf("\n------------------------------------------------------------\n");
            printf("[+] Guest CPU halted cleanly (KVM_EXIT_HLT).\n");
            goto done;
        case KVM_EXIT_FAIL_ENTRY:
            printf("\n[-] KVM_EXIT_FAIL_ENTRY (hardware_entry_failure_reason = 0x%llx)\n",
                (unsigned long long)run->fail_entry.hardware_entry_failure_reason);
            goto done;
        case KVM_EXIT_INTERNAL_ERROR:
            printf("\n[-] KVM_EXIT_INTERNAL_ERROR (suberror = 0x%x)\n",
                run->internal.suberror);
            goto done;
        default:
            printf("\n[i] KVM exit_reason = 0x%x\n", run->exit_reason);
            goto done;
        }
    }

done:
    alarm(0);
    if (tdx_caps)
        free(tdx_caps);
    close(vcpu_fd);
    close(vm_fd);
    close(kvm_fd);
    printf("============================================================\n");
    return 0;
}
