//! Direct KVM harness for an Intel TDX TDVF payload.
//!
//! This is the Rust equivalent of `tools/kvm_runner.c`.  TDX ioctls are not
//! exposed by stable high-level KVM crates yet, so the small UAPI surface used
//! here is represented explicitly with `#[repr(C)]` structures.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, bail};
use log::{debug, error};

const LOW_MEM_SIZE: u64 = 2 * 1024 * 1024 * 1024;
const FW_BASE: u64 = 0xff00_0000;
const FW_SIZE: u64 = 0x0100_0000;
const TDVF_METADATA_OFFSET: usize = 0x20;
const TDVF_SIGNATURE: u32 = 0x4656_4454;
const TDVF_SECTION_HOB: u32 = 2;

const KVM_API_VERSION: i32 = 12;
const KVM_X86_TDX_VM: libc::c_ulong = 5;
const KVM_CAP_SPLIT_IRQCHIP: u32 = 121;
const KVM_CAP_EXIT_HYPERCALL: u32 = 201;
const KVM_CAP_X86_APIC_BUS_CYCLES_NS: u32 = 237;
const TDX_APIC_BUS_CYCLES_NS: u64 = 40;
const KVM_HC_MAP_GPA_RANGE: u64 = 12;
const KVM_MAP_GPA_RANGE_ENCRYPTED: u64 = 1 << 4;
const KVM_MEMORY_ATTRIBUTE_PRIVATE: u64 = 1 << 3;
const KVM_MEMORY_EXIT_FLAG_PRIVATE: u64 = 1 << 3;
const KVM_MEM_GUEST_MEMFD: u32 = 1 << 2;
const KVM_TDX_MEASURE_MEMORY_REGION: u32 = 1;
const TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE: u64 = 1 << 28;

const KVM_TDX_CAPABILITIES: u32 = 0;
const KVM_TDX_INIT_VM: u32 = 1;
const KVM_TDX_INIT_VCPU: u32 = 2;
const KVM_TDX_INIT_MEM_REGION: u32 = 3;
const KVM_TDX_FINALIZE_VM: u32 = 4;

const KVM_EXIT_EXCEPTION: u32 = 1;
const KVM_EXIT_IO: u32 = 2;
const KVM_EXIT_HYPERCALL: u32 = 3;
const KVM_EXIT_HLT: u32 = 5;
const KVM_EXIT_SHUTDOWN: u32 = 8;
const KVM_EXIT_FAIL_ENTRY: u32 = 9;
const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
const KVM_EXIT_MEMORY_FAULT: u32 = 39;
const KVM_EXIT_IO_OUT: u8 = 1;
const TD_REPORT_IO_PORT: u16 = 0x500;
pub const TD_REPORT_SIZE: usize = 1024;
pub type TdReport = [u8; TD_REPORT_SIZE];

const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const KVMIO: u32 = 0xae;

const fn ioc(direction: u32, kind: u32, number: u32, size: usize) -> libc::c_ulong {
    ((direction << IOC_DIRSHIFT)
        | (kind << IOC_TYPESHIFT)
        | (number << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

const fn io(number: u32) -> libc::c_ulong {
    ioc(IOC_NONE, KVMIO, number, 0)
}

const fn iow<T>(number: u32) -> libc::c_ulong {
    ioc(IOC_WRITE, KVMIO, number, size_of::<T>())
}

const fn iowr<T>(number: u32) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, KVMIO, number, size_of::<T>())
}

const KVM_GET_API_VERSION: libc::c_ulong = io(0x00);
const KVM_CREATE_VM: libc::c_ulong = io(0x01);
const KVM_CHECK_EXTENSION: libc::c_ulong = io(0x03);
const KVM_GET_VCPU_MMAP_SIZE: libc::c_ulong = io(0x04);
const KVM_GET_SUPPORTED_CPUID: libc::c_ulong = iowr::<KvmCpuid2>(0x05);
const KVM_CREATE_VCPU: libc::c_ulong = io(0x41);
const KVM_SET_USER_MEMORY_REGION2: libc::c_ulong = iow::<KvmUserspaceMemoryRegion2>(0x49);
const KVM_CREATE_IRQCHIP: libc::c_ulong = io(0x60);
const KVM_RUN: libc::c_ulong = io(0x80);
const KVM_SET_CPUID2: libc::c_ulong = iow::<KvmCpuid2>(0x90);
const KVM_ENABLE_CAP: libc::c_ulong = iow::<KvmEnableCap>(0xa3);
// The upstream UAPI defines this ioctl with `unsigned long`, not the TDX command size.
const KVM_MEMORY_ENCRYPT_OP: libc::c_ulong = iowr::<libc::c_ulong>(0xba);
const KVM_SET_MEMORY_ATTRIBUTES: libc::c_ulong = iow::<KvmMemoryAttributes>(0xd2);
const KVM_CREATE_GUEST_MEMFD: libc::c_ulong = iowr::<KvmCreateGuestMemfd>(0xd4);

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct KvmCpuidEntry2 {
    function: u32,
    index: u32,
    flags: u32,
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
    padding: [u32; 3],
}

#[repr(C)]
struct KvmCpuid2 {
    nent: u32,
    padding: u32,
}

#[repr(C)]
#[derive(Default)]
struct KvmTdxCmd {
    id: u32,
    flags: u32,
    data: u64,
    hw_error: u64,
}

#[repr(C)]
#[derive(Default)]
struct KvmTdxInitMemRegion {
    source_addr: u64,
    gpa: u64,
    nr_pages: u64,
}

#[repr(C)]
#[derive(Default)]
struct KvmMemoryAttributes {
    address: u64,
    size: u64,
    attributes: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct KvmCreateGuestMemfd {
    size: u64,
    flags: u64,
    reserved: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct KvmUserspaceMemoryRegion2 {
    slot: u32,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    guest_memfd_offset: u64,
    guest_memfd: u32,
    pad1: u32,
    pad2: [u64; 14],
}

#[repr(C)]
struct KvmEnableCap {
    cap: u32,
    flags: u32,
    args: [u64; 4],
    pad: [u8; 64],
}

impl Default for KvmEnableCap {
    fn default() -> Self {
        Self {
            cap: 0,
            flags: 0,
            args: [0; 4],
            pad: [0; 64],
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TdvfSection {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    section_type: u32,
    attributes: u32,
}

struct Mapping {
    address: *mut u8,
    size: usize,
}

impl Mapping {
    fn anonymous(size: usize, no_reserve: bool) -> Result<Self> {
        let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        if no_reserve {
            flags |= libc::MAP_NORESERVE;
        }
        // SAFETY: mmap is called with a null hint and anonymous backing.  The
        // returned mapping is uniquely owned by this value and unmapped in Drop.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                flags,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self {
            address: address.cast(),
            size,
        })
    }

    fn shared(fd: RawFd, size: usize) -> Result<Self> {
        // SAFETY: KVM exposes a shared kvm_run mapping at offset zero.
        let address = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self {
            address: address.cast(),
            size,
        })
    }

    fn as_ptr(&self) -> *mut u8 {
        self.address
    }

    fn slice_mut(&mut self, offset: u64, size: u64) -> Result<&mut [u8]> {
        let offset = usize::try_from(offset).context("mapping offset overflow")?;
        let size = usize::try_from(size).context("mapping size overflow")?;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= self.size)
            .context("mapping range out of bounds")?;
        // SAFETY: bounds were checked against the owned mapping above.
        Ok(unsafe { slice::from_raw_parts_mut(self.address.add(offset), end - offset) })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: address and size came from a successful mmap and are unmapped once.
        unsafe { libc::munmap(self.address.cast(), self.size) };
    }
}

struct TdvfImage {
    sections: Vec<TdvfSection>,
    low_mem: Mapping,
    fw_mem: Mapping,
    hob_gpa: u64,
    _guest_memfds: Vec<File>,
}

impl TdvfImage {
    fn source_ptr(&self, section: &TdvfSection) -> *mut u8 {
        if section.memory_address < LOW_MEM_SIZE {
            // SAFETY: section ranges were validated while loading.
            unsafe { self.low_mem.as_ptr().add(section.memory_address as usize) }
        } else {
            // SAFETY: section ranges were validated while loading.
            unsafe {
                self.fw_mem
                    .as_ptr()
                    .add((section.memory_address - FW_BASE) as usize)
            }
        }
    }
}

struct CpuidSet {
    entries: Vec<KvmCpuidEntry2>,
}

impl CpuidSet {
    fn supported(kvm_fd: RawFd, capacity: usize) -> Result<Self> {
        let mut buffer = vec![0u8; size_of::<KvmCpuid2>() + capacity * size_of::<KvmCpuidEntry2>()];
        write_u32(&mut buffer, 0, capacity as u32)?;
        ioctl_ptr(kvm_fd, KVM_GET_SUPPORTED_CPUID, buffer.as_mut_ptr().cast())?;
        let count = read_u32(&buffer, 0)? as usize;
        if count > capacity {
            bail!("KVM returned too many CPUID entries");
        }
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let offset = size_of::<KvmCpuid2>() + index * size_of::<KvmCpuidEntry2>();
            // SAFETY: the buffer contains count entries and read_unaligned handles alignment.
            entries.push(unsafe {
                ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<KvmCpuidEntry2>())
            });
        }
        Ok(Self { entries })
    }

    fn as_ioctl_buffer(&self) -> Vec<u8> {
        let mut buffer =
            vec![0u8; size_of::<KvmCpuid2>() + self.entries.len() * size_of::<KvmCpuidEntry2>()];
        buffer[0..4].copy_from_slice(&(self.entries.len() as u32).to_ne_bytes());
        for (index, entry) in self.entries.iter().enumerate() {
            let offset = size_of::<KvmCpuid2>() + index * size_of::<KvmCpuidEntry2>();
            // SAFETY: destination has exactly enough space for each entry and may be unaligned.
            unsafe {
                ptr::write_unaligned(
                    buffer.as_mut_ptr().add(offset).cast::<KvmCpuidEntry2>(),
                    *entry,
                )
            };
        }
        buffer
    }

    fn find_mut(&mut self, function: u32, index: u32) -> Option<&mut KvmCpuidEntry2> {
        self.entries
            .iter_mut()
            .find(|entry| entry.function == function && entry.index == index)
    }
}

struct TdxCapabilities {
    supported_attrs: u64,
    supported_xfam: u64,
    cpuid: CpuidSet,
}

fn errno(error: &anyhow::Error) -> Option<i32> {
    error
        .downcast_ref::<io::Error>()
        .and_then(io::Error::raw_os_error)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let data = bytes.get(offset..offset + 4).context("truncated u32")?;
    Ok(u32::from_le_bytes(data.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let data = bytes.get(offset..offset + 8).context("truncated u64")?;
    Ok(u64::from_le_bytes(data.try_into().unwrap()))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    bytes
        .get_mut(offset..offset + 2)
        .context("truncated u16 destination")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    bytes
        .get_mut(offset..offset + 4)
        .context("truncated u32 destination")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    bytes
        .get_mut(offset..offset + 8)
        .context("truncated u64 destination")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn ioctl_value(fd: RawFd, request: libc::c_ulong, value: libc::c_ulong) -> Result<i32> {
    // SAFETY: request determines whether value is an integer argument; all callers match UAPI.
    let result = unsafe { libc::ioctl(fd, request, value) };
    if result < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(result)
    }
}

fn ioctl_ptr(fd: RawFd, request: libc::c_ulong, value: *mut libc::c_void) -> Result<i32> {
    // SAFETY: callers provide a live UAPI-compatible object for the duration of ioctl.
    let result = unsafe { libc::ioctl(fd, request, value) };
    if result < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(result)
    }
}

fn ioctl_none(fd: RawFd, request: libc::c_ulong) -> Result<i32> {
    ioctl_value(fd, request, 0)
}

fn fd_from_ioctl(result: Result<i32>) -> Result<File> {
    let fd = result?;
    // SAFETY: a successful descriptor-returning KVM ioctl transfers ownership to userspace.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn tdx_cmd(fd: RawFd, id: u32, flags: u32, data: *mut libc::c_void) -> Result<()> {
    let mut command = KvmTdxCmd {
        id,
        flags,
        data: data as u64,
        hw_error: 0,
    };
    match ioctl_ptr(
        fd,
        KVM_MEMORY_ENCRYPT_OP,
        (&mut command as *mut KvmTdxCmd).cast(),
    ) {
        Ok(_) => Ok(()),
        Err(error) => {
            if command.hw_error != 0 {
                error!(
                    "    [TDX SEAMCALL Error] cmd_id={} hw_error=0x{:x}",
                    id, command.hw_error
                );
            }
            Err(error)
        }
    }
}

fn set_private(vm_fd: RawFd, gpa: u64, size: u64, private: bool) -> Result<()> {
    let mut attributes = KvmMemoryAttributes {
        address: gpa,
        size,
        attributes: if private {
            KVM_MEMORY_ATTRIBUTE_PRIVATE
        } else {
            0
        },
        flags: 0,
    };
    ioctl_ptr(
        vm_fd,
        KVM_SET_MEMORY_ATTRIBUTES,
        (&mut attributes as *mut KvmMemoryAttributes).cast(),
    )?;
    Ok(())
}

fn register_gmem_slot(vm_fd: RawFd, slot: u32, gpa: u64, size: u64, host: *mut u8) -> Result<File> {
    let mut create = KvmCreateGuestMemfd {
        size,
        ..Default::default()
    };
    let guest_memfd = fd_from_ioctl(ioctl_ptr(
        vm_fd,
        KVM_CREATE_GUEST_MEMFD,
        (&mut create as *mut KvmCreateGuestMemfd).cast(),
    ))?;
    let mut region = KvmUserspaceMemoryRegion2 {
        slot,
        flags: KVM_MEM_GUEST_MEMFD,
        guest_phys_addr: gpa,
        memory_size: size,
        userspace_addr: host as u64,
        guest_memfd: guest_memfd.as_raw_fd() as u32,
        ..Default::default()
    };
    ioctl_ptr(
        vm_fd,
        KVM_SET_USER_MEMORY_REGION2,
        (&mut region as *mut KvmUserspaceMemoryRegion2).cast(),
    )?;
    Ok(guest_memfd)
}

fn build_hob(buffer: &mut [u8], hob_gpa: u64) -> Result<()> {
    // Packed EFI HOB sizes from the td-shim interface.
    const HANDOFF_SIZE: usize = 56;
    const RESOURCE_SIZE: usize = 48;
    const HEADER_SIZE: usize = 8;
    const NEED: usize = HANDOFF_SIZE + 2 * RESOURCE_SIZE + HEADER_SIZE;
    if buffer.len() < NEED {
        bail!("TDVF HOB section is too small");
    }
    buffer[..NEED].fill(0);

    write_u16(buffer, 0, 1)?;
    write_u16(buffer, 2, HANDOFF_SIZE as u16)?;
    write_u32(buffer, 8, 9)?;

    let resources = [(0u64, 0xa0000u64), (0x100000u64, LOW_MEM_SIZE - 0x100000)];
    for (index, (start, length)) in resources.into_iter().enumerate() {
        let offset = HANDOFF_SIZE + index * RESOURCE_SIZE;
        write_u16(buffer, offset, 3)?;
        write_u16(buffer, offset + 2, RESOURCE_SIZE as u16)?;
        write_u32(buffer, offset + 24, 7)?;
        write_u32(buffer, offset + 28, 7)?;
        write_u64(buffer, offset + 32, start)?;
        write_u64(buffer, offset + 40, length)?;
    }

    let end_offset = HANDOFF_SIZE + 2 * RESOURCE_SIZE;
    write_u16(buffer, end_offset, 0xffff)?;
    write_u16(buffer, end_offset + 2, HEADER_SIZE as u16)?;
    write_u64(buffer, 48, hob_gpa + NEED as u64)?;
    Ok(())
}

fn load_tdvf_image(vm_fd: RawFd, data: &[u8]) -> Result<TdvfImage> {
    if data.len() < TDVF_METADATA_OFFSET + 4 {
        bail!("TDVF image too small");
    }
    let metadata_offset = read_u32(&data, data.len() - TDVF_METADATA_OFFSET)? as usize;
    if metadata_offset
        .checked_add(16)
        .filter(|end| *end <= data.len())
        .is_none()
    {
        bail!("invalid TDVF metadata offset");
    }
    let signature = read_u32(&data, metadata_offset)?;
    let metadata_length = read_u32(&data, metadata_offset + 4)? as usize;
    let version = read_u32(&data, metadata_offset + 8)?;
    let section_count = read_u32(&data, metadata_offset + 12)? as usize;
    let expected_length = 16usize
        .checked_add(
            section_count
                .checked_mul(32)
                .context("TDVF section count overflow")?,
        )
        .context("TDVF metadata length overflow")?;
    if signature != TDVF_SIGNATURE
        || version != 1
        || metadata_length != expected_length
        || metadata_offset
            .checked_add(metadata_length)
            .filter(|end| *end <= data.len())
            .is_none()
    {
        bail!("invalid TDVF metadata");
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = metadata_offset + 16 + index * 32;
        sections.push(TdvfSection {
            data_offset: read_u32(&data, offset)?,
            raw_data_size: read_u32(&data, offset + 4)?,
            memory_address: read_u64(&data, offset + 8)?,
            memory_data_size: read_u64(&data, offset + 16)?,
            section_type: read_u32(&data, offset + 24)?,
            attributes: read_u32(&data, offset + 28)?,
        });
    }
    debug!(
        "[+] Loaded embedded TDVF ({} bytes, {} sections)",
        data.len(),
        sections.len()
    );

    let mut low_mem = Mapping::anonymous(LOW_MEM_SIZE as usize, true)?;
    let mut fw_mem = Mapping::anonymous(FW_SIZE as usize, false)?;
    let mut hob_gpa = 0;
    for (index, section) in sections.iter().enumerate() {
        if (section.memory_address | section.memory_data_size) & 0xfff != 0
            || section.raw_data_size as u64 > section.memory_data_size
            || (section.data_offset as usize)
                .checked_add(section.raw_data_size as usize)
                .filter(|end| *end <= data.len())
                .is_none()
        {
            bail!("invalid TDVF section {index}");
        }
        let destination = if section
            .memory_address
            .checked_add(section.memory_data_size)
            .filter(|end| *end <= LOW_MEM_SIZE)
            .is_some()
        {
            low_mem.slice_mut(section.memory_address, section.memory_data_size)?
        } else if section.memory_address >= FW_BASE
            && section
                .memory_address
                .checked_add(section.memory_data_size)
                .filter(|end| *end <= FW_BASE + FW_SIZE)
                .is_some()
        {
            fw_mem.slice_mut(section.memory_address - FW_BASE, section.memory_data_size)?
        } else {
            bail!("TDVF section {index} outside guest slots");
        };
        let source_start = section.data_offset as usize;
        let source_end = source_start + section.raw_data_size as usize;
        destination[..section.raw_data_size as usize]
            .copy_from_slice(&data[source_start..source_end]);
        if section.section_type == TDVF_SECTION_HOB {
            hob_gpa = section.memory_address;
            build_hob(destination, hob_gpa)?;
        }
    }
    if hob_gpa == 0 {
        bail!("TDVF has no TD_HOB section");
    }

    let low_gmem = register_gmem_slot(vm_fd, 0, 0, LOW_MEM_SIZE, low_mem.as_ptr())?;
    let fw_gmem = register_gmem_slot(vm_fd, 1, FW_BASE, FW_SIZE, fw_mem.as_ptr())?;
    set_private(vm_fd, 0, LOW_MEM_SIZE, true)?;
    set_private(vm_fd, FW_BASE, FW_SIZE, true)?;
    debug!("[+] Registered 2 GiB low RAM and 16 MiB TDVF firmware as private memory.");

    Ok(TdvfImage {
        sections,
        low_mem,
        fw_mem,
        hob_gpa,
        _guest_memfds: vec![low_gmem, fw_gmem],
    })
}

fn get_tdx_capabilities(vm_fd: RawFd) -> Result<TdxCapabilities> {
    const CAP_CPUID_OFFSET: usize = 2048;
    let mut capacity = 6usize;
    loop {
        let mut buffer =
            vec![
                0u8;
                CAP_CPUID_OFFSET + size_of::<KvmCpuid2>() + capacity * size_of::<KvmCpuidEntry2>()
            ];
        write_u32(&mut buffer, CAP_CPUID_OFFSET, capacity as u32)?;
        match tdx_cmd(vm_fd, KVM_TDX_CAPABILITIES, 0, buffer.as_mut_ptr().cast()) {
            Ok(()) => {
                let count = read_u32(&buffer, CAP_CPUID_OFFSET)? as usize;
                if count > capacity {
                    bail!("TDX returned too many CPUID configurations");
                }
                let mut entries = Vec::with_capacity(count);
                for index in 0..count {
                    let offset = CAP_CPUID_OFFSET
                        + size_of::<KvmCpuid2>()
                        + index * size_of::<KvmCpuidEntry2>();
                    // SAFETY: KVM filled count entries in the allocated flexible array.
                    entries.push(unsafe {
                        ptr::read_unaligned(buffer.as_ptr().add(offset).cast::<KvmCpuidEntry2>())
                    });
                }
                let capabilities = TdxCapabilities {
                    supported_attrs: read_u64(&buffer, 0)?,
                    supported_xfam: read_u64(&buffer, 8)?,
                    cpuid: CpuidSet { entries },
                };
                debug!(
                    "[+] get_tdx_capabilities succeeded! (cpuid nent={})",
                    capabilities.cpuid.entries.len()
                );
                debug!(
                    "    supported_attrs = 0x{:x}, supported_xfam = 0x{:x}",
                    capabilities.supported_attrs, capabilities.supported_xfam
                );
                return Ok(capabilities);
            }
            Err(error) if errno(&error) == Some(libc::E2BIG) => {
                capacity *= 2;
                if capacity > 512 {
                    bail!("KVM TDX CPUID entries exceed limit 512");
                }
            }
            Err(error) => return Err(error),
        }
    }
}

fn initialize_tdx_vm(kvm_fd: RawFd, vm_fd: RawFd, caps: &TdxCapabilities) -> Result<()> {
    const INIT_CPUID_OFFSET: usize = 256;
    let mut cpuid = CpuidSet::supported(kvm_fd, 512)?;
    cpuid.entries.retain_mut(|entry| {
        let Some(config) = caps
            .cpuid
            .entries
            .iter()
            .find(|config| config.function == entry.function && config.index == entry.index)
        else {
            return false;
        };
        entry.eax &= config.eax;
        entry.ebx &= config.ebx;
        entry.ecx &= config.ecx;
        entry.edx &= config.edx;
        true
    });
    debug!(
        "[+] Filtered CPUID entries for TDX: {} entries",
        cpuid.entries.len()
    );

    let cpuid_buffer = cpuid.as_ioctl_buffer();
    let mut init = vec![0u8; INIT_CPUID_OFFSET + cpuid_buffer.len()];
    let attributes = caps.supported_attrs & TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    write_u64(&mut init, 0, attributes)?;
    write_u64(&mut init, 8, caps.supported_xfam)?;
    init[INIT_CPUID_OFFSET..].copy_from_slice(&cpuid_buffer);

    let mut retries = 10_000;
    loop {
        match tdx_cmd(vm_fd, KVM_TDX_INIT_VM, 0, init.as_mut_ptr().cast()) {
            Ok(()) => break,
            Err(error) if errno(&error) == Some(libc::EAGAIN) && retries > 1 => {
                retries -= 1;
            }
            Err(error) => return Err(error),
        }
    }
    debug!(
        "[+] KVM_TDX_INIT_VM succeeded! (attributes=0x{:x}, xfam=0x{:x}, cpuid nent={})",
        attributes,
        caps.supported_xfam,
        cpuid.entries.len()
    );
    Ok(())
}

fn configure_vcpu(kvm_fd: RawFd, vm_fd: RawFd, hob_gpa: u64) -> Result<File> {
    debug!("[+] Creating TDX vCPU (KVM_CREATE_VCPU)...");
    let vcpu = fd_from_ioctl(ioctl_value(vm_fd, KVM_CREATE_VCPU, 0))?;
    debug!(
        "[+] TDX vCPU created successfully! (fd={})",
        vcpu.as_raw_fd()
    );

    let mut cpuid = CpuidSet::supported(kvm_fd, 512)?;
    let x2apic = {
        let leaf1 = cpuid.find_mut(1, 0).context("host CPUID has no leaf 1")?;
        leaf1.ecx |= 1 << 21;
        u8::from(leaf1.ecx & (1 << 21) != 0)
    };
    debug!(
        "[+] Installing full vCPU CPUID ({} entries, x2APIC={}).",
        cpuid.entries.len(),
        x2apic
    );
    let mut buffer = cpuid.as_ioctl_buffer();
    ioctl_ptr(vcpu.as_raw_fd(), KVM_SET_CPUID2, buffer.as_mut_ptr().cast())?;
    tdx_cmd(
        vcpu.as_raw_fd(),
        KVM_TDX_INIT_VCPU,
        0,
        hob_gpa as usize as *mut libc::c_void,
    )?;
    debug!("[+] KVM_TDX_INIT_VCPU succeeded (HOB GPA 0x{hob_gpa:x}).");
    Ok(vcpu)
}

fn initialize_tdvf_memory(vcpu_fd: RawFd, tdvf: &TdvfImage) -> Result<()> {
    for (index, section) in tdvf.sections.iter().enumerate() {
        let mut region = KvmTdxInitMemRegion {
            source_addr: tdvf.source_ptr(section) as u64,
            gpa: section.memory_address,
            nr_pages: section.memory_data_size >> 12,
        };
        let flags = if section.attributes & 1 != 0 {
            KVM_TDX_MEASURE_MEMORY_REGION
        } else {
            0
        };
        loop {
            match tdx_cmd(
                vcpu_fd,
                KVM_TDX_INIT_MEM_REGION,
                flags,
                (&mut region as *mut KvmTdxInitMemRegion).cast(),
            ) {
                Ok(()) => break,
                Err(error) if matches!(errno(&error), Some(libc::EAGAIN | libc::EINTR)) => {}
                Err(error) => {
                    bail!("KVM_TDX_INIT_MEM_REGION section {index} failed: {error}");
                }
            }
        }
        debug!(
            "[+] Initialized TDVF section {} at GPA 0x{:x} ({} pages).",
            index, section.memory_address, region.nr_pages
        );
    }
    Ok(())
}

fn enable_capability(vm_fd: RawFd, cap: u32, first_arg: u64) -> Result<()> {
    let mut enable = KvmEnableCap {
        cap,
        args: [first_arg, 0, 0, 0],
        ..Default::default()
    };
    ioctl_ptr(
        vm_fd,
        KVM_ENABLE_CAP,
        (&mut enable as *mut KvmEnableCap).cast(),
    )?;
    Ok(())
}

static WATCHDOG_FIRED: AtomicBool = AtomicBool::new(false);

extern "C" fn watchdog_handler(_: libc::c_int) {
    WATCHDOG_FIRED.store(true, Ordering::Relaxed);
}

fn native_u16(address: *const u8) -> u16 {
    // SAFETY: caller provides a readable kvm_run union field.
    unsafe { ptr::read_unaligned(address.cast()) }
}

fn native_u32(address: *const u8) -> u32 {
    // SAFETY: caller provides a readable kvm_run field.
    unsafe { ptr::read_unaligned(address.cast()) }
}

fn native_u64(address: *const u8) -> u64 {
    // SAFETY: caller provides a readable kvm_run union field.
    unsafe { ptr::read_unaligned(address.cast()) }
}

fn write_native_i64(address: *mut u8, value: i64) {
    // SAFETY: caller provides the writable hypercall return field.
    unsafe { ptr::write_unaligned(address.cast(), value) };
}

fn run_vcpu(kvm_fd: RawFd, vm_fd: RawFd, vcpu_fd: RawFd) -> Result<TdReport> {
    let mmap_size = ioctl_none(kvm_fd, KVM_GET_VCPU_MMAP_SIZE)? as usize;
    let run = Mapping::shared(vcpu_fd, mmap_size)?;
    debug!("[+] TDX vCPU ready for execution!");
    debug!("[+] Executing guest CPU run loop (capturing COM1 UART 0x3F8 I/O exits)...");
    debug!("------------------------------------------------------------");
    let mut td_report = Vec::with_capacity(TD_REPORT_SIZE);

    // SAFETY: the zeroed sigaction is initialized before installation.  The
    // handler only performs an atomic store, which is async-signal-safe.  No
    // SA_RESTART flag is set because SIGALRM must interrupt KVM_RUN.
    unsafe {
        let mut action: libc::sigaction = zeroed();
        action.sa_sigaction = watchdog_handler as *const () as libc::sighandler_t;
        libc::sigemptyset(&mut action.sa_mask);
        if libc::sigaction(libc::SIGALRM, &action, ptr::null_mut()) < 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    loop {
        WATCHDOG_FIRED.store(false, Ordering::Relaxed);
        // SAFETY: alarm only changes the process alarm timer.
        unsafe { libc::alarm(60) };
        let result = ioctl_none(vcpu_fd, KVM_RUN);
        unsafe { libc::alarm(0) };

        if let Err(error) = result {
            if errno(&error) == Some(libc::EINTR) && WATCHDOG_FIRED.load(Ordering::Relaxed) {
                bail!(
                    "guest made no userspace-visible progress for 60 seconds; guest execution is likely halted"
                );
            }
            if matches!(errno(&error), Some(libc::EINTR | libc::EAGAIN)) {
                continue;
            }
            return Err(error);
        }

        let base = run.as_ptr();
        // kvm_run is 32 bytes before its architecture-independent exit union on x86_64.
        let exit_reason = native_u32(unsafe { base.add(8) });
        let union = unsafe { base.add(32) };
        match exit_reason {
            KVM_EXIT_HYPERCALL => {
                let number = native_u64(union);
                if number != KVM_HC_MAP_GPA_RANGE {
                    bail!("unexpected hypercall {number}");
                }
                let gpa = native_u64(unsafe { union.add(8) });
                let pages = native_u64(unsafe { union.add(16) });
                let flags = native_u64(unsafe { union.add(24) });
                let status = match set_private(
                    vm_fd,
                    gpa,
                    pages << 12,
                    flags & KVM_MAP_GPA_RANGE_ENCRYPTED != 0,
                ) {
                    Ok(()) => 0,
                    Err(error) => -(errno(&error).unwrap_or(libc::EIO) as i64),
                };
                write_native_i64(unsafe { union.add(56) }, status);
            }
            KVM_EXIT_MEMORY_FAULT => {
                let flags = native_u64(union);
                let gpa = native_u64(unsafe { union.add(8) });
                let size = native_u64(unsafe { union.add(16) });
                set_private(vm_fd, gpa, size, flags & KVM_MEMORY_EXIT_FLAG_PRIVATE != 0)?;
            }
            KVM_EXIT_IO => {
                // Layout: direction:u8, size:u8, port:u16, count:u32, data_offset:u64.
                let direction = unsafe { *union };
                let size = unsafe { *union.add(1) };
                let port = native_u16(unsafe { union.add(2) });
                let count = native_u32(unsafe { union.add(4) });
                let data_offset = native_u64(unsafe { union.add(8) }) as usize;
                let byte_count = (count as usize)
                    .checked_mul(size as usize)
                    .context("KVM I/O byte count overflow")?;
                if data_offset
                    .checked_add(byte_count)
                    .filter(|end| *end <= mmap_size)
                    .is_none()
                {
                    bail!("KVM I/O data outside kvm_run mapping");
                }
                let bytes = unsafe { slice::from_raw_parts(base.add(data_offset), byte_count) };
                if direction == KVM_EXIT_IO_OUT && port == 0x3f8 {
                    io::stdout().write_all(bytes)?;
                    io::stdout().flush()?;
                } else if direction == KVM_EXIT_IO_OUT && port == TD_REPORT_IO_PORT && size == 1 {
                    if td_report
                        .len()
                        .checked_add(bytes.len())
                        .filter(|len| *len <= TD_REPORT_SIZE)
                        .is_none()
                    {
                        bail!("guest sent more than {TD_REPORT_SIZE} TDREPORT bytes");
                    }
                    td_report.extend_from_slice(bytes);
                } else if direction == KVM_EXIT_IO_OUT && port == 0xf4 && size == 1 && count >= 1 {
                    debug!("\n------------------------------------------------------------");
                    if bytes[0] == 0 {
                        if td_report.len() != TD_REPORT_SIZE {
                            bail!(
                                "guest completed after sending {} of {TD_REPORT_SIZE} TDREPORT bytes",
                                td_report.len()
                            );
                        }
                        debug!(
                            "[+] Guest payload completed successfully with a complete TDREPORT."
                        );
                        return td_report
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid TDREPORT length"));
                    }
                    bail!("guest payload reported failure (status={})", bytes[0]);
                }
            }
            KVM_EXIT_SHUTDOWN => {
                debug!("\n------------------------------------------------------------");
                debug!("[+] KVM Intercepted Guest Shutdown / Triple Fault (KVM_EXIT_SHUTDOWN).");
                bail!("guest shut down before completing the TDREPORT transfer");
            }
            KVM_EXIT_EXCEPTION => {
                let vector = native_u32(union);
                let error_code = native_u32(unsafe { union.add(4) });
                bail!("guest exception (vector={vector}, error_code={error_code})");
            }
            KVM_EXIT_HLT => {
                debug!("\n------------------------------------------------------------");
                debug!("[+] Guest CPU halted cleanly (KVM_EXIT_HLT).");
                bail!("guest halted before completing the TDREPORT transfer");
            }
            KVM_EXIT_FAIL_ENTRY => {
                bail!(
                    "KVM_EXIT_FAIL_ENTRY (hardware_entry_failure_reason=0x{:x})",
                    native_u64(union)
                );
            }
            KVM_EXIT_INTERNAL_ERROR => {
                bail!(
                    "KVM_EXIT_INTERNAL_ERROR (suberror=0x{:x})",
                    native_u32(union)
                );
            }
            other => bail!("KVM exit_reason=0x{other:x}"),
        }
    }
}

/// Run an in-memory TDVF image in a minimal Intel TDX VM and forward its console output.
pub fn run_image(image: &[u8]) -> Result<TdReport> {
    debug!("============================================================");
    debug!("     Direct KVM Runner for Intel TDX Bare-Metal Payload");
    debug!("============================================================");

    let kvm = OpenOptions::new().read(true).write(true).open("/dev/kvm")?;
    let api_version = ioctl_none(kvm.as_raw_fd(), KVM_GET_API_VERSION)?;
    if api_version != KVM_API_VERSION {
        bail!("unexpected KVM API version: {api_version} (expected {KVM_API_VERSION})");
    }

    debug!("[+] Attempting KVM_CREATE_VM (type=5: KVM_X86_TDX_VM)...");
    let vm = fd_from_ioctl(ioctl_value(kvm.as_raw_fd(), KVM_CREATE_VM, KVM_X86_TDX_VM))?;
    debug!(
        "[+] Successfully created KVM_X86_TDX_VM instance! (fd={})",
        vm.as_raw_fd()
    );

    let tdvf = load_tdvf_image(vm.as_raw_fd(), image)?;

    let mut split_irqchip = KvmEnableCap {
        cap: KVM_CAP_SPLIT_IRQCHIP,
        args: [24, 0, 0, 0],
        ..Default::default()
    };
    if ioctl_ptr(
        vm.as_raw_fd(),
        KVM_ENABLE_CAP,
        (&mut split_irqchip as *mut KvmEnableCap).cast(),
    )
    .is_ok()
    {
        debug!("[+] Enabled KVM_CAP_SPLIT_IRQCHIP (in-kernel Local APIC).");
    } else if ioctl_none(vm.as_raw_fd(), KVM_CREATE_IRQCHIP).is_ok() {
        debug!("[+] Created in-kernel IRQCHIP (KVM_CREATE_IRQCHIP).");
    }

    if ioctl_value(
        kvm.as_raw_fd(),
        KVM_CHECK_EXTENSION,
        KVM_CAP_X86_APIC_BUS_CYCLES_NS as libc::c_ulong,
    )? > 0
        && enable_capability(
            vm.as_raw_fd(),
            KVM_CAP_X86_APIC_BUS_CYCLES_NS,
            TDX_APIC_BUS_CYCLES_NS,
        )
        .is_ok()
    {
        debug!("[+] Set APIC bus frequency to 25MHz (KVM_CAP_X86_APIC_BUS_CYCLES_NS = 40ns).");
    }

    enable_capability(
        vm.as_raw_fd(),
        KVM_CAP_EXIT_HYPERCALL,
        1u64 << KVM_HC_MAP_GPA_RANGE,
    )?;

    debug!("[+] Fetching hardware TDX capabilities (get_tdx_capabilities)...");
    let capabilities = get_tdx_capabilities(vm.as_raw_fd())?;
    debug!("[+] Initializing TDX VM (KVM_TDX_INIT_VM)...");
    initialize_tdx_vm(kvm.as_raw_fd(), vm.as_raw_fd(), &capabilities)?;

    let vcpu = configure_vcpu(kvm.as_raw_fd(), vm.as_raw_fd(), tdvf.hob_gpa)?;
    initialize_tdvf_memory(vcpu.as_raw_fd(), &tdvf)?;

    debug!("[+] Finalizing TDX VM state (KVM_TDX_FINALIZE_VM)...");
    tdx_cmd(vm.as_raw_fd(), KVM_TDX_FINALIZE_VM, 0, ptr::null_mut())?;
    debug!("[+] KVM_TDX_FINALIZE_VM finalized VM to RUNNABLE state!");

    let report = run_vcpu(kvm.as_raw_fd(), vm.as_raw_fd(), vcpu.as_raw_fd())?;
    debug!("============================================================");
    Ok(report)
}

/// Read a TDVF image from a file and run it in a minimal Intel TDX VM.
pub fn run_file(payload_path: impl AsRef<Path>) -> Result<TdReport> {
    let image = std::fs::read(payload_path.as_ref()).with_context(|| {
        format!(
            "failed to read TDVF image {}",
            payload_path.as_ref().display()
        )
    })?;
    run_image(&image)
}

/// Backwards-compatible alias for [`run_file`].
pub fn run(payload_path: impl AsRef<Path>) -> Result<TdReport> {
    run_file(payload_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kvm_uapi_layout_matches_linux_x86_64() {
        assert_eq!(size_of::<KvmCpuidEntry2>(), 40);
        assert_eq!(size_of::<KvmCpuid2>(), 8);
        assert_eq!(size_of::<KvmUserspaceMemoryRegion2>(), 160);
        assert_eq!(size_of::<KvmEnableCap>(), 104);
        assert_eq!(size_of::<KvmMemoryAttributes>(), 32);
        assert_eq!(size_of::<KvmCreateGuestMemfd>(), 64);
    }

    #[test]
    fn kvm_ioctl_numbers_match_linux_x86_64() {
        assert_eq!(KVM_GET_API_VERSION, 0xae00);
        assert_eq!(KVM_CREATE_VM, 0xae01);
        assert_eq!(KVM_CHECK_EXTENSION, 0xae03);
        assert_eq!(KVM_GET_VCPU_MMAP_SIZE, 0xae04);
        assert_eq!(KVM_GET_SUPPORTED_CPUID, 0xc008_ae05);
        assert_eq!(KVM_CREATE_VCPU, 0xae41);
        assert_eq!(KVM_SET_USER_MEMORY_REGION2, 0x40a0_ae49);
        assert_eq!(KVM_CREATE_IRQCHIP, 0xae60);
        assert_eq!(KVM_RUN, 0xae80);
        assert_eq!(KVM_SET_CPUID2, 0x4008_ae90);
        assert_eq!(KVM_ENABLE_CAP, 0x4068_aea3);
        assert_eq!(KVM_MEMORY_ENCRYPT_OP, 0xc008_aeba);
        assert_eq!(KVM_SET_MEMORY_ATTRIBUTES, 0x4020_aed2);
        assert_eq!(KVM_CREATE_GUEST_MEMFD, 0xc040_aed4);
    }
}
