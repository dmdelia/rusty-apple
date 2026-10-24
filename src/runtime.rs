//! Minimal native PE32+ loader for a single vetted x86_64 Windows test program.
//! WARNING: native execution gives guest machine code the host process's privileges.
//! Do not remove the exact-fixture allowlist without building an isolation strategy.

use crate::{fixture, pe::PeImage};

pub const EXPECTED_RETURN: u32 = 42;

/// Execute only the exact deterministic RustyApple test PE.
/// It really maps, relocates and calls AMD64 Windows entry-point machine code;
/// it does not interpret or return a simulated result.
pub fn execute_demo(bytes: &[u8]) -> Result<u32, String> {
    if bytes != fixture::demo_exe() {
        return Err("execution denied: only RustyApple's exact vetted demo PE is supported; arbitrary EXEs are inspect-only".into());
    }
    let pe = PeImage::parse(bytes)?;
    let issues = pe.execution_limitations();
    if !issues.is_empty() {
        return Err(format!("unsupported PE: {}", issues.join("; ")));
    }
    #[cfg(all(unix, target_arch = "x86_64"))]
    {
        unix_x64::execute(&pe)
    }
    #[cfg(not(all(unix, target_arch = "x86_64")))]
    {
        let _ = pe;
        Err("execution unsupported: x86_64 Unix host required (macOS Intel; Linux x86_64 for CI)".into())
    }
}

#[cfg(all(unix, target_arch = "x86_64"))]
mod unix_x64 {
    use crate::pe::PeImage;
    use std::ffi::{c_int, c_void};
    use std::ptr;

    const PROT_READ: c_int = 1;
    const PROT_WRITE: c_int = 2;
    const PROT_EXEC: c_int = 4;
    const MAP_PRIVATE: c_int = 2;
    #[cfg(target_os = "macos")]
    const MAP_ANON: c_int = 0x1000;
    #[cfg(not(target_os = "macos"))]
    const MAP_ANON: c_int = 0x20;

    extern "C" {
        fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
        fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> c_int;
        fn munmap(addr: *mut c_void, len: usize) -> c_int;
        fn getpagesize() -> c_int;
    }

    struct Memory {
        addr: *mut u8,
        len: usize,
    }

    impl Memory {
        fn allocate(len: usize) -> Result<Self, String> {
            // Initially writable and NOT executable. W^X is maintained at all times.
            let ptr = unsafe {
                mmap(ptr::null_mut(), len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
            };
            if ptr as isize == -1 {
                return Err(format!("mmap failed: {}", std::io::Error::last_os_error()));
            }
            Ok(Self { addr: ptr.cast(), len })
        }

        fn slice_mut(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.addr, self.len) }
        }

        fn set_protection(&self, start: usize, len: usize, prot: c_int) -> Result<(), String> {
            if start.checked_add(len).is_none_or(|end| end > self.len) {
                return Err("invalid mprotect range".into());
            }
            if unsafe { mprotect(self.addr.add(start).cast(), len, prot) } != 0 {
                return Err(format!("mprotect failed: {}", std::io::Error::last_os_error()));
            }
            Ok(())
        }
    }

    impl Drop for Memory {
        fn drop(&mut self) {
            unsafe { munmap(self.addr.cast(), self.len); }
        }
    }

    fn round_up(n: usize, page: usize) -> Result<usize, String> {
        n.checked_add(page - 1).map(|v| (v / page) * page).ok_or("page rounding overflow".into())
    }

    fn relocate(mem: &mut Memory, pe: &PeImage<'_>) -> Result<(), String> {
        let base = mem.addr as u64;
        let delta = base as i128 - pe.image_base as i128;
        if delta == 0 { return Ok(()); }
        let dir = pe.relocations;
        if dir.rva == 0 || dir.size == 0 {
            return Err("image was not mapped at preferred base and has no relocations".into());
        }
        let table = pe.file_slice_at_rva(dir.rva, dir.size as usize)?;
        let mut cursor = 0;
        while cursor < table.len() {
            if table.len() - cursor < 8 {
                return Err("truncated base relocation block".into());
            }
            let page_rva = u32::from_le_bytes(table[cursor..cursor+4].try_into().unwrap());
            let block_size = u32::from_le_bytes(table[cursor+4..cursor+8].try_into().unwrap()) as usize;
            if block_size < 8 || !block_size.is_multiple_of(2) || block_size > table.len() - cursor {
                return Err("invalid base relocation block size".into());
            }
            let mut ent = cursor + 8;
            while ent < cursor + block_size {
                let item = u16::from_le_bytes(table[ent..ent+2].try_into().unwrap());
                let kind = item >> 12;
                let offset = (item & 0xfff) as usize;
                if kind != 0 {
                    if kind != 10 {
                        return Err(format!("unsupported relocation type {kind}; only DIR64 supported"));
                    }
                    let at = (page_rva as usize).checked_add(offset).ok_or("relocation RVA overflow")?;
                    let end = at.checked_add(8).ok_or("relocation range overflow")?;
                    if end > mem.len {
                        return Err("relocation outside mapped image".into());
                    }
                    let image = mem.slice_mut();
                    let old = u64::from_le_bytes(image[at..end].try_into().unwrap());
                    let new = old as i128 + delta;
                    if !(0..=u64::MAX as i128).contains(&new) {
                        return Err("relocated pointer does not fit in 64 bits".into());
                    }
                    image[at..end].copy_from_slice(&(new as u64).to_le_bytes());
                }
                ent += 2;
            }
            cursor += block_size;
        }
        Ok(())
    }

    pub(super) fn execute(pe: &PeImage<'_>) -> Result<u32, String> {
        let page = unsafe { getpagesize() } as usize;
        if page == 0 || !page.is_power_of_two() {
            return Err("unsupported host page size".into());
        }
        let len = round_up(pe.size_of_image as usize, page)?;
        let mut mem = Memory::allocate(len)?;
        {
            let image = mem.slice_mut();
            image[..pe.size_of_headers as usize].copy_from_slice(&pe.bytes[..pe.size_of_headers as usize]);
            for section in &pe.sections {
                let start = section.virtual_address as usize;
                let raw = section.raw_size as usize;
                let from = section.raw_offset as usize;
                image[start..start + raw].copy_from_slice(&pe.bytes[from..from + raw]);
            }
        }

        relocate(&mut mem, pe)?;

        // All pages read-only by default. Individual sections are made RX or RW,
        // never RWX. A section sharing a page with another section is rejected.
        mem.set_protection(0, len, PROT_READ)?;
        let mut protected = std::collections::HashSet::new();
        for section in &pe.sections {
            let start = section.virtual_address as usize / page * page;
            let end = round_up(section.virtual_address as usize + section.span() as usize, page)?;
            let writable = section.characteristics & 0x8000_0000 != 0;
            let executable = section.characteristics & 0x2000_0000 != 0;
            if writable && executable {
                return Err("W+X section rejected".into());
            }
            for at in (start..end).step_by(page) {
                if !protected.insert(at) {
                    return Err("sections sharing a host memory page are unsupported".into());
                }
            }
            let mut prot = PROT_READ;
            if writable { prot |= PROT_WRITE; }
            if executable { prot |= PROT_EXEC; }
            mem.set_protection(start, end - start, prot)?;
        }

        let entry_address = unsafe { mem.addr.add(pe.entry_rva as usize) };
        // Exact known fixture only. Windows x64 ABI provides the required call
        // frame and shadow space. The guest returns a u32 instead of ExitProcess.
        type Entry = unsafe extern "win64" fn() -> u32;
        let entry: Entry = unsafe { std::mem::transmute(entry_address) };
        let result = unsafe { entry() };
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn will_not_execute_untrusted_input() {
        assert!(execute_demo(b"MZ").is_err());
    }
    #[test]
    fn actual_machine_code_returns_42_where_supported() {
        let result = execute_demo(&fixture::demo_exe());
        #[cfg(all(unix, target_arch = "x86_64"))]
        assert_eq!(result.expect("execute relocatable PE fixture"), EXPECTED_RETURN);
        #[cfg(not(all(unix, target_arch = "x86_64")))]
        assert!(result.is_err());
    }
}
