//! Deterministic, deliberately tiny PE32+ Windows *test program*.
//! Entry point reads a relocated pointer to an integer and returns 42.
//! It has no CRT, imports, Windows API calls, GUI, filesystem or threading.
//! This fixture exercises PE parsing, section loading, DIR64 relocation,
//! executable memory protection and Windows x64 calling convention.

fn w16(out: &mut [u8], off: usize, value: u16) {
    out[off..off + 2].copy_from_slice(&value.to_le_bytes());
}
fn w32(out: &mut [u8], off: usize, value: u32) {
    out[off..off + 4].copy_from_slice(&value.to_le_bytes());
}
fn w64(out: &mut [u8], off: usize, value: u64) {
    out[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

/// Returns a syntactically valid 64-bit PE console executable (1536 bytes).
pub fn demo_exe() -> Vec<u8> {
    const BASE: u64 = 0x0000_0001_4000_0000;
    let mut b = vec![0_u8; 0x600];
    b[0..2].copy_from_slice(b"MZ");
    w32(&mut b, 0x3c, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    w16(&mut b, coff, 0x8664); // AMD64
    w16(&mut b, coff + 2, 2); // section count
    w16(&mut b, coff + 16, 0xf0); // optional header bytes
    w16(&mut b, coff + 18, 0x22); // executable + large address aware
    let o = 0x98;
    w16(&mut b, o, 0x20b); // PE32+
    w32(&mut b, o + 16, 0x1000); // AddressOfEntryPoint
    w32(&mut b, o + 20, 0x1000); // BaseOfCode
    w64(&mut b, o + 24, BASE); // ImageBase
    w32(&mut b, o + 32, 0x1000); // SectionAlignment
    w32(&mut b, o + 36, 0x200); // FileAlignment
    w16(&mut b, o + 48, 6); // minimum Windows version
    w32(&mut b, o + 56, 0x3000); // SizeOfImage
    w32(&mut b, o + 60, 0x200); // SizeOfHeaders
    w16(&mut b, o + 68, 3); // console subsystem
    w16(&mut b, o + 70, 0x140); // dynamic base + NX compatible
    w64(&mut b, o + 72, 0x100000); // stack reserve
    w64(&mut b, o + 80, 0x1000); // stack commit
    w64(&mut b, o + 88, 0x100000); // heap reserve
    w64(&mut b, o + 96, 0x1000); // heap commit
    w32(&mut b, o + 108, 16); // data directories
    w32(&mut b, o + 112 + 5 * 8, 0x2000); // .reloc RVA
    w32(&mut b, o + 112 + 5 * 8 + 4, 12); // .reloc size

    // PE section headers.
    let s1 = 0x188;
    b[s1..s1 + 5].copy_from_slice(b".text");
    w32(&mut b, s1 + 8, 0x40);
    w32(&mut b, s1 + 12, 0x1000);
    w32(&mut b, s1 + 16, 0x200);
    w32(&mut b, s1 + 20, 0x200);
    w32(&mut b, s1 + 36, 0x6000_0020); // code, read, execute
    let s2 = s1 + 40;
    b[s2..s2 + 6].copy_from_slice(b".reloc");
    w32(&mut b, s2 + 8, 12);
    w32(&mut b, s2 + 12, 0x2000);
    w32(&mut b, s2 + 16, 0x200);
    w32(&mut b, s2 + 20, 0x400);
    w32(&mut b, s2 + 36, 0x4200_0040); // initialized, read, discardable

    // x86_64: mov rax,[rip+0x19]; mov eax,[rax]; ret
    b[0x200..0x20a].copy_from_slice(&[0x48, 0x8b, 0x05, 0x19, 0, 0, 0, 0x8b, 0, 0xc3]);
    w64(&mut b, 0x220, BASE + 0x1030); // relocated pointer
    w32(&mut b, 0x230, 42); // constant reached via that pointer

    // .reloc block (page 0x1000; entry IMAGE_REL_BASED_DIR64 at +0x20).
    w32(&mut b, 0x400, 0x1000);
    w32(&mut b, 0x404, 12);
    w16(&mut b, 0x408, 0xa020);
    w16(&mut b, 0x40a, 0); // ABSOLUTE padding entry
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::PeImage;

    #[test]
    fn fixture_is_valid_pe32_plus() {
        let bytes = demo_exe();
        let pe = PeImage::parse(&bytes).expect("valid PE");
        assert_eq!(pe.machine, 0x8664);
        assert_eq!(pe.entry_rva, 0x1000);
        assert_eq!(pe.sections.len(), 2);
        assert_eq!(pe.relocations.size, 12);
        assert!(pe.execution_limitations().is_empty());
    }
}
