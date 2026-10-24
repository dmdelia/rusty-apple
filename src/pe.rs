//! Bounded, read-only PE32+ inspection. No executable bytes are run here.

#[derive(Debug, Clone, Copy)]
pub struct Directory {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    pub fn span(&self) -> u32 {
        self.virtual_size.max(self.raw_size)
    }
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }
}

#[derive(Debug)]
pub struct PeImage<'a> {
    pub bytes: &'a [u8],
    pub machine: u16,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub sections: Vec<Section>,
    pub imports: Directory,
    pub relocations: Directory,
    pub tls: Directory,
    pub clr: Directory,
}

fn slice(bytes: &[u8], offset: usize, size: usize) -> Result<&[u8], String> {
    let end = offset.checked_add(size).ok_or("PE offset overflow")?;
    bytes.get(offset..end).ok_or_else(|| format!("PE truncated at offset 0x{offset:x}"))
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(slice(bytes, offset, 2)?.try_into().unwrap()))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(slice(bytes, offset, 4)?.try_into().unwrap()))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, String> {
    Ok(u64::from_le_bytes(slice(bytes, offset, 8)?.try_into().unwrap()))
}

impl<'a> PeImage<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if slice(bytes, 0, 2)? != b"MZ" {
            return Err("not a DOS/PE executable (missing MZ)".into());
        }
        let pe_off = u32_at(bytes, 0x3c)? as usize;
        if slice(bytes, pe_off, 4)? != b"PE\0\0" {
            return Err("invalid PE signature".into());
        }
        let coff = pe_off.checked_add(4).ok_or("PE offset overflow")?;
        let machine = u16_at(bytes, coff)?;
        let nsections = u16_at(bytes, coff + 2)? as usize;
        let optional_size = u16_at(bytes, coff + 16)? as usize;
        let opt = coff.checked_add(20).ok_or("PE offset overflow")?;
        let optional = slice(bytes, opt, optional_size)?;
        if u16_at(optional, 0)? != 0x20b {
            return Err("PE32 is not implemented: only PE32+ (64-bit) can be inspected".into());
        }
        if optional_size < 240 {
            return Err("PE32+ optional header is too small".into());
        }
        if nsections == 0 || nsections > 96 {
            return Err("unsupported section count".into());
        }
        let entry_rva = u32_at(optional, 16)?;
        let image_base = u64_at(optional, 24)?;
        let section_alignment = u32_at(optional, 32)?;
        let file_alignment = u32_at(optional, 36)?;
        let size_of_image = u32_at(optional, 56)?;
        let size_of_headers = u32_at(optional, 60)?;
        if section_alignment == 0 || file_alignment == 0 ||
            size_of_image == 0 || size_of_image > 256 * 1024 * 1024 ||
            size_of_headers == 0 || size_of_headers > size_of_image ||
            size_of_headers as usize > bytes.len() {
            return Err("invalid or oversized PE image layout".into());
        }
        if section_alignment < 4096 || section_alignment % 4096 != 0 {
            return Err("only page-aligned PE32+ sections are currently supported".into());
        }
        if u32_at(optional, 108)? < 16 {
            return Err("PE32+ must have 16 data directory slots for this loader".into());
        }
        let dir = |idx: usize| -> Result<Directory, String> {
            let off = 112 + idx * 8;
            Ok(Directory { rva: u32_at(optional, off)?, size: u32_at(optional, off + 4)? })
        };
        let table = opt.checked_add(optional_size).ok_or("section table overflow")?;
        let mut sections = Vec::with_capacity(nsections);
        for i in 0..nsections {
            let header = slice(bytes, table.checked_add(i * 40).ok_or("section table overflow")?, 40)?;
            let raw_name = &header[0..8];
            let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&raw_name[..name_end]).to_string();
            let section = Section {
                name,
                virtual_size: u32_at(header, 8)?,
                virtual_address: u32_at(header, 12)?,
                raw_size: u32_at(header, 16)?,
                raw_offset: u32_at(header, 20)?,
                characteristics: u32_at(header, 36)?,
            };
            let end = section.virtual_address.checked_add(section.span())
                .ok_or("section virtual address overflow")?;
            if section.span() == 0 || section.virtual_address < size_of_headers ||
                section.virtual_address % section_alignment != 0 || end > size_of_image {
                return Err(format!("invalid mapping for section {}", section.name));
            }
            if section.raw_size > 0 {
                slice(bytes, section.raw_offset as usize, section.raw_size as usize)?;
            }
            if sections.iter().any(|other: &Section| {
                section.virtual_address < other.virtual_address + other.span() &&
                    other.virtual_address < end
            }) {
                return Err("overlapping sections are unsupported".into());
            }
            sections.push(section);
        }
        if !sections.iter().any(|s| s.is_executable() &&
            entry_rva >= s.virtual_address &&
            entry_rva < s.virtual_address + s.span()) {
            return Err("PE entry point is not inside an executable section".into());
        }
        let image = Self {
            bytes, machine, image_base, entry_rva, size_of_image, size_of_headers,
            sections,
            imports: dir(1)?,
            relocations: dir(5)?,
            tls: dir(9)?,
            clr: dir(14)?,
        };
        Ok(image)
    }

    /// Translate a RVA into bytes physically present in the PE file.
    /// This is NOT a virtual-memory mapper: zero-fill areas are excluded.
    pub fn file_slice_at_rva(&self, rva: u32, size: usize) -> Result<&'a [u8], String> {
        let end = (rva as usize).checked_add(size).ok_or("RVA overflow")?;
        if end <= self.size_of_headers as usize {
            return slice(self.bytes, rva as usize, size);
        }
        for s in &self.sections {
            let start = s.virtual_address as usize;
            let raw_end = start.checked_add(s.raw_size as usize).ok_or("raw RVA overflow")?;
            if (rva as usize) >= start && end <= raw_end {
                return slice(self.bytes, s.raw_offset as usize + (rva as usize - start), size);
            }
        }
        Err(format!("RVA 0x{rva:x} is not backed by file bytes"))
    }

    pub fn execution_limitations(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if self.machine != 0x8664 {
            issues.push("only AMD64 machine code is implemented".into());
        }
        if self.imports.rva != 0 || self.imports.size != 0 {
            issues.push("Windows DLL imports are not implemented".into());
        }
        if self.tls.rva != 0 || self.tls.size != 0 {
            issues.push("TLS callbacks/Windows TLS are not implemented".into());
        }
        if self.clr.rva != 0 || self.clr.size != 0 {
            issues.push(".NET/CLR executables are not implemented".into());
        }
        if self.relocations.rva == 0 || self.relocations.size == 0 {
            issues.push("no usable relocation table (preferred-base mapping unsupported)".into());
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_pe() {
        assert!(PeImage::parse(b"hello").is_err());
        assert!(PeImage::parse(&[0_u8; 128]).is_err());
    }
}
