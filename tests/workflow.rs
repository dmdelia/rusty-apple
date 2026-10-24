use rustyapple::{fixture, pe::PeImage, runtime};

#[test]
fn fixture_parses_and_has_dir64_relocation() {
    let bytes = fixture::demo_exe();
    let image = PeImage::parse(&bytes).unwrap();
    assert!(image.execution_limitations().is_empty());
    assert_eq!(image.file_slice_at_rva(0x1030, 4).unwrap(), &42u32.to_le_bytes());
    assert_eq!(image.file_slice_at_rva(0x2000, 4).unwrap(), &0x1000u32.to_le_bytes());
}

#[test]
fn changed_fixture_is_denied_execution() {
    let mut bytes = fixture::demo_exe();
    bytes[0x230] = 41;
    assert!(runtime::execute_demo(&bytes).is_err());
}

#[test]
fn corrupt_raw_offset_is_rejected() {
    let mut bytes = fixture::demo_exe();
    bytes[0x188 + 20..0x188 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(PeImage::parse(&bytes).is_err());
}

#[test]
fn native_guest_code_returns_42_on_supported_hosts() {
    let result = runtime::execute_demo(&fixture::demo_exe());
    #[cfg(all(unix, target_arch = "x86_64"))]
    assert_eq!(result.unwrap(), 42);
    #[cfg(not(all(unix, target_arch = "x86_64")))]
    assert!(result.is_err());
}
