//! Standalone unsigned macOS .app bundling for the *validated demo only*.
//! A bundle is not a Windows executable translator. Embedded RustyApple
//! performs the actual loading when launched without CLI arguments.

use crate::fixture;
use std::{fs, path::{Path, PathBuf}};

pub fn bundle_demo(guest: &Path, output_dir: &Path) -> Result<PathBuf, String> {
    if !cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        return Err("native .app packaging requires the macOS x86_64 build of RustyApple".into());
    }
    let bytes = fs::read(guest).map_err(|e| e.to_string())?;
    if bytes != fixture::demo_exe() {
        return Err("only RustyApple's exact demo EXE can currently be bundled".into());
    }

    let app = output_dir.join("RustyApple Demo.app");
    if app.exists() {
        return Err(format!("output already exists: {}", app.display()));
    }
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    fs::create_dir_all(&macos).map_err(|e| e.to_string())?;
    fs::create_dir_all(&resources).map_err(|e| e.to_string())?;
    let launcher = macos.join("RustyAppleDemo");
    let source_launcher = std::env::current_exe().map_err(|e| e.to_string())?;
    fs::copy(source_launcher, &launcher).map_err(|e| e.to_string())?;
    fs::write(resources.join("guest.exe"), &bytes).map_err(|e| e.to_string())?;
    fs::write(contents.join("Info.plist"), r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDevelopmentRegion</key><string>en</string>
<key>CFBundleExecutable</key><string>RustyAppleDemo</string>
<key>CFBundleIdentifier</key><string>org.rustyapple.research.demo</string>
<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
<key>CFBundleName</key><string>RustyApple Demo</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>0.1.0</string>
<key>CFBundleVersion</key><string>1</string>
<key>LSUIElement</key><true/>
</dict></plist>
"#).map_err(|e| e.to_string())?;
    Ok(app)
}

/// The Finder-launched app's native Rust binary invokes this when no arguments
/// are present. No GUI is implemented; demo writes the result to a diagnostic
/// text file alongside the guest inside the bundle? No: that would violate
/// read-only .app storage. Write to stdout and a user-writable report instead.
pub fn launch_from_bundle() -> Result<u32, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let macos = executable.parent().ok_or("executable has no parent")?;
    if macos.file_name().and_then(|s| s.to_str()) != Some("MacOS") {
        return Err("not launched from an application bundle".into());
    }
    let contents = macos.parent().ok_or("bundle missing Contents")?;
    if contents.file_name().and_then(|s| s.to_str()) != Some("Contents") {
        return Err("not launched from an application bundle".into());
    }
    let guest = contents.join("Resources").join("guest.exe");
    let bytes = fs::read(&guest).map_err(|e| e.to_string())?;
    crate::runtime::execute_demo(&bytes)
}
