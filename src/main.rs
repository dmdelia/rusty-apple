use rustyapple::{bundle, fixture, pe::PeImage, runtime};
use std::{env, fs, path::Path, process};

fn usage() {
    eprintln!("RustyApple experimental CLI v{}\n\
Usage:\n\
  rustyapple fixture <output.exe>    Generate the deterministic PE32+ test EXE\n\
  rustyapple inspect <input.exe>     Read-only PE inspection (arbitrary input)\n\
  rustyapple run <input.exe>         Execute only the vetted test EXE\n\
  rustyapple bundle <input.exe> <output-directory>  Build standalone macOS Intel demo .app\n\
\nNo Wine, no general Windows API layer, no game compatibility and no desktop GUI yet.",
        env!("CARGO_PKG_VERSION"));
}
fn work() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() == 1 {
        match bundle::launch_from_bundle() {
            Ok(code) => {
                println!("RustyApple Demo: PE entry returned {code}");
                return if code == runtime::EXPECTED_RETURN { Ok(()) } else { Err(format!("unexpected guest result {code}")) };
            }
            Err(_) => { usage(); return Err("no command provided".into()); }
        }
    }
    match (args[1].as_str(), args.len()) {
        ("fixture", 3) => {
            fs::write(&args[2], fixture::demo_exe()).map_err(|e| e.to_string())?;
            println!("Wrote verified minimal PE32+ test program to {}", args[2]);
        }
        ("inspect", 3) => {
            let bytes = fs::read(&args[2]).map_err(|e| e.to_string())?;
            let pe = PeImage::parse(&bytes)?;
            println!("Format: PE32+\nMachine: 0x{:04x}\nEntry RVA: 0x{:x}\nImage base: 0x{:x}\nSections: {}",
                pe.machine, pe.entry_rva, pe.image_base, pe.sections.len());
            for s in &pe.sections {
                println!("  {}: RVA=0x{:x} raw={} executable={}", s.name, s.virtual_address, s.raw_size, s.is_executable());
            }
            let issues = pe.execution_limitations();
            if issues.is_empty() {
                println!("Static subset requirements: no known blockers (NOT a compatibility guarantee)");
            } else {
                println!("Unsupported requirements:\n  - {}", issues.join("\n  - "));
            }
            println!("Execution policy: ONLY exact RustyApple test fixture; arbitrary binaries denied.");
        }
        ("run", 3) => {
            let bytes = fs::read(&args[2]).map_err(|e| e.to_string())?;
            let code = runtime::execute_demo(&bytes)?;
            println!("Executed Windows PE32+ machine code; entry returned {code}");
            if code != runtime::EXPECTED_RETURN {
                return Err("test PE returned unexpected value".into());
            }
        }
        ("bundle", 4) => {
            let app = bundle::bundle_demo(Path::new(&args[2]), Path::new(&args[3]))?;
            println!("Created unsigned, headless, self-contained demo app: {}", app.display());
            println!("NOT signed, notarized, GUI-enabled, or compatible with general Windows applications.");
        }
        _ => { usage(); return Err("invalid command line".into()); }
    }
    Ok(())
}

fn main() {
    if let Err(e) = work() {
        eprintln!("RustyApple error: {e}");
        process::exit(1);
    }
}
