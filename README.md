# RustyApple

Experimental independent Windows PE execution research, written in Rust.

**v0.1.0: research prototype, NOT a Wine replacement or general-purpose EXE converter.**

The first milestone demonstrates PE32+ inspection, load/relocate/invoke of a *strictly allowlisted* Windows AMD64 test PE, and native standalone unsigned macOS Intel .app packaging. There is no Windows API implementation, GUI, DirectX, game compatibility or generic Windows executable support.

## Usage

Requires stable Rust and Cargo.

    cargo fmt --all -- --check
    cargo clippy --all-targets -- -D warnings
    cargo test --all-targets
    cargo build --release
    cargo run -- fixture demo.exe
    cargo run -- inspect demo.exe
    cargo run -- run demo.exe

On Intel macOS, package and run the standalone headless example:

    mkdir -p dist
    cargo run --release -- fixture dist/demo.exe
    cargo run --release -- bundle dist/demo.exe dist
    "dist/RustyApple Demo.app/Contents/MacOS/RustyAppleDemo"

The bundle is unsigned and not notarized. Finder launch has no visual GUI yet. It cannot convert normal Windows EXEs or games. **Only the exact generated fixture may execute**; arbitrary PE files can be inspected but cannot run.

## Supported

| Feature | State |
| --- | --- |
| PE32+ bounded parser | Implemented, pending CI |
| AMD64 no-import fixture and DIR64 relocations | Experimental |
| macOS Intel AMD64 machine code invocation | Experimental, pending real-mac CI |
| Linux AMD64 fixture execution for CI | Experimental |
| Unsigned Intel macOS .app bundling | Experimental |
| Apple Silicon execution, PE32, DLLs, Windows APIs, graphics, GUI, DMG | Unsupported |
| General Windows app or game conversion | Unsupported |

See [architecture and roadmap](docs/ARCHITECTURE.md), [contribution guide](CONTRIBUTING.md) and [changelog](CHANGELOG.md).

MIT licensed.
