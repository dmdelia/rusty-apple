# Engineering architecture

## First host and guest

Initial execution combination is **Intel macOS x86_64 host and PE32+ Windows AMD64 guest**. Shared CPU instructions let us verify PE mapping and the Win64 calling convention before building a CPU translator. Linux x86_64 is an auxiliary CI host, not an intended product target. ARM64 macOS cannot directly execute this guest; Rosetta is not an arbitrary PE loader.

## Existing modules

- PE32+ parser: MZ/PE signature, optional headers, bounds-checked sections and directory metadata.
- Deterministic fixture generator: Windows AMD64 PE that loads a relocated pointer to a constant and returns 42.
- Native loader: anonymous mmap, section copy, DIR64 relocation, mprotect W^X, win64 ABI invocation.
- macOS bundler: standalone unsigned headless Intel .app containing guest payload and native Rust launcher.
- CLI: fixture, inspect, run, bundle.

## Isolation and security

**Native guest machine code is not sandboxed.** Unknown executables can only be parsed, never run. The loader rejects all inputs except the exact Rust-generated fixture. Never remove this gate without a separate privilege/IPC, resource-limits and guest-code-isolation design. File parsing uses bounds checks but still requires fuzz testing.

## Roadmap

1. M0: controlled native Win64-ABI proof of concept; Linux and Intel macOS tests.
2. M1: hardened PE image loader and import/export/relocation corpus, fuzz tests.
3. M2: real Windows process/thread semantics; kernel32/ntdll, PEB/TEB, virtual memory, filesystem and DLL loading.
4. M3: native Rust desktop UX, application profiles, crash logs, signing and notarizable .app distribution.
5. M4: User32/GDI, audio and legacy graphics compatibility; test legally obtained FNaF 1 only when prerequisites work.
6. M5: Apple Silicon AMD64 interpreter/DBT, 32-bit guest strategy, modern Direct3D to Metal.
7. M6: security hardening, game/application compatibility benchmarks and public signed releases.

## Explicit non-features

No CRT, kernel32, user32, DLL imports, registry, filesystem mapping, DirectX, Metal, Windows GUI, .NET, 32-bit or ARM host execution. Passing an entrypoint test is not equivalent to running a Windows app.

## Critical risks

Guest execution without isolation, Windows API coverage, image loader edge cases, SEH/TLS, ARM64 x86 translation, GPU translation, macOS security/signing and anti-cheat/DRM barriers.

No Wine/Whisky/CrossOver/Proton used. Rust standard library and minimal Unix C ABI for memory mapping.
