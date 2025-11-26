# Donut-rs
> A spiritual successor for [TheWover's Donut](https://github.com/TheWover/donut) written in Rust

This crate provides the full API for building Donut-rs payloads.
For the CLI tool, visit [this link](https://github.com/mrLochness350/donut-cli)

> [!WARNING]
> Currently only the Windows loader is supported.
> The Unix loader is currently gated behind the `unstable` feature due to unexpected segmentation faults.
> The Script loader is currently unavailable as well due to time constraints.


## Using in other tools
* Via the `cargo` cli:
```shell
cargo add libdonut-rs
```
* Via `Cargo.toml`:
```toml
libdonut-rs = "0.1.0"
```

## Features
| name       | description                                                                             |
|------------|-----------------------------------------------------------------------------------------|
| `loader`   | Feature that enables the `no_std` loader components used for in-memory execution        |
| `logging`  | Enables verbose console logging (intended only for debugging since it's **VERY** noisy) |
| `libc`     | Required by the (currently unstable) Unix loader. May be removed in the future          |
| `unstable` | WIP components and features that are not yet ready for release                          |
| `std`      | Enables the high-level API for generating and building payloads. Enabled by default.    |

## Example Usage

```rust
use std::io;
use libdonut_rs::{Donut, DonutConfig, DonutHttpInstance};

fn main() -> io::Result<()> {
    let http_opts = DonutHttpInstance::new("http://127.0.0.1:9001", Some("/payload.bin"), 5, Some("GET"), false);
    let cfg = DonutConfig::new("C:\\Windows\\System32\\calc.exe").http_options(Some(http_opts));
    println!("Created config: {cfg:?}");

    let mut donut = Donut::new(&cfg)?;
    println!("Created donut object");
    donut.build()?;
    println!("Finished building donut object");

    let p = donut.payload()?;
    let md = donut.metadata();
    println!("Metadata: {md:?}");
    println!("Payload size: {}", p.len());
    Ok(())
}
```

## Known Issues
* Binaries built using Visual Studio (the `msvc` toolkit in general) currently cause segfaults
* Arguments aren't being passed to the executed binary
* Unix loader causes segfaults when run
* AV bypass still doesn't work

## References
* [Donut by TheWover](https://github.com/TheWover/donut)
* [sliver-stage-helper by Esonhugh](https://github.com/Esonhugh/sliver-stage-helper) (ty Eson <3)
* [memexec](https://github.com/EddieIvan01/memexec)
* [Venom-rs](https://github.com/memN0ps/venom-rs)
* https://landaire.net/reflective-pe-loader-for-xbox/
* https://wiki.chainreactors.red/blog/2025/01/07/IoM_advanced_TLS/
* https://github.com/ichildyu/load-elf
* https://github.com/b1tg/rust-windows-shellcode
* https://github.com/AWBroch/rsbmalloc
* https://github.com/hasherezade/pe_to_shellcode
