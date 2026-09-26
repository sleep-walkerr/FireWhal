use aya_build::{build_ebpf, Package, Toolchain};

/// The eBPF toolchain is pinned here, in-repo, rather than relying on
/// whichever `nightly` happens to resolve on the build host. aya-build
/// drives the eBPF build with `rustup run <toolchain> cargo -Z build-std=core`,
/// and the host's bpf-linker must be able to parse the LLVM bitcode that
/// *this* toolchain emits (bpf-linker's linked libLLVM vs. the nightly's
/// bitcode version). The working pairing for the 2026-09-26 host (CachyOS,
/// libLLVM 22) is this nightly + bpf-linker 0.11.1 built with `llvm-22`;
/// see `test-vm/README.md` for the full pairing rules.
const EBFPC_TOOLCHAIN: &str = "nightly-2026-07-15";

fn main() -> anyhow::Result<()> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let root_dir = std::path::Path::new(&manifest)
        .join("..")
        .join("firewhal-kernel-ebpf");
    let root_dir = root_dir.to_str().expect("non-utf8 path");

    build_ebpf(
        [Package {
            name: "firewhal-kernel-ebpf",
            root_dir,
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom(EBFPC_TOOLCHAIN),
    )
}
