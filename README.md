# chisel-elftree

[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![chisel](https://img.shields.io/badge/%F0%9F%94%A8-chisel-E95420)](https://github.com/canonical/chisel)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/lczyk/chisel-elftree)
![GitHub Tag](https://img.shields.io/github/v/tag/lczyk/chisel-elftree?filter=v*&sort=semver&label=release)
[![lint_and_test](https://github.com/lczyk/chisel-elftree/actions/workflows/lint_and_test.yml/badge.svg)](https://github.com/lczyk/chisel-elftree/actions/workflows/lint_and_test.yml)

`lddtree` for what [chisel](https://github.com/canonical/chisel) slices deliver.

a development tool for [chisel-releases](https://github.com/canonical/chisel-releases) work, and a sister of [chisel-coverage](https://github.com/lczyk/chisel-coverage), [chisel-file](https://github.com/lczyk/chisel-file), [chisel-diff](https://github.com/lczyk/chisel-diff) and [chisel-proxy](https://github.com/lczyk/chisel-proxy). for a set of slices it cuts each one with the real chisel, essentials and all, on every architecture asked for, and follows every file the cut delivers the way the kernel and the dynamic loader would: interpreters, needed libraries, symlinks, shebangs and dlopen notes. then it says what does not resolve.

## why

a slice that ships a binary must ship what the binary needs to start, on every architecture, and what it dlopens must be delivered by some slice of the release. a yaml review cannot tell: what a slice delivers depends on its essentials and globs, and what a binary needs on its ELF headers and where the loader looks. so chisel is asked to cut the slice, and the rootfs is read as `ld.so` would read it. nothing is run, so any architecture is checked from any host.

## use

```shell
chisel-elftree --release ubuntu-26.04 --arch all systemd --slice tpm2 --file systemd-measure
systemd_tpm2 259.9-0ubuntu0.1 [amd64, arm64, armhf, ppc64el, riscv64, s390x]
/usr/lib/<arch>-linux-<gnu>/systemd/libsystemd-shared-259.so (libsystemd-shared_libs): soft dlopen libdw.so.1 (dw, suggested): no slice declares it
/usr/lib/<arch>-linux-<gnu>/systemd/libsystemd-shared-259.so (libsystemd-shared_libs): soft dlopen libtss2-esys.so.0 (tpm, suggested): no slice declares it
/usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs): info strings libgcc_s.so.1: delivered by libgcc-s1_libs
...
systemd_tpm2 [i386]: no file matches
```

one block per named slice and group of architectures that agree, with the architecture in paths folded to `<arch>` and `<gnu>`. a line is `<path> (<owner>): <severity> <kind> <name>: <reason>`, worst first, so `grep ': hard '` is what does not run.

`-T` / `--tree` draws the same blocks as trees:

```shell
chisel-elftree --release ubuntu-26.04 --arch amd64,arm64 openssl --slice bins -T --fold-repeats
openssl_bins 3.5.5-1ubuntu3.7 [amd64, arm64]
/usr/bin/openssl (openssl_bins): executable
├─ needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)
│  ├─ ? strings libgcc_s.so.1 (libgcc-s1_libs)
│  ├─ ? strings libidn2.so.0 (libidn2-0_libs)
│  └─ strings libnss_files.so.2 -> /usr/lib/<arch>-linux-<gnu>/libnss_files.so.2 (libc6_libs)
├─ needed libcrypto.so.3 -> /usr/lib/<arch>-linux-<gnu>/libcrypto.so.3 (libssl3t64_libs)
│  ├─ needed libz.so.1 -> /usr/lib/<arch>-linux-<gnu>/libz.so.1.3.1 (zlib1g_libs)
│  └─ needed libzstd.so.1 -> /usr/lib/<arch>-linux-<gnu>/libzstd.so.1.5.7 (libzstd1_libs)
└─ needed libssl.so.3 -> /usr/lib/<arch>-linux-<gnu>/libssl.so.3 (libssl3t64_libs)
/usr/lib/ssl/cert.pem -> /etc/ssl/certs/ca-certificates.crt (openssl_data): symlink
└─ ! symlink /etc/ssl/certs/ca-certificates.crt: /etc/ssl/certs/ca-certificates.crt does not exist
```

an edge is `<kind> <name> -> <path> (<owner>)`. `!` is a finding. `?` is a dlopen the cut does not answer: with the slice that delivers it in parens, bare when no slice declares it. a line only some architectures have is a block of those, under the lines above it, dimmed.

what is followed:

- **hard** -- `interp`, `needed`, `filter`, symbol `version`s, `symlink`s, a script's `shebang` and what `env` runs. a miss means it does not start.
- **soft** -- `dlopen` entries of the ELF's `.note.dlopen`, as the [FDO spec](https://uapi-group.org/specifications/specs/elf_dlopen_metadata/) has them, and `strings`: a library's name among the file's strings that nothing else explains. need not be in the cut, but some slice should deliver it.

a finding counts against the named slice whose file it starts from, and one about a file a reached slice delivers names that slice. what a slice outside the cut would deliver is cut too, to check it loads.

- `--file` narrows to the start nodes matching, and what they go on to.
- `--prune` leaves libraries out of what is drawn, never a finding. the dynamic loader (`@ld`) is left out by default; `--prune=` brings it back.
- `--fold-repeats` draws a library once under a start node, as lddtree does.
- `--show-missing` draws what a dlopen outside the cut would load.
- `--no-group` gives one block per architecture with its real paths.
- `--json` is the graph of every cut, the findings with their chains, and the blocks.

a package can be given as the path of its file (`slices/openssl.yaml`), so tab completion works, and `--slice` picks slices as the sister tools do. `--release` takes a checkout or a release name, which chisel fetches into its cache.

`--fail-missing` makes it a check. exit codes:

- 0 -- ran fine, whatever it found.
- 1 -- only with `--fail-missing`: a hard finding, or a `required` dlopen nothing delivers, counting against a named slice. `--strict` adds any dlopen, `--fail-reached` what counts only against reached slices.
- 2 -- a cut failed, a release chisel refuses, an ELF the reader cannot parse.

## known gaps

- config-driven loading is not followed: `nsswitch.conf`, `/etc/pam.d`, `openssl.cnf` providers, `gconv-modules`. every module a cut ships is still checked on its own.
- a dlopen with no note and no library name in the file's strings is not seen.
- which `glibc-hwcaps/` variant a cpu would pick is not modelled; every variant is checked.
- 26.10's archive has sha512 digests only, and chisel cannot write the manifest the tool reads without sha256.

`design.md` is the design note the tool was built from.

## library

`pkg/validate-trick` answers which slices of a release declare a path, with chisel's own glob matching and nothing cut, through chisel's release validation. it knows nothing of ELFs, so any tool can use it:

```shell
go get github.com/lczyk/chisel-elftree/pkg
```

## build

```shell
make build     # ./bin/chisel-elftree
make verify    # lint + tests
make e2e       # against the real archive
```

needs `chisel` on `PATH`, or `CHISEL=`.
