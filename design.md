# chisel-elftree: design

`lddtree` for [chisel](https://github.com/canonical/chisel) slices. a development tool for [chisel-releases](https://github.com/canonical/chisel-releases) work, sister of [chisel-coverage](https://github.com/lczyk/chisel-coverage), [chisel-file](https://github.com/lczyk/chisel-file), [chisel-diff](https://github.com/lczyk/chisel-diff) and [chisel-proxy](https://github.com/lczyk/chisel-proxy). for a set of slices, on every architecture asked for, it cuts each slice for real, follows how the files of the rootfs reach each other at run time (dynamic loader, symlinks, shebangs, dlopen), and reports what does not resolve.

## why

two uses, one tool:

- **authoring** -- "cut this slice and show me its tree". every ELF and script the slice delivers, every edge followed, every node labelled with the slice it comes from.
- **review** -- "does every binary in these slices have everything it needs". what the dynamic loader loads must be in the slice's own cut, on every arch. what is only dlopen'd need not be, but some slice in the release must deliver it and itself be sound.

a yaml review cannot answer either. what a slice delivers depends on its essentials, globs and mutate scripts, and what a binary needs depends on its ELF headers, its rpath and what the loader finds where.

## principle

- chisel does the cutting and all the glob matching. the tool never reads an archive, extracts a `.deb`, evaluates a glob or resolves an essential. every listing is a real `chisel cut` against the release as it is, so it is what a user of that slice gets.
- the tool's own work is reading ELF files and scripts out of the rootfs, resolving their edges the way `ld.so` and `execve` would inside that rootfs, and folding.
- static only. nothing from a rootfs is ever executed, so every arch is checked from any host, macos included.
- not git-aware. it takes a release dir or name and a set of packages or slices. which slices to check is the caller's business; `chisel-diff --name-status` is one way to get that list.
- no changes to chisel. what chisel cannot answer directly is answered through what it already does (see "provider lookup").

## how it works

1. resolve `--release` (`chisel-coverage/pkg/release`) and the arches (`pool.ResolveArches`).
2. copy the release (`chisel-proxy/pkg/temp-release`) and give each package to be cut a slice `elftree-manifest` holding `/var/lib/chisel-elftree/**: {generate: manifest}`, added through the file's yaml nodes so anchors and comments stay.
3. one `pool.Unit` per (named slice, arch) with that slice alongside, through `chisel-coverage/pkg/pool`: lead arch first, the rest after, a kept view of chisel's cache per worker. a package missing on an arch is `not available`.
4. while each rootfs exists: read the manifest for the slice of every path, walk the tree, read every ELF (mapped, not copied), shebang line and symlink. keep only what was read; the rootfs goes.
5. resolve from every start node, apply the hard rule, collect the soft edges the cut does not answer.
6. look those up across the release (below). candidates are cut through the same pool, as units of their own.
7. build each named slice's tree per arch, fold the arches, render.

### the graph

nodes are paths in a cut's rootfs, each with what was read of it and the slices the manifest says it came from. edges are typed. a missing target is a dangling edge. resolving is per start node, since one `DT_NEEDED` can resolve differently from two.

hard edges, the binary does not start or the script does not run without them:

- **interp** -- `PT_INTERP`, through `/lib64` and the like, so a missing link there shows.
- **needed**, **filter** -- `DT_NEEDED` and `DT_FILTER`, resolved as `ld.so` does.
- **symlink** -- every hop its own edge, absolute targets re-rooted. a loop is hard. a missing target is a warning, since a slice may ship a link another slice completes.
- **shebang**, **env** -- `#!/usr/bin/perl`, and `#!/usr/bin/env python3` as two edges, the second on the default `PATH`. the interpreter is a new process, resolved as a start node of its own.
- **version** -- a `DT_VERNEED` version a provider with `DT_VERDEF` lacks is fatal unless weak. a provider with no `DT_VERDEF` is a warning, as glibc says it.

warnings, the loader carries on:

- **auxiliary** -- `DT_AUXILIARY`.
- **preload** -- an `/etc/ld.so.preload` entry that cannot be mapped. one that can is loaded with every dynamic executable of the cut.

soft edges, loaded by the program itself, need not be in the cut:

- **dlopen** -- the [ELF dlopen metadata](https://uapi-group.org/specifications/specs/elf_dlopen_metadata/) note, found by owner `FDO` and type in `PT_NOTE` segments and note sections. each entry is one edge, `{feature, priority, soname: [...]}`, its sonames alternatives in order. priority is `required`, `recommended` or `suggested`.
- **strings** -- a string of the file shaped like a library's name (a whole printable run, `lib*.so[.N...]`) that its link table, notes, interpreter and own name do not explain. most likely a dlopen with no note: libc's `libgcc_s.so.1`. never worse than a warning. `--no-strings` turns it off.

not followed: config-driven loading (`nsswitch.conf`, `/etc/pam.d`, `openssl.cnf`, `gconv-modules`), dlopen by a name built at run time, language-level imports, commands run from scripts, anything outside the rootfs, and which `glibc-hwcaps/` variant a cpu picks. every module a cut ships is still checked as an ELF of its own, so a broken one shows; a missing one does not.

### the resolver

per start node, per arch, inside the rootfs. only ELFs a loader of the arch could start or load are start nodes: `ET_EXEC` or `ET_DYN`, the arch's machine and class, a linux or sysv abi. anything else (`.o`, `.ko`, ebpf, another arch's binaries) is listed as foreign, never fails, and is checked only when a start node reaches it.

loading follows glibc's `dl-deps.c`: breadth first, with the objects loaded so far. a name matching one of them is that object. otherwise:

1. `$ORIGIN`, `$LIB`, `$PLATFORM` expanded. a name with a `/` is a path. a relative one is a finding.
2. `DT_RPATH` of the asker and each object that loaded it, back to the executable, when the asker has no `DT_RUNPATH`.
3. `DT_RUNPATH` of the asker.
4. the default dirs, unless `DF_1_NODEFLIB`: `/lib/<triplet>`, `/usr/lib/<triplet>`, `/lib`, `/usr/lib` on every arch, from ubuntu 26.04's `ld.so --help`.

in every dir, `glibc-hwcaps/<subdir>/` comes first for the arch's subdirs (amd64 `x86-64-v4/v3/v2`, ppc64el `power10/9`, s390x `z17` to `z13`). an empty or relative rpath component is a warning. a candidate of another class or machine is skipped, as `ld.so` skips it. what is found must load as a library: `ET_DYN` with a `PT_DYNAMIC`, not a PIE, and for dlopen not `DF_1_NOOPEN`.

a chisel rootfs has no `/etc/ld.so.cache` and `ld.so` reads no `ld.so.conf`, so a library found only through an `/etc/ld.so.conf.d/*.conf` dir is hard ("only reachable through ld.so.conf.d"). a cut that does ship a cache is marked unsupported, never a pass.

a library checked on its own is loaded as if by an executable with no rpath. one whose need is in the cut only off the search path is a warning: systemd's `libsystemd-core-*.so` only loads after an executable whose runpath loaded `libsystemd-shared-*.so`.

the ELF reader works from program headers, not section headers, so a section-stripped file reads the same. a dynamic ELF it cannot parse is an error, never a pass. it agreed with `debug/elf` on every ELF of a systemd cut, and the resolver with the real loader (`LD_TRACE_LOADED_OBJECTS` in the rootfs under docker) on every executable of a multi-slice 26.04 cut on arm64, amd64 and s390x.

### rules

per (slice, arch), on the slice's own real cut:

- **hard** -- every hard edge reached from a start node resolves inside the cut.
- **soft** -- every dlopen resolves inside the cut and loads there, or some slice in the release delivers its target on that arch and passes the hard rule for it in its own cut. one delivered elsewhere is info naming the slice. one no slice declares is soft, with the note's feature and priority. a `required` one fails like a hard one.

### named and reached

a slice given on the command line is named. one whose files are in a named slice's cut only through essentials is reached. the manifest says which slice every file came from.

a finding counts against a named slice when the start node it was found from is delivered by one, or run by one through a script or a link. a named executable that cannot start because a reached library lacks something is the named slice's failure. a finding only reached slices' start nodes have counts against the slice delivering its file, shown and failing only with `--fail-reached`.

### provider lookup

a dlopen target the cut does not deliver: does some slice of the release deliver it on that arch, and pass the hard rule for it in its own cut. one provider is enough per entry. cheapest first, chisel deciding every answer:

1. **the cut itself**, resolved already.
2. **any cut of this run** whose manifest has the target. a slice that was only reached is a candidate, not an answer, since its essentials' cut may have filled its gaps.
3. **the shortlist**: the literal strings a slice would write for the target (`/usr/lib/*-linux-*`, `/lib/*-linux-*` and the triplet dirs, crossed with `libkmod.so.2`, `libkmod.so.2*`, `libkmod.so.2.*`, `libkmod.so.*`, `libkmod.so*`), looked up by string equality among every `contents` key of the release, the key's `arch:` read as written.
4. **`pkg/validate-trick`**, the backstop. it finds a slice whose glob covers the target with chisel's own matcher, and says for sure when nothing declares it.

every candidate is cut on its own and must deliver the target and pass the hard rule for it. a wrong shortlist costs time, never correctness. a candidate that does not hold up (not available, matches nothing, lacks the target, fails the rule) is rejected with its reason and the lookup moves on. only a failure of the run itself is exit 2. targets are looked up under every spelling merged-usr makes equal (`/lib` and `/usr/lib`, `/lib64`, `/bin`, `/sbin`).

### `pkg/validate-trick`

which slices of a release declare a path, answered by chisel's conflict check. a public package in the nested `pkg/` module, knowing nothing of ELFs, so the sister tools can use it.

chisel validates a release whenever it loads one, offline. a probe package declaring the target as generated `text:` conflicts with any other package's extracted content there, and chisel names the declarer in one of three shapes: path against path, glob against path, and a path with `prefer` relationships declared outside them.

1. one probe declares every target a round waits on. a clean validation clears them all at once; a conflict names a target someone declares, which leaves the probe for the next round. nothing-declares-it, the common answer, costs one validation for the lot.
2. a declared target gets a copy of the release of its own (`chisel.yaml` copied, slice files symlinked, a file replaced only when a key is deleted from it) and a probe of its own. each conflict yields `(target, slice, key)`, the key is deleted from the copy, and it validates again until clean.
3. a prefer conflict is answered by string equality on the keys, since such a path is only ever a literal key.
4. any other error, or a round deleting nothing, is an error, never "no slice".

the api is a lazy sequence; the caller stops pulling once satisfied. validation ignores `arch:`, so the confirming cut, per arch, settles it. chisel's error text could change, so the real-chisel tests pin all three shapes.

## cli

```
chisel-elftree [flags] <package|path/to/package.yaml>...
```

packages are positionals or the paths of their files, `--slice` picks slices as the sister tools do (`chisel-coverage/pkg/packageslicesfile`), lists split on commas and repeat, `-T` is `--tree`, `version` and `help` as the first argument are aliases. `--help` lists the start nodes, edges and severities.

- `--file` narrows the named cuts to the start nodes matching, and what they go on to, before the lookup. a glob matching nothing, or nothing that is a start node, is an error; an arch where it matches nothing says so.
- `--prune` leaves libraries out of the trees by name or path, never a finding. `@ld` is the arch's loader by its soname and is pruned by default. each value adds to the list, and an empty one forgets what came before, `@ld` too.
- `--fold-repeats` draws a library once under a start node, as lddtree does without `--all`: the lines right under a node claim their libraries before any is expanded, and an alert is never folded.
- `--show-missing` draws under a dlopen a slice outside the cut delivers what that slice's cut would load.
- both `--file` and `--prune` take chisel's glob syntax through a small matcher of the tool's own, chisel's being internal.

exit codes, as the sisters (report by default, fail on opt-in):

- 0 -- ran fine, whatever it found.
- 1 -- only with `--fail-missing`: a hard finding, or a `required` dlopen not delivered, counting against a named slice. `--strict` adds every soft one, `--fail-reached` the ones counting against reached slices only.
- 2 -- usage, a cut that failed, a release chisel refuses, an ELF the reader cannot parse, a cut with an `ld.so.cache`.
- 130 -- interrupted.

## report

every report draws from the same blocks. per named slice and arch the tree is built as the loader would load each file alone: a library's children are its own start node's, and its own `PT_INTERP` (libc has one) is not drawn. the loader is drawn once for a program, as its interpreter, and not where libc needs it again. under a node: the loader, then the link table by name, then findings, then dlopens by priority (required, recommended, suggested, strings), each by name. a node is drawn in full wherever it is reached; only one already on the way down is cut, marked `(cycle)`.

### folding

a line of a tree is told apart by its chain from the root, with what names the architecture normalised (`chisel-coverage/pkg/fold`: `x86_64` to `<arch>`, the triplet's abi to `<gnu>`) and the package's version as what must agree. `fold.Fold` groups the arches per line, as the sister tools group their findings, so a package of another version never folds. each set of arches that shares lines is a block, most arches first, its tree grown back from its chains. a line above that belongs to a bigger block is drawn as context, dim. `--no-group` makes every arch its own block with its real paths.

```
systemd_tpm2 259.9-0ubuntu0.1 [amd64, arm64, armhf, ppc64el, riscv64, s390x]
/usr/lib/systemd/systemd-measure (systemd_tpm2): executable
├─ needed libc.so.6 -> /usr/lib/<arch>-linux-<gnu>/libc.so.6 (libc6_libs)
│  ├─ ? strings libgcc_s.so.1 (libgcc-s1_libs)
│  └─ strings libnss_files.so.2 -> /usr/lib/<arch>-linux-<gnu>/libnss_files.so.2 (libc6_libs)
...
systemd_tpm2 259.9-0ubuntu0.1 [amd64, arm64, ppc64el, s390x]
/usr/lib/systemd/systemd-measure (systemd_tpm2): executable
└─ needed libsystemd-shared-259.so -> /usr/lib/<arch>-linux-<gnu>/systemd/libsystemd-shared-259.so (libsystemd-shared_libs)
   └─ ? dlopen libbpf.so.1 or libbpf.so.0 (bpf, suggested) (libbpf1_libs)
systemd_tpm2 [i386]: no file matches
```

an edge is `<kind> <name> -> <path> (<owner>)`. `!` is a finding. `?` is a dlopen the cut does not answer: with the delivering slice in parens, bare when no slice declares it, with the reason otherwise.

the three renderings:

- **text**, the default -- the findings and `?` lines of each block, flat, worst first, as `<path> (<owner>): <severity> <kind> <name>: <reason>`, the owner only when it is another slice. nothing indented, so `grep ': hard '` is what does not run. a line every arch of a block was told in a block before is not told again.
- **`--tree`** -- each block's tree.
- **`--json`** -- every cut's graph unpruned, the findings with their chains, and the blocks with their trees.

a start node of a slice not named, reached by nothing, is drawn when something is wrong with it, so the tree and the text tell the same.

colour as the sisters, only on a terminal with `NO_COLOR` unset: slice names bold blue, edge kinds, owners and context dim, dlopen kinds cyan, hard red, soft and warning yellow, info dim.

## cost

`systemd --slice tpm2 --file systemd-measure` across seven arches is 89 cuts, most of them candidates, in about 8s on a warm cache with eight jobs. chisel is nearly all of it, half a second a cut. what made it so, in order:

- the validate trick's one probe for many targets: 98 validations to 1.
- kept cache views (`chisel-coverage/pkg` v0.9.0): a run no longer links and unlinks a view of the whole cache per worker.
- the suites' `InRelease` fetched once a run through the pool's proxy, not once a cut.

our own process is under 100mb and a fifth of a second of gc. a sweep of a whole release is a cut per slice per arch, an hour or more; per-slice runs are the use.

## layout

- `pkg/validate-trick` -- above, in its own module `github.com/lczyk/chisel-elftree/pkg`, tagged `pkg/vX.Y.Z` with the tool.
- `internal/elf` -- an ELF from its program headers, and the library-name scan of its strings. no other ELF knowledge anywhere.
- `internal/rootfs` -- a cut's rootfs in memory: the walk, symlinks, shebangs, the ELFs, lookups the way the kernel walks a path.
- `internal/resolve` -- the loader model per start node, and the per-arch tables.
- `internal/manifest` -- the manifest slice, and reading chisel's manifest back.
- `internal/lookup` -- the release's contents keys and the shortlist.
- `internal/check` -- the run: units through the pool, the rules, named and reached, the lookup.
- `internal/glob` -- chisel's glob syntax for `--file` and `--prune`.
- `internal/cli` -- flags, the blocks, text, tree and json, exit codes.

deps: `chisel-coverage/pkg` (`pool`, `cut`, `cache`, `fold`, `release`, `packageslicesfile`), `chisel-proxy/pkg` (`temp-release`, `deb`), `canonical/chisel`'s public manifest reader, `klauspost/compress`, `go-flags`, `yaml.v3`, `lczyk/version`.

## testing

- unit tests for the reader, the resolver's rules, the strings scan (with a fuzz test against a byte-by-byte reference, and benches), the glob matcher, the lookup, prune, the tree and its folding across arches.
- `pkg/validate-trick` against the real chisel and the cached 26.04 release, skipped without either: the three conflict shapes, one probe for many targets, a key deleted in a copy only.
- the resolver against the real loader, and every ELF of a cut read two ways (`ELFTREE_SCAN_DIR`), opt in.
- `e2e/` behind `-tags e2e` and `CHISEL_ELFTREE_E2E=1`, against the real archive: `dash_bins` on two arches, folded, with and without the loader, and its json.

## decided

- two uses, authoring and review, in one tool.
- real cuts with essentials, as chisel-diff, and the manifest for owners and for named and reached.
- not git-aware. no chisel changes, no single cut of the whole release, no lookup by package name, no providers given by hand.
- the shortlist of literal keys before the validate trick.
- a `required` dlopen fails like a hard edge. findings that count only against reached slices fail only with `--fail-reached`.
- which hwcaps variant a cpu picks is not modelled; every variant is checked as an ELF of its own.
- config-driven dlopen is a known gap.
- every report is a drawing of one fold of the trees; `--tree` only changes the drawing.

## later, maybe

- 26.10's archive gives sha512 digests only, and chisel cannot write a manifest without sha256. until it can, 26.10 is refused.
- a whole-release sweep, and caching verdicts between runs, which would need a key covering the release and the archive state.
- whether `#!/usr/bin/env` on the default `PATH` is right for scripts run from systemd units, which set their own.
- absolute path literals among the strings: `/bin/sh` from `system()`, `/etc/ssl/openssl.cnf`, `/usr/share/zoneinfo`.
