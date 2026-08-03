```
  █████▒     ▓█████       ██▒   █▓
▓██   ▒      ▓█   ▀      ▓██░   █▒
▒████ ░      ▒███         ▓██  █▒░
░▓█▒  ░      ▒▓█  ▄        ▒██ █░░
░▒█░     ██▓ ░▒████▒ ██▓    ▒▀█░
 ▒ ░     ▒▓▒ ░░ ▒░ ░ ▒▓▒    ░ ▐░
 ░       ░▒   ░ ░  ░ ░▒     ░ ░░
 ░ ░     ░      ░    ░        ░░
          ░     ░  ░  ░        ░
          ░           ░       ░
```

# FEV

Source-to-source C/C++ obfuscator built on **ClangTooling**.

FEV parses a translation unit, runs a pipeline of registered passes against the AST, and emits rewritten source via `clang::Rewriter`. Optionally compiles the result to a host binary, MinGW PE, or Windows DLL.

Made by [@tmajik](https://github.com/tmajik).

---

## Requirements

- CMake ≥ 3.20
- Clang / LLVM development packages (tested with **LLVM 22**)
- A C++17 compiler to build FEV
- Optional toolchains for `--emit-binary` / `--emit-dll`:
  - host: `clang` or `gcc`
  - Windows PE: `x86_64-w64-mingw32-gcc` (or clang with a MinGW sysroot)
  - DLL via clang-cl: `clang-cl` + MSVC SDK (Windows); on Linux use `mingw-dll` instead

---

## Build

```bash
cd CUSTOM/FEV
make                    # configure + build → build/fev
# or
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

```bash
./build/fev --list-passes
./build/fev --list-targets
```

---

## Quick start

```bash
# Default passes (encrypt-strings, encrypt-buffers) → examples/sample_obf.c
./build/fev examples/sample.c --

# Full pipeline (every pass except opt-in to-dll)
./build/fev --passes=all --seed=0xC0FFEE --outdir=examples/out examples/sample.c --

# Also compile
./build/fev --passes=all --emit-binary --binary-target=host examples/sample.c --
./build/fev --passes=all --emit-binary --binary-target=mingw-x64 examples/sample2.c --

# Convert to DLL source + link (Linux: mingw-dll; Windows/VS: clang-cl-dll)
./build/fev --passes=all,to-dll --emit-dll --outdir=examples/out \
  examples/sample2.c --
```

Via Make:

```bash
make FILE=examples/sample.c
make FILE=examples/sample.c BINARY=1
make FILE=examples/sample2.c BINARY=1 TARGET=mingw-x64
make FILE=examples/sample2.c PASSES=to-dll BINARY=1 TARGET=mingw-dll SUFFIX=_dll
make help
```

`PASSES` defaults to `all`. Use `PASSES=none` for an unchanged baseline copy (`SUFFIX=_orig`).

---

## CLI

| Flag | Meaning |
| --- | --- |
| `-o <file>` | Output file (default: `<input_stem>_obf.<ext>`) |
| `--outdir=dir` | Put outputs (and multi-pass temps) under `dir` (created if missing). With `-o`, only the filename is used under outdir |
| `--passes=a,b` | Passes to run. `all` = every registered pass **except** `to-dll` |
| `--emit-binary` | Compile rewritten source (`--binary-target`) |
| `--emit-dll` | Compile to a Windows DLL (implies emit-binary) |
| `--binary-target=id` | See `--list-targets` (`host`, `mingw-x64`, `mingw-dll`, `clang-cl-dll`, …) |
| `--binary-output=path` | Binary/DLL path (default: `<obf_stem>` / `.exe` / `.dll`) |
| `--seed=N` | Seed for crypto, MBA, flatten, dict, junk, … |
| `--clang-flags="…"` | Extra flags for rewrite parse **and** final compile |
| `--` | Clang parse flags for the rewriter (merged with `--clang-flags`) |
| `-v` / `--verbose` | Debug logging |
| `--log-file=PATH` | Append logs to a file (`FEV_LOG_FILE` also works) |
| `--validate=off\|warn\|strict` | Pass integrity checks (default `warn`; or `FEV_VALIDATE`) |
| `--list-passes` / `--list-targets` | Catalog and exit |
| `--no-banner` | Skip splash |

### `to-dll` knobs

| Flag | Default | Meaning |
| --- | --- | --- |
| `--dll-entry=ident` | `_fev_dll_entry` | Renamed former `main` |
| `--dll-export` | on | `__declspec(dllexport)` the entry |
| `--dll-thread` | on | Run entry via `CreateThread` from `DllMain` (avoids loader lock) |

`--emit-dll` defaults to `clang-cl-dll` on Windows and `mingw-dll` elsewhere. Override with `--binary-target=…`.

---

## Passes

Multi-pass runs **re-parse between steps** so later AST passes see text from earlier ones.

| Pass | Role |
| --- | --- |
| `encrypt-strings` | ChaCha20-encrypt call-site string literals; lazy decrypt + FNV |
| `encrypt-buffers` | ChaCha20-encrypt global/static byte arrays; decrypt at `main` |
| `encode-constants` | Integer literals → `(enc ^ key)` ICE forms |
| `scramble-arrays` | Fisher–Yates + XOR on byte arrays; restore at `main` |
| `array-split` | Split large byte arrays into chunks; join at `main` |
| `dict-bytes` | Encode byte arrays via seeded two-word slot table |
| `dict-rename` | Rename fns/vars/types/fields to two-word dictionary idents (last in `all`) |
| `flatten-cfg` | László-style control-flow flattening |
| `mba-substitute` | Leaf `+ - ^ \| &` → MBA identities |
| `opaque-predicates` | Anti-DSE bogus control flow |
| `junk-code` | Inert Windows-API junk blocks |
| `winapi-hash` | Windows API → DJB2 PEB/export resolution |
| `sandbox-sleep` | Wall-clock sleep timing check at `main` |
| `wrap-functions` | Extra call frame around `static` functions |
| `annotate` | Debug marker comments before function defs |
| `xor-strings` | Legacy single-byte XOR strings |
| `to-dll` | **Opt-in only** — `main` → export entry + `DllMain` |

### Ordering notes

- In `--passes=all`: buffer order is **scramble-arrays → encrypt-buffers → dict-bytes → array-split** (ChaCha before dict encoding); `dict-rename` is forced last; **`to-dll` is never included**.
- Passes that inject at `main` (`encrypt-buffers`, `sandbox-sleep`, array restore, …) must run **before** `to-dll`.
- Typical DLL pipeline: obfuscate first, then convert:

```bash
./build/fev --passes=encrypt-buffers,scramble-arrays,to-dll --emit-dll \
  examples/sample2.c --
```

---

## Layout

```text
CUSTOM/FEV/
├── CMakeLists.txt          # globs src/passes/*.cpp automatically
├── Makefile
├── cmake/                  # pass-name discovery → GeneratedPassNames.h
├── dicts/                  # optional name dictionaries
├── examples/
├── include/fev/
└── src/
    ├── main.cpp
    ├── Compiler.cpp
    ├── PassRegistry.cpp
    ├── TargetSupport.cpp
    ├── support/
    └── passes/             # one .cpp per pass; FEV_REGISTER_PASS
```

---

## Writing a pass

Passes self-register. Drop a file under `src/passes/` — CMake globs it; no central switch.

```cpp
#include "fev/Pass.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class YourPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "your-pass"; }
  llvm::StringRef description() const override {
    return "Shown by --list-passes";
  }
  bool run(fev::PassContext &Ctx) override {
    // Match AST nodes; edit with Ctx.Rewriter; return false on hard failure.
    return true;
  }
};

FEV_REGISTER_PASS(YourPass);

} // namespace
```

| Field | Use |
| --- | --- |
| `Ctx.AST` | Types, parents, diagnostics |
| `Ctx.Rewriter` | `InsertText` / `ReplaceText` / `RemoveText` on the main file |
| `Ctx.Config` | Shared knobs (`Seed`, densities, dll options, …) |

Add knobs to `fev::PassConfig` in `include/fev/Pass.h` and wire CLI flags in `src/main.cpp`.

Tips:

- Prefer ASTMatchers; use a visitor when you need full-tree state.
- Restrict edits to the main file; keep replacements token-accurate.
- Avoid overlapping rewrites on the same location.
- Round-trip: rewrite → compile → run.

---

## Smoke tests

```bash
make test              # sample.c encrypt + host binary
make test-sample2      # sample2.c MinGW PE
make test-cff          # flatten-cfg
make test-opaque       # opaque-predicates
```
