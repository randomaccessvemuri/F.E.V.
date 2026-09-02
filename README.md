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

Source-to-source C/C++ obfuscator built on **ClangTooling**. Named after the Forced Evolutionary Virus from Fallout lore.

FEV parses a translation unit, runs a pipeline of registered passes against the AST, and emits rewritten source via `clang::Rewriter`. Optionally compiles the result to a host binary, MinGW PE, or Windows DLL.

Made by [@tmajik](https://www.linkedin.com/in/tanmay-vemuri-213ba8256/).

---

## Requirements

- CMake ≥ 3.20
- Clang / LLVM development packages (tested with **LLVM 22**)
- A C++17 compiler to build FEV
- Optional toolchains for linking:
  - host: `clang` or `gcc`
  - Windows PE: `x86_64-w64-mingw32-gcc`
  - DLL via clang-cl: `clang-cl` + MSVC SDK (Windows); on Linux use `mingw-dll`

---

## Build

```bash
cd CUSTOM/FEV
make                    # → build/fev
# or
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
```

```bash
./build/fev --list-passes
./build/fev --list-targets
```

---

## Quick start (configs)

Recipes live under [`configs/`](configs/). Pick one and go:

```bash
# Windows EXE (full pipeline)
./build/fev --config configs/win-exe.json workspace/sample2.c

# Windows DLL (full pipeline + to-dll)
./build/fev --config configs/win-dll.json workspace/sample2.c

# Host smoke
./build/fev --config configs/host-smoke.json workspace/sample.c

# Override one knob from the recipe
./build/fev --config configs/win-exe.json --seed=1 workspace/sample2.c
```

Make:

```bash
make FILE=workspace/sample2.c CONFIG=configs/win-exe.json
make FILE=workspace/sample2.c CONFIG=configs/win-dll.json
make FILE=workspace/sample.c  CONFIG=configs/host-smoke.json
```

Personal sources live under **`workspace/`** (gitignored). Automated tests use **`tests/fixtures/`**.

Each config sets `passes`, `emit` (`none`|`exe`|`dll`), `target`, `outdir`, `clang_flags`, and related knobs so you do not juggle `--emit-binary` vs `--emit-dll` vs `--binary-target` by hand.

---

## Config schema

JSON object. Unknown keys are warned and ignored.

| Key | Meaning |
| --- | --- |
| `description` | Logged at start |
| `passes` | Comma string or array (`"all"`, `"all,to-dll"`, …) |
| `emit` | `none` \| `exe` \| `dll` |
| `target` | `host` \| `mingw-x64` \| `mingw-dll` \| `clang-cl-dll` \| … |
| `outdir` / `output` | Output directory / file (`-o`) |
| `binary_output` | Linked binary path |
| `seed`, `validate`, `clang_flags` | Same as CLI |
| `interpass_validate` | After each multi-pass step, verify buffers still restore (and host TUs compile+run). Developer safety net. |
| `dll_entry`, `dll_export`, `dll_thread` | `to-dll` knobs |
| densities / sleep / array_* | Matching CLI names (`mba_density` or `mba-density`) |

**Merge rule:** config loads first; any CLI flag you set explicitly wins.

**Guards:** `to-dll` + `emit:exe` errors; Windows sources + `target:host` + emit errors.

---

## CLI overrides

| Flag | Meaning |
| --- | --- |
| `--config=path` | Load JSON recipe |
| `-o` / `--outdir` | Output file / directory |
| `--passes=a,b` | Pass list (`all` excludes opt-in `to-dll`) |
| `--emit-binary` / `--emit-dll` | Link EXE or DLL (overrides config `emit`) |
| `--binary-target=id` | Compile target override |
| `--seed=N` | Crypto / MBA / flatten / dict seed |
| `--clang-flags="…"` | Rewriter + link flags |
| `--` | Extra rewriter parse flags |
| `-v`, `--log-file`, `--validate` | Logging / integrity |
| `--interpass-validate` | After each pass step, check buffer restore (see below) |

### Inter-pass buffer checks

When developing buffer-touching passes, enable:

```bash
# Config (preferred)
./build/fev --config configs/test-buffers.json tests/fixtures/buffers.c

# Or CLI
./build/fev --passes=scramble-arrays,encrypt-buffers,flatten-cfg \
  --interpass-validate --validate=strict --emit-binary --binary-target=host \
  tests/fixtures/buffers.c --
```

After **each** pipeline step FEV:
1. Confirms scramble restore helpers were not control-flow-flattened
2. Re-simulates ChaCha/scramble decode against the golden payloads from the input
3. On host TUs, compiles and runs the step output (injected ensures + fixture checks)

Failures keep the step file for debugging. Run the suite with `make test-buffers` or `make check`.

---
## Passes

Multi-pass runs **re-parse between steps**.

| Pass | Role |
| --- | --- |
| `encrypt-strings` | ChaCha20 call-site strings |
| `encrypt-buffers` | ChaCha20 global/static byte arrays |
| `encode-constants` | Integer literals → `(enc ^ key)` |
| `scramble-arrays` | Fisher–Yates + XOR on byte arrays |
| `array-split` | Split large byte arrays |
| `dict-bytes` | Two-word slot encoding of byte arrays |
| `dict-rename` | Two-word dictionary rename (last in `all`) |
| `flatten-cfg` | László-style CFF |
| `mba-substitute` | Leaf arithmetic → MBA |
| `opaque-predicates` | Anti-DSE bogus CF |
| `junk-code` | Windows-API junk blocks |
| `winapi-hash` | Hashed PEB/export resolution |
| `sandbox-sleep` | Anti-sandbox sleep check at `main` |
| `wrap-functions` | Extra frame on `static` fns |
| `annotate` | Debug markers |
| `xor-strings` | Legacy XOR strings |
| `to-dll` | **Opt-in** — `main` → export + `DllMain` |

In `--passes=all`: **scramble → encrypt-buffers → dict-bytes → array-split**; `dict-rename` last; `to-dll` never included (use `configs/win-dll.json` or `all,to-dll`).

---

## Layout

```text
CUSTOM/FEV/
├── configs/           # win-exe.json, win-dll.json, host-smoke.json, test-*.json
├── tests/
│   ├── fixtures/      # committed smoke/regression inputs
│   └── out/           # generated (gitignored)
├── workspace/         # personal scratch (gitignored)
├── CMakeLists.txt
├── Makefile
├── include/fev/
└── src/
    ├── Config.cpp
    ├── main.cpp
    └── passes/
```

---

## Writing a pass

Drop `src/passes/YourPass.cpp` with `FEV_REGISTER_PASS` — CMake globs it.

Add knobs to `fev::PassConfig` / JSON keys in `Config.cpp` / CLI in `main.cpp` as needed.

---

## Smoke tests

```bash
make test          # host encrypt smoke + interpass buffers
make test-buffers  # configs/test-buffers.json (scramble→…→dict-rename)
make test-mba      # MBA + flatten arithmetic oracle
make test-cff
make test-opaque
make test-sample2  # MinGW PE smoke
make test-dll      # to-dll MinGW DLL smoke
make check         # all of the above
```
