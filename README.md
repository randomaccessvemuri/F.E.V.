# FEV — Source-to-Source Compiler (ClangTooling)

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

Made by @tmajik

FEV is a small, extensible **ClangTooling** front-end that rewrites C/C++ source before it is compiled. It parses a translation unit into Clang’s AST, runs a pipeline of registered **passes**, and emits transformed source via `clang::Rewriter`.

It lives under `CUSTOM/FEV` as the source-oriented mutation path for the broader Dx_Trojan hardening pipeline (see repo `SRS.md`). The default pass is **ChaCha20 string encryption** (`encrypt-strings`) with lazy decrypt and FNV-1a integrity.

---

## Requirements

- CMake ≥ 3.20
- Clang / LLVM development packages (tested with **LLVM 22**)
- A C++17 compiler to *build* FEV; `clang` or `gcc` to compile rewritten output

---

## Quick start

```bash
cd CUSTOM/FEV
make                                    # configure + build → build/fev
make list                               # registered passes
make FILE=examples/sample.c             # all passes → examples/sample_obf.c
make FILE=examples/sample.c BINARY=1    # also emit host binary
make FILE=examples/sample_cff.c PASSES=flatten-cfg BINARY=1 SEED=1
make clean
```

`PASSES` defaults to `all` (sequential pipeline). Use `PASSES=none` for an unchanged baseline copy. `SUFFIX` defaults to `_obf`, or `_orig` when `PASSES=none` (override with `SUFFIX=_test`, etc.). Other knobs: `OUT`, `TARGET`, `BINARY_OUT`, `CLANG_FLAGS`, `FEV_FLAGS`, `SEED`. See `make help`.

Or without Make:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
./build/fev --list-passes
./build/fev --list-targets
./build/fev examples/sample.c --
# → examples/sample_obf.c
./build/fev --emit-binary --binary-target=host examples/sample.c --
# → examples/sample_obf.c + examples/sample_obf
./build/fev --passes=all examples/sample.c --
./build/fev --emit-binary --binary-target=mingw-x64 examples/sample2.c -- \
  --target=x86_64-w64-mingw32 -isystem /usr/x86_64-w64-mingw32/include
```

### CLI

| Flag | Meaning |
| --- | --- |
| `-o <file>` | Obfuscated source path (default: `<input_stem>_obf.<ext>`) |
| `--passes=a,b` | Passes to run (`all` = every registered pass) |
| `--emit-binary` | Also compile the obfuscated source to a binary |
| `--binary-target=id` | Compile target (`host`, `mingw-x64`, …; see `--list-targets`) |
| `--binary-output=path` | Binary path (default: `<obf_stem>` or `.exe`) |
| `--list-passes` | List passes |
| `--list-targets` | List compile targets and whether their compilers are installed |
| `--seed=N` | Seed for ChaCha20 / MBA / flatten |
| `-v` / `--verbose` | Debug-level logging on stderr |
| `--log-color=auto\|always\|never` | Colorize fev logs (TTY auto-detect; also `NO_COLOR` / `FORCE_COLOR`) |
| `--log-file=PATH` | Append info/debug (and warn/error) to one file; tags lines `[pass-name]`; debug is recorded even without `-v`. Also `FEV_LOG_FILE`. Makefile: `LOG_FILE=fev.log` |
| `--validate=off\|warn\|strict` | Per-pass integrity checks (default **warn**). Buffer passes round-trip at rewrite time and inject FNV restore checks. `strict` fails the pass on mismatch. Also `FEV_VALIDATE` / Makefile `VALIDATE=` |
| `--` | Clang parse flags for the rewriter |

CMake globs `src/passes/*.cpp`, extracts each `name() const override { return "…"; }`, and generates `GeneratedPassNames.h`. Runtime `FEV_REGISTER_PASS` must match.
---

## Layout

```text
CUSTOM/FEV/
├── CMakeLists.txt
├── Makefile
├── include/fev/
│   ├── Compiler.h
│   ├── Log.h
│   ├── Pass.h
│   ├── ChaCha20.h
│   ├── TargetSupport.h
│   └── RewriteUtils.h
├── src/
│   ├── main.cpp
│   ├── Compiler.cpp
│   ├── PassRegistry.cpp
│   ├── TargetSupport.cpp
│   ├── support/
│   │   ├── ChaCha20.cpp
│   │   └── Log.cpp
│   └── passes/
│       ├── EncryptStrings.cpp      # ChaCha20 + lazy decrypt (default)
│       ├── EncodeConstants.cpp
│       ├── OpaquePredicates.cpp
│       ├── FlattenCFG.cpp
│       ├── MbaSubstitute.cpp
│       ├── WrapFunctions.cpp
│       ├── AnnotateFunctions.cpp
│       └── XorStrings.cpp          # legacy
└── examples/
    └── sample.c
```

---

## How to write a new pass

Passes are self-registering plugins. You do **not** edit a central switch statement.

### 1. Implement `fev::Pass`

Create `src/passes/YourPass.cpp`:

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
    return "One-line summary shown by --list-passes";
  }

  bool run(fev::PassContext &Ctx) override {
    // 1. Match interesting AST nodes (ASTMatchers or RecursiveASTVisitor)
    // 2. Edit source with Ctx.Rewriter (InsertText / ReplaceText / RemoveText)
    // 3. Return false only on hard failure
    return true;
  }
};

FEV_REGISTER_PASS(YourPass);

} // namespace
```

### 2. Use the context

| Field | Use |
| --- | --- |
| `Ctx.AST` | `ASTContext` — types, parents, diagnostics |
| `Ctx.Rewriter` | Source edits against the main file buffer |
| `Ctx.Config` | Shared knobs (`XorKey`, enabled pass list, …) |

Add new knobs to `fev::PassConfig` in `include/fev/Pass.h` and wire CLI flags in `src/main.cpp`.

### 3. Register with the build

Append the file to `FEV_SOURCES` in `CMakeLists.txt`:

```cmake
set(FEV_SOURCES
  ...
  src/passes/YourPass.cpp
)
```

Rebuild (`make` or `cmake --build build`). Confirm with:

```bash
./build/fev --list-passes
./build/fev --passes=your-pass -o out.c examples/sample.c --
```

### 4. Matcher / rewriter tips

- Prefer **ASTMatchers** for “find X then rewrite” passes; use a `RecursiveASTVisitor` when you need full-tree state.
- Restrict edits to the **main file** (`SourceManager::isInMainFile`) and skip **macro IDs** unless you intentionally rewrite expansions.
- Keep replacements **token-accurate** (`CharSourceRange::getTokenRange`) so punctuation and string quotes stay valid.
- Inject helpers **once** at file start (`getLocForStartOfFile`) when a pass needs a runtime stub (see `XorStrings.cpp`).
- Avoid overlapping rewrites on the same `SourceLocation`; collect edits or rewrite from back-to-front if needed.
- Always round-trip: rewrite → compile → run → compare behavior to the baseline.

### 5. Pass ordering

`--passes=a,b` (and `--passes=all`) **re-parse between passes** so each step
sees the rewritten source. Prefer `make FILE=... PASSES=all` for the same
behavior plus binary compile helpers.

---

## Built-in passes

| Name | Exercise | Role |
| --- | --- | --- |
| `array-split` | — | Split large global/static byte arrays into ≤`--array-chunk` pieces (shuffled decl order; join at `main`) |
| `dict-bytes` | — | Encode global/static byte arrays (`{0x..}` **or** `"\x.."` string inits) via a seed-random 256-entry **two-word** slot table with **shuffled** integer indices + inverse map; restore at `main` (`--name-dict`, `--seed`). Runs before `array-split` / `scramble-arrays` in `PASSES=all` |
| `dict-rename` | — | **Final scrub:** rename functions, variables, typedefs, structs, and fields to **two-word** dictionary names (including `_fev_*`); `--name-dict`, `--seed`. Forced last in `PASSES=all` |
| `scramble-arrays` | — | Fisher–Yates permute + position XOR on global/static byte arrays (`{0x..}` or `"\x.."`); lazy restore at `main` (`--seed`) |
| `junk-code` | — | Insert inert Windows-API junk blocks into functions (`--junk-density`, `--seed`) |
| `winapi-hash` | — | Replace Windows API calls with DJB2-hashed PEB/export resolution (`--seed`) |
| `sandbox-sleep` | — | Wall-clock sleep timing check at `main` (anti-sandbox; `--sleep-seconds` / `--sleep-min` / `--sleep-max`) |
| `encrypt-strings` | 1 | **ChaCha20** (RFC 8439) encrypt call-site string literals; per-literal nonce; **lazy** decrypt into a `static` buffer; **FNV-1a** integrity tag (fail-closed wipe) |
| `encrypt-buffers` | 1b | ChaCha20-encrypt global/static byte-array initializers (`{0x..}` or `"\x.."`); lazy decrypt at `main` (`--seed`); layers on `_fev_sc_*` from scramble-arrays |
| `encode-constants` | 2 | Replace integer literals with `(enc ^ key)` ICE forms |
| `opaque-predicates` | 3 | Anti-DSE bogus CF: CityHash / Fermat / Fib / Collatz / volatile (`--opaque-density`, `--opaque-fib-n`) |
| `flatten-cfg` | 4 | László-style CFF: lowers if/while/do/for/switch/try, rewrites break/continue, permutes XOR+volatile dispatcher |
| `mba-substitute` | 5 | Rewrite leaf `+` / `-` / `^` into MBA identities |
| `wrap-functions` | 6 | Rename `static` defs to `_fev_impl_*` and emit a forwarding wrapper |
| `annotate` | — | Debug marker comments before function defs |
| `xor-strings` | — | Legacy single-byte XOR (kept for comparison) |

`encrypt-strings` skips array initializers like `char s[] = "x"`. `flatten-cfg` implements László & Kiss control-flow flattening (recursive lowering of structured control flow); it skips functions with local arrays/statics/refs/aggregates that cannot be safely hoisted and prints a yellow `fev: warn: flatten-cfg skipped …` with file:line and the offending variable.

---

## Exercises — implement more obfuscation

Exercises **1–6 are implemented** as the passes above (`make test-passes`, `make test-pipe`). Use this section as a backlog for hardening and Exercise 7.

### Exercise 1 — Stronger string protection — done (`encrypt-strings`)

Shipped beyond XOR: ChaCha20 stream cipher, per-literal nonces from `--seed`, lazy decrypt, FNV integrity.

Possible follow-ups: AES-GCM tags, stack decrypt buffers, encrypt wide strings.

### Exercise 2 — Constant encoding — done (`encode-constants`)

### Exercise 3 — Opaque predicates + junk — done (`opaque-predicates`)

Implements Cao et al. (CMC 2025) anti-DSE constructions as **bogus control flow** around leaf statements:

- **CityHash64** single-way wrapper over classic evenness opaques  
- **Fermat** modular exponentiation predicates  
- **Fibonacci** (memoized) and **Collatz** path-explosion predicates  
- **Volatile** always-true mix-in (optimizer-resistant)  
- Local/ASLR-tied inputs (not foldable global zeros); density default **0.5**

```bash
make FILE=examples/sample_opaque.c PASSES=opaque-predicates BINARY=1 \
  FEV_FLAGS='--opaque-density=1.0 --opaque-fib-n=12'
# or: make test-opaque
```

Stretch: pointer/alias opaques; tune fib-n vs DSE cost.

### Exercise 4 — Control-flow flattening — done (`flatten-cfg`)

László & Kiss style: `while`/`switch` dispatcher, loop heads → predicate cases, `break`/`continue` → state assigns, nested flatten for `try`, permuted random state IDs, XOR+volatile encoding.

### Exercise 5 — MBA substitution — done (`mba-substitute`)

Stretch: denser identity tables; resist InstCombine re-simplification.

### Exercise 6 — Function outlining / wrappers — done (`wrap-functions`)

Stretch: outline arbitrary statement ranges; indirect call tables.

### Exercise 7 — Mini virtualization (hard) — not done

Select one function, lower its body to a tiny bytecode array + interpreter stub in the same TU (Loki-adjacent).

---

## Advanced techniques (survey)

These appear widely in academic work (e.g. Collberg’s obfuscation taxonomy) and in modern **LLVM IR** obfuscators (OLLVM / Hikari / Pluto, [O-MVLL](https://obfuscator.re/omvll/passes/control-flow-flattening/), research plugins such as Kilij, Amice, and industrial bitcode obfuscators discussed at the LLVM Developers’ Meeting). FEV operates at **source/AST** level; many of the same *ideas* apply, with different engineering trade-offs than IR passes.

### Control-flow

| Technique | Idea | Source-level angle |
| --- | --- | --- |
| **Control-flow flattening** | Replace structured CFG with a state-machine dispatcher (`switch` in a loop) | Rewrite function bodies into dispatcher form; encode state transitions |
| **Bogus control flow** | Insert branches that never (or rarely) execute real logic | Guard real stmts with opaque predicates; put junk in dead arms |
| **Basic-block split / shuffle** | Fragment straight-line code; reorder blocks | Split compound stmts; emit labels/`goto` or dispatcher cases in shuffled order |
| **Indirect branches / calls** | Hide targets behind tables | Emit function-pointer tables; replace direct calls with `table[i](…)` (index may be encoded) |
| **Branch functions** | Route jumps through a helper that computes the target | Source: `goto *fev_br(id)` patterns (GNU computed goto) or dispatcher IDs |

### Predicates and anti-analysis

| Technique | Idea | Notes |
| --- | --- | --- |
| **Opaque predicates** | Conditions that are invariant at runtime but hard to prove statically | Algebraic, number-theoretic, or alias/heap based; recent work targets resistance to **dynamic symbolic execution** (path explosion / hard-to-invert functions) |
| **Path-explosion opaques** | Multiply feasible-looking paths to overwhelm solvers | Combine carefully with size/time budgets |
| **Anti-DSE / anti-taint tricks** | Frustrate symbolic engines | Often stronger at IR/binary level; at source, prefer opaque constructions that survive `-O2` constant folding |

### Data and arithmetic

| Technique | Idea | Source-level angle |
| --- | --- | --- |
| **String / constant encryption** | Keep literals ciphertext at rest; decrypt at use | FEV’s `xor-strings` is the minimal version; upgrade to stream ciphers, AES stubs, or per-use stack buffers |
| **MBA (mixed Boolean-arithmetic)** | Replace ops with equivalent messy Boolean+arithmetic expressions | Match `BinaryOperator` / integer literals; emit expanded exprs; watch undefined behavior and optimizers that re-simplify |
| **Variable splitting** | Store `x` as `(a,b)` with `x = f(a,b)` | Rewrite DeclStmt + all uses; high engineering cost at AST level |
| **Opaque field / GEP encoding** | Hide structure offsets | Emit encoded index expressions for member access (harder in pure C without structs metadata) |

### Abstraction / virtualization

| Technique | Idea | Source-level angle |
| --- | --- | --- |
| **Code virtualization** | Compile selected functions to custom bytecode + embed VM | Emit bytecode blob + interpreter as C (aligns with Loki VM work in this repo) |
| **Function wrapping / cloning** | Extra frames; specialized clones for constant args | AST call-graph rewrites |
| **Junk / dead code insertion** | Inflate and distract | Only useful if junk is not trivially DCE’d; pair with opaques |

### Practical constraints (read before going deep)

1. **Optimizers fight you.** Clang/LLVM at `-O2` will fold weak opaques and simplify naive MBA. Test with the same flags you ship.
2. **Semantics first.** Obfuscation that breaks aliasing, `volatile`, atomics, or exception edges is a bug, not a feature.
3. **Source vs IR.** Flattening, indirectbr, and virtualization are often *easier* and more robust as LLVM passes; FEV is ideal for **literal/data** transforms, macro-friendly rewrites, and experiments you want to *read* as C.
4. **Compose passes.** Real strength comes from pipelines (encode data → flatten → MBA → bogus CF), with budgets on size and runtime — same layering described in O-MVLL and industrial obfuscator talks.
5. **Scope.** This tree is for **IP protection / research** on code you own (see `SRS.md`). Do not treat these notes as a guide for malware evasion.

### Further reading

- Christian Collberg — obfuscation taxonomies and opaque predicate constructions (classic course notes / papers).
- [O-MVLL control-flow flattening](https://obfuscator.re/omvll/passes/control-flow-flattening/) — modern CFF design notes (state encoding, default-case traps).
- LLVM Developers’ Meeting talk: *Challenges when building an LLVM bitcode obfuscator* — IR-level realities (runtime injection, linker wrappers, interaction with InstCombine).
- Praetorian: *Extending LLVM for code obfuscation* — approachable junk-insert + string encrypt pass walkthrough.
- Survey of open IR obfuscators (OLLVM lineage, Hikari, Pluto, Amice, etc.) for pass inventories you can mirror at source level where it makes sense.

---

## Testing checklist for new passes

1. `make` builds cleanly; pass appears in `--list-passes`.
2. Rewritten file compiles with `clang -std=c11 -Wall` (or your target dialect).
3. Runtime output matches an unobfuscated baseline.
4. Spot-check that the transform actually fired (grep ciphertext / dispatcher / helper symbols).
5. Try `-O0` and `-O2`; note anything the optimizer erased.

---

## License / context

FEV is part of the ripperLoader / Dx_Trojan research workspace. Prefer transforming **source you control**; keep validation gates (compile + behavioral parity) as you add stronger passes.
