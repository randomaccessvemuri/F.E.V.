#pragma once

#include "clang/AST/ASTContext.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace fev {

/// Rewrite-time (+ optional runtime) integrity checks for each pass.
enum class ValidateMode {
  Off = 0,   ///< No rewrite-time / injected checks
  Warn = 1,  ///< Log failures; continue
  Strict = 2 ///< Log failures; fail the pass
};

/// Shared knobs for every pass. Add fields here as new passes need config.
struct PassConfig {
  /// Empty means default pipeline: encrypt-strings, encrypt-buffers.
  /// Use {"all"} or --passes=all for every registered pass.
  std::vector<std::string> EnabledPasses;

  /// Legacy single-byte key for xor-strings.
  std::uint8_t XorKey = 0x5A;

  /// Seed for ChaCha20 key/nonce derivation, MBA sampling, flatten state XOR.
  std::uint64_t Seed = 0xC0FFEEULL;

  /// Probability in [0,1] that an eligible binary operator is MBA-rewritten.
  double MbaDensity = 1.0;

  /// Probability in [0,1] that an eligible leaf stmt gets a bogus opaque branch
  /// (Cao et al. CMC 2025; paper uses ~0.3–0.7).
  double OpaqueDensity = 0.5;

  /// Probability in [0,1] that a function body gets a Windows-API junk block.
  double JunkDensity = 0.7;

  /// Fibonacci opaque parameter n (memoized; keep modest for runtime cost).
  unsigned OpaqueFibN = 14;

  /// sandbox-sleep: wall-clock sleep duration and acceptance window (seconds).
  unsigned SleepSeconds = 10;
  unsigned SleepMinSeconds = 0; ///< 0 → SleepSeconds - 2
  unsigned SleepMaxSeconds = 0; ///< 0 → SleepSeconds * 3

  /// Minimum statements before flatten-cfg runs on a function.
  unsigned FlattenMinStmts = 2;

  /// array-split: max bytes per chunk (default 16) and minimum array size
  /// before splitting (default 2× chunk).
  unsigned ArrayChunkSize = 16;
  unsigned ArraySplitMin = 0; ///< 0 → 2 * ArrayChunkSize

  /// dict-rename / dict-bytes: optional dictionary path (one ident/line).
  /// Empty → built-in benign word list.
  std::string NameDictPath;

  /// Rewrite-time (+ optional runtime) integrity checks for each pass.
  /// Off = none, Warn = log and continue, Strict = fail the pass on mismatch.
  ValidateMode Validate = ValidateMode::Warn;
};

struct PassContext {
  clang::ASTContext &AST;
  clang::Rewriter &Rewriter;
  const PassConfig &Config;
};

class Pass {
public:
  virtual ~Pass() = default;
  virtual llvm::StringRef name() const = 0;
  virtual llvm::StringRef description() const = 0;
  virtual bool run(PassContext &Ctx) = 0;
};

class PassRegistry {
public:
  static PassRegistry &instance();
  bool add(std::unique_ptr<Pass> P);
  Pass *find(llvm::StringRef Name) const;
  const std::vector<std::unique_ptr<Pass>> &all() const { return Passes_; }
  std::vector<Pass *> resolve(const PassConfig &Config) const;
  void list(llvm::raw_ostream &OS) const;

  /// Cross-check runtime FEV_REGISTER_PASS entries against CMake-discovered
  /// name() strings from src/passes/*.cpp.
  void validateCompiledManifest() const;

private:
  PassRegistry() = default;
  std::vector<std::unique_ptr<Pass>> Passes_;
};

bool runPasses(PassContext &Ctx);

} // namespace fev

#define FEV_REGISTER_PASS(Type)                                                \
  static bool FEV_CONCAT_INNER(_fev_reg_, __COUNTER__) = []() -> bool {        \
    return ::fev::PassRegistry::instance().add(std::make_unique<Type>());      \
  }()

#define FEV_CONCAT_INNER(a, b) a##b
