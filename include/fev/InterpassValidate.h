#pragma once

#include "fev/Pass.h"

#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <string>
#include <vector>

namespace fev {

/// Original user byte-array captured before the pipeline mutates it.
struct GoldenBuffer {
  std::string Name;
  std::vector<std::uint8_t> Bytes;
  std::uint32_t Fnv = 0;
};

/// Harvest global/static byte arrays (≥8 bytes) from a C/C++ source path.
/// Best-effort text parse — good enough for fixtures and typical payload TUs.
bool harvestGoldenBuffers(llvm::StringRef SourcePath,
                          std::vector<GoldenBuffer> &Out);

/// After a pipeline step: verify buffer restore math still recovers each golden
/// and that scramble helpers were not control-flow-flattened.
/// Returns false only when Mode is Strict (or AlwaysFail) and a check fails.
/// When TryExecute is true and the TU looks host-runnable, also compile+run.
bool interpassValidateAfterPass(llvm::StringRef StepPath,
                                llvm::StringRef PassName,
                                const std::vector<GoldenBuffer> &Goldens,
                                std::uint64_t Seed, ValidateMode Mode,
                                bool TryExecute, bool AlwaysFail = true);

} // namespace fev
