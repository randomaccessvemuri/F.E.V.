#pragma once

#include "fev/ChaCha20.h"
#include "fev/Log.h"
#include "fev/Pass.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>
#include <vector>

namespace fev {

inline llvm::StringRef validateModeName(ValidateMode M) {
  switch (M) {
  case ValidateMode::Off:
    return "off";
  case ValidateMode::Warn:
    return "warn";
  case ValidateMode::Strict:
    return "strict";
  }
  return "off";
}

inline ValidateMode parseValidateMode(llvm::StringRef S) {
  if (S.equals_insensitive("off") || S.equals_insensitive("0") ||
      S.equals_insensitive("false") || S.equals_insensitive("no"))
    return ValidateMode::Off;
  if (S.equals_insensitive("strict") || S.equals_insensitive("error") ||
      S.equals_insensitive("fail"))
    return ValidateMode::Strict;
  return ValidateMode::Warn;
}

/// Log a validation result. Returns false only when mode is Strict and !Ok
/// (caller should abort the pass). Always returns true when mode is Off.
inline bool validateExpect(ValidateMode Mode, bool Ok,
                           llvm::StringRef What) {
  if (Mode == ValidateMode::Off)
    return true;
  if (Ok) {
    logDebug() << "validate ok: " << What;
    return true;
  }
  if (Mode == ValidateMode::Strict) {
    logError() << "validate failed: " << What;
    return false;
  }
  logWarn() << "validate failed: " << What;
  return true;
}

inline bool validateExpect(const PassConfig &Cfg, bool Ok,
                           llvm::StringRef What) {
  return validateExpect(Cfg.Validate, Ok, What);
}

/// Compare two buffers; on mismatch describe first differing index.
inline bool buffersEqual(const std::vector<std::uint8_t> &A,
                         const std::vector<std::uint8_t> &B,
                         std::string *Detail = nullptr) {
  if (A.size() != B.size()) {
    if (Detail) {
      llvm::raw_string_ostream OS(*Detail);
      OS << "length " << A.size() << " vs " << B.size();
    }
    return false;
  }
  for (size_t I = 0; I < A.size(); ++I) {
    if (A[I] != B[I]) {
      if (Detail) {
        llvm::raw_string_ostream OS(*Detail);
        OS << "byte[" << I << "] got " << (unsigned)A[I] << " want "
           << (unsigned)B[I];
      }
      return false;
    }
  }
  return true;
}

/// Round-trip check helper for encodes: Dec == Plain.
inline bool validateRoundTrip(ValidateMode Mode, llvm::StringRef PassOrBuf,
                              const std::vector<std::uint8_t> &Plain,
                              const std::vector<std::uint8_t> &Decoded) {
  std::string Detail;
  const bool Ok = buffersEqual(Decoded, Plain, &Detail);
  std::string Msg;
  llvm::raw_string_ostream OS(Msg);
  OS << PassOrBuf << " round-trip (" << Plain.size() << "B)";
  if (!Ok)
    OS << ": " << Detail;
  else
    OS << ", fnv="
       << llvm::format("0x%08x", fnv1a32(Plain.data(), Plain.size()));
  return validateExpect(Mode, Ok, Msg);
}

/// Shared FNV runtime used by injected integrity checks (idempotent watermark).
inline std::string buildValidateRuntimeC() {
  return R"C(/* FEV_VALIDATE_RUNTIME */
#include <stdint.h>
static uint32_t _fev_val_fnv1a32(const uint8_t *p, unsigned n) {
  uint32_t h = 2166136261u;
  for (unsigned i = 0; i < n; ++i) {
    h ^= (uint32_t)p[i];
    h *= 16777619u;
  }
  return h;
}
)C";
}

/// Append after a restore/join/decrypt body: verify FNV or wipe on mismatch.
inline std::string emitBufferIntegrityCheck(llvm::StringRef BufName, unsigned N,
                                            std::uint32_t Tag) {
  std::string Out;
  llvm::raw_string_ostream OS(Out);
  OS << "    if (_fev_val_fnv1a32((const uint8_t *)" << BufName << ", " << N
     << "u) != " << llvm::format("0x%08xu", Tag) << ") {\n"
     << "      /* fev-validate: integrity mismatch — wipe buffer */\n"
     << "      for (unsigned _fev_vi = 0; _fev_vi < " << N
     << "u; ++_fev_vi)\n"
     << "        " << BufName << "[_fev_vi] = 0;\n"
     << "    }\n";
  return OS.str();
}

/// Names that must never be treated as user byte payloads by later passes.
inline bool isFeVArtifactName(llvm::StringRef Name) {
  return Name.starts_with("_fev_") || Name.starts_with("fev_") ||
         Name.starts_with("FEV_");
}

} // namespace fev
