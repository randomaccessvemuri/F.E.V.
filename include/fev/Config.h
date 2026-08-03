#pragma once

#include "fev/Pass.h"

#include "llvm/ADT/StringRef.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace fev {

/// What to produce after rewriting.
enum class EmitKind {
  None, ///< Source only
  Exe,  ///< Link an executable (.exe on MinGW / bare on host)
  Dll   ///< Link a Windows DLL
};

/// File-level run recipe loaded from JSON (--config). All fields are optional
/// in the file; unset means "leave CLI / built-in defaults alone".
struct FileConfig {
  std::string Path; ///< Config file path (for logging)
  std::string Description;

  std::optional<std::string> Passes; ///< Comma-separated or "all"
  std::optional<std::uint64_t> Seed;
  std::optional<std::uint8_t> XorKey;
  std::optional<double> MbaDensity;
  std::optional<double> OpaqueDensity;
  std::optional<double> JunkDensity;
  std::optional<unsigned> OpaqueFibN;
  std::optional<unsigned> SleepSeconds;
  std::optional<unsigned> SleepMinSeconds;
  std::optional<unsigned> SleepMaxSeconds;
  std::optional<unsigned> FlattenMinStmts;
  std::optional<unsigned> ArrayChunkSize;
  std::optional<unsigned> ArraySplitMin;
  std::optional<std::string> NameDictPath;
  std::optional<std::string> DllEntryName;
  std::optional<bool> DllExport;
  std::optional<bool> DllThread;
  std::optional<std::string> Validate; ///< off|warn|strict
  std::optional<bool> InterpassValidate;

  std::optional<std::string> Output;      ///< -o
  std::optional<std::string> OutDir;      ///< --outdir
  std::optional<EmitKind> Emit;
  std::optional<std::string> Target;      ///< --binary-target
  std::optional<std::string> BinaryOutput;
  std::optional<std::string> ClangFlags;
};

/// Load a JSON config file. Returns nullopt on hard failure (logged).
std::optional<FileConfig> loadConfigFile(llvm::StringRef Path);

/// Parse emit string: none|exe|dll (case-insensitive).
std::optional<EmitKind> parseEmitKind(llvm::StringRef S);

llvm::StringRef emitKindName(EmitKind K);

/// True if TargetId needs MinGW windows.h parse flags.
bool targetNeedsMingwParseFlags(llvm::StringRef TargetId);

/// True if the source text (or path contents) looks like a Windows TU.
bool sourceLooksLikeWindows(llvm::StringRef SourcePath);

/// Split a comma-separated passes string into tokens (trims empties).
std::vector<std::string> splitPasses(llvm::StringRef Spec);

} // namespace fev
