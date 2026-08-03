#pragma once

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

namespace fev {

enum class DriverStyle {
  Gnu,     ///< argv: compiler [flags…] -o <out> <src>
  ClangCl  ///< argv: clang-cl [flags…] /Fe:<out> <src>
};

struct CompileTarget {
  std::string Id;          // e.g. "host", "mingw-x64", "clang-cl-dll"
  std::string Description;
  std::string Triple;      // empty ⇒ native host triple
  std::string Compiler;    // resolved absolute/PATH name when Available
  std::vector<std::string> ExtraFlags;
  std::string ExeSuffix;   // "" , ".exe", or ".dll"
  DriverStyle Style = DriverStyle::Gnu;
  bool Available = false;
};

/// Probe PATH for known toolchains and return the catalog (available + missing).
std::vector<CompileTarget> discoverCompileTargets();

CompileTarget *findCompileTarget(std::vector<CompileTarget> &Targets,
                                 llvm::StringRef Id);

void listCompileTargets(llvm::raw_ostream &OS);

/// Split a user-supplied flag string (GNU/shell-style quoting) into argv tokens.
std::vector<std::string> tokenizeFlagString(llvm::StringRef Flags);

/// Default binary path: <obf_stem> or <obf_stem>.exe beside the .c file.
std::string defaultBinaryPath(llvm::StringRef ObfuscatedSource,
                              llvm::StringRef ExeSuffix);

/// Compile ObfuscatedSource → BinaryOut with the given target.
/// ExtraFlags are appended after the target's built-in flags.
/// Returns 0 on success.
int compileToBinary(const CompileTarget &Target,
                    llvm::StringRef ObfuscatedSource,
                    llvm::StringRef BinaryOut,
                    llvm::ArrayRef<std::string> ExtraFlags = {});

} // namespace fev
