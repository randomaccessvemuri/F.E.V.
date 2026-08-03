#include "fev/Log.h"
#include "fev/TargetSupport.h"

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/StringSaver.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>

namespace fev {
namespace {

bool resolveCompiler(CompileTarget &T, std::initializer_list<const char *> Cands) {
  for (const char *Cand : Cands) {
    if (llvm::ErrorOr<std::string> P = llvm::sys::findProgramByName(Cand)) {
      T.Compiler = *P;
      T.Available = true;
      return true;
    }
  }
  T.Available = false;
  return false;
}

} // namespace

std::vector<std::string> tokenizeFlagString(llvm::StringRef Flags) {
  std::vector<std::string> Out;
  if (Flags.trim().empty())
    return Out;

  llvm::BumpPtrAllocator Alloc;
  llvm::StringSaver Saver(Alloc);
  llvm::SmallVector<const char *, 32> Argv;
  llvm::cl::TokenizeGNUCommandLine(Flags, Saver, Argv);
  Out.reserve(Argv.size());
  for (const char *A : Argv)
    Out.emplace_back(A);
  return Out;
}

std::vector<CompileTarget> discoverCompileTargets() {
  std::vector<CompileTarget> Targets;

  {
    CompileTarget Host;
    Host.Id = "host";
    Host.Description = "Native host compiler (clang/gcc)";
    Host.Triple = "";
    Host.ExeSuffix = "";
    Host.ExtraFlags = {"-std=c11", "-Wall", "-Wextra"};
    resolveCompiler(Host, {"clang", "gcc", "cc"});
    Targets.push_back(std::move(Host));
  }

  {
    CompileTarget Mingw;
    Mingw.Id = "mingw-x64";
    Mingw.Description = "Windows x86_64 PE via MinGW-w64";
    Mingw.Triple = "x86_64-w64-mingw32";
    Mingw.ExeSuffix = ".exe";
    Mingw.ExtraFlags = {
        "-std=c11",
        "-Wall",
        "-Wextra",
        "--target=x86_64-w64-mingw32",
        "-isystem",
        "/usr/x86_64-w64-mingw32/include",
    };
    // Prefer the MinGW-prefixed GCC; clang --target also works if mingw is
    // installed, but the prefixed driver finds libs more reliably.
    if (!resolveCompiler(Mingw, {"x86_64-w64-mingw32-gcc"})) {
      // Fall back to clang with explicit target (ExtraFlags already set).
      if (resolveCompiler(Mingw, {"clang", "clang++"})) {
        // Keep ExtraFlags; clang needs the triple.
      }
    } else {
      // Prefixed gcc does not want --target=…
      Mingw.ExtraFlags = {"-std=c11", "-Wall", "-Wextra"};
    }
    Targets.push_back(std::move(Mingw));
  }

  {
    CompileTarget CrossAarch64;
    CrossAarch64.Id = "linux-aarch64";
    CrossAarch64.Description = "Linux aarch64 cross (aarch64-linux-gnu-gcc)";
    CrossAarch64.Triple = "aarch64-linux-gnu";
    CrossAarch64.ExeSuffix = "";
    CrossAarch64.ExtraFlags = {"-std=c11", "-Wall", "-Wextra"};
    resolveCompiler(CrossAarch64, {"aarch64-linux-gnu-gcc", "aarch64-linux-gnu-clang"});
    Targets.push_back(std::move(CrossAarch64));
  }

  {
    CompileTarget CrossArm;
    CrossArm.Id = "linux-arm";
    CrossArm.Description = "Linux armhf cross (arm-linux-gnueabihf-gcc)";
    CrossArm.Triple = "arm-linux-gnueabihf";
    CrossArm.ExeSuffix = "";
    CrossArm.ExtraFlags = {"-std=c11", "-Wall", "-Wextra"};
    resolveCompiler(CrossArm, {"arm-linux-gnueabihf-gcc"});
    Targets.push_back(std::move(CrossArm));
  }

  {
    CompileTarget ClangClDll;
    ClangClDll.Id = "clang-cl-dll";
    ClangClDll.Description =
        "Windows DLL via clang-cl /LD (needs MSVC SDK on the host; "
        "on Linux without VS prefer mingw-dll)";
    ClangClDll.Triple = "x86_64-pc-windows-msvc";
    ClangClDll.ExeSuffix = ".dll";
    ClangClDll.Style = DriverStyle::ClangCl;
    ClangClDll.ExtraFlags = {"/nologo", "/LD", "/std:c11", "/W3"};
    resolveCompiler(ClangClDll, {"clang-cl"});
    Targets.push_back(std::move(ClangClDll));
  }

  {
    CompileTarget MingwDll;
    MingwDll.Id = "mingw-dll";
    MingwDll.Description = "Windows x86_64 DLL via MinGW-w64 (-shared)";
    MingwDll.Triple = "x86_64-w64-mingw32";
    MingwDll.ExeSuffix = ".dll";
    MingwDll.Style = DriverStyle::Gnu;
    MingwDll.ExtraFlags = {
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-shared",
        "--target=x86_64-w64-mingw32",
        "-isystem",
        "/usr/x86_64-w64-mingw32/include",
    };
    if (!resolveCompiler(MingwDll, {"x86_64-w64-mingw32-gcc"})) {
      if (resolveCompiler(MingwDll, {"clang", "clang++"})) {
        // Keep --target / -isystem for clang.
      }
    } else {
      MingwDll.ExtraFlags = {"-std=c11", "-Wall", "-Wextra", "-shared"};
    }
    Targets.push_back(std::move(MingwDll));
  }

  return Targets;
}

CompileTarget *findCompileTarget(std::vector<CompileTarget> &Targets,
                                 llvm::StringRef Id) {
  for (CompileTarget &T : Targets) {
    if (T.Id == Id)
      return &T;
  }
  return nullptr;
}

void listCompileTargets(llvm::raw_ostream &OS) {
  auto Targets = discoverCompileTargets();
  OS << "Compile targets (--binary-target=…, used with --emit-binary):\n";
  for (const CompileTarget &T : Targets) {
    OS << "  " << T.Id;
    if (T.Available)
      OS << "  [available]  compiler=" << T.Compiler;
    else
      OS << "  [missing]";
    OS << "\n      " << T.Description;
    if (!T.Triple.empty())
      OS << "  (triple " << T.Triple << ")";
    OS << "\n";
  }
  OS << "\nExample:\n"
        "  fev --emit-binary --binary-target=host examples/sample.c --\n"
        "  fev --emit-binary --binary-target=mingw-x64 examples/sample2.c -- \\\n"
        "      --target=x86_64-w64-mingw32 -isystem /usr/x86_64-w64-mingw32/include\n"
        "  fev --passes=to-dll --emit-dll --binary-target=mingw-dll \\\n"
        "      examples/sample2.c --\n"
        "  fev --passes=to-dll --emit-dll --binary-target=clang-cl-dll \\\n"
        "      examples/sample2.c --   # needs MSVC SDK\n";
}

std::string defaultBinaryPath(llvm::StringRef ObfuscatedSource,
                              llvm::StringRef ExeSuffix) {
  llvm::SmallString<256> Dir(ObfuscatedSource);
  llvm::sys::path::remove_filename(Dir);
  const llvm::StringRef Stem =
      llvm::sys::path::stem(llvm::sys::path::filename(ObfuscatedSource));

  llvm::SmallString<256> Out;
  if (!Dir.empty()) {
    Out = Dir;
    llvm::sys::path::append(Out, Stem.str() + ExeSuffix.str());
  } else {
    Out = Stem.str() + ExeSuffix.str();
  }
  // Avoid clobbering the .c when suffix is empty and stem equals full name —
  // stem of foo_obf.c is foo_obf, so binary is foo_obf (no extension). Good.
  return std::string(Out);
}

int compileToBinary(const CompileTarget &Target,
                    llvm::StringRef ObfuscatedSource,
                    llvm::StringRef BinaryOut,
                    llvm::ArrayRef<std::string> ExtraFlags) {
  if (!Target.Available || Target.Compiler.empty()) {
    logError() << "compile target '" << Target.Id
               << "' is not available on this system";
    return 1;
  }

  // Keep owned strings alive for StringRef args.
  std::vector<std::string> Owned;
  Owned.push_back(Target.Compiler);
  for (const std::string &F : Target.ExtraFlags)
    Owned.push_back(F);
  for (const std::string &F : ExtraFlags)
    Owned.push_back(F);

  if (Target.Style == DriverStyle::ClangCl) {
    // clang-cl: /Fe:out.dll  (colon form handles paths cleanly)
    Owned.push_back(std::string("/Fe:") + BinaryOut.str());
    Owned.push_back(ObfuscatedSource.str());
  } else {
    Owned.emplace_back("-o");
    Owned.emplace_back(BinaryOut.str());
    Owned.emplace_back(ObfuscatedSource.str());
  }

  std::vector<llvm::StringRef> Args;
  Args.reserve(Owned.size());
  for (const std::string &S : Owned)
    Args.push_back(S);

  {
    auto Msg = logInfo();
    Msg << "compiling [" << Target.Id << "]";
    for (llvm::StringRef A : Args)
      Msg << ' ' << A;
  }

  std::string Err;
  const int RC = llvm::sys::ExecuteAndWait(
      Target.Compiler, Args, /*Env=*/std::nullopt,
      /*Redirects=*/{}, /*SecondsToWait=*/0,
      /*MemoryLimit=*/0, &Err);
  if (RC != 0) {
    auto Msg = logError();
    Msg << "compile failed (exit " << RC << ")";
    if (!Err.empty())
      Msg << ": " << Err;
    return RC == 0 ? 1 : RC;
  }

  logInfo() << "binary written " << BinaryOut;
  return 0;
}

} // namespace fev
