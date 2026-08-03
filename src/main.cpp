#include "fev/Compiler.h"
#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/TargetSupport.h"
#include "fev/Validate.h"

#include "clang/Tooling/ArgumentsAdjusters.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory FevCategory("fev options");

static cl::opt<std::string>
    OutputPath("o",
               cl::desc("Obfuscated source output file (default: "
                        "<input_stem>_obf.<ext>, or under --outdir)"),
               cl::value_desc("file"), cl::init(""), cl::cat(FevCategory));

static cl::opt<std::string>
    OutDir("outdir",
           cl::desc("Directory for rewritten source, step temps, and default "
                    "binary/DLL outputs (created if missing). When set, -o is "
                    "treated as a filename under this directory"),
           cl::value_desc("dir"), cl::init(""), cl::cat(FevCategory));

static cl::list<std::string>
    PassList("passes",
             cl::desc("Comma-separated passes to run. Use 'all' for every "
                      "registered pass (auto re-parses between passes). "
                      "Default: encrypt-strings,encrypt-buffers"),
             cl::value_desc("pass[,pass...]"), cl::CommaSeparated,
             cl::cat(FevCategory));

static cl::opt<unsigned>
    XorKey("xor-key",
           cl::desc("XOR key for legacy xor-strings (0-255, default 0x5A)"),
           cl::init(0x5A), cl::cat(FevCategory));

static cl::opt<std::uint64_t>
    Seed("seed",
         cl::desc("Seed for ChaCha20 key/nonces, MBA sampling, flatten masks"),
         cl::init(0xC0FFEEULL), cl::cat(FevCategory));

static cl::opt<double>
    MbaDensity("mba-density",
               cl::desc("Probability [0,1] of MBA-rewriting an eligible op "
                        "(default 1.0)"),
               cl::init(1.0), cl::cat(FevCategory));

static cl::opt<double> OpaqueDensity(
    "opaque-density",
    cl::desc("Probability [0,1] of wrapping an eligible leaf stmt in an "
             "anti-DSE opaque branch (default 0.5)"),
    cl::init(0.5), cl::cat(FevCategory));

static cl::opt<double> JunkDensity(
    "junk-density",
    cl::desc("Probability [0,1] of inserting a Windows-API junk block per "
             "function (default 0.7)"),
    cl::init(0.7), cl::cat(FevCategory));

static cl::opt<unsigned>
    OpaqueFibN("opaque-fib-n",
               cl::desc("Base n for Fibonacci opaque predicates (default 14)"),
               cl::init(14), cl::cat(FevCategory));

static cl::opt<unsigned> SleepSeconds(
    "sleep-seconds",
    cl::desc("sandbox-sleep wall-clock sleep duration in seconds (default 10)"),
    cl::init(10), cl::cat(FevCategory));

static cl::opt<unsigned> SleepMinSeconds(
    "sleep-min",
    cl::desc("sandbox-sleep minimum accepted elapsed seconds (default sleep-2)"),
    cl::init(0), cl::cat(FevCategory));

static cl::opt<unsigned> SleepMaxSeconds(
    "sleep-max",
    cl::desc("sandbox-sleep maximum accepted elapsed seconds (default sleep*3)"),
    cl::init(0), cl::cat(FevCategory));

static cl::opt<unsigned>
    FlattenMinStmts("flatten-min-stmts",
                    cl::desc("Minimum stmts for flatten-cfg (default 2)"),
                    cl::init(2), cl::cat(FevCategory));

static cl::opt<unsigned> ArrayChunkSize(
    "array-chunk",
    cl::desc("array-split: max bytes per chunk (default 16)"),
    cl::init(16), cl::cat(FevCategory));

static cl::opt<unsigned> ArraySplitMin(
    "array-split-min",
    cl::desc("array-split: only split arrays at least this many bytes "
             "(default 2× --array-chunk)"),
    cl::init(0), cl::cat(FevCategory));

static cl::opt<std::string> NameDict(
    "name-dict",
    cl::desc("dict-rename / dict-bytes: path to dictionary file (one C "
             "identifier per line; default: built-in word list)"),
    cl::value_desc("file"), cl::init(""), cl::cat(FevCategory));

static cl::opt<bool>
    ListPasses("list-passes", cl::desc("List registered passes and exit"),
               cl::init(false), cl::cat(FevCategory));

static cl::opt<bool>
    ListTargets("list-targets",
                cl::desc("List compile targets for --emit-binary and exit"),
                cl::init(false), cl::cat(FevCategory));

static cl::opt<bool>
    EmitBinary("emit-binary",
               cl::desc("After rewriting, compile the obfuscated source to a "
                        "binary (--binary-target)"),
               cl::init(false), cl::cat(FevCategory));

static cl::opt<bool>
    EmitDll("emit-dll",
            cl::desc("After rewriting, compile to a Windows DLL (implies "
                     "--emit-binary). Default target: clang-cl-dll on Windows, "
                     "mingw-dll elsewhere; override with --binary-target"),
            cl::init(false), cl::cat(FevCategory));

static cl::opt<std::string>
    BinaryTarget("binary-target",
                 cl::desc("Compile target id (see --list-targets; default: host)"),
                 cl::init("host"), cl::cat(FevCategory));

static cl::opt<std::string>
    BinaryOutput("binary-output",
                 cl::desc("Binary/DLL output path (default: <obf_stem>[.exe|.dll])"),
                 cl::value_desc("file"), cl::init(""), cl::cat(FevCategory));

static cl::opt<std::string> DllEntry(
    "dll-entry",
    cl::desc("to-dll: name of the renamed former main() entry "
             "(default _fev_dll_entry)"),
    cl::value_desc("ident"), cl::init("_fev_dll_entry"), cl::cat(FevCategory));

static cl::opt<bool> DllExport(
    "dll-export",
    cl::desc("to-dll: __declspec(dllexport) the entry (default true)"),
    cl::init(true), cl::cat(FevCategory));

static cl::opt<bool> DllThread(
    "dll-thread",
    cl::desc("to-dll: CreateThread from DllMain instead of calling entry "
             "directly (default true; avoids loader lock)"),
    cl::init(true), cl::cat(FevCategory));

static cl::opt<std::string> ClangFlags(
    "clang-flags",
    cl::desc(
        "Extra Clang/compiler flags as one string (GNU quoting). Applied to "
        "the rewriter parse step and to --emit-binary. "
        "Example: --clang-flags=\"-O2 -g -DFOO=1 -isystem /opt/inc\""),
    cl::value_desc("flags"), cl::init(""), cl::cat(FevCategory));

static cl::opt<bool> NoBanner(
    "no-banner", cl::desc("Skip the FEV splash banner"), cl::init(false),
    cl::cat(FevCategory));

static cl::opt<bool> Verbose(
    "verbose", cl::desc("Verbose logging (debug level)"), cl::init(false),
    cl::cat(FevCategory));
static cl::alias VerboseShort("v", cl::desc("Alias for --verbose"),
                              cl::aliasopt(Verbose), cl::cat(FevCategory));

static cl::opt<std::string> LogColor(
    "log-color",
    cl::desc("Colorize fev log output: auto (default), always, never"),
    cl::value_desc("mode"), cl::init("auto"), cl::cat(FevCategory));

static cl::opt<std::string> LogFile(
    "log-file",
    cl::desc("Append info/debug (and warn/error) logs to this file; "
             "debug lines are written even without -v. Also: FEV_LOG_FILE"),
    cl::value_desc("path"), cl::init(""), cl::cat(FevCategory));

static cl::opt<std::string> ValidateOpt(
    "validate",
    cl::desc("Pass integrity checks: off | warn (default) | strict. "
             "Rewrite-time round-trips for buffer passes; inject FNV checks. "
             "Also: FEV_VALIDATE"),
    cl::value_desc("mode"), cl::init("warn"), cl::cat(FevCategory));

static cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
static cl::extrahelp MoreHelp(R"(
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

  FEV — source-to-source obfuscator (ClangTooling)
  Made by @tmajik

Examples:
  fev --list-passes
  fev --list-targets
  fev examples/sample.c --
      → examples/sample_obf.c
  fev --emit-binary --binary-target=host --clang-flags="-O2 -g" examples/sample.c --
  fev --emit-binary --binary-target=mingw-x64 \
        --clang-flags="--target=x86_64-w64-mingw32 -isystem /usr/x86_64-w64-mingw32/include" \
        examples/sample2.c --
  fev --passes=all --emit-binary examples/sample.c --
  fev --passes=to-dll --emit-dll --binary-target=mingw-dll examples/sample2.c --
  fev --passes=encrypt-buffers,to-dll --emit-dll --binary-target=clang-cl-dll \\
        examples/sample2.c --
  fev -v --log-color=always --passes=flatten-cfg examples/sample_cff.c --

Multiple passes (including --passes=all) re-parse between each step so
AST-based passes like dict-rename see text injected by earlier passes.
to-dll is opt-in only (not part of --passes=all); run it last after
passes that inject at main().

--clang-flags is a single string tokenized like a shell command line.
Flags after '--' are still accepted as rewriter parse flags (merged with
--clang-flags).

Logging: debug (-v), info, warn, error. Color when stderr is a TTY
(--log-color=always|never, or NO_COLOR / FORCE_COLOR).
Pass runs tag console/file lines as [pass-name]. Use --log-file=fev.log
(or FEV_LOG_FILE) to append all info/debug lines to one file (debug is
always recorded in the file, even without -v).

Validation: --validate=warn|strict|off (default warn; FEV_VALIDATE).
Buffer passes (dict-bytes, scramble-arrays, array-split, encrypt-buffers)
do rewrite-time round-trips and inject FNV integrity checks when not off.
)");

static bool hasFlag(int argc, const char **argv, StringRef Flag) {
  for (int I = 1; I < argc; ++I) {
    const StringRef Arg(argv[I]);
    if (Arg == Flag || Arg.starts_with((Flag + "=").str()))
      return true;
    if (Arg == "--")
      break;
  }
  return false;
}

static std::vector<std::string> collectPasses() {
  std::vector<std::string> Out;
  for (const std::string &P : PassList)
    Out.push_back(P);
  return Out;
}

static std::string defaultObfuscatedPath(StringRef InputPath) {
  SmallString<256> Dir(InputPath);
  sys::path::remove_filename(Dir);

  const StringRef File = sys::path::filename(InputPath);
  const StringRef Stem = sys::path::stem(File);
  const StringRef Ext = sys::path::extension(File);

  SmallString<256> Out;
  if (!Dir.empty()) {
    Out = Dir;
    sys::path::append(Out, Stem.str() + "_obf" + Ext.str());
  } else {
    Out = Stem.str() + "_obf" + Ext.str();
  }
  return std::string(Out);
}

/// Resolve final source output path from -o / --outdir / input.
static std::string resolveOutputPath(StringRef InputPath, StringRef OutOpt,
                                     StringRef OutDirOpt) {
  std::string File;
  if (!OutOpt.empty())
    File = OutOpt.str();
  else
    File = defaultObfuscatedPath(InputPath);

  if (!OutDirOpt.empty()) {
    // Place under outdir using the filename only (ignore any dir in -o).
    const std::string Base = sys::path::filename(File).str();
    SmallString<256> Joined;
    sys::path::append(Joined, OutDirOpt, Base);
    File = std::string(Joined.str());
  }
  return File;
}

static bool ensureParentDir(StringRef FilePath) {
  SmallString<256> Parent(FilePath);
  sys::path::remove_filename(Parent);
  if (Parent.empty())
    return true;
  if (std::error_code EC = sys::fs::create_directories(Parent)) {
    fev::logError() << "cannot create output directory '" << Parent.str()
                    << "': " << EC.message();
    return false;
  }
  return true;
}

/// When compiling for mingw / DLL targets, ensure the rewriter can parse
/// windows.h even if the user forgot parse flags after '--'.
static void maybeAddMingwParseFlags(ClangTool &Tool, StringRef TargetId) {
  if (TargetId != "mingw-x64" && TargetId != "mingw-dll" &&
      TargetId != "clang-cl-dll")
    return;
  Tool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
      {"--target=x86_64-w64-mingw32", "-isystem",
       "/usr/x86_64-w64-mingw32/include"},
      ArgumentInsertPosition::END));
}

static void applyLogCli() {
  fev::initLogFromEnvironment();
  if (Verbose)
    fev::setLogLevel(fev::LogLevel::Debug);

  if (LogColor == "always" || LogColor == "on" || LogColor == "yes")
    fev::setLogColorMode(fev::LogColorMode::Always);
  else if (LogColor == "never" || LogColor == "off" || LogColor == "no")
    fev::setLogColorMode(fev::LogColorMode::Never);
  else
    fev::setLogColorMode(fev::LogColorMode::Auto);

  // CLI overrides FEV_LOG_FILE from the environment.
  if (!LogFile.empty()) {
    if (!fev::setLogFile(LogFile))
      std::exit(1);
  } else if (const char *EnvLog = std::getenv("FEV_LOG_FILE")) {
    if (EnvLog[0] != '\0' && !fev::setLogFile(EnvLog))
      std::exit(1);
  }
}

int main(int argc, const char **argv) {
  fev::initLogFromEnvironment();

  const bool SkipBanner =
      hasFlag(argc, argv, "--no-banner") ||
      hasFlag(argc, argv, "-no-banner") ||
      (std::getenv("FEV_NO_BANNER") != nullptr &&
       std::string(std::getenv("FEV_NO_BANNER")) != "0");
  if (!SkipBanner)
    fev::printBanner(llvm::errs());

  auto &Registry = fev::PassRegistry::instance();

  if (hasFlag(argc, argv, "--list-passes") ||
      hasFlag(argc, argv, "-list-passes")) {
    Registry.validateCompiledManifest();
    Registry.list(outs());
    return 0;
  }

  if (hasFlag(argc, argv, "--list-targets") ||
      hasFlag(argc, argv, "-list-targets")) {
    fev::listCompileTargets(outs());
    return 0;
  }

  auto ExpectedParser = CommonOptionsParser::create(argc, argv, FevCategory);
  if (!ExpectedParser) {
    fev::logError() << toString(ExpectedParser.takeError());
    return 1;
  }

  applyLogCli();

  if (XorKey > 255) {
    fev::logError() << "--xor-key must be in 0..255";
    return 1;
  }
  if (MbaDensity < 0.0 || MbaDensity > 1.0) {
    fev::logError() << "--mba-density must be in [0,1]";
    return 1;
  }
  if (OpaqueDensity < 0.0 || OpaqueDensity > 1.0) {
    fev::logError() << "--opaque-density must be in [0,1]";
    return 1;
  }
  if (JunkDensity < 0.0 || JunkDensity > 1.0) {
    fev::logError() << "--junk-density must be in [0,1]";
    return 1;
  }
  if (OpaqueFibN < 3 || OpaqueFibN > 40) {
    fev::logError() << "--opaque-fib-n must be in 3..40";
    return 1;
  }
  if (SleepSeconds < 1 || SleepSeconds > 600) {
    fev::logError() << "--sleep-seconds must be in 1..600";
    return 1;
  }
  if (LogColor != "auto" && LogColor != "always" && LogColor != "never" &&
      LogColor != "on" && LogColor != "off" && LogColor != "yes" &&
      LogColor != "no") {
    fev::logError() << "--log-color must be auto, always, or never (got '"
                    << LogColor << "')";
    return 1;
  }

  Registry.validateCompiledManifest();

  CommonOptionsParser &OptionsParser = ExpectedParser.get();
  const auto &Sources = OptionsParser.getSourcePathList();
  if (Sources.empty()) {
    fev::logError() << "no input source file";
    return 1;
  }
  if (Sources.size() > 1) {
    fev::logError() << "expected a single input file (got " << Sources.size()
                    << ")";
    return 1;
  }

  std::string OutFile =
      resolveOutputPath(Sources.front(), OutputPath, OutDir);
  if (!ensureParentDir(OutFile))
    return 1;

  auto Targets = fev::discoverCompileTargets();
  fev::CompileTarget *Chosen = nullptr;

  const bool WantBinary = EmitBinary || EmitDll;
  std::string EffectiveTarget = BinaryTarget;
  if (EmitDll && BinaryTarget.getNumOccurrences() == 0) {
    // clang-cl /LD needs an MSVC SDK. On Linux (and similar) prefer MinGW
    // -shared when available; use clang-cl-dll explicitly on Windows/VS hosts.
#if defined(_WIN32)
    EffectiveTarget = "clang-cl-dll";
#else
    if (fev::CompileTarget *Mw =
            fev::findCompileTarget(Targets, "mingw-dll");
        Mw && Mw->Available) {
      EffectiveTarget = "mingw-dll";
    } else {
      EffectiveTarget = "clang-cl-dll";
    }
#endif
    fev::logInfo() << "--emit-dll: using --binary-target=" << EffectiveTarget;
  }

  if (WantBinary) {
    Chosen = fev::findCompileTarget(Targets, EffectiveTarget);
    if (!Chosen) {
      fev::logError() << "unknown --binary-target='" << EffectiveTarget
                      << "' (try --list-targets)";
      return 1;
    }
    if (!Chosen->Available) {
      fev::logError() << "--binary-target='" << EffectiveTarget
                      << "' is not available on this system";
      fev::listCompileTargets(errs());
      return 1;
    }
  }

  fev::PassConfig Config;
  Config.EnabledPasses = collectPasses();
  Config.XorKey = static_cast<std::uint8_t>(XorKey);
  Config.Seed = Seed;
  Config.MbaDensity = MbaDensity;
  Config.OpaqueDensity = OpaqueDensity;
  Config.JunkDensity = JunkDensity;
  Config.OpaqueFibN = OpaqueFibN;
  Config.SleepSeconds = SleepSeconds;
  Config.SleepMinSeconds = SleepMinSeconds;
  Config.SleepMaxSeconds = SleepMaxSeconds;
  Config.FlattenMinStmts = FlattenMinStmts;
  Config.ArrayChunkSize = ArrayChunkSize;
  Config.ArraySplitMin = ArraySplitMin;
  Config.NameDictPath = NameDict;
  Config.DllEntryName = DllEntry;
  Config.DllExport = DllExport;
  Config.DllThread = DllThread;
  {
    std::string Mode = ValidateOpt;
    if (const char *Env = std::getenv("FEV_VALIDATE")) {
      if (Env[0] != '\0' && ValidateOpt.getNumOccurrences() == 0)
        Mode = Env;
    }
    Config.Validate = fev::parseValidateMode(Mode);
  }

  const std::vector<std::string> ExtraClangFlags =
      fev::tokenizeFlagString(ClangFlags);
  if (!ExtraClangFlags.empty())
    fev::logDebug() << "extra clang flags: " << ClangFlags;

  fev::logInfo() << "writing " << OutFile;
  fev::logDebug() << "input '" << Sources.front() << "', seed=" << Seed;

  // Multi-pass must re-parse between steps: later passes (esp. dict-rename)
  // match the AST, but earlier passes only mutate Rewriter text. One shared
  // AST then renames at stale byte offsets and shreds the file.
  const std::vector<fev::Pass *> Pipeline =
      fev::PassRegistry::instance().resolve(Config);
  if (Pipeline.empty()) {
    fev::logError() << "no passes selected";
    return 1;
  }

  auto runOne = [&](fev::PassConfig StepConfig, const std::string &InPath,
                    const std::string &StepOut) -> int {
    ClangTool StepTool(OptionsParser.getCompilations(),
                       std::vector<std::string>{InPath});
    StepTool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
        {"-resource-dir", FEV_CLANG_RESOURCE_DIR},
        ArgumentInsertPosition::BEGIN));
    if (WantBinary)
      maybeAddMingwParseFlags(StepTool, EffectiveTarget);
    if (!ExtraClangFlags.empty()) {
      std::vector<std::string> Adjust = ExtraClangFlags;
      StepTool.appendArgumentsAdjuster(
          [Adjust](const CommandLineArguments &Args, StringRef) {
            CommandLineArguments Out = Args;
            Out.insert(Out.end(), Adjust.begin(), Adjust.end());
            return Out;
          });
    }
    fev::RewriteActionFactory Factory(std::move(StepConfig), StepOut);
    return StepTool.run(&Factory);
  };

  int RewriteRC = 0;
  if (Pipeline.size() == 1) {
    RewriteRC = runOne(std::move(Config), Sources.front(), OutFile);
  } else {
    fev::logInfo() << "multi-pass: re-parsing between " << Pipeline.size()
                   << " passes";
    // Keep a .c/.cpp suffix — Clang treats unknown extensions as linker inputs.
    std::string Ext = llvm::sys::path::extension(OutFile).str();
    if (Ext.empty())
      Ext = ".c";
    const std::string Stem = OutFile.substr(0, OutFile.size() - Ext.size());
    const std::string TmpA = Stem + ".fev_step_a" + Ext;
    const std::string TmpB = Stem + ".fev_step_b" + Ext;
    if (!ensureParentDir(TmpA) || !ensureParentDir(TmpB))
      return 1;
    std::string CurrentIn = Sources.front();
    bool UseA = true;
    for (size_t I = 0; I < Pipeline.size(); ++I) {
      const bool Last = (I + 1 == Pipeline.size());
      const std::string StepOut = Last ? OutFile : (UseA ? TmpA : TmpB);
      fev::PassConfig StepConfig = Config;
      StepConfig.EnabledPasses = {Pipeline[I]->name().str()};
      fev::logInfo() << "→ " << Pipeline[I]->name() << " — "
                     << Pipeline[I]->description();
      RewriteRC = runOne(std::move(StepConfig), CurrentIn, StepOut);
      if (RewriteRC != 0)
        break;
      // EndSourceFileAction used to log write failures without failing the
      // tool run — refuse to continue on a missing step output.
      if (!llvm::sys::fs::exists(StepOut)) {
        fev::logError() << "pass '" << Pipeline[I]->name()
                        << "' did not write '" << StepOut << "'";
        RewriteRC = 1;
        break;
      }
      CurrentIn = StepOut;
      UseA = !UseA;
    }
    llvm::sys::fs::remove(TmpA);
    llvm::sys::fs::remove(TmpB);
  }

  if (RewriteRC != 0) {
    fev::logError() << "rewrite failed (exit " << RewriteRC << ")";
    return RewriteRC;
  }

  if (!WantBinary)
    return 0;

  std::string BinOut = BinaryOutput;
  if (BinOut.empty())
    BinOut = fev::defaultBinaryPath(OutFile, Chosen->ExeSuffix);

  return fev::compileToBinary(*Chosen, OutFile, BinOut, ExtraClangFlags);
}
