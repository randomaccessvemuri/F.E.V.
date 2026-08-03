#include "fev/Compiler.h"
#include "fev/Config.h"
#include "fev/InterpassValidate.h"
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
#include <optional>
#include <string>
#include <vector>

using namespace clang::tooling;
using namespace llvm;

static cl::OptionCategory FevCategory("fev options");

static cl::opt<std::string>
    ConfigFile("config",
               cl::desc("JSON recipe file (passes, emit, target, outdir, …). "
                        "CLI flags that are explicitly set override the file"),
               cl::value_desc("path"), cl::init(""), cl::cat(FevCategory));

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

static cl::opt<bool> InterpassValidateOpt(
    "interpass-validate",
    cl::desc(
        "After each multi-pass step, verify original byte buffers still restore "
        "(crypto round-trip + scramble helper not CFF'd). Host TUs also "
        "compile+run. Config: interpass_validate. Developer safety net."),
    cl::init(false), cl::cat(FevCategory));

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
  fev --config configs/win-exe.json examples/sample2.c
  fev --config configs/win-dll.json examples/sample2.c
  fev --config configs/host-smoke.json examples/sample.c
  fev --list-passes
  fev --list-targets
  fev --config configs/win-exe.json --seed=1 examples/sample2.c
  fev --passes=all --emit-binary --binary-target=mingw-x64 examples/sample2.c --
  fev -v --passes=flatten-cfg examples/sample_cff.c --

Prefer --config for EXE/DLL recipes. Explicit CLI flags override the file.
Multiple passes (including --passes=all) re-parse between each step.
to-dll is opt-in (not in --passes=all); configs/win-dll.json includes it.

--clang-flags / config clang_flags apply to rewriter parse and final compile.
Flags after '--' are also rewriter parse flags (merged).

Logging: debug (-v), info, warn, error. --log-file / FEV_LOG_FILE.
Validation: --validate=warn|strict|off (default warn; FEV_VALIDATE).
Inter-pass buffers: --interpass-validate / config interpass_validate
  (crypto restore + helper CFF check after each step; host TUs also run).
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

/// When compiling for mingw / DLL targets (or Windows sources), ensure the
/// rewriter can parse windows.h even if the user forgot flags after '--'.
static void maybeAddMingwParseFlags(ClangTool &Tool, bool Enable) {
  if (!Enable)
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

  // --- Load optional JSON recipe; explicit CLI wins on every field. ---
  std::optional<fev::FileConfig> FileCfg;
  if (!ConfigFile.empty()) {
    FileCfg = fev::loadConfigFile(ConfigFile);
    if (!FileCfg)
      return 1;
  }

  auto cliUnset = [](const auto &Opt) { return Opt.getNumOccurrences() == 0; };

  std::string EffectiveOut = OutputPath;
  if (cliUnset(OutputPath) && FileCfg && FileCfg->Output)
    EffectiveOut = *FileCfg->Output;
  std::string EffectiveOutDir = OutDir;
  if (cliUnset(OutDir) && FileCfg && FileCfg->OutDir)
    EffectiveOutDir = *FileCfg->OutDir;

  std::string OutFile =
      resolveOutputPath(Sources.front(), EffectiveOut, EffectiveOutDir);
  if (!ensureParentDir(OutFile))
    return 1;

  // Emit: CLI --emit-dll / --emit-binary, else config emit, else none.
  fev::EmitKind Emit = fev::EmitKind::None;
  if (EmitDll)
    Emit = fev::EmitKind::Dll;
  else if (EmitBinary)
    Emit = fev::EmitKind::Exe;
  else if (FileCfg && FileCfg->Emit)
    Emit = *FileCfg->Emit;

  auto Targets = fev::discoverCompileTargets();
  fev::CompileTarget *Chosen = nullptr;

  std::string EffectiveTarget = BinaryTarget;
  if (cliUnset(BinaryTarget)) {
    if (FileCfg && FileCfg->Target) {
      EffectiveTarget = *FileCfg->Target;
    } else if (Emit == fev::EmitKind::Dll) {
#if defined(_WIN32)
      EffectiveTarget = "clang-cl-dll";
#else
      if (fev::CompileTarget *Mw =
              fev::findCompileTarget(Targets, "mingw-dll");
          Mw && Mw->Available)
        EffectiveTarget = "mingw-dll";
      else
        EffectiveTarget = "clang-cl-dll";
#endif
    } else if (Emit == fev::EmitKind::Exe) {
      if (fev::sourceLooksLikeWindows(Sources.front()))
        EffectiveTarget = "mingw-x64";
      // else keep default "host"
    }
  }

  const bool WantBinary = Emit != fev::EmitKind::None;
  if (WantBinary) {
    Chosen = fev::findCompileTarget(Targets, EffectiveTarget);
    if (!Chosen) {
      fev::logError() << "unknown --binary-target/target='" << EffectiveTarget
                      << "' (try --list-targets)";
      return 1;
    }
    if (!Chosen->Available) {
      fev::logError() << "target '" << EffectiveTarget
                      << "' is not available on this system";
      fev::listCompileTargets(errs());
      return 1;
    }
  }

  if (WantBinary && EffectiveTarget == "host" &&
      fev::sourceLooksLikeWindows(Sources.front())) {
    fev::logError()
        << "refusing to compile Windows source with target=host "
           "(missing windows.h). Use --config configs/win-exe.json "
           "(or --binary-target=mingw-x64 / configs/win-dll.json)";
    return 1;
  }

  fev::PassConfig Config;
  if (!cliUnset(PassList))
    Config.EnabledPasses = collectPasses();
  else if (FileCfg && FileCfg->Passes)
    Config.EnabledPasses = fev::splitPasses(*FileCfg->Passes);
  // else empty → default encrypt-strings,encrypt-buffers

  Config.XorKey = static_cast<std::uint8_t>(XorKey);
  if (cliUnset(XorKey) && FileCfg && FileCfg->XorKey)
    Config.XorKey = *FileCfg->XorKey;

  Config.Seed = Seed;
  if (cliUnset(Seed) && FileCfg && FileCfg->Seed)
    Config.Seed = *FileCfg->Seed;

  Config.MbaDensity = MbaDensity;
  if (cliUnset(MbaDensity) && FileCfg && FileCfg->MbaDensity)
    Config.MbaDensity = *FileCfg->MbaDensity;
  Config.OpaqueDensity = OpaqueDensity;
  if (cliUnset(OpaqueDensity) && FileCfg && FileCfg->OpaqueDensity)
    Config.OpaqueDensity = *FileCfg->OpaqueDensity;
  Config.JunkDensity = JunkDensity;
  if (cliUnset(JunkDensity) && FileCfg && FileCfg->JunkDensity)
    Config.JunkDensity = *FileCfg->JunkDensity;
  Config.OpaqueFibN = OpaqueFibN;
  if (cliUnset(OpaqueFibN) && FileCfg && FileCfg->OpaqueFibN)
    Config.OpaqueFibN = *FileCfg->OpaqueFibN;
  Config.SleepSeconds = SleepSeconds;
  if (cliUnset(SleepSeconds) && FileCfg && FileCfg->SleepSeconds)
    Config.SleepSeconds = *FileCfg->SleepSeconds;
  Config.SleepMinSeconds = SleepMinSeconds;
  if (cliUnset(SleepMinSeconds) && FileCfg && FileCfg->SleepMinSeconds)
    Config.SleepMinSeconds = *FileCfg->SleepMinSeconds;
  Config.SleepMaxSeconds = SleepMaxSeconds;
  if (cliUnset(SleepMaxSeconds) && FileCfg && FileCfg->SleepMaxSeconds)
    Config.SleepMaxSeconds = *FileCfg->SleepMaxSeconds;
  Config.FlattenMinStmts = FlattenMinStmts;
  if (cliUnset(FlattenMinStmts) && FileCfg && FileCfg->FlattenMinStmts)
    Config.FlattenMinStmts = *FileCfg->FlattenMinStmts;
  Config.ArrayChunkSize = ArrayChunkSize;
  if (cliUnset(ArrayChunkSize) && FileCfg && FileCfg->ArrayChunkSize)
    Config.ArrayChunkSize = *FileCfg->ArrayChunkSize;
  Config.ArraySplitMin = ArraySplitMin;
  if (cliUnset(ArraySplitMin) && FileCfg && FileCfg->ArraySplitMin)
    Config.ArraySplitMin = *FileCfg->ArraySplitMin;

  Config.NameDictPath = NameDict;
  if (cliUnset(NameDict) && FileCfg && FileCfg->NameDictPath)
    Config.NameDictPath = *FileCfg->NameDictPath;
  Config.DllEntryName = DllEntry;
  if (cliUnset(DllEntry) && FileCfg && FileCfg->DllEntryName)
    Config.DllEntryName = *FileCfg->DllEntryName;
  Config.DllExport = DllExport;
  if (cliUnset(DllExport) && FileCfg && FileCfg->DllExport)
    Config.DllExport = *FileCfg->DllExport;
  Config.DllThread = DllThread;
  if (cliUnset(DllThread) && FileCfg && FileCfg->DllThread)
    Config.DllThread = *FileCfg->DllThread;

  {
    std::string Mode = ValidateOpt;
    if (cliUnset(ValidateOpt) && FileCfg && FileCfg->Validate)
      Mode = *FileCfg->Validate;
    else if (const char *Env = std::getenv("FEV_VALIDATE")) {
      if (Env[0] != '\0' && cliUnset(ValidateOpt) &&
          !(FileCfg && FileCfg->Validate))
        Mode = Env;
    }
    Config.Validate = fev::parseValidateMode(Mode);
  }

  Config.InterpassValidate = InterpassValidateOpt;
  if (cliUnset(InterpassValidateOpt) && FileCfg && FileCfg->InterpassValidate)
    Config.InterpassValidate = *FileCfg->InterpassValidate;

  // Re-validate ranges after config merge.
  if (Config.MbaDensity < 0.0 || Config.MbaDensity > 1.0 ||
      Config.OpaqueDensity < 0.0 || Config.OpaqueDensity > 1.0 ||
      Config.JunkDensity < 0.0 || Config.JunkDensity > 1.0 ||
      Config.OpaqueFibN < 3 || Config.OpaqueFibN > 40 ||
      Config.SleepSeconds < 1 || Config.SleepSeconds > 600) {
    fev::logError() << "config/CLI combination has out-of-range knobs "
                       "(densities, fib-n, sleep-seconds)";
    return 1;
  }

  std::string EffectiveClangFlags = ClangFlags;
  if (cliUnset(ClangFlags) && FileCfg && FileCfg->ClangFlags)
    EffectiveClangFlags = *FileCfg->ClangFlags;

  const std::vector<std::string> ExtraClangFlags =
      fev::tokenizeFlagString(EffectiveClangFlags);
  if (!ExtraClangFlags.empty())
    fev::logDebug() << "extra clang flags: " << EffectiveClangFlags;

  std::string PassesLog;
  if (Config.EnabledPasses.empty())
    PassesLog = "(default encrypt-strings,encrypt-buffers)";
  else {
    for (size_t I = 0; I < Config.EnabledPasses.size(); ++I) {
      if (I)
        PassesLog += ',';
      PassesLog += Config.EnabledPasses[I];
    }
  }
  if (FileCfg) {
    const std::string CfgName =
        llvm::sys::path::filename(FileCfg->Path).str();
    fev::logInfo() << "config: " << CfgName << " → passes=" << PassesLog
                   << " emit=" << fev::emitKindName(Emit)
                   << " target=" << EffectiveTarget;
    if (!FileCfg->Description.empty())
      fev::logInfo() << "  " << FileCfg->Description;
  }

  fev::logInfo() << "writing " << OutFile;
  fev::logDebug() << "input '" << Sources.front() << "', seed=" << Config.Seed;

  // Multi-pass must re-parse between steps: later passes (esp. dict-rename)
  // match the AST, but earlier passes only mutate Rewriter text. One shared
  // AST then renames at stale byte offsets and shreds the file.
  const std::vector<fev::Pass *> Pipeline =
      fev::PassRegistry::instance().resolve(Config);
  if (Pipeline.empty()) {
    fev::logError() << "no passes selected";
    return 1;
  }

  bool HasToDll = false;
  for (fev::Pass *P : Pipeline) {
    if (P->name() == "to-dll") {
      HasToDll = true;
      break;
    }
  }
  if (HasToDll && Emit == fev::EmitKind::Exe) {
    fev::logError()
        << "to-dll produces DLL source but emit=exe. Use "
           "--config configs/win-dll.json (or --emit-dll / emit:\"dll\"), "
           "or drop to-dll from --passes";
    return 1;
  }
  if (HasToDll && WantBinary && EffectiveTarget != "mingw-dll" &&
      EffectiveTarget != "clang-cl-dll") {
    fev::logError() << "to-dll requires a DLL target (mingw-dll or "
                       "clang-cl-dll), got '"
                    << EffectiveTarget << "'";
    return 1;
  }

  const bool NeedMingwParse =
      fev::targetNeedsMingwParseFlags(EffectiveTarget) ||
      fev::sourceLooksLikeWindows(Sources.front()) ||
      EffectiveClangFlags.find("mingw") != std::string::npos;

  auto runOne = [&](fev::PassConfig StepConfig, const std::string &InPath,
                    const std::string &StepOut) -> int {
    ClangTool StepTool(OptionsParser.getCompilations(),
                       std::vector<std::string>{InPath});
    StepTool.appendArgumentsAdjuster(getInsertArgumentAdjuster(
        {"-resource-dir", FEV_CLANG_RESOURCE_DIR},
        ArgumentInsertPosition::BEGIN));
    maybeAddMingwParseFlags(StepTool, NeedMingwParse);
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

  std::vector<fev::GoldenBuffer> Goldens;
  if (Config.InterpassValidate) {
    fev::logInfo() << "interpass-validate: harvesting golden buffers from "
                   << Sources.front();
    if (!fev::harvestGoldenBuffers(Sources.front(), Goldens))
      return 1;
    if (Goldens.empty())
      fev::logWarn() << "interpass-validate: no buffers to track "
                        "(need ≥8-byte char arrays)";
  }

  // Host execute probe only when linking for host (or source-only host smoke).
  const bool InterpassExecute =
      Config.InterpassValidate &&
      (EffectiveTarget == "host" || EffectiveTarget.empty());

  int RewriteRC = 0;
  if (Pipeline.size() == 1) {
    fev::PassConfig Single = Config;
    RewriteRC = runOne(std::move(Single), Sources.front(), OutFile);
    if (RewriteRC == 0 && Config.InterpassValidate && !Goldens.empty()) {
      if (!fev::interpassValidateAfterPass(
              OutFile, Pipeline[0]->name(), Goldens, Config.Seed,
              Config.Validate, InterpassExecute, /*AlwaysFail=*/true))
        return 1;
    }
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
    bool KeepTemps = false;
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
      if (Config.InterpassValidate && !Goldens.empty()) {
        if (!fev::interpassValidateAfterPass(
                StepOut, Pipeline[I]->name(), Goldens, Config.Seed,
                Config.Validate, InterpassExecute, /*AlwaysFail=*/true)) {
          fev::logError() << "interpass-validate stopped after '"
                          << Pipeline[I]->name() << "'; keeping "
                          << StepOut << " for debugging";
          KeepTemps = true;
          RewriteRC = 1;
          break;
        }
      }
      CurrentIn = StepOut;
      UseA = !UseA;
    }
    if (!KeepTemps) {
      llvm::sys::fs::remove(TmpA);
      llvm::sys::fs::remove(TmpB);
    }
  }

  if (RewriteRC != 0) {
    fev::logError() << "rewrite failed (exit " << RewriteRC << ")";
    return RewriteRC;
  }

  if (!WantBinary)
    return 0;

  std::string BinOut = BinaryOutput;
  if (cliUnset(BinaryOutput) && FileCfg && FileCfg->BinaryOutput)
    BinOut = *FileCfg->BinaryOutput;
  if (BinOut.empty())
    BinOut = fev::defaultBinaryPath(OutFile, Chosen->ExeSuffix);

  // Prefixed MinGW gcc rejects Clang's --target=; keep it for the rewriter only.
  std::vector<std::string> LinkFlags = ExtraClangFlags;
  const bool PrefixedMingwGcc =
      Chosen->Compiler.find("mingw") != std::string::npos &&
      Chosen->Compiler.find("gcc") != std::string::npos;
  if (PrefixedMingwGcc) {
    std::vector<std::string> Filtered;
    Filtered.reserve(LinkFlags.size());
    for (const std::string &F : LinkFlags) {
      if (F.rfind("--target=", 0) == 0)
        continue;
      Filtered.push_back(F);
    }
    LinkFlags = std::move(Filtered);
  }

  return fev::compileToBinary(*Chosen, OutFile, BinOut, LinkFlags);
}
