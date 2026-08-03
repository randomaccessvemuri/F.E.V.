#include "fev/Config.h"
#include "fev/Log.h"

#include "llvm/Support/Error.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

#include <fstream>
#include <sstream>

namespace fev {
namespace {

std::optional<std::uint64_t> parseSeedValue(const llvm::json::Value &V) {
  if (auto N = V.getAsInteger()) {
    if (*N < 0)
      return std::nullopt;
    return static_cast<std::uint64_t>(*N);
  }
  if (auto S = V.getAsString()) {
    llvm::StringRef T = S->trim();
    unsigned long long Val = 0;
    if (T.consumeInteger(0, Val))
      return std::nullopt;
    return static_cast<std::uint64_t>(Val);
  }
  return std::nullopt;
}

std::optional<double> parseDoubleValue(const llvm::json::Value &V) {
  if (auto N = V.getAsNumber())
    return *N;
  if (auto I = V.getAsInteger())
    return static_cast<double>(*I);
  if (auto S = V.getAsString()) {
    double Out = 0.0;
    llvm::StringRef T = S->trim();
    if (T.getAsDouble(Out))
      return Out;
  }
  return std::nullopt;
}

std::optional<unsigned> parseUnsignedValue(const llvm::json::Value &V) {
  if (auto N = V.getAsInteger()) {
    if (*N < 0)
      return std::nullopt;
    return static_cast<unsigned>(*N);
  }
  if (auto S = V.getAsString()) {
    llvm::StringRef T = S->trim();
    unsigned long long Val = 0;
    if (T.consumeInteger(0, Val))
      return std::nullopt;
    return static_cast<unsigned>(Val);
  }
  return std::nullopt;
}

std::optional<bool> parseBoolValue(const llvm::json::Value &V) {
  if (auto B = V.getAsBoolean())
    return *B;
  if (auto S = V.getAsString()) {
    const llvm::StringRef T = S->trim().lower();
    if (T == "true" || T == "yes" || T == "on" || T == "1")
      return true;
    if (T == "false" || T == "no" || T == "off" || T == "0")
      return false;
  }
  if (auto N = V.getAsInteger())
    return *N != 0;
  return std::nullopt;
}

std::optional<std::string> asString(const llvm::json::Value &V) {
  if (auto S = V.getAsString())
    return S->str();
  return std::nullopt;
}

} // namespace

std::optional<EmitKind> parseEmitKind(llvm::StringRef S) {
  const llvm::StringRef T = S.trim().lower();
  if (T == "none" || T == "off" || T.empty())
    return EmitKind::None;
  if (T == "exe" || T == "binary" || T == "executable")
    return EmitKind::Exe;
  if (T == "dll" || T == "shared" || T == "library")
    return EmitKind::Dll;
  return std::nullopt;
}

llvm::StringRef emitKindName(EmitKind K) {
  switch (K) {
  case EmitKind::None:
    return "none";
  case EmitKind::Exe:
    return "exe";
  case EmitKind::Dll:
    return "dll";
  }
  return "none";
}

bool targetNeedsMingwParseFlags(llvm::StringRef TargetId) {
  return TargetId == "mingw-x64" || TargetId == "mingw-dll" ||
         TargetId == "clang-cl-dll";
}

bool sourceLooksLikeWindows(llvm::StringRef SourcePath) {
  std::ifstream In(SourcePath.str());
  if (!In)
    return false;
  std::ostringstream SS;
  SS << In.rdbuf();
  const std::string Text = SS.str();
  return Text.find("windows.h") != std::string::npos ||
         Text.find("Windows.h") != std::string::npos ||
         Text.find("WINAPI") != std::string::npos;
}

std::vector<std::string> splitPasses(llvm::StringRef Spec) {
  std::vector<std::string> Out;
  llvm::SmallVector<llvm::StringRef, 16> Parts;
  Spec.split(Parts, ',', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
  for (llvm::StringRef P : Parts) {
    P = P.trim();
    if (!P.empty())
      Out.push_back(P.str());
  }
  return Out;
}

std::optional<FileConfig> loadConfigFile(llvm::StringRef Path) {
  auto BufOrErr = llvm::MemoryBuffer::getFile(Path);
  if (!BufOrErr) {
    logError() << "cannot read --config '" << Path
               << "': " << BufOrErr.getError().message();
    return std::nullopt;
  }

  llvm::Expected<llvm::json::Value> Parsed =
      llvm::json::parse(BufOrErr.get()->getBuffer());
  if (!Parsed) {
    logError() << "invalid JSON in --config '" << Path
               << "': " << toString(Parsed.takeError());
    return std::nullopt;
  }

  const llvm::json::Object *Obj = Parsed->getAsObject();
  if (!Obj) {
    logError() << "--config '" << Path << "' must be a JSON object";
    return std::nullopt;
  }

  FileConfig Cfg;
  Cfg.Path = Path.str();

  auto warnUnknown = [&](llvm::StringRef Key) {
    logWarn() << "config '" << Path << "': ignoring unknown key '" << Key
              << "'";
  };

  for (const auto &KV : *Obj) {
    const llvm::StringRef Key = KV.first;
    const llvm::json::Value &Val = KV.second;

    if (Key == "description") {
      if (auto S = asString(Val))
        Cfg.Description = *S;
      else
        logWarn() << "config: 'description' must be a string";
      continue;
    }
    if (Key == "passes") {
      if (auto S = asString(Val)) {
        Cfg.Passes = *S;
      } else if (const auto *A = Val.getAsArray()) {
        std::string Joined;
        for (const auto &E : *A) {
          if (auto PS = asString(E)) {
            if (!Joined.empty())
              Joined += ',';
            Joined += *PS;
          }
        }
        Cfg.Passes = Joined;
      } else {
        logWarn() << "config: 'passes' must be a string or array of strings";
      }
      continue;
    }
    if (Key == "seed") {
      if (auto V = parseSeedValue(Val))
        Cfg.Seed = *V;
      else
        logWarn() << "config: invalid 'seed'";
      continue;
    }
    if (Key == "xor_key" || Key == "xor-key") {
      if (auto V = parseUnsignedValue(Val); V && *V <= 255)
        Cfg.XorKey = static_cast<std::uint8_t>(*V);
      else
        logWarn() << "config: invalid 'xor_key'";
      continue;
    }
    if (Key == "mba_density" || Key == "mba-density") {
      if (auto V = parseDoubleValue(Val))
        Cfg.MbaDensity = *V;
      else
        logWarn() << "config: invalid 'mba_density'";
      continue;
    }
    if (Key == "opaque_density" || Key == "opaque-density") {
      if (auto V = parseDoubleValue(Val))
        Cfg.OpaqueDensity = *V;
      else
        logWarn() << "config: invalid 'opaque_density'";
      continue;
    }
    if (Key == "junk_density" || Key == "junk-density") {
      if (auto V = parseDoubleValue(Val))
        Cfg.JunkDensity = *V;
      else
        logWarn() << "config: invalid 'junk_density'";
      continue;
    }
    if (Key == "opaque_fib_n" || Key == "opaque-fib-n") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.OpaqueFibN = *V;
      else
        logWarn() << "config: invalid 'opaque_fib_n'";
      continue;
    }
    if (Key == "sleep_seconds" || Key == "sleep-seconds") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.SleepSeconds = *V;
      else
        logWarn() << "config: invalid 'sleep_seconds'";
      continue;
    }
    if (Key == "sleep_min" || Key == "sleep-min") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.SleepMinSeconds = *V;
      else
        logWarn() << "config: invalid 'sleep_min'";
      continue;
    }
    if (Key == "sleep_max" || Key == "sleep-max") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.SleepMaxSeconds = *V;
      else
        logWarn() << "config: invalid 'sleep_max'";
      continue;
    }
    if (Key == "flatten_min_stmts" || Key == "flatten-min-stmts") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.FlattenMinStmts = *V;
      else
        logWarn() << "config: invalid 'flatten_min_stmts'";
      continue;
    }
    if (Key == "array_chunk" || Key == "array-chunk") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.ArrayChunkSize = *V;
      else
        logWarn() << "config: invalid 'array_chunk'";
      continue;
    }
    if (Key == "array_split_min" || Key == "array-split-min") {
      if (auto V = parseUnsignedValue(Val))
        Cfg.ArraySplitMin = *V;
      else
        logWarn() << "config: invalid 'array_split_min'";
      continue;
    }
    if (Key == "name_dict" || Key == "name-dict") {
      if (auto S = asString(Val))
        Cfg.NameDictPath = *S;
      else
        logWarn() << "config: 'name_dict' must be a string";
      continue;
    }
    if (Key == "dll_entry" || Key == "dll-entry") {
      if (auto S = asString(Val))
        Cfg.DllEntryName = *S;
      else
        logWarn() << "config: 'dll_entry' must be a string";
      continue;
    }
    if (Key == "dll_export" || Key == "dll-export") {
      if (auto V = parseBoolValue(Val))
        Cfg.DllExport = *V;
      else
        logWarn() << "config: invalid 'dll_export'";
      continue;
    }
    if (Key == "dll_thread" || Key == "dll-thread") {
      if (auto V = parseBoolValue(Val))
        Cfg.DllThread = *V;
      else
        logWarn() << "config: invalid 'dll_thread'";
      continue;
    }
    if (Key == "validate") {
      if (auto S = asString(Val))
        Cfg.Validate = *S;
      else
        logWarn() << "config: 'validate' must be a string";
      continue;
    }
    if (Key == "output" || Key == "o") {
      if (auto S = asString(Val))
        Cfg.Output = *S;
      else
        logWarn() << "config: 'output' must be a string";
      continue;
    }
    if (Key == "outdir") {
      if (auto S = asString(Val))
        Cfg.OutDir = *S;
      else
        logWarn() << "config: 'outdir' must be a string";
      continue;
    }
    if (Key == "emit") {
      if (auto S = asString(Val)) {
        if (auto E = parseEmitKind(*S))
          Cfg.Emit = *E;
        else
          logWarn() << "config: invalid 'emit' (use none|exe|dll)";
      } else {
        logWarn() << "config: 'emit' must be a string";
      }
      continue;
    }
    if (Key == "target" || Key == "binary_target" || Key == "binary-target") {
      if (auto S = asString(Val))
        Cfg.Target = *S;
      else
        logWarn() << "config: 'target' must be a string";
      continue;
    }
    if (Key == "binary_output" || Key == "binary-output") {
      if (auto S = asString(Val))
        Cfg.BinaryOutput = *S;
      else
        logWarn() << "config: 'binary_output' must be a string";
      continue;
    }
    if (Key == "clang_flags" || Key == "clang-flags") {
      if (auto S = asString(Val))
        Cfg.ClangFlags = *S;
      else
        logWarn() << "config: 'clang_flags' must be a string";
      continue;
    }
    warnUnknown(Key);
  }

  return Cfg;
}

} // namespace fev
