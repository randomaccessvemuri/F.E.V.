#include "fev/Pass.h"
#include "fev/Log.h"
#include "fev/Validate.h"

#include "GeneratedPassNames.h"
#include "llvm/ADT/StringSet.h"

#include <algorithm>

namespace fev {

PassRegistry &PassRegistry::instance() {
  static PassRegistry Registry;
  return Registry;
}

bool PassRegistry::add(std::unique_ptr<Pass> P) {
  if (!P)
    return false;
  const std::string Name = P->name().str();
  if (find(Name)) {
    logError() << "duplicate pass registration: " << Name;
    return false;
  }
  Passes_.push_back(std::move(P));
  logDebug() << "registered pass '" << Name << "'";
  return true;
}

Pass *PassRegistry::find(llvm::StringRef Name) const {
  for (const auto &P : Passes_) {
    if (P->name() == Name)
      return P.get();
  }
  return nullptr;
}

void PassRegistry::validateCompiledManifest() const {
  llvm::StringSet<> Runtime;
  for (const auto &P : Passes_)
    Runtime.insert(P->name());

  for (unsigned I = 0; I < kCompiledPassCount; ++I) {
    const llvm::StringRef Name = kCompiledPassNames[I];
    if (!Runtime.contains(Name)) {
      logError() << "compile-time pass '" << Name
                 << "' was discovered in src/passes/ but did not "
                    "self-register (missing FEV_REGISTER_PASS?)";
    }
  }

  for (const auto &P : Passes_) {
    bool Found = false;
    for (unsigned I = 0; I < kCompiledPassCount; ++I) {
      if (P->name() == kCompiledPassNames[I]) {
        Found = true;
        break;
      }
    }
    if (!Found) {
      logWarn() << "runtime pass '" << P->name()
                << "' registered but was not found by CMake name() scan";
    }
  }
}

std::vector<Pass *> PassRegistry::resolve(const PassConfig &Config) const {
  std::vector<Pass *> Out;

  auto pushUnique = [&](Pass *P) {
    if (!P)
      return;
    if (std::find(Out.begin(), Out.end(), P) == Out.end())
      Out.push_back(P);
  };

  if (Config.EnabledPasses.empty()) {
    // Default: encrypt call-site strings and global byte buffers.
    pushUnique(find("encrypt-strings"));
    pushUnique(find("encrypt-buffers"));
    return Out;
  }

  for (const std::string &Name : Config.EnabledPasses) {
    if (Name == "all") {
      // Buffer pipeline (in order):
      //   scramble-arrays → encrypt-buffers → dict-bytes → array-split
      // so ChaCha runs on plain/scrambled bytes before dict-bytes rewrites
      // the initializer. dict-rename last. to-dll is opt-in only.
      Pass *DictRename = nullptr;
      Pass *DictBytes = nullptr;
      Pass *EncryptBuffers = nullptr;
      for (const auto &P : Passes_) {
        if (P->name() == "dict-rename") {
          DictRename = P.get();
          continue;
        }
        if (P->name() == "dict-bytes") {
          DictBytes = P.get();
          continue;
        }
        if (P->name() == "encrypt-buffers") {
          EncryptBuffers = P.get();
          continue;
        }
        if (P->name() == "to-dll")
          continue;
        pushUnique(P.get());
      }
      // Insert encrypt-buffers then dict-bytes immediately after scramble
      // (or before array-split if scramble is absent).
      auto InsertAt = Out.end();
      for (auto It = Out.begin(); It != Out.end(); ++It) {
        if ((*It)->name() == "scramble-arrays") {
          InsertAt = std::next(It);
          break;
        }
        if ((*It)->name() == "array-split" && InsertAt == Out.end())
          InsertAt = It;
      }
      if (EncryptBuffers)
        InsertAt = std::next(Out.insert(InsertAt, EncryptBuffers));
      if (DictBytes)
        Out.insert(InsertAt, DictBytes);
      pushUnique(DictRename);
      continue;
    }
    if (Pass *P = find(Name)) {
      pushUnique(P);
    } else {
      logError() << "unknown pass '" << Name << "' (try --list-passes)";
    }
  }
  return Out;
}

void PassRegistry::list(llvm::raw_ostream &OS) const {
  OS << "Available passes (" << Passes_.size()
     << " registered, " << kCompiledPassCount
     << " discovered at compile time):\n";
  for (const auto &P : Passes_) {
    OS << "  " << P->name() << "\n      " << P->description() << "\n";
  }
  OS << "\nSelect with --passes=name[,name...] or --passes=all\n";
  OS << "Default output: <input_stem>_obf.<ext>\n";
}

bool runPasses(PassContext &Ctx) {
  const auto Pipeline = PassRegistry::instance().resolve(Ctx.Config);
  if (Pipeline.empty()) {
    logError() << "no passes selected";
    return false;
  }

  logInfo() << "running " << Pipeline.size()
            << (Pipeline.size() == 1 ? " pass" : " passes")
            << " (validate=" << validateModeName(Ctx.Config.Validate) << ")";
  if (hasLogFile())
    logDebug() << "log file: " << getLogFilePath();

  for (Pass *P : Pipeline) {
    PassLogScope Scope(P->name());
    logInfo() << "start — " << P->description();
    if (!P->run(Ctx)) {
      logError() << "failed";
      return false;
    }
    logInfo() << "finished";
  }
  return true;
}

} // namespace fev
