#include "fev/InterpassValidate.h"
#include "fev/ChaCha20.h"
#include "fev/Log.h"
#include "fev/Validate.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/raw_ostream.h"

#include <cctype>
#include <optional>
#include <string>
#include <vector>

namespace fev {
namespace {

class XorShift64 {
public:
  explicit XorShift64(std::uint64_t Seed)
      : S_(Seed ? Seed : 0x9E3779B97F4A7C15ULL) {}
  std::uint64_t next() {
    std::uint64_t X = S_;
    X ^= X >> 12;
    X ^= X << 25;
    X ^= X >> 27;
    S_ = X;
    return X * 0x2545F4914F6CDD1DULL;
  }
  std::uint32_t nextBounded(std::uint32_t Bound) {
    return (std::uint32_t)(next() % Bound);
  }

private:
  std::uint64_t S_;
};

std::uint8_t posXor(std::uint64_t Seed, unsigned I) {
  return (std::uint8_t)((Seed >> ((I & 3u) * 8u)) ^ (I * 0x9Eu) ^ 0xA5u);
}

std::vector<unsigned> fisherYates(unsigned N, std::uint64_t Seed) {
  std::vector<unsigned> Perm(N);
  for (unsigned I = 0; I < N; ++I)
    Perm[I] = I;
  XorShift64 Rng(Seed);
  for (unsigned I = N; I > 1; --I) {
    unsigned J = Rng.nextBounded(I);
    std::swap(Perm[I - 1], Perm[J]);
  }
  return Perm;
}

std::uint64_t arrSeedFor(std::uint64_t Seed, unsigned Idx, unsigned Size) {
  return Seed ^ (0xD1B54A32D192ED03ULL * (Idx + 1)) ^
         (std::uint64_t)Size * 0x9E3779B97F4A7C15ULL;
}

std::vector<std::uint8_t> unscramble(const std::vector<std::uint8_t> &Sc,
                                     std::uint64_t Seed) {
  const unsigned N = (unsigned)Sc.size();
  auto Perm = fisherYates(N, Seed);
  std::vector<std::uint8_t> Out(N);
  for (unsigned I = 0; I < N; ++I)
    Out[Perm[I]] = (std::uint8_t)(Sc[I] ^ posXor(Seed, I));
  return Out;
}

std::optional<std::string> readFile(llvm::StringRef Path) {
  auto MB = llvm::MemoryBuffer::getFile(Path);
  if (!MB)
    return std::nullopt;
  return MB.get()->getBuffer().str();
}

/// Parse `{ 0xabu, 0xcdu, ... }` byte lists (optional `u` suffix).
bool parseBraceBytes(llvm::StringRef Body, std::vector<std::uint8_t> &Out) {
  Out.clear();
  size_t I = 0;
  while (I < Body.size()) {
    while (I < Body.size() &&
           (std::isspace((unsigned char)Body[I]) || Body[I] == ','))
      ++I;
    if (I >= Body.size())
      break;
    if (Body[I] == '}')
      break;
    if (I + 2 < Body.size() && Body[I] == '0' &&
        (Body[I + 1] == 'x' || Body[I + 1] == 'X')) {
      unsigned Val = 0;
      size_t J = I + 2;
      while (J < Body.size() && std::isxdigit((unsigned char)Body[J])) {
        Val <<= 4;
        char C = Body[J];
        Val |= (C >= 'a')   ? (C - 'a' + 10)
               : (C >= 'A') ? (C - 'A' + 10)
                            : (C - '0');
        ++J;
      }
      if (J < Body.size() && (Body[J] == 'u' || Body[J] == 'U'))
        ++J;
      Out.push_back((std::uint8_t)Val);
      I = J;
      continue;
    }
    // Decimal?
    if (std::isdigit((unsigned char)Body[I])) {
      unsigned Val = 0;
      while (I < Body.size() && std::isdigit((unsigned char)Body[I])) {
        Val = Val * 10u + (unsigned)(Body[I] - '0');
        ++I;
      }
      if (I < Body.size() && (Body[I] == 'u' || Body[I] == 'U'))
        ++I;
      Out.push_back((std::uint8_t)Val);
      continue;
    }
    return false;
  }
  return !Out.empty();
}

/// Decode a C string-literal payload (narrow escapes); caller adds trailing NUL
/// for `unsigned char x[] = "…"` semantics when Requested.
bool parseCStringBytes(llvm::StringRef Lit, std::vector<std::uint8_t> &Out) {
  Out.clear();
  for (size_t I = 0; I < Lit.size();) {
    if (Lit[I] != '\\') {
      Out.push_back((std::uint8_t)Lit[I++]);
      continue;
    }
    ++I;
    if (I >= Lit.size())
      return false;
    char C = Lit[I++];
    switch (C) {
    case 'n':
      Out.push_back('\n');
      break;
    case 't':
      Out.push_back('\t');
      break;
    case 'r':
      Out.push_back('\r');
      break;
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7': {
      unsigned V = (unsigned)(C - '0');
      for (int K = 0; K < 2 && I < Lit.size() && Lit[I] >= '0' && Lit[I] <= '7';
           ++K)
        V = (V << 3) | (unsigned)(Lit[I++] - '0');
      Out.push_back((std::uint8_t)V);
      break;
    }
    case 'x': {
      if (I >= Lit.size() || !std::isxdigit((unsigned char)Lit[I]))
        return false;
      unsigned V = 0;
      for (int K = 0; K < 2 && I < Lit.size() &&
                      std::isxdigit((unsigned char)Lit[I]);
           ++K) {
        char H = Lit[I++];
        V <<= 4;
        V |= (H >= 'a')   ? (H - 'a' + 10)
             : (H >= 'A') ? (H - 'A' + 10)
                          : (H - '0');
      }
      Out.push_back((std::uint8_t)V);
      break;
    }
    default:
      Out.push_back((std::uint8_t)C);
      break;
    }
  }
  return true;
}

void harvestFromText(llvm::StringRef Text, std::vector<GoldenBuffer> &Out) {
  // Match: [static] [const] (unsigned )?char Name[] = …
  size_t Pos = 0;
  while (Pos < Text.size()) {
    size_t Decl = Text.find("char ", Pos);
    if (Decl == llvm::StringRef::npos)
      break;
    // Walk back for "unsigned " / "signed "
    size_t Start = Decl;
    if (Start >= 9 && Text.substr(Start - 9, 9) == "unsigned ")
      Start -= 9;
    else if (Start >= 7 && Text.substr(Start - 7, 7) == "signed ")
      Start -= 7;

    size_t NameBegin = Decl + 5;
    while (NameBegin < Text.size() &&
           std::isspace((unsigned char)Text[NameBegin]))
      ++NameBegin;
    size_t NameEnd = NameBegin;
    while (NameEnd < Text.size() &&
           (std::isalnum((unsigned char)Text[NameEnd]) || Text[NameEnd] == '_'))
      ++NameEnd;
    if (NameBegin == NameEnd) {
      Pos = Decl + 5;
      continue;
    }
    std::string Name = Text.substr(NameBegin, NameEnd - NameBegin).str();
    if (isFeVArtifactName(Name)) {
      Pos = NameEnd;
      continue;
    }

    size_t Eq = Text.find('=', NameEnd);
    if (Eq == llvm::StringRef::npos || Eq > NameEnd + 64) {
      Pos = NameEnd;
      continue;
    }
    // Skip if this looks like a function param / unrelated.
    llvm::StringRef Between = Text.substr(NameEnd, Eq - NameEnd);
    if (!Between.contains('[')) {
      Pos = NameEnd;
      continue;
    }

    size_t Init = Eq + 1;
    while (Init < Text.size() && std::isspace((unsigned char)Text[Init]))
      ++Init;
    if (Init >= Text.size())
      break;

    std::vector<std::uint8_t> Bytes;
    if (Text[Init] == '{') {
      size_t Close = Text.find('}', Init);
      if (Close == llvm::StringRef::npos) {
        Pos = Init + 1;
        continue;
      }
      if (!parseBraceBytes(Text.substr(Init + 1, Close - Init - 1), Bytes) ||
          Bytes.size() < 8) {
        Pos = Close + 1;
        continue;
      }
    } else if (Text[Init] == '"') {
      // Adjacent string literals.
      size_t Cur = Init;
      std::vector<std::uint8_t> Acc;
      while (Cur < Text.size() && Text[Cur] == '"') {
        size_t EndLit = Cur + 1;
        while (EndLit < Text.size()) {
          if (Text[EndLit] == '\\' && EndLit + 1 < Text.size()) {
            EndLit += 2;
            continue;
          }
          if (Text[EndLit] == '"')
            break;
          ++EndLit;
        }
        if (EndLit >= Text.size())
          break;
        std::vector<std::uint8_t> Part;
        if (!parseCStringBytes(Text.substr(Cur + 1, EndLit - Cur - 1), Part)) {
          Acc.clear();
          break;
        }
        Acc.insert(Acc.end(), Part.begin(), Part.end());
        Cur = EndLit + 1;
        while (Cur < Text.size() &&
               (std::isspace((unsigned char)Text[Cur]) || Text[Cur] == '\n'))
          ++Cur;
      }
      if (Acc.empty()) {
        Pos = Init + 1;
        continue;
      }
      Acc.push_back(0); // C array-from-string trailing NUL
      Bytes = std::move(Acc);
      if (Bytes.size() < 8) {
        Pos = Cur;
        continue;
      }
    } else {
      Pos = Init + 1;
      continue;
    }

    GoldenBuffer G;
    G.Name = Name;
    G.Bytes = std::move(Bytes);
    G.Fnv = fnv1a32(G.Bytes.data(), G.Bytes.size());
    Out.push_back(std::move(G));
    Pos = Init + 1;
  }
}

std::vector<std::vector<std::uint8_t>>
extractConstArraysOfSize(llvm::StringRef Text, size_t Want) {
  std::vector<std::vector<std::uint8_t>> Found;
  size_t Pos = 0;
  while (Pos < Text.size()) {
    size_t Brace = Text.find("= {", Pos);
    if (Brace == llvm::StringRef::npos)
      Brace = Text.find("={", Pos);
    if (Brace == llvm::StringRef::npos)
      break;
    size_t Open = Text.find('{', Brace);
    size_t Close = Text.find('}', Open);
    if (Open == llvm::StringRef::npos || Close == llvm::StringRef::npos) {
      Pos = Brace + 2;
      continue;
    }
    std::vector<std::uint8_t> Bytes;
    if (parseBraceBytes(Text.substr(Open + 1, Close - Open - 1), Bytes) &&
        Bytes.size() == Want)
      Found.push_back(std::move(Bytes));
    Pos = Close + 1;
  }
  return Found;
}

bool tryRestoreFromCandidates(
    const GoldenBuffer &G, const std::vector<std::vector<std::uint8_t>> &Cands,
    std::uint64_t Seed) {
  const auto Key = deriveChaChaKey(Seed);
  // encrypt-buffers starts nonces at index 1000; scramble ArrSeed idx 0..7.
  for (const auto &Cand : Cands) {
    // Already plain?
    if (Cand == G.Bytes)
      return true;
    // Scramble only (indices 0..7).
    for (unsigned Si = 0; Si < 8; ++Si) {
      const std::uint64_t AS = arrSeedFor(Seed, Si, (unsigned)G.Bytes.size());
      if (unscramble(Cand, AS) == G.Bytes)
        return true;
    }
    // Encrypt only (plain CT) — nonce indices around 1000.
    for (unsigned Ni = 1000; Ni < 1008; ++Ni) {
      auto Nonce = deriveNonce(Seed, Ni);
      std::vector<std::uint8_t> Dec(Cand.size());
      chacha20Xor(Dec.data(), Cand.data(), Cand.size(), Key.data(),
                  Nonce.data());
      if (Dec == G.Bytes)
        return true;
      // Encrypt(scramble(plain)): decrypt then unscramble.
      for (unsigned Si = 0; Si < 8; ++Si) {
        const std::uint64_t AS = arrSeedFor(Seed, Si, (unsigned)G.Bytes.size());
        if (unscramble(Dec, AS) == G.Bytes)
          return true;
      }
    }
  }
  return false;
}

bool checkHelpersNotFlattened(llvm::StringRef Text, std::string &Detail) {
  // Unscramble runtime carries this comment; it must stay as straight-line code.
  const char *Marker = "Rebuild the same Fisher";
  size_t Pos = 0;
  while ((Pos = Text.find(Marker, Pos)) != llvm::StringRef::npos) {
    // Function body: from marker back to '{' of function, forward to matching.
    size_t FnBrace = Text.rfind('{', Pos);
    if (FnBrace == llvm::StringRef::npos) {
      Pos += 8;
      continue;
    }
    // Walk to end of function (naive brace count from FnBrace).
    int Depth = 0;
    size_t End = FnBrace;
    for (; End < Text.size(); ++End) {
      if (Text[End] == '{')
        ++Depth;
      else if (Text[End] == '}') {
        --Depth;
        if (Depth == 0) {
          ++End;
          break;
        }
      }
    }
    llvm::StringRef Body = Text.substr(FnBrace, End - FnBrace);
    if (Body.contains("goto _fev_L0") || Body.contains("László-style CFF") ||
        Body.contains("Laszlo-style CFF")) {
      Detail = "scramble restore helper was control-flow-flattened "
               "(breaks buffer integrity)";
      return false;
    }
    Pos = End;
  }
  return true;
}

bool sourceLooksHostRunnable(llvm::StringRef Text) {
  return !Text.contains("windows.h") && !Text.contains("Windows.h") &&
         !Text.contains("DllMain") && Text.contains("main");
}

bool compileAndRunProbe(llvm::StringRef StepPath, std::string &Detail) {
  llvm::SmallString<256> BinPath(StepPath);
  BinPath += ".fev_probe";
  std::string Err;
  // Prefer host cc.
  llvm::ErrorOr<std::string> CC = llvm::sys::findProgramByName("cc");
  if (!CC)
    CC = llvm::sys::findProgramByName("gcc");
  if (!CC)
    CC = llvm::sys::findProgramByName("clang");
  if (!CC) {
    Detail = "no host C compiler (cc/gcc/clang) for interpass execute";
    return false;
  }
  std::vector<llvm::StringRef> Args = {*CC, "-std=c11", "-O0", "-o", BinPath,
                                       StepPath};
  if (int RC = llvm::sys::ExecuteAndWait(*CC, Args, std::nullopt, {}, 0, 0,
                                         &Err)) {
    Detail = "interpass compile failed (rc=" + std::to_string(RC) + "): " + Err;
    return false;
  }
  std::vector<llvm::StringRef> RunArgs = {BinPath};
  int RunRC =
      llvm::sys::ExecuteAndWait(BinPath, RunArgs, std::nullopt, {}, 0, 0, &Err);
  llvm::sys::fs::remove(BinPath);
  if (RunRC != 0) {
    Detail = "interpass execute exit " + std::to_string(RunRC) +
             " — restored buffer check failed after this pass";
    return false;
  }
  return true;
}

bool report(ValidateMode Mode, bool AlwaysFail, bool Ok,
            llvm::StringRef What) {
  if (Ok) {
    logInfo() << "interpass ok: " << What;
    return true;
  }
  if (AlwaysFail || Mode == ValidateMode::Strict) {
    logError() << "interpass failed: " << What;
    return false;
  }
  if (Mode == ValidateMode::Off)
    return true;
  logWarn() << "interpass failed: " << What;
  return true;
}

} // namespace

bool harvestGoldenBuffers(llvm::StringRef SourcePath,
                          std::vector<GoldenBuffer> &Out) {
  Out.clear();
  auto Text = readFile(SourcePath);
  if (!Text) {
    logError() << "interpass: cannot read '" << SourcePath << "'";
    return false;
  }
  harvestFromText(*Text, Out);
  // De-dup by name (keep first).
  std::vector<GoldenBuffer> Unique;
  for (auto &G : Out) {
    bool Seen = false;
    for (const auto &U : Unique) {
      if (U.Name == G.Name) {
        Seen = true;
        break;
      }
    }
    if (!Seen)
      Unique.push_back(std::move(G));
  }
  Out = std::move(Unique);
  if (Out.empty()) {
    logWarn() << "interpass: no ≥8-byte char arrays harvested from "
              << SourcePath;
    return true;
  }
  for (const auto &G : Out)
    logInfo() << "interpass golden: " << G.Name << " (" << G.Bytes.size()
              << "B, fnv="
              << llvm::format("0x%08x", G.Fnv) << ")";
  return true;
}

bool interpassValidateAfterPass(llvm::StringRef StepPath,
                                llvm::StringRef PassName,
                                const std::vector<GoldenBuffer> &Goldens,
                                std::uint64_t Seed, ValidateMode Mode,
                                bool TryExecute, bool AlwaysFail) {
  if (Goldens.empty())
    return true;

  auto Text = readFile(StepPath);
  if (!Text) {
    return report(Mode, AlwaysFail, false,
                  ("cannot read step output after " + PassName).str());
  }

  std::string Detail;
  if (!checkHelpersNotFlattened(*Text, Detail)) {
    return report(Mode, AlwaysFail, false, (PassName + ": " + Detail).str());
  }

  for (const auto &G : Goldens) {
    auto Cands = extractConstArraysOfSize(*Text, G.Bytes.size());
    // After scramble/encrypt the plain init is gone; CT/scramble remain as
    // const arrays of the same length. Before those passes, plain is present.
    if (Cands.empty()) {
      // Buffer may live only as zero-filled BSS + restore — still OK if we
      // cannot find tables yet (pass did not touch buffers). Require either
      // the identifier still appears or we are past a rename.
      if (Text->find(G.Name) == std::string::npos &&
          Text->find("fev scramble") == std::string::npos &&
          Text->find("fev encrypt-buffers") == std::string::npos &&
          Text->find("_fev_sc_") == std::string::npos &&
          Text->find("_fev_ct_") == std::string::npos) {
        std::string Msg;
        llvm::raw_string_ostream OS(Msg);
        OS << PassName << ": lost track of buffer '" << G.Name << "' ("
           << G.Bytes.size() << "B)";
        return report(Mode, AlwaysFail, false, Msg);
      }
      // No const payload of this size — could be only BSS dest. If scramble
      // hasn't run, plain init should have been found. Fail soft only when
      // buffer passes already ran.
      if (Text->find("_fev_sc_") != std::string::npos ||
          Text->find("_fev_ct_") != std::string::npos ||
          Text->find("fev scramble") != std::string::npos ||
          Text->find("fev encrypt-buffers") != std::string::npos) {
        std::string Msg;
        llvm::raw_string_ostream OS(Msg);
        OS << PassName << ": no " << G.Bytes.size()
           << "B const array to restore for '" << G.Name << "'";
        return report(Mode, AlwaysFail, false, Msg);
      }
      continue;
    }
    if (!tryRestoreFromCandidates(G, Cands, Seed)) {
      std::string Msg;
      llvm::raw_string_ostream OS(Msg);
      OS << PassName << ": cannot restore '" << G.Name << "' (fnv="
         << llvm::format("0x%08x", G.Fnv)
         << ") from step output — pass likely broke buffer encoding";
      return report(Mode, AlwaysFail, false, Msg);
    }
  }

  if (TryExecute && sourceLooksHostRunnable(*Text)) {
    if (!compileAndRunProbe(StepPath, Detail))
      return report(Mode, AlwaysFail, false, (PassName + ": " + Detail).str());
  }

  std::string OkMsg;
  llvm::raw_string_ostream OS(OkMsg);
  OS << PassName << " (" << Goldens.size() << " buffer(s))";
  return report(Mode, AlwaysFail, true, OkMsg);
}

} // namespace fev
