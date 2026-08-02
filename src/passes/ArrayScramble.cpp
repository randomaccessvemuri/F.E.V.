#include "fev/Pass.h"
#include "fev/RewriteUtils.h"
#include "fev/ByteArrayUtils.h"
#include "fev/Log.h"
#include "fev/Validate.h"
#include "fev/ChaCha20.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdint>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

/// Deterministic xorshift64* — same sequence in the pass and the injected C.
class XorShift64 {
public:
  explicit XorShift64(std::uint64_t Seed) : S_(Seed ? Seed : 0x9E3779B97F4A7C15ULL) {}

  std::uint64_t next() {
    std::uint64_t X = S_;
    X ^= X >> 12;
    X ^= X << 25;
    X ^= X >> 27;
    S_ = X;
    return X * 0x2545F4914F6CDD1DULL;
  }

  /// Uniform in [0, Bound) (Bound > 0).
  std::uint32_t nextBounded(std::uint32_t Bound) {
    return (std::uint32_t)(next() % Bound);
  }

private:
  std::uint64_t S_;
};

std::uint8_t posXor(std::uint64_t Seed, unsigned I) {
  return (std::uint8_t)((Seed >> ((I & 3u) * 8u)) ^ (I * 0x9Eu) ^ 0xA5u);
}

std::string formatBytes(const std::vector<std::uint8_t> &Bytes) {
  std::string Out = "{";
  llvm::raw_string_ostream OS(Out);
  for (size_t I = 0; I < Bytes.size(); ++I) {
    if (I)
      OS << ", ";
    if (I && (I % 12) == 0)
      OS << "\n  ";
    OS << llvm::format("0x%02xu", Bytes[I]);
  }
  OS << "}";
  return OS.str();
}

/// Fisher–Yates: perm[i] = source index for scrambled slot i.
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

std::string scrambleRuntimeC() {
  return R"C(/* FEV_SCRAMBLE_RUNTIME */
#include <stdint.h>
static uint64_t _fev_xs64(uint64_t *s) {
  uint64_t x = *s;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *s = x;
  return x * 0x2545F4914F6CDD1DULL;
}
static void _fev_unscramble(uint8_t *out, const uint8_t *sc, unsigned n,
                            uint64_t seed) {
  /* Rebuild the same Fisher–Yates perm used at rewrite time (no table in binary). */
  unsigned *perm = (unsigned *)__builtin_alloca(n * sizeof(unsigned));
  for (unsigned i = 0; i < n; ++i)
    perm[i] = i;
  uint64_t st = seed ? seed : 0x9E3779B97F4A7C15ULL;
  for (unsigned i = n; i > 1; --i) {
    unsigned j = (unsigned)(_fev_xs64(&st) % i);
    unsigned t = perm[i - 1];
    perm[i - 1] = perm[j];
    perm[j] = t;
  }
  for (unsigned i = 0; i < n; ++i) {
    uint8_t x = (uint8_t)((seed >> ((i & 3u) * 8u)) ^ (i * 0x9Eu) ^ 0xA5u);
    out[perm[i]] = (uint8_t)(sc[i] ^ x);
  }
}
)C";
}

class ScrambleArraysPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "scramble-arrays"; }

  llvm::StringRef description() const override {
    return "Permute+XOR global/static byte-array initializers (anti-signature); "
           "lazy unscramble at main (--seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    bool Edited = false;
    unsigned Next = 0;
    std::vector<std::string> EnsureCalls;
    bool NeedRuntime = false;
    bool NeedValidateRuntime = false;
    bool Failed = false;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO, std::uint64_t Seed,
              fev::ValidateMode VMode, unsigned &Next, bool &Edited,
              bool &NeedRuntime, bool &NeedValidateRuntime, bool &Failed,
              std::vector<std::string> &Calls)
          : Rewriter_(R), LangOpts_(LO), Seed_(Seed), VMode_(VMode),
            Next_(Next), Edited_(Edited), NeedRuntime_(NeedRuntime),
            NeedValidateRuntime_(NeedValidateRuntime), Failed_(Failed),
            Calls_(Calls) {}

      void run(const MatchFinder::MatchResult &Result) override {
        if (Failed_)
          return;
        const auto *VD = Result.Nodes.getNodeAs<VarDecl>("buf");
        if (!VD || !VD->hasInit() || VD->getName().empty())
          return;
        if (VD->isLocalVarDecl())
          return;

        StringRef NameRef = VD->getName();
        if (fev::isFeVArtifactName(NameRef))
          return;

        if (!fev::isByteOrientedArray(VD->getType()))
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(VD->getLocation(), SM))
          return;

        std::vector<std::uint8_t> Plain;
        if (!fev::collectVarInitBytes(VD->getInit(), Plain))
          return;
        // Tiny arrays aren't useful signature targets; skip noise.
        if (Plain.size() < 8)
          return;

        SourceLocation Begin = VD->getBeginLoc();
        SourceLocation End = VD->getEndLoc();
        SourceLocation AfterSemi = Lexer::findLocationAfterToken(
            End, tok::semi, SM, LangOpts_, false);
        CharSourceRange Range;
        if (AfterSemi.isValid())
          Range = CharSourceRange::getCharRange(Begin, AfterSemi);
        else
          Range = CharSourceRange::getTokenRange(Begin, End);
        if (Range.isInvalid())
          return;

        // Skip if an earlier pass (e.g. dict-bytes) already rewrote this span
        // within the same FEV invocation (shared Rewriter/AST).
        {
          const std::string Cur = Rewriter_.getRewrittenText(Range);
          if (Cur.find("_fev_db_idx_") != std::string::npos ||
              Cur.find("_fev_dictbytes_") != std::string::npos ||
              Cur.find("dict-bytes:") != std::string::npos)
            return;
        }

        const unsigned Idx = Next_++;
        const std::uint64_t ArrSeed =
            Seed_ ^ (0xD1B54A32D192ED03ULL * (Idx + 1)) ^
            (std::uint64_t)Plain.size() * 0x9E3779B97F4A7C15ULL;

        auto Perm = fisherYates((unsigned)Plain.size(), ArrSeed);
        std::vector<std::uint8_t> Scrambled(Plain.size());
        for (unsigned I = 0; I < Plain.size(); ++I)
          Scrambled[I] =
              (std::uint8_t)(Plain[Perm[I]] ^ posXor(ArrSeed, I));

        // Rewrite-time unscramble (same as injected runtime).
        std::vector<std::uint8_t> RoundTrip(Plain.size());
        for (unsigned I = 0; I < Plain.size(); ++I)
          RoundTrip[Perm[I]] =
              (std::uint8_t)(Scrambled[I] ^ posXor(ArrSeed, I));
        const std::string BufLabel =
            "scramble-arrays " + VD->getNameAsString();
        if (!fev::validateRoundTrip(VMode_, BufLabel, Plain, RoundTrip)) {
          Failed_ = true;
          return;
        }

        const std::uint32_t Tag =
            fev::fnv1a32(Plain.data(), Plain.size());
        const std::string Name = VD->getNameAsString();
        const std::string ScName = "_fev_sc_" + Name;
        const std::string Ensure = "_fev_unscramble_" + Name;

        std::string Replacement;
        llvm::raw_string_ostream OS(Replacement);
        OS << "/* fev scramble-arrays: " << Name << " (perm+xor, seed="
           << llvm::format("0x%llx", (unsigned long long)ArrSeed) << ", fnv="
           << llvm::format("0x%08x", Tag) << ") */\n"
           << "static const unsigned char " << ScName << "[" << Plain.size()
           << "] = " << formatBytes(Scrambled) << ";\n"
           << "unsigned char " << Name << "[" << Plain.size() << "];\n"
           << "static void " << Ensure << "(void) {\n"
           << "  static int ready;\n"
           << "  if (!ready) {\n"
           << "    _fev_unscramble(" << Name << ", " << ScName << ", "
           << Plain.size() << "u, "
           << llvm::format("0x%llxull", (unsigned long long)ArrSeed) << ");\n";
        if (VMode_ != fev::ValidateMode::Off) {
          OS << fev::emitBufferIntegrityCheck(Name, (unsigned)Plain.size(),
                                              Tag);
          NeedValidateRuntime_ = true;
        }
        OS << "    ready = 1;\n"
           << "  }\n"
           << "}\n";

        if (Rewriter_.ReplaceText(Range, OS.str()))
          return;

        Calls_.push_back(Ensure + "();");
        Edited_ = true;
        NeedRuntime_ = true;
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
      std::uint64_t Seed_;
      fev::ValidateMode VMode_;
      unsigned &Next_;
      bool &Edited_;
      bool &NeedRuntime_;
      bool &NeedValidateRuntime_;
      bool &Failed_;
      std::vector<std::string> &Calls_;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts(), Ctx.Config.Seed,
              Ctx.Config.Validate, Next, Edited, NeedRuntime,
              NeedValidateRuntime, Failed, EnsureCalls);
    MatchFinder Finder;
    Finder.addMatcher(varDecl(hasInitializer(expr()),
                              unless(isExpansionInSystemHeader()),
                              unless(hasLocalStorage()))
                          .bind("buf"),
                      &H);
    Finder.matchAST(Ctx.AST);

    if (Failed)
      return false;
    if (!Edited) {
      fev::logInfo() << "rewrote 0 array(s)";
      return true;
    }

    if (NeedRuntime || NeedValidateRuntime) {
      SourceManager &SM = Ctx.Rewriter.getSourceMgr();
      StringRef Buf = SM.getBufferData(SM.getMainFileID());
      if (NeedValidateRuntime &&
          Buf.find("FEV_VALIDATE_RUNTIME") == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, fev::buildValidateRuntimeC());
      if (NeedRuntime && Buf.find("FEV_SCRAMBLE_RUNTIME") == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, scrambleRuntimeC());
    }

    class MainHandler : public MatchFinder::MatchCallback {
    public:
      MainHandler(Rewriter &R, std::vector<std::string> InCalls)
          : Rewriter_(R), Calls_(std::move(InCalls)) {}
      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("mainfn");
        if (!Fn || !Fn->hasBody())
          return;
        auto *Body = dyn_cast<CompoundStmt>(Fn->getBody());
        if (!Body)
          return;
        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Body->getLBracLoc(), SM))
          return;
        SourceLocation AfterL = Lexer::getLocForEndOfToken(
            Body->getLBracLoc(), 0, SM, Result.Context->getLangOpts());
        if (AfterL.isInvalid())
          return;
        std::string Insert = "\n";
        for (const std::string &C : Calls_)
          Insert += "  " + C + "\n";
        Rewriter_.InsertText(AfterL, Insert, true, false);
      }

    private:
      Rewriter &Rewriter_;
      std::vector<std::string> Calls_;
    };

    MainHandler MH(Ctx.Rewriter, EnsureCalls);
    MatchFinder MF;
    MF.addMatcher(
        functionDecl(isDefinition(), hasName("main")).bind("mainfn"), &MH);
    MF.matchAST(Ctx.AST);
    fev::logInfo() << "rewrote " << EnsureCalls.size() << " array(s)";
    return true;
  }
};

FEV_REGISTER_PASS(ScrambleArraysPass);

} // namespace
