#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"
#include "fev/ByteArrayUtils.h"
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

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

/// Deterministic xorshift64* (matches scramble-arrays).
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

class ArraySplitPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "array-split"; }

  llvm::StringRef description() const override {
    return "Split large global/static byte arrays into smaller chunks "
           "(shuffled .rodata order; reassemble at main; --array-chunk, "
           "--array-split-min, --seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const unsigned Chunk = Ctx.Config.ArrayChunkSize
                               ? Ctx.Config.ArrayChunkSize
                               : 16u;
    const unsigned MinSize = Ctx.Config.ArraySplitMin
                                 ? Ctx.Config.ArraySplitMin
                                 : (Chunk * 2u);
    if (Chunk < 4) {
      fev::logError() << "array-split: --array-chunk must be >= 4";
      return false;
    }

    bool Edited = false;
    unsigned Next = 0;
    std::vector<std::string> EnsureCalls;
    bool NeedValidateRuntime = false;
    bool Failed = false;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO, std::uint64_t Seed,
              fev::ValidateMode VMode, unsigned Chunk, unsigned MinSize,
              unsigned &Next, bool &Edited, bool &NeedValidateRuntime,
              bool &Failed, std::vector<std::string> &Calls)
          : Rewriter_(R), LangOpts_(LO), Seed_(Seed), VMode_(VMode),
            Chunk_(Chunk), MinSize_(MinSize), Next_(Next), Edited_(Edited),
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
        // Already a split chunk (name_asN) from a prior invocation.
        {
          const size_t As = NameRef.rfind("_as");
          if (As != StringRef::npos && As + 3 < NameRef.size()) {
            StringRef Tail = NameRef.drop_front(As + 3);
            bool Digits = !Tail.empty();
            for (char C : Tail) {
              if (C < '0' || C > '9') {
                Digits = false;
                break;
              }
            }
            if (Digits)
              return;
          }
        }

        if (!fev::isByteOrientedArray(VD->getType()))
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(VD->getLocation(), SM))
          return;

        std::vector<std::uint8_t> Plain;
        if (!fev::collectVarInitBytes(VD->getInit(), Plain))
          return;
        if (Plain.size() < MinSize_)
          return;
        // Need at least two chunks to be a meaningful split.
        if (Plain.size() <= Chunk_)
          return;

        const unsigned Idx = Next_++;
        const std::uint64_t ArrSeed =
            Seed_ ^ (0xC2B2AE3D27D4EB4FULL * (Idx + 1)) ^
            (std::uint64_t)Plain.size() * 0x9E3779B97F4A7C15ULL;

        const unsigned N = (unsigned)Plain.size();
        const unsigned NumChunks = (N + Chunk_ - 1) / Chunk_;
        // Physical declaration order ≠ logical index order (breaks contiguous
        // .rodata signatures); join() still copies by logical index.
        auto DeclOrder = fisherYates(NumChunks, ArrSeed);

        // Rewrite-time join simulation (logical chunk order).
        {
          std::vector<std::uint8_t> RoundTrip(N);
          for (unsigned L = 0; L < NumChunks; ++L) {
            const unsigned Off = L * Chunk_;
            const unsigned Len = std::min(Chunk_, N - Off);
            std::copy(Plain.begin() + Off, Plain.begin() + Off + Len,
                      RoundTrip.begin() + Off);
          }
          const std::string BufLabel =
              "array-split " + VD->getNameAsString();
          if (!fev::validateRoundTrip(VMode_, BufLabel, Plain, RoundTrip)) {
            Failed_ = true;
            return;
          }
        }

        const std::uint32_t Tag =
            fev::fnv1a32(Plain.data(), Plain.size());
        const std::string Name = VD->getNameAsString();
        const std::string Ensure = "_fev_join_" + Name;

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

        // Skip if dict-bytes (or another prior rewriter) already transformed this
        // span in the same FEV invocation.
        {
          const std::string Cur = Rewriter_.getRewrittenText(Range);
          if (Cur.find("_fev_db_idx_") != std::string::npos ||
              Cur.find("_fev_dictbytes_") != std::string::npos ||
              Cur.find("dict-bytes:") != std::string::npos)
            return;
        }

        std::string Replacement;
        llvm::raw_string_ostream OS(Replacement);
        OS << "/* fev array-split: " << Name << " → " << NumChunks
           << "×≤" << Chunk_ << "B chunks (seed="
           << llvm::format("0x%llx", (unsigned long long)ArrSeed) << ", fnv="
           << llvm::format("0x%08x", Tag) << ") */\n";

        for (unsigned Ord = 0; Ord < NumChunks; ++Ord) {
          const unsigned L = DeclOrder[Ord];
          const unsigned Off = L * Chunk_;
          const unsigned Len = std::min(Chunk_, N - Off);
          std::vector<std::uint8_t> Piece(Plain.begin() + Off,
                                          Plain.begin() + Off + Len);
          OS << "static unsigned char " << Name << "_as" << L << "[" << Len
             << "] = " << formatBytes(Piece) << ";\n";
        }

        OS << "unsigned char " << Name << "[" << N << "];\n"
           << "static void " << Ensure << "(void) {\n"
           << "  static int ready;\n"
           << "  if (ready) return;\n";
        for (unsigned L = 0; L < NumChunks; ++L) {
          const unsigned Off = L * Chunk_;
          const unsigned Len = std::min(Chunk_, N - Off);
          OS << "  for (unsigned _i = 0; _i < " << Len << "u; ++_i)\n"
             << "    " << Name << "[" << Off << "u + _i] = " << Name << "_as"
             << L << "[_i];\n";
        }
        if (VMode_ != fev::ValidateMode::Off) {
          OS << fev::emitBufferIntegrityCheck(Name, N, Tag);
          NeedValidateRuntime_ = true;
        }
        OS << "  ready = 1;\n"
           << "}\n";

        if (Rewriter_.ReplaceText(Range, OS.str()))
          return;

        Calls_.push_back(Ensure + "();");
        Edited_ = true;
        fev::logDebug() << "array-split: " << Name << " (" << N << "B → "
                        << NumChunks << " chunks of ≤" << Chunk_ << "B)";
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
      std::uint64_t Seed_;
      fev::ValidateMode VMode_;
      unsigned Chunk_;
      unsigned MinSize_;
      unsigned &Next_;
      bool &Edited_;
      bool &NeedValidateRuntime_;
      bool &Failed_;
      std::vector<std::string> &Calls_;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts(), Ctx.Config.Seed,
              Ctx.Config.Validate, Chunk, MinSize, Next, Edited,
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
      fev::logInfo() << "rewrote 0 array(s) (chunk=" << Chunk
                     << ", min=" << MinSize << ")";
      return true;
    }

    if (NeedValidateRuntime) {
      SourceManager &SM = Ctx.Rewriter.getSourceMgr();
      StringRef Buf = SM.getBufferData(SM.getMainFileID());
      if (Buf.find("FEV_VALIDATE_RUNTIME") == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, fev::buildValidateRuntimeC());
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

    fev::logInfo() << "array-split: rewrote " << EnsureCalls.size()
                   << " array(s) (chunk=" << Chunk << ", min=" << MinSize
                   << ")";
    return true;
  }
};

FEV_REGISTER_PASS(ArraySplitPass);

} // namespace
