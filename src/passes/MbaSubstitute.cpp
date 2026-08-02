#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

double unitFloat(std::uint64_t Seed, unsigned Salt) {
  std::uint64_t X = Seed ^ (0x9E3779B97F4A7C15ULL * (Salt + 1));
  X ^= X >> 30;
  X *= 0xBF58476D1CE4E5B9ULL;
  X ^= X >> 27;
  return (double)(X >> 11) / (double)(1ULL << 53);
}

/// Prefer a writable main-file spelling; for macro-expanded integer literals
/// fall back to a numeric token (MEM_COMMIT etc. expand in system headers).
std::string operandText(const Expr *E, const SourceManager &SM,
                        const LangOptions &LangOpts) {
  if (const auto *Lit = dyn_cast<IntegerLiteral>(E)) {
    SourceLocation Spell = SM.getSpellingLoc(Lit->getLocation());
    if (Spell.isValid() && SM.isInMainFile(Spell) && !Spell.isMacroID()) {
      std::string T = fev::stmtText(Lit, SM, LangOpts);
      if (!T.empty())
        return T;
    }
    llvm::SmallString<32> Buf;
    Lit->getValue().toString(Buf, /*Radix=*/10, /*Signed=*/true);
    return std::string(Buf);
  }
  SourceLocation Begin = SM.getExpansionLoc(E->getBeginLoc());
  if (Begin.isValid() && SM.isInMainFile(Begin)) {
    std::string T = fev::stmtText(E, SM, LangOpts);
    if (!T.empty())
      return T;
  }
  return {};
}

bool containsNestedBinaryOp(const Stmt *S) {
  if (!S)
    return false;
  for (const Stmt *C : S->children()) {
    if (!C)
      continue;
    if (isa<BinaryOperator>(C))
      return true;
    if (containsNestedBinaryOp(C))
      return true;
  }
  return false;
}

struct MbaEdit {
  unsigned Begin = 0;
  unsigned End = 0;
  CharSourceRange Range;
  std::string Text;
};

class MbaSubstitutePass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "mba-substitute"; }

  llvm::StringRef description() const override {
    return "Rewrite leaf +, -, ^, |, & into MBA identities "
           "(--mba-density, --seed); skips nested/overlapping ops and fev_* "
           "helpers";
  }

  bool run(fev::PassContext &Ctx) override {
    unsigned Salt = 0;
    std::vector<MbaEdit> Edits;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(ASTContext &AST, const LangOptions &LO, std::uint64_t Seed,
              double Density, unsigned &Salt, std::vector<MbaEdit> &Edits)
          : AST_(AST), LangOpts_(LO), Seed_(Seed), Density_(Density),
            Salt_(Salt), Edits_(Edits) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *BO = Result.Nodes.getNodeAs<BinaryOperator>("bo");
        if (!BO || !BO->getType()->isIntegerType())
          return;

        SourceManager &SM = *Result.SourceManager;
        const SourceLocation ExpOp =
            SM.getExpansionLoc(BO->getOperatorLoc());
        if (ExpOp.isInvalid() || !SM.isInMainFile(ExpOp))
          return;

        // Do not MBA-rewrite FEV-injected ChaCha / opaque / flatten helpers.
        if (const auto *FD = BO->getBeginLoc().isValid()
                                 ? findEnclosingFunction(BO)
                                 : nullptr) {
          StringRef N = FD->getName();
          if (N.starts_with("fev_") || N.starts_with("_fev_"))
            return;
        }

        // Only true leaves: no nested binary ops under either operand.
        // Prevents overlapping rewrites like rewriting both `off+i` and
        // `in[off+i] ^ block[i]` (which corrupts the source text).
        if (containsNestedBinaryOp(BO->getLHS()) ||
            containsNestedBinaryOp(BO->getRHS()))
          return;

        const Expr *LHS = BO->getLHS()->IgnoreParenImpCasts();
        const Expr *RHS = BO->getRHS()->IgnoreParenImpCasts();
        if (isa<BinaryOperator>(LHS) || isa<BinaryOperator>(RHS))
          return;

        if (unitFloat(Seed_, Salt_++) > Density_)
          return;

        const std::string A = operandText(LHS, SM, LangOpts_);
        const std::string B = operandText(RHS, SM, LangOpts_);
        if (A.empty() || B.empty())
          return;

        std::string Repl;
        switch (BO->getOpcode()) {
        case BO_Add:
          Repl = "((" + A + ") ^ (" + B + ")) + (2 * ((" + A + ") & (" + B +
                 ")))";
          break;
        case BO_Sub:
          Repl = "((" + A + ") ^ (" + B + ")) - (2 * ((~(" + A + ")) & (" + B +
                 ")))";
          break;
        case BO_Xor:
          Repl = "((" + A + ") | (" + B + ")) - ((" + A + ") & (" + B + "))";
          break;
        case BO_Or:
          Repl = "((" + A + ") ^ (" + B + ")) + ((" + A + ") & (" + B + "))";
          break;
        case BO_And:
          Repl = "((" + A + ") + (" + B + ")) - ((" + A + ") | (" + B + "))";
          break;
        default:
          return;
        }

        CharSourceRange Range = Lexer::makeFileCharRange(
            CharSourceRange::getTokenRange(BO->getSourceRange()), SM,
            LangOpts_);
        if (Range.isInvalid()) {
          Range = CharSourceRange::getTokenRange(
              SM.getExpansionLoc(BO->getBeginLoc()),
              SM.getExpansionLoc(BO->getEndLoc()));
        }
        if (Range.isInvalid())
          return;

        const unsigned Begin = SM.getFileOffset(Range.getBegin());
        std::string Old = Lexer::getSourceText(Range, SM, LangOpts_).str();
        if (Old.empty())
          return;
        const unsigned End = Begin + (unsigned)Old.size();

        Edits_.push_back(MbaEdit{Begin, End, Range, std::move(Repl)});
      }

    private:
      const FunctionDecl *findEnclosingFunction(const BinaryOperator *BO) {
        std::vector<DynTypedNode> Stack;
        {
          const auto Parents = AST_.getParents(*BO);
          for (const DynTypedNode &N : Parents)
            Stack.push_back(N);
        }
        for (int Depth = 0; Depth < 64 && !Stack.empty(); ++Depth) {
          std::vector<DynTypedNode> Next;
          for (const DynTypedNode &N : Stack) {
            if (const auto *FD = N.get<FunctionDecl>())
              return FD;
            if (const auto *S = N.get<Stmt>()) {
              for (const DynTypedNode &P : AST_.getParents(*S))
                Next.push_back(P);
            } else if (const auto *D = N.get<Decl>()) {
              for (const DynTypedNode &P : AST_.getParents(*D))
                Next.push_back(P);
            }
          }
          Stack.swap(Next);
        }
        return nullptr;
      }

      ASTContext &AST_;
      const LangOptions &LangOpts_;
      std::uint64_t Seed_;
      double Density_;
      unsigned &Salt_;
      std::vector<MbaEdit> &Edits_;
    };

    Handler H(Ctx.AST, Ctx.AST.getLangOpts(), Ctx.Config.Seed,
              Ctx.Config.MbaDensity, Salt, Edits);
    MatchFinder Finder;
    Finder.addMatcher(
        binaryOperator(anyOf(hasOperatorName("+"), hasOperatorName("-"),
                             hasOperatorName("^"), hasOperatorName("|"),
                             hasOperatorName("&")))
            .bind("bo"),
        &H);
    Finder.matchAST(Ctx.AST);

    // Drop overlapping edits (keep earlier / smaller). Sort by begin asc,
    // then apply from the end so offsets stay stable.
    std::sort(Edits.begin(), Edits.end(),
              [](const MbaEdit &X, const MbaEdit &Y) {
                if (X.Begin != Y.Begin)
                  return X.Begin < Y.Begin;
                return (X.End - X.Begin) < (Y.End - Y.Begin);
              });
    std::vector<MbaEdit> Kept;
    for (const MbaEdit &E : Edits) {
      bool Overlaps = false;
      for (const MbaEdit &K : Kept) {
        if (E.Begin < K.End && K.Begin < E.End) {
          Overlaps = true;
          break;
        }
      }
      if (!Overlaps)
        Kept.push_back(E);
    }
    std::sort(Kept.begin(), Kept.end(),
              [](const MbaEdit &X, const MbaEdit &Y) {
                return X.Begin > Y.Begin;
              });
    for (const MbaEdit &E : Kept)
      (void)Ctx.Rewriter.ReplaceText(E.Range, E.Text);

    return true;
  }
};

FEV_REGISTER_PASS(MbaSubstitutePass);

} // namespace
