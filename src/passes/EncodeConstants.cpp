#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

std::string encodeInt(std::int64_t Value, std::uint64_t Seed, unsigned Salt) {
  const std::uint32_t K =
      (std::uint32_t)(Seed ^ (0x9E3779B9u * (Salt + 1))) | 1u;
  const std::uint32_t Enc = (std::uint32_t)Value ^ K;
  std::string S;
  llvm::raw_string_ostream OS(S);
  OS << "((int)(" << llvm::format("0x%x", Enc) << "u ^ "
     << llvm::format("0x%x", K) << "u))";
  return OS.str();
}

class EncodeConstantsPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "encode-constants"; }

  llvm::StringRef description() const override {
    return "Replace integer literals with (enc ^ key) ICE forms (--seed); "
           "skips init lists / case / enums";
  }

  bool run(fev::PassContext &Ctx) override {
    unsigned Salt = 0;
    llvm::DenseSet<unsigned> SeenOffsets;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, std::uint64_t Seed, unsigned &Salt,
              llvm::DenseSet<unsigned> &Seen)
          : Rewriter_(R), Seed_(Seed), Salt_(Salt), Seen_(Seen) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Lit = Result.Nodes.getNodeAs<IntegerLiteral>("lit");
        if (!Lit)
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Lit->getLocation(), SM))
          return;

        // anyOf() can deliver the same literal multiple times; rewriting the
        // same original range twice corrupts the buffer.
        const unsigned Off = SM.getFileOffset(Lit->getBeginLoc());
        if (!Seen_.insert(Off).second)
          return;

        const auto &Parents = Result.Context->getParents(*Lit);
        for (const auto &P : Parents) {
          if (P.get<CaseStmt>() || P.get<EnumConstantDecl>() ||
              P.get<EnumDecl>() || P.get<InitListExpr>())
            return;
        }

        const llvm::APInt Bits = Lit->getValue();
        if (Bits.getActiveBits() > 31)
          return;
        const std::int64_t Value = Bits.getSExtValue();
        if (Value == 0 || Value == 1)
          return;

        const CharSourceRange Range =
            CharSourceRange::getTokenRange(Lit->getSourceRange());
        if (Range.isInvalid())
          return;

        const std::string Repl = encodeInt(Value, Seed_, Salt_++);
        (void)Rewriter_.ReplaceText(Range, Repl);
      }

    private:
      Rewriter &Rewriter_;
      std::uint64_t Seed_;
      unsigned &Salt_;
      llvm::DenseSet<unsigned> &Seen_;
    };

    Handler H(Ctx.Rewriter, Ctx.Config.Seed, Salt, SeenOffsets);
    MatchFinder Finder;
    Finder.addMatcher(
        integerLiteral(
            unless(isExpansionInSystemHeader()),
            unless(hasAncestor(initListExpr())),
            anyOf(hasAncestor(binaryOperator()), hasAncestor(callExpr()),
                  hasAncestor(returnStmt()), hasAncestor(varDecl()),
                  hasAncestor(unaryOperator())))
            .bind("lit"),
        &H);
    Finder.matchAST(Ctx.AST);
    return true;
  }
};

FEV_REGISTER_PASS(EncodeConstantsPass);

} // namespace
