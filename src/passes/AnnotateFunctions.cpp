#include "fev/Pass.h"

#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class AnnotateFunctionsPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "annotate"; }

  llvm::StringRef description() const override {
    return "Insert a marker comment before each function definition (debug)";
  }

  bool run(fev::PassContext &Ctx) override {
    class Handler : public MatchFinder::MatchCallback {
    public:
      explicit Handler(Rewriter &R) : Rewriter_(R) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn");
        if (!Fn || !Fn->hasBody())
          return;

        SourceManager &SM = *Result.SourceManager;
        SourceLocation Loc = Fn->getBeginLoc();
        if (Loc.isInvalid() || !SM.isInMainFile(Loc))
          return;

        Loc = SM.getSpellingLoc(Loc);
        Rewriter_.InsertTextBefore(
            Loc, "/* [fev] transformed: " + Fn->getNameAsString() + " */\n");
      }

    private:
      Rewriter &Rewriter_;
    };

    Handler H(Ctx.Rewriter);
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &H);
    Finder.matchAST(Ctx.AST);
    return true;
  }
};

FEV_REGISTER_PASS(AnnotateFunctionsPass);

} // namespace
