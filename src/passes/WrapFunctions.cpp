#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class WrapFunctionsPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "wrap-functions"; }

  llvm::StringRef description() const override {
    return "Wrap static functions in a forwarding stub (extra call frame)";
  }

  bool run(fev::PassContext &Ctx) override {
    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO) : Rewriter_(R), LangOpts_(LO) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn");
        if (!Fn || !Fn->isThisDeclarationADefinition() || !Fn->hasBody())
          return;
        if (!Fn->isStatic())
          return;
        if (Fn->getName() == "main" || Fn->getName().starts_with("_fev_") ||
            Fn->getName().starts_with("fev_"))
          return;
        // Skip variadic / weird cases for the exercise.
        if (Fn->isVariadic())
          return;

        SourceManager &SM = *Result.SourceManager;
        const DeclarationNameInfo NameInfo = Fn->getNameInfo();
        if (!fev::isInMainFile(NameInfo.getLoc(), SM))
          return;

        const std::string Orig = Fn->getNameAsString();
        const std::string Impl = "_fev_impl_" + Orig;

        // Rename definition.
        const CharSourceRange NameRange =
            CharSourceRange::getTokenRange(NameInfo.getSourceRange());
        if (NameRange.isInvalid())
          return;
        if (Rewriter_.ReplaceText(NameRange, Impl))
          return;

        // Build wrapper with original name after the function.
        std::string RetTy = "void";
        if (!Fn->getReturnType()->isVoidType()) {
          RetTy = Fn->getReturnType().getAsString();
        }

        std::string Params;
        std::string Args;
        llvm::raw_string_ostream POS(Params);
        llvm::raw_string_ostream AOS(Args);
        unsigned I = 0;
        for (const ParmVarDecl *P : Fn->parameters()) {
          if (I) {
            POS << ", ";
            AOS << ", ";
          }
          const std::string PTy = P->getType().getAsString();
          const std::string PName =
              P->getName().empty() ? ("_p" + std::to_string(I))
                                   : P->getNameAsString();
          POS << PTy << " " << PName;
          AOS << PName;
          ++I;
        }
        if (Fn->getNumParams() == 0)
          POS << "void";

        std::string Wrapper;
        llvm::raw_string_ostream WOS(Wrapper);
        WOS << "\nstatic " << RetTy << " " << Orig << "(" << POS.str()
            << ") {\n";
        if (Fn->getReturnType()->isVoidType())
          WOS << "  " << Impl << "(" << AOS.str() << ");\n";
        else
          WOS << "  return " << Impl << "(" << AOS.str() << ");\n";
        WOS << "}\n";

        SourceLocation AfterFn = Lexer::getLocForEndOfToken(
            Fn->getBody()->getEndLoc(), 0, SM, LangOpts_);
        if (AfterFn.isInvalid())
          AfterFn = Fn->getEndLoc();
        Rewriter_.InsertTextAfter(AfterFn, WOS.str());
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts());
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &H);
    Finder.matchAST(Ctx.AST);
    return true;
  }
};

FEV_REGISTER_PASS(WrapFunctionsPass);

} // namespace
