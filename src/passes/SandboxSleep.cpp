#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"

#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

constexpr const char *kMarker = "/* FEV_SANDBOX_SLEEP */";

std::string runtimeHelpers(unsigned SleepSec, unsigned MinSec, unsigned MaxSec) {
  std::string Out = kMarker;
  Out += "\n#include <time.h>\n";
  Out += "#if defined(_WIN32)\n";
  Out += "#ifndef WIN32_LEAN_AND_MEAN\n";
  Out += "#define WIN32_LEAN_AND_MEAN\n";
  Out += "#endif\n";
  Out += "#include <windows.h>\n";
  Out += "static void _fev_sleep_sec(unsigned s) { Sleep(s * 1000u); }\n";
  Out += "#else\n";
  Out += "#include <unistd.h>\n";
  Out += "static void _fev_sleep_sec(unsigned s) { (void)sleep(s); }\n";
  Out += "#endif\n";
  Out += "/* Returns 1 if wall-clock sleep looks real; 0 if accelerated/skipped. */\n";
  Out += "static int _fev_sandbox_sleep_ok(void) {\n";
  Out += "  time_t t0 = time(NULL);\n";
  Out += "  if (t0 == (time_t)-1)\n";
  Out += "    return 0;\n";
  Out += "  _fev_sleep_sec(";
  Out += std::to_string(SleepSec);
  Out += "u);\n";
  Out += "  time_t t1 = time(NULL);\n";
  Out += "  if (t1 == (time_t)-1)\n";
  Out += "    return 0;\n";
  Out += "  double dt = difftime(t1, t0);\n";
  Out += "  return dt >= ";
  Out += std::to_string(MinSec);
  Out += ".0 && dt <= ";
  Out += std::to_string(MaxSec);
  Out += ".0;\n";
  Out += "}\n";
  return Out;
}

class SandboxSleepPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "sandbox-sleep"; }

  llvm::StringRef description() const override {
    return "Insert wall-clock sleep timing check at main (anti-sandbox; "
           "--sleep-seconds, --sleep-min, --sleep-max)";
  }

  bool run(fev::PassContext &Ctx) override {
    unsigned SleepSec = Ctx.Config.SleepSeconds;
    if (SleepSec == 0)
      SleepSec = 10;
    unsigned MinSec = Ctx.Config.SleepMinSeconds;
    unsigned MaxSec = Ctx.Config.SleepMaxSeconds;
    if (MinSec == 0)
      MinSec = SleepSec > 2 ? SleepSec - 2 : 1;
    if (MaxSec == 0)
      MaxSec = SleepSec * 3;
    if (MinSec > SleepSec)
      MinSec = SleepSec;
    if (MaxSec < SleepSec)
      MaxSec = SleepSec + 5;

    bool InsertedCall = false;

    class MainHandler : public MatchFinder::MatchCallback {
    public:
      MainHandler(Rewriter &R, bool &Inserted)
          : Rewriter_(R), Inserted_(Inserted) {}

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

        // Avoid double-insert if pass re-run on already transformed source.
        std::string BodyText =
            fev::stmtText(Body, SM, Result.Context->getLangOpts());
        if (BodyText.find("_fev_sandbox_sleep_ok") != std::string::npos)
          return;

        SourceLocation AfterL = Lexer::getLocForEndOfToken(
            Body->getLBracLoc(), 0, SM, Result.Context->getLangOpts());
        if (AfterL.isInvalid())
          return;

        const bool IsVoid = Fn->getReturnType()->isVoidType();
        std::string Insert =
            "\n  /* fev sandbox-sleep: abort if sleep was accelerated */\n"
            "  if (!_fev_sandbox_sleep_ok()) {\n";
        if (IsVoid)
          Insert += "    return;\n";
        else
          Insert += "    return 1;\n";
        Insert += "  }\n";

        Rewriter_.InsertText(AfterL, Insert, /*InsertAfter=*/true,
                             /*indentNewLines=*/false);
        Inserted_ = true;
      }

    private:
      Rewriter &Rewriter_;
      bool &Inserted_;
    };

    MainHandler MH(Ctx.Rewriter, InsertedCall);
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), hasName("main")).bind("mainfn"), &MH);
    Finder.matchAST(Ctx.AST);

    if (!InsertedCall) {
      fev::logWarn() << "sandbox-sleep: no main() found; skipped";
      return true;
    }

    SourceManager &SM = Ctx.Rewriter.getSourceMgr();
    StringRef Buf = SM.getBufferData(SM.getMainFileID());
    if (Buf.find(kMarker) == StringRef::npos)
      fev::insertAtFileStart(Ctx.Rewriter,
                             runtimeHelpers(SleepSec, MinSec, MaxSec));

    fev::logInfo() << "sandbox-sleep: " << SleepSec << "s sleep, accept ["
                   << MinSec << ", " << MaxSec << "]s";
    return true;
  }
};

FEV_REGISTER_PASS(SandboxSleepPass);

} // namespace
