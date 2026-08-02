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

constexpr const char *kMarker = "/* FEV_JUNK_CODE */";

double unitFloat(std::uint64_t Seed, unsigned Salt) {
  std::uint64_t X = Seed ^ (0x9E3779B97F4A7C15ULL * (Salt + 1));
  X ^= X >> 30;
  X *= 0xBF58476D1CE4E5B9ULL;
  X ^= X >> 27;
  return (double)(X >> 11) / (double)(1ULL << 53);
}

unsigned pickFlavor(std::uint64_t Seed, unsigned Salt, unsigned N) {
  std::uint64_t X = Seed ^ (0xD1B54A32D192ED03ULL * (Salt + 1));
  X ^= X >> 33;
  X *= 0xFF51AFD7ED558CCDULL;
  return (unsigned)(X % N);
}

/// Windows API junk — results only feed volatile sinks (no control effect).
std::string junkBlock(unsigned Flavor, unsigned Salt) {
  const std::string Tag = std::to_string(Salt);
  std::string S = "{\n";
  S += "  /* fev junk-code #" + Tag + " */\n";
  S += "#if defined(_WIN32)\n";
  switch (Flavor % 4) {
  case 0:
    S += "  {\n"
         "    volatile DWORD _fev_jk" +
         Tag +
         " = GetTickCount();\n"
         "    _fev_jk" +
         Tag +
         " ^= GetCurrentProcessId();\n"
         "    _fev_jk" +
         Tag +
         " += GetCurrentThreadId();\n"
         "    if (IsDebuggerPresent())\n"
         "      _fev_jk" +
         Tag +
         " ^= 0xA5A5u;\n"
         "    (void)_fev_jk" +
         Tag +
         ";\n"
         "  }\n";
    break;
  case 1:
    S += "  {\n"
         "    LARGE_INTEGER _fev_li" +
         Tag +
         ";\n"
         "    FILETIME _fev_ft" +
         Tag +
         ";\n"
         "    volatile DWORD _fev_jk" +
         Tag +
         " = 0;\n"
         "    if (QueryPerformanceCounter(&_fev_li" +
         Tag +
         "))\n"
         "      _fev_jk" +
         Tag +
         " ^= (DWORD)_fev_li" +
         Tag +
         ".LowPart;\n"
         "    GetSystemTimeAsFileTime(&_fev_ft" +
         Tag +
         ");\n"
         "    _fev_jk" +
         Tag +
         " ^= _fev_ft" +
         Tag +
         ".dwLowDateTime;\n"
         "    (void)_fev_jk" +
         Tag +
         ";\n"
         "  }\n";
    break;
  case 2:
    S += "  {\n"
         "    volatile HMODULE _fev_m" +
         Tag +
         " = GetModuleHandleA(NULL);\n"
         "    volatile DWORD _fev_jk" +
         Tag +
         " = GetTickCount() ^ GetCurrentProcessId();\n"
         "    if (_fev_m" +
         Tag +
         ")\n"
         "      _fev_jk" +
         Tag +
         " ^= (DWORD)(uintptr_t)_fev_m" +
         Tag +
         ";\n"
         "    Sleep(0);\n"
         "    (void)_fev_jk" +
         Tag +
         ";\n"
         "  }\n";
    break;
  default:
    S += "  {\n"
         "    volatile DWORD _fev_jk" +
         Tag +
         " = GetCurrentThreadId();\n"
         "    LARGE_INTEGER _fev_li" +
         Tag +
         ";\n"
         "    QueryPerformanceCounter(&_fev_li" +
         Tag +
         ");\n"
         "    _fev_jk" +
         Tag +
         " = (_fev_jk" +
         Tag +
         " << 3) ^ (DWORD)_fev_li" +
         Tag +
         ".LowPart ^ GetTickCount();\n"
         "    if (!IsDebuggerPresent())\n"
         "      _fev_jk" +
         Tag +
         " += 1u;\n"
         "    (void)_fev_jk" +
         Tag +
         ";\n"
         "  }\n";
    break;
  }
  S += "#else\n"
       "  { volatile unsigned _fev_jk" +
       Tag +
       " = " + Tag +
       "u; _fev_jk" +
       Tag +
       " ^= _fev_jk" +
       Tag +
       "; (void)_fev_jk" +
       Tag +
       "; }\n"
       "#endif\n"
       "}\n";
  return S;
}

std::string ensureWindowsInclude() {
  return std::string(kMarker) + R"C(
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdint.h>
#endif
)C";
}

class JunkCodePass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "junk-code"; }

  llvm::StringRef description() const override {
    return "Insert inert Windows-API junk blocks (volatile sinks; "
           "--junk-density, --seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const double Density = Ctx.Config.JunkDensity;
    const std::uint64_t Seed = Ctx.Config.Seed;
    unsigned Salt = 0;
    bool Edited = false;
    bool NeedInclude = false;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, double Density, std::uint64_t Seed, unsigned &Salt,
              bool &Edited, bool &NeedInclude)
          : Rewriter_(R), Density_(Density), Seed_(Seed), Salt_(Salt),
            Edited_(Edited), NeedInclude_(NeedInclude) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn");
        if (!Fn || !Fn->hasBody())
          return;
        StringRef Name = Fn->getName();
        if (Name.starts_with("fev_") || Name.starts_with("_fev_"))
          return;

        auto *Body = dyn_cast<CompoundStmt>(Fn->getBody());
        if (!Body)
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Body->getLBracLoc(), SM))
          return;

        unsigned MySalt = Salt_++;
        if (unitFloat(Seed_, MySalt) > Density_)
          return;

        // Skip if we already junked this function.
        std::string BodyTxt =
            fev::stmtText(Body, SM, Result.Context->getLangOpts());
        if (BodyTxt.find("fev junk-code") != std::string::npos)
          return;

        SourceLocation AfterL = Lexer::getLocForEndOfToken(
            Body->getLBracLoc(), 0, SM, Result.Context->getLangOpts());
        if (AfterL.isInvalid())
          return;

        const unsigned Flavor = pickFlavor(Seed_, MySalt, 4);
        std::string Insert = "\n" + junkBlock(Flavor, MySalt);
        Rewriter_.InsertText(AfterL, Insert, /*InsertAfter=*/true,
                             /*indentNewLines=*/false);
        Edited_ = true;
        NeedInclude_ = true;
      }

    private:
      Rewriter &Rewriter_;
      double Density_;
      std::uint64_t Seed_;
      unsigned &Salt_;
      bool &Edited_;
      bool &NeedInclude_;
    };

    Handler H(Ctx.Rewriter, Density, Seed, Salt, Edited, NeedInclude);
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &H);
    Finder.matchAST(Ctx.AST);

    if (!Edited)
      return true;

    if (NeedInclude) {
      SourceManager &SM = Ctx.Rewriter.getSourceMgr();
      StringRef Buf = SM.getBufferData(SM.getMainFileID());
      if (Buf.find(kMarker) == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, ensureWindowsInclude());
    }

    fev::logInfo() << "junk-code: inserted blocks (density=" << Density << ")";
    return true;
  }
};

FEV_REGISTER_PASS(JunkCodePass);

} // namespace
