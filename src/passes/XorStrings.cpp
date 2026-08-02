#include "fev/Pass.h"

#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

constexpr char kHelperName[] = "fev_xd";

std::string buildHelper() {
  // Tiny runtime decoder injected once per rewritten TU.
  return R"(/* === fev xor-strings helper (generated) === */
static inline char *fev_xd(char *out, const unsigned char *in, unsigned n,
                          unsigned char key) {
  for (unsigned i = 0; i < n; ++i)
    out[i] = (char)(in[i] ^ key);
  out[n] = '\0';
  return out;
}
/* === end fev helper === */

)";
}

std::string encodeLiteral(const StringLiteral *SL, std::uint8_t Key) {
  const StringRef Bytes = SL->getString();
  std::string Enc;
  llvm::raw_string_ostream OS(Enc);

  // VLA-style compound literal keeps this valid C99 and avoids a heap alloc.
  OS << kHelperName << "((char[" << (Bytes.size() + 1) << "]){0}, "
     << "(const unsigned char[]){";

  for (size_t I = 0, E = Bytes.size(); I != E; ++I) {
    if (I)
      OS << ", ";
    const auto Encoded =
        static_cast<unsigned>(static_cast<unsigned char>(Bytes[I]) ^ Key);
    OS << llvm::format("0x%02xu", Encoded);
  }

  OS << "}, " << Bytes.size() << "u, "
     << llvm::format("0x%02xu", static_cast<unsigned>(Key)) << ")";
  return OS.str();
}

class XorStringsPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "xor-strings"; }

  llvm::StringRef description() const override {
    return "XOR-encode ordinary string literals used as call arguments "
           "(key via --xor-key)";
  }

  bool run(fev::PassContext &Ctx) override {
    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, std::uint8_t Key)
          : Rewriter_(R), Key_(Key), Edited_(false) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *SL = Result.Nodes.getNodeAs<StringLiteral>("str");
        if (!SL || !SL->isOrdinary() || SL->getLength() == 0)
          return;

        SourceManager &SM = *Result.SourceManager;
        SourceLocation Begin = SL->getBeginLoc();
        if (Begin.isInvalid() || !SM.isInMainFile(Begin))
          return;

        // Skip macro expansions; rewriting those is fragile.
        if (Begin.isMacroID())
          return;

        const CharSourceRange Range = CharSourceRange::getTokenRange(
            SL->getBeginLoc(), SL->getEndLoc());
        if (Range.isInvalid())
          return;

        const std::string Replacement = encodeLiteral(SL, Key_);
        if (Rewriter_.ReplaceText(Range, Replacement)) {
          // ReplaceText returns true on failure.
          return;
        }
        Edited_ = true;
      }

      bool edited() const { return Edited_; }

    private:
      Rewriter &Rewriter_;
      std::uint8_t Key_;
      bool Edited_;
    };

    Handler H(Ctx.Rewriter, Ctx.Config.XorKey);
    MatchFinder Finder;

    // Only touch literals that feed a call (e.g. printf). Array initializers
    // like `char s[] = "x"` are left alone — a call expression is invalid there.
    Finder.addMatcher(
        stringLiteral(hasAncestor(callExpr()),
                      unless(isExpansionInSystemHeader()))
            .bind("str"),
        &H);
    Finder.matchAST(Ctx.AST);

    if (!H.edited())
      return true;

    SourceManager &SM = Ctx.Rewriter.getSourceMgr();
    const FileID MainFileID = SM.getMainFileID();
    const SourceLocation FileStart = SM.getLocForStartOfFile(MainFileID);
    Ctx.Rewriter.InsertText(FileStart, buildHelper(), /*InsertAfter=*/false,
                            /*indentNewLines=*/false);
    return true;
  }
};

FEV_REGISTER_PASS(XorStringsPass);

} // namespace
