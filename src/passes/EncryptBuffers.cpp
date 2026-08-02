#include "fev/ChaCha20.h"
#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"
#include "fev/ByteArrayUtils.h"
#include "fev/Validate.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

class EncryptBuffersPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "encrypt-buffers"; }

  llvm::StringRef description() const override {
    return "ChaCha20-encrypt global/static char/uchar array initializers; "
           "lazy decrypt at main entry (--seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const auto Key = fev::deriveChaChaKey(Ctx.Config.Seed);
    unsigned NextIndex = 1000;
    bool Edited = false;
    bool Failed = false;
    std::vector<std::string> DecryptCalls;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO,
              const std::array<std::uint8_t, 32> &Key, std::uint64_t Seed,
              fev::ValidateMode VMode, unsigned &Next, bool &Edited,
              bool &Failed, std::vector<std::string> &Calls)
          : Rewriter_(R), LangOpts_(LO), Key_(Key), Seed_(Seed), VMode_(VMode),
            Next_(Next), Edited_(Edited), Failed_(Failed), Calls_(Calls) {}

      void run(const MatchFinder::MatchResult &Result) override {
        if (Failed_)
          return;
        const auto *VD = Result.Nodes.getNodeAs<VarDecl>("buf");
        if (!VD || !VD->hasInit() || VD->getName().empty())
          return;
        if (VD->isLocalVarDecl())
          return;
        // Leave FEV helpers / ciphertext alone; do encrypt `_fev_sc_*`
        // (output of scramble-arrays) so decrypt-then-unscramble layers.
        StringRef NameRef = VD->getName();
        if (NameRef.starts_with("fev_") || NameRef.starts_with("_fev_ct_") ||
            NameRef.starts_with("_fev_ensure_") ||
            NameRef.starts_with("_fev_unscramble_"))
          return;
        if (NameRef.starts_with("_fev_") && !NameRef.starts_with("_fev_sc_"))
          return;
        if (!fev::isByteOrientedArray(VD->getType()))
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(VD->getLocation(), SM))
          return;

        std::vector<std::uint8_t> Plain;
        if (!fev::collectVarInitBytes(VD->getInit(), Plain))
          return;

        const unsigned Idx = Next_++;
        auto Nonce = fev::deriveNonce(Seed_, Idx);
        std::vector<std::uint8_t> Ct(Plain.size());
        fev::chacha20Xor(Ct.data(), Plain.data(), Plain.size(), Key_.data(),
                         Nonce.data());
        {
          std::vector<std::uint8_t> RoundTrip(Plain.size());
          fev::chacha20Xor(RoundTrip.data(), Ct.data(), Ct.size(), Key_.data(),
                           Nonce.data());
          const std::string BufLabel =
              "encrypt-buffers " + VD->getNameAsString();
          if (!fev::validateRoundTrip(VMode_, BufLabel, Plain, RoundTrip)) {
            Failed_ = true;
            return;
          }
        }
        const std::uint32_t Tag = fev::fnv1a32(Plain.data(), Plain.size());

        const std::string Name = VD->getNameAsString();
        const std::string CtName = "_fev_ct_" + Name;
        const std::string Ensure = "_fev_ensure_" + Name;

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

        std::string Replacement;
        llvm::raw_string_ostream OS(Replacement);
        OS << "/* fev encrypt-buffers: " << Name << " (fnv="
           << llvm::format("0x%08x", Tag) << ") */\n"
           << "static const unsigned char " << CtName << "[" << Plain.size()
           << "] = " << fev::formatByteArray(Ct.data(), Ct.size()) << ";\n"
           << "unsigned char " << Name << "[" << Plain.size() << "];\n"
           << "static void " << Ensure << "(void) {\n"
           << "  static int ready;\n"
           << "  static const uint8_t nonce[12] = "
           << fev::formatByteArray(Nonce.data(), Nonce.size()) << ";\n"
           << "  if (!ready) {\n"
           << "    fev_chacha20_xor(" << Name << ", " << CtName << ", "
           << Plain.size() << "u, fev_chacha_key, nonce);\n"
           << "    if (fev_fnv1a32(" << Name << ", " << Plain.size()
           << "u) != " << llvm::format("0x%08xu", Tag) << ")\n"
           << "      memset(" << Name << ", 0, " << Plain.size() << ");\n"
           << "    ready = 1;\n"
           << "  }\n"
           << "}\n";

        if (Rewriter_.ReplaceText(Range, OS.str()))
          return;

        Calls_.push_back(Ensure + "();");
        Edited_ = true;
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
      const std::array<std::uint8_t, 32> &Key_;
      std::uint64_t Seed_;
      fev::ValidateMode VMode_;
      unsigned &Next_;
      bool &Edited_;
      bool &Failed_;
      std::vector<std::string> &Calls_;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts(), Key, Ctx.Config.Seed,
              Ctx.Config.Validate, NextIndex, Edited, Failed, DecryptCalls);
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
      fev::logInfo() << "rewrote 0 buffer(s)";
      return true;
    }

    fev::insertAtFileStart(Ctx.Rewriter, fev::buildChaChaRuntimeC(Key) + "\n");

    class MainHandler : public MatchFinder::MatchCallback {
    public:
      MainHandler(Rewriter &R, std::vector<std::string> Calls)
          : Rewriter_(R), Calls_(std::move(Calls)) {}
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

    MainHandler MH(Ctx.Rewriter, DecryptCalls);
    MatchFinder MF;
    MF.addMatcher(
        functionDecl(isDefinition(), hasName("main")).bind("mainfn"), &MH);
    MF.matchAST(Ctx.AST);
    fev::logInfo() << "rewrote " << DecryptCalls.size() << " buffer(s)";
    return true;
  }
};

FEV_REGISTER_PASS(EncryptBuffersPass);

} // namespace
