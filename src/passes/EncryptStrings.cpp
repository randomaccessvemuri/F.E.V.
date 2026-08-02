#include "fev/ChaCha20.h"
#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"
#include "fev/Validate.h"

#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/SourceManager.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

struct EncodedString {
  std::string GetterName;
  std::string GetterDef;
};

class EncryptStringsPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "encrypt-strings"; }

  llvm::StringRef description() const override {
    return "ChaCha20-encrypt string literals used as call arguments "
           "(lazy decrypt + FNV; --seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const auto Key = fev::deriveChaChaKey(Ctx.Config.Seed);
    std::vector<EncodedString> Encoded;
    unsigned NextIndex = 0;
    bool Edited = false;
    bool Failed = false;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const std::array<std::uint8_t, 32> &Key,
              std::uint64_t Seed, fev::ValidateMode VMode,
              std::vector<EncodedString> &Out, unsigned &Next, bool &Edited,
              bool &Failed)
          : Rewriter_(R), Key_(Key), Seed_(Seed), VMode_(VMode), Out_(Out),
            Next_(Next), Edited_(Edited), Failed_(Failed) {}

      void run(const MatchFinder::MatchResult &Result) override {
        if (Failed_)
          return;
        const auto *SL = Result.Nodes.getNodeAs<StringLiteral>("str");
        if (!SL || !SL->isOrdinary() || SL->getLength() == 0)
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(SL->getBeginLoc(), SM))
          return;

        const CharSourceRange Range = CharSourceRange::getTokenRange(
            SL->getBeginLoc(), SL->getEndLoc());
        if (Range.isInvalid())
          return;

        const StringRef Plain = SL->getString();
        const unsigned Idx = Next_++;
        auto Nonce = fev::deriveNonce(Seed_, Idx);
        std::vector<std::uint8_t> Ct(Plain.size());
        fev::chacha20Xor(Ct.data(),
                         reinterpret_cast<const std::uint8_t *>(Plain.data()),
                         Plain.size(), Key_.data(), Nonce.data());
        {
          std::vector<std::uint8_t> RoundTrip(Plain.size());
          fev::chacha20Xor(RoundTrip.data(), Ct.data(), Ct.size(), Key_.data(),
                           Nonce.data());
          std::vector<std::uint8_t> PlainBytes(
              reinterpret_cast<const std::uint8_t *>(Plain.data()),
              reinterpret_cast<const std::uint8_t *>(Plain.data()) +
                  Plain.size());
          const std::string Label =
              "encrypt-strings #" + std::to_string(Idx);
          if (!fev::validateRoundTrip(VMode_, Label, PlainBytes, RoundTrip)) {
            Failed_ = true;
            return;
          }
        }
        const std::uint32_t Tag = fev::fnv1a32(
            reinterpret_cast<const std::uint8_t *>(Plain.data()), Plain.size());

        EncodedString E;
        E.GetterName = "fev_str_" + std::to_string(Idx);
        {
          std::string Def;
          llvm::raw_string_ostream OS(Def);
          OS << "static char *" << E.GetterName << "(void) {\n"
             << "  static char buf[" << (Plain.size() + 1) << "];\n"
             << "  static int ready;\n"
             << "  static const uint8_t ct[" << Plain.size()
             << "] = " << fev::formatByteArray(Ct.data(), Ct.size()) << ";\n"
             << "  static const uint8_t nonce[12] = "
             << fev::formatByteArray(Nonce.data(), Nonce.size()) << ";\n"
             << "  return fev_lazy_str(buf, sizeof(buf), ct, "
             << Plain.size() << "u, nonce, " << llvm::format("0x%08xu", Tag)
             << ", &ready);\n"
             << "}\n";
          E.GetterDef = OS.str();
        }

        if (Rewriter_.ReplaceText(Range, E.GetterName + "()"))
          return;
        Out_.push_back(std::move(E));
        Edited_ = true;
      }

    private:
      Rewriter &Rewriter_;
      const std::array<std::uint8_t, 32> &Key_;
      std::uint64_t Seed_;
      fev::ValidateMode VMode_;
      std::vector<EncodedString> &Out_;
      unsigned &Next_;
      bool &Edited_;
      bool &Failed_;
    };

    Handler H(Ctx.Rewriter, Key, Ctx.Config.Seed, Ctx.Config.Validate, Encoded,
              NextIndex, Edited, Failed);
    MatchFinder Finder;
    Finder.addMatcher(
        stringLiteral(hasAncestor(callExpr()),
                      unless(isExpansionInSystemHeader()))
            .bind("str"),
        &H);
    Finder.matchAST(Ctx.AST);

    if (Failed)
      return false;

    if (!Edited) {
      fev::logInfo() << "rewrote 0 string(s)";
      return true;
    }

    std::string Preamble = fev::buildChaChaRuntimeC(Key);
    for (const EncodedString &E : Encoded)
      Preamble += E.GetterDef;
    Preamble += "\n";
    fev::insertAtFileStart(Ctx.Rewriter, Preamble);
    fev::logInfo() << "rewrote " << Encoded.size() << " string(s)";
    return true;
  }
};

FEV_REGISTER_PASS(EncryptStringsPass);

} // namespace
