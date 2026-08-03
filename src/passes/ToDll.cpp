#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Decl.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <cctype>
#include <string>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

constexpr const char *kMarker = "/* FEV_TO_DLL */";

bool isValidCIdent(llvm::StringRef S) {
  if (S.empty())
    return false;
  if (!(std::isalpha(static_cast<unsigned char>(S[0])) || S[0] == '_'))
    return false;
  for (char C : S) {
    if (!(std::isalnum(static_cast<unsigned char>(C)) || C == '_'))
      return false;
  }
  return true;
}

bool fileAlreadyHasWindowsH(llvm::StringRef Text) {
  return Text.contains("#include <windows.h>") ||
         Text.contains("#include <Windows.h>") ||
         Text.contains("#include \"windows.h\"");
}

bool fileAlreadyHasDllMain(llvm::StringRef Text) {
  // Rough but enough for idempotency / already-DLL sources.
  return Text.contains("DllMain") || Text.contains(kMarker);
}

/// Build a call to the renamed entry matching main's arity.
std::string buildEntryCall(const FunctionDecl *Main, llvm::StringRef Entry) {
  std::string Call = Entry.str();
  Call += "(";
  const unsigned N = Main->getNumParams();
  if (N == 0) {
    Call += ")";
    return Call;
  }
  // Common: main(void) still reports 0 params; main(int,char**) → 2.
  for (unsigned I = 0; I < N; ++I) {
    if (I)
      Call += ", ";
    const QualType Ty = Main->getParamDecl(I)->getType().getCanonicalType();
    if (Ty->isPointerType())
      Call += "NULL";
    else if (Ty->isIntegralOrEnumerationType())
      Call += "0";
    else
      Call += "0";
  }
  Call += ")";
  return Call;
}

std::string buildDllMainBlock(const FunctionDecl *Main, llvm::StringRef Entry,
                              bool Export, bool UseThread) {
  std::string Out;
  llvm::raw_string_ostream OS(Out);

  OS << "\n" << kMarker << "\n";
  if (UseThread) {
    OS << "static DWORD WINAPI _fev_dll_thread(LPVOID _fev_param) {\n";
    OS << "  (void)_fev_param;\n";
    OS << "  (void)" << buildEntryCall(Main, Entry) << ";\n";
    OS << "  return 0;\n";
    OS << "}\n\n";
  }

  OS << "BOOL WINAPI DllMain(HINSTANCE _fev_hinst, DWORD _fev_reason,\n";
  OS << "                    LPVOID _fev_reserved) {\n";
  OS << "  (void)_fev_hinst;\n";
  OS << "  (void)_fev_reserved;\n";
  OS << "  if (_fev_reason == DLL_PROCESS_ATTACH) {\n";
  if (UseThread) {
    OS << "    HANDLE _fev_th = CreateThread(NULL, 0, _fev_dll_thread, NULL, 0, "
          "NULL);\n";
    OS << "    if (_fev_th)\n";
    OS << "      CloseHandle(_fev_th);\n";
  } else {
    OS << "    (void)" << buildEntryCall(Main, Entry) << ";\n";
  }
  OS << "  }\n";
  OS << "  return TRUE;\n";
  OS << "}\n";

  (void)Export; // export applied on the entry declaration itself
  return OS.str();
}

class ToDllPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "to-dll"; }

  llvm::StringRef description() const override {
    return "Convert main() into a Windows DLL: rename to export entry + "
           "DllMain (opt-in; excluded from --passes=all). "
           "--dll-entry, --dll-export, --dll-thread";
  }

  bool run(fev::PassContext &Ctx) override {
    std::string Entry = Ctx.Config.DllEntryName;
    if (Entry.empty())
      Entry = "_fev_dll_entry";
    if (!isValidCIdent(Entry)) {
      fev::logError() << "to-dll: invalid --dll-entry '" << Entry << "'";
      return false;
    }
    if (Entry == "main" || Entry == "DllMain" || Entry == "wDllMain") {
      fev::logError() << "to-dll: --dll-entry must not be main/DllMain";
      return false;
    }

    SourceManager &SM = Ctx.AST.getSourceManager();
    const FileID MainFile = SM.getMainFileID();
    const llvm::StringRef FileText =
        SM.getBufferData(MainFile, /*Invalid=*/nullptr);

    if (fileAlreadyHasDllMain(FileText)) {
      fev::logInfo() << "to-dll: DllMain/marker already present — skipping";
      return true;
    }

    const FunctionDecl *MainFn = nullptr;
    class Finder : public MatchFinder::MatchCallback {
    public:
      explicit Finder(const FunctionDecl *&Out) : Out_(Out) {}
      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("mainfn");
        if (!Fn || !Fn->isThisDeclarationADefinition() || !Fn->hasBody())
          return;
        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Fn->getLocation(), SM))
          return;
        Out_ = Fn;
      }
      const FunctionDecl *&Out_;
    };

    Finder CB(MainFn);
    MatchFinder MF;
    MF.addMatcher(functionDecl(isDefinition(), hasName("main")).bind("mainfn"),
                  &CB);
    MF.matchAST(Ctx.AST);

    if (!MainFn) {
      fev::logError() << "to-dll: no main() definition found in the main file";
      return false;
    }

    // Ensure windows.h for DllMain / HANDLE / CreateThread.
    if (!fileAlreadyHasWindowsH(FileText)) {
      std::string Inc = std::string(kMarker) + "\n";
      Inc += "#ifndef WIN32_LEAN_AND_MEAN\n";
      Inc += "#define WIN32_LEAN_AND_MEAN\n";
      Inc += "#endif\n";
      Inc += "#include <windows.h>\n\n";
      fev::insertAtFileStart(Ctx.Rewriter, Inc);
    } else {
      // Still drop a marker so re-runs are idempotent even if include existed.
      fev::insertAtFileStart(Ctx.Rewriter, std::string(kMarker) + "\n");
    }

    // Rename main → entry; optionally prepend __declspec(dllexport).
    const DeclarationNameInfo NameInfo = MainFn->getNameInfo();
    const CharSourceRange NameRange =
        CharSourceRange::getTokenRange(NameInfo.getSourceRange());
    if (NameRange.isInvalid()) {
      fev::logError() << "to-dll: cannot locate main name token";
      return false;
    }

    std::string Replacement = Entry;
    if (Ctx.Config.DllExport)
      Replacement = "__declspec(dllexport) " + Entry;

    // Prefer putting dllexport on the declaration start when possible so the
    // name token stays a bare identifier; fall back to replacing the name.
    SourceLocation DeclStart = MainFn->getBeginLoc();
    bool PlacedExport = false;
    if (Ctx.Config.DllExport && DeclStart.isValid() &&
        fev::isInMainFile(DeclStart, SM)) {
      // Insert export attribute before the declaration; rename name alone.
      Ctx.Rewriter.InsertText(DeclStart, "__declspec(dllexport) ",
                              /*InsertAfter=*/false,
                              /*indentNewLines=*/false);
      if (Ctx.Rewriter.ReplaceText(NameRange, Entry)) {
        fev::logError() << "to-dll: failed to rename main";
        return false;
      }
      PlacedExport = true;
    }
    if (!PlacedExport) {
      if (Ctx.Rewriter.ReplaceText(NameRange, Replacement)) {
        fev::logError() << "to-dll: failed to rename main";
        return false;
      }
    }

    SourceLocation AfterFn = Lexer::getLocForEndOfToken(
        MainFn->getBody()->getEndLoc(), 0, SM, Ctx.AST.getLangOpts());
    if (AfterFn.isInvalid())
      AfterFn = MainFn->getEndLoc();

    const std::string Block = buildDllMainBlock(
        MainFn, Entry, Ctx.Config.DllExport, Ctx.Config.DllThread);
    Ctx.Rewriter.InsertTextAfter(AfterFn, Block);

    fev::logInfo() << "to-dll: main → " << Entry
                   << (Ctx.Config.DllExport ? " (dllexport)" : "")
                   << (Ctx.Config.DllThread ? ", DllMain+CreateThread"
                                            : ", DllMain direct call");
    return true;
  }
};

FEV_REGISTER_PASS(ToDllPass);

} // namespace
