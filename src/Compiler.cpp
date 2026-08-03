#include "fev/Compiler.h"
#include "fev/Log.h"
#include "fev/Pass.h"

#include "clang/Frontend/CompilerInstance.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <system_error>

namespace fev {

RewriteConsumer::RewriteConsumer(clang::Rewriter &Rewriter, PassConfig Config,
                                 std::string OutputPath)
    : Rewriter_(Rewriter), Config_(std::move(Config)),
      OutputPath_(std::move(OutputPath)) {}

void RewriteConsumer::HandleTranslationUnit(clang::ASTContext &Context) {
  PassContext Ctx{Context, Rewriter_, Config_};
  if (!runPasses(Ctx)) {
    Context.getDiagnostics().Report(
        Context.getDiagnostics().getCustomDiagID(
            clang::DiagnosticsEngine::Error, "fev pass pipeline failed"));
  }
}

RewriteAction::RewriteAction(PassConfig Config, std::string OutputPath)
    : Config_(std::move(Config)), OutputPath_(std::move(OutputPath)) {}

std::unique_ptr<clang::ASTConsumer>
RewriteAction::CreateASTConsumer(clang::CompilerInstance &CI,
                                 llvm::StringRef /*InFile*/) {
  Rewriter_.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
  return std::make_unique<RewriteConsumer>(Rewriter_, Config_, OutputPath_);
}

void RewriteAction::EndSourceFileAction() {
  clang::SourceManager &SM = Rewriter_.getSourceMgr();
  const clang::FileID MainFileID = SM.getMainFileID();
  const llvm::RewriteBuffer *Buffer =
      Rewriter_.getRewriteBufferFor(MainFileID);

  std::string Content;
  if (Buffer) {
    Content.assign(Buffer->begin(), Buffer->end());
  } else if (SM.getFileEntryRefForID(MainFileID)) {
    const auto FileContent = SM.getBufferData(MainFileID);
    Content.assign(FileContent.begin(), FileContent.end());
  } else {
    logError() << "unable to read main source file";
    getCompilerInstance().getDiagnostics().Report(
        getCompilerInstance().getDiagnostics().getCustomDiagID(
            clang::DiagnosticsEngine::Error,
            "fev: unable to read main source file"));
    return;
  }

  if (OutputPath_.empty()) {
    llvm::outs() << Content;
    return;
  }

  llvm::SmallString<256> Parent(OutputPath_);
  llvm::sys::path::remove_filename(Parent);
  if (!Parent.empty()) {
    if (std::error_code EC = llvm::sys::fs::create_directories(Parent)) {
      logError() << "failed to create directory '" << Parent.str()
                 << "': " << EC.message();
      getCompilerInstance().getDiagnostics().Report(
          getCompilerInstance().getDiagnostics().getCustomDiagID(
              clang::DiagnosticsEngine::Error,
              "fev: failed to create output directory"));
      return;
    }
  }

  std::error_code EC;
  llvm::raw_fd_ostream Out(OutputPath_, EC, llvm::sys::fs::OF_Text);
  if (EC) {
    logError() << "failed to open '" << OutputPath_ << "': " << EC.message();
    getCompilerInstance().getDiagnostics().Report(
        getCompilerInstance().getDiagnostics().getCustomDiagID(
            clang::DiagnosticsEngine::Error,
            "fev: failed to write obfuscated source"));
    return;
  }
  Out << Content;
  Out.flush();
  if (Out.has_error()) {
    logError() << "failed while writing '" << OutputPath_ << "'";
    Out.clear_error();
    getCompilerInstance().getDiagnostics().Report(
        getCompilerInstance().getDiagnostics().getCustomDiagID(
            clang::DiagnosticsEngine::Error,
            "fev: failed while writing obfuscated source"));
    return;
  }
  logDebug() << "wrote " << Content.size() << " bytes to '" << OutputPath_
             << "'";
}

RewriteActionFactory::RewriteActionFactory(PassConfig Config,
                                           std::string OutputPath)
    : Config_(std::move(Config)), OutputPath_(std::move(OutputPath)) {}

std::unique_ptr<clang::FrontendAction> RewriteActionFactory::create() {
  return std::make_unique<RewriteAction>(Config_, OutputPath_);
}

} // namespace fev
