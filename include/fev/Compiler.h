#pragma once

#include "fev/Pass.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/Tooling.h"

#include <memory>
#include <string>

namespace fev {

class RewriteConsumer final : public clang::ASTConsumer {
public:
  RewriteConsumer(clang::Rewriter &Rewriter, PassConfig Config,
                  std::string OutputPath);

  void HandleTranslationUnit(clang::ASTContext &Context) override;

private:
  clang::Rewriter &Rewriter_;
  PassConfig Config_;
  std::string OutputPath_;
};

class RewriteAction final : public clang::ASTFrontendAction {
public:
  RewriteAction(PassConfig Config, std::string OutputPath);

  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(clang::CompilerInstance &CI,
                    llvm::StringRef InFile) override;

  void EndSourceFileAction() override;

private:
  clang::Rewriter Rewriter_;
  PassConfig Config_;
  std::string OutputPath_;
};

class RewriteActionFactory final : public clang::tooling::FrontendActionFactory {
public:
  RewriteActionFactory(PassConfig Config, std::string OutputPath);

  std::unique_ptr<clang::FrontendAction> create() override;

private:
  PassConfig Config_;
  std::string OutputPath_;
};

} // namespace fev
