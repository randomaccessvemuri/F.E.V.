#pragma once

#include "clang/AST/Stmt.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Lex/Lexer.h"
#include "clang/Rewrite/Core/Rewriter.h"

#include <string>

namespace fev {

inline std::string stmtText(const clang::Stmt *S, const clang::SourceManager &SM,
                            const clang::LangOptions &LangOpts) {
  if (!S)
    return {};
  const clang::CharSourceRange Range =
      clang::CharSourceRange::getTokenRange(S->getSourceRange());
  if (Range.isInvalid())
    return {};
  return clang::Lexer::getSourceText(Range, SM, LangOpts).str();
}

inline bool isInMainFile(const clang::SourceLocation Loc,
                         const clang::SourceManager &SM) {
  return Loc.isValid() && !Loc.isMacroID() && SM.isInMainFile(Loc);
}

inline void insertAtFileStart(clang::Rewriter &R, const std::string &Text) {
  clang::SourceManager &SM = R.getSourceMgr();
  R.InsertText(SM.getLocForStartOfFile(SM.getMainFileID()), Text,
               /*InsertAfter=*/false, /*indentNewLines=*/false);
}

} // namespace fev
