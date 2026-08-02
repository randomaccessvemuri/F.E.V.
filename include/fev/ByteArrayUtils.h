#pragma once

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"

#include <cstdint>
#include <vector>

namespace fev {

/// True for char / unsigned char / signed char arrays (shellcode buffers).
inline bool isByteOrientedArray(clang::QualType T) {
  clang::QualType Canon = T.getCanonicalType();
  clang::QualType Elem;
  if (const auto *AT = clang::dyn_cast<clang::ConstantArrayType>(Canon))
    Elem = AT->getElementType();
  else if (const auto *IAT = clang::dyn_cast<clang::IncompleteArrayType>(Canon))
    Elem = IAT->getElementType();
  else
    return false;
  Elem = Elem.getUnqualifiedType();
  return Elem->isCharType() ||
         Elem->isSpecificBuiltinType(clang::BuiltinType::UChar) ||
         Elem->isSpecificBuiltinType(clang::BuiltinType::Char_U) ||
         Elem->isSpecificBuiltinType(clang::BuiltinType::Char_S);
}

inline bool collectInitListBytes(const clang::InitListExpr *IL,
                                 std::vector<std::uint8_t> &Out) {
  if (!IL)
    return false;
  const clang::InitListExpr *Semantic =
      IL->isSemanticForm() ? IL : IL->getSemanticForm();
  if (!Semantic)
    Semantic = IL;
  for (const clang::Expr *E : Semantic->inits()) {
    E = E->IgnoreParenImpCasts();
    if (const auto *Lit = clang::dyn_cast<clang::IntegerLiteral>(E)) {
      const llvm::APInt V = Lit->getValue();
      if (V.getActiveBits() > 8)
        return false;
      Out.push_back((std::uint8_t)V.getZExtValue());
      continue;
    }
    if (const auto *CL = clang::dyn_cast<clang::CharacterLiteral>(E)) {
      Out.push_back((std::uint8_t)CL->getValue());
      continue;
    }
    return false;
  }
  return !Out.empty();
}

/// Collect bytes from a global/static byte-array initializer.
/// Supports `{ 0xfc, 0x48, … }` and C string/shellcode forms
/// `unsigned char buf[] = "\xfc\x48" "\x83…";` (includes the trailing NUL that
/// array size semantics give you for string initializers).
inline bool collectVarInitBytes(const clang::Expr *Init,
                                std::vector<std::uint8_t> &Out) {
  Out.clear();
  if (!Init)
    return false;
  Init = Init->IgnoreParenImpCasts();

  if (const auto *IL = clang::dyn_cast<clang::InitListExpr>(Init))
    return collectInitListBytes(IL, Out);

  if (const auto *SL = clang::dyn_cast<clang::StringLiteral>(Init)) {
    // Only narrow (1-byte) string literals — shellcode payload form.
    if (SL->getCharByteWidth() != 1)
      return false;
    const llvm::StringRef Bytes = SL->getBytes();
    Out.assign(Bytes.begin(), Bytes.end());
    // `unsigned char a[] = "…"` always includes a trailing '\0' in sizeof(a).
    Out.push_back(0);
    return true;
  }

  return false;
}

} // namespace fev
