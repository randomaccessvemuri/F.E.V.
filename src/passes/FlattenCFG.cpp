#include "fev/Pass.h"
#include "fev/Log.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/StmtCXX.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Basic/TokenKinds.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

/// László & Kiss (control-flow flattening) adapted to Clang AST + rewriter.
/// Emits a while/switch dispatcher with:
///   - recursive lowering of if / while / do / for / switch / try
///   - break / continue rewritten to control-variable assigns (+ cross-level goto)
///   - random non-sequential state IDs, permuted case order
///   - XOR-encoded + volatile state transitions (optimizer-resistant)

struct LevelInfo {
  std::string Var;
  std::string Label;
};

struct BreakContInfo {
  size_t Level = 0;
  unsigned Entry = 0;
};

enum class PartKind {
  Block,
  If,
  Switch,
  While,
  Do,
  For,
  Try,
  Sequence
};

struct BlockPart {
  PartKind Kind = PartKind::Sequence;
  const Stmt *Node = nullptr;           // compound / control stmt
  std::vector<const Stmt *> Sequence;   // for Sequence parts
};

bool isControlOrCompound(const Stmt *S) {
  return isa<CompoundStmt>(S) || isa<IfStmt>(S) || isa<WhileStmt>(S) ||
         isa<DoStmt>(S) || isa<ForStmt>(S) || isa<SwitchStmt>(S) ||
         isa<CXXTryStmt>(S);
}

bool isSequenceBreaker(const Stmt *S) {
  return isa<BreakStmt>(S) || isa<ContinueStmt>(S) || isa<ReturnStmt>(S) ||
         isa<GotoStmt>(S);
}

std::string srcRange(const Stmt *S, const SourceManager &SM,
                     const LangOptions &LO) {
  if (!S)
    return {};
  return fev::stmtText(S, SM, LO);
}

std::string stmtWithSemi(const Stmt *S, const SourceManager &SM,
                         const LangOptions &LO) {
  SourceLocation Begin = S->getBeginLoc();
  SourceLocation End = S->getEndLoc();
  if (Begin.isInvalid() || End.isInvalid())
    return {};
  SourceLocation AfterSemi = Lexer::findLocationAfterToken(
      End, tok::semi, SM, LO, /*SkipTrailingWhitespaceAndNewLine=*/false);
  CharSourceRange Range;
  if (AfterSemi.isValid())
    Range = CharSourceRange::getCharRange(Begin, AfterSemi);
  else
    Range = CharSourceRange::getTokenRange(Begin, End);
  if (Range.isInvalid())
    return {};
  return Lexer::getSourceText(Range, SM, LO).str();
}

/// Collect statements from a "block" view (CompoundStmt or single stmt).
void collectBlockStmts(const Stmt *Block, std::vector<const Stmt *> &Out) {
  if (const auto *CS = dyn_cast<CompoundStmt>(Block)) {
    for (const Stmt *S : CS->body())
      Out.push_back(S);
  } else if (Block) {
    Out.push_back(Block);
  }
}

std::vector<BlockPart> splitBlock(const Stmt *Block) {
  std::vector<const Stmt *> Stmts;
  collectBlockStmts(Block, Stmts);

  std::vector<BlockPart> Parts;
  std::vector<const Stmt *> Seq;

  auto flushSeq = [&]() {
    if (Seq.empty())
      return;
    BlockPart P;
    P.Kind = PartKind::Sequence;
    P.Sequence = Seq;
    Parts.push_back(std::move(P));
    Seq.clear();
  };

  for (const Stmt *S : Stmts) {
    // Transparent wrappers.
    if (const auto *LS = dyn_cast<LabelStmt>(S)) {
      S = LS->getSubStmt();
    }
    if (const auto *CS = dyn_cast<CaseStmt>(S)) {
      // Switch bodies are preprocessed; if still present, unwrap.
      while (CS) {
        if (const auto *Inner = dyn_cast<CaseStmt>(CS->getSubStmt()))
          CS = Inner;
        else {
          S = CS->getSubStmt();
          CS = nullptr;
        }
      }
    }
    if (const auto *DS = dyn_cast<DefaultStmt>(S))
      S = DS->getSubStmt();

    if (isa<CompoundStmt>(S)) {
      flushSeq();
      BlockPart P;
      P.Kind = PartKind::Block;
      P.Node = S;
      Parts.push_back(P);
    } else if (isa<IfStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::If, S, {}};
      Parts.push_back(P);
    } else if (isa<SwitchStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::Switch, S, {}};
      Parts.push_back(P);
    } else if (isa<WhileStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::While, S, {}};
      Parts.push_back(P);
    } else if (isa<DoStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::Do, S, {}};
      Parts.push_back(P);
    } else if (isa<ForStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::For, S, {}};
      Parts.push_back(P);
    } else if (isa<CXXTryStmt>(S)) {
      flushSeq();
      BlockPart P{PartKind::Try, S, {}};
      Parts.push_back(P);
    } else if (isSequenceBreaker(S)) {
      flushSeq();
      BlockPart P;
      P.Kind = PartKind::Sequence;
      P.Sequence = {S};
      Parts.push_back(P);
    } else {
      Seq.push_back(S);
    }
  }
  flushSeq();
  return Parts;
}

enum class HoistReject {
  None,
  StaticLocal,
  VLA,
  Reference,
  Array,
  Record,
  InitList,
};

const char *hoistRejectMessage(HoistReject R) {
  switch (R) {
  case HoistReject::None:
    return "";
  case HoistReject::StaticLocal:
    return "local static variable cannot be hoisted";
  case HoistReject::VLA:
    return "variable-length array cannot be hoisted";
  case HoistReject::Reference:
    return "reference local cannot be hoisted";
  case HoistReject::Array:
    return "local array cannot be hoisted";
  case HoistReject::Record:
    return "local struct/union/class cannot be hoisted";
  case HoistReject::InitList:
    return "aggregate/init-list initializer cannot be hoisted";
  }
  return "unsupported local declaration";
}

class HoistCollector : public RecursiveASTVisitor<HoistCollector> {
public:
  explicit HoistCollector(std::vector<const VarDecl *> &Out) : Out_(Out) {}

  bool VisitVarDecl(VarDecl *VD) {
    if (!VD->isLocalVarDecl() || isa<ParmVarDecl>(VD))
      return true;
    if (VD->isStaticLocal())
      return reject(HoistReject::StaticLocal, VD);
    QualType T = VD->getType();
    if (T->isVariableArrayType())
      return reject(HoistReject::VLA, VD);
    if (T->isReferenceType())
      return reject(HoistReject::Reference, VD);
    // Avoid `int[N] name` vs `int name[N]` print ambiguity; skip arrays.
    if (T->isArrayType())
      return reject(HoistReject::Array, VD);
    if (T->isRecordType())
      return reject(HoistReject::Record, VD);
    if (VD->hasInit() && isa<InitListExpr>(VD->getInit()))
      return reject(HoistReject::InitList, VD);
    Out_.push_back(VD);
    return true;
  }

  bool ok() const { return Reject_ == HoistReject::None; }
  HoistReject rejectKind() const { return Reject_; }
  const VarDecl *culprit() const { return Culprit_; }

private:
  bool reject(HoistReject Kind, const VarDecl *VD) {
    Reject_ = Kind;
    Culprit_ = VD;
    return false;
  }

  std::vector<const VarDecl *> &Out_;
  HoistReject Reject_ = HoistReject::None;
  const VarDecl *Culprit_ = nullptr;
};

struct FlattenResult {
  std::string Body;
  std::string SkipReason;
  const VarDecl *Culprit = nullptr;
};

void warnFlattenSkip(const FunctionDecl *Fn, const SourceManager &SM,
                     llvm::StringRef Reason, const VarDecl *Culprit) {
  auto Msg = fev::logWarn();
  Msg << "flatten-cfg skipped '";
  if (Fn->getIdentifier())
    Msg << Fn->getName();
  else
    Msg << "<anonymous>";
  Msg << "'";

  SourceLocation Loc = Culprit ? Culprit->getLocation() : Fn->getLocation();
  if (Loc.isValid()) {
    PresumedLoc PLoc = SM.getPresumedLoc(Loc);
    if (PLoc.isValid())
      Msg << " at " << PLoc.getFilename() << ":" << PLoc.getLine() << ":"
          << PLoc.getColumn();
  }

  Msg << ": " << Reason;
  if (Culprit && Culprit->getIdentifier())
    Msg << " (variable '" << Culprit->getName() << "')";
}

unsigned countStmts(const Stmt *S) {
  if (!S)
    return 0;
  if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
    unsigned N = 0;
    for (const Stmt *C : CS->body())
      N += countStmts(C);
    return N;
  }
  if (const auto *If = dyn_cast<IfStmt>(S))
    return 1 + countStmts(If->getThen()) + countStmts(If->getElse());
  if (const auto *W = dyn_cast<WhileStmt>(S))
    return 1 + countStmts(W->getBody());
  if (const auto *D = dyn_cast<DoStmt>(S))
    return 1 + countStmts(D->getBody());
  if (const auto *F = dyn_cast<ForStmt>(S))
    return 1 + countStmts(F->getInit()) + countStmts(F->getBody());
  if (const auto *Sw = dyn_cast<SwitchStmt>(S))
    return 1 + countStmts(Sw->getBody());
  if (const auto *T = dyn_cast<CXXTryStmt>(S)) {
    unsigned N = 1 + countStmts(T->getTryBlock());
    for (unsigned I = 0; I < T->getNumHandlers(); ++I)
      N += countStmts(T->getHandler(I)->getHandlerBlock());
    return N;
  }
  return 1;
}

class LaszloFlattener {
public:
  LaszloFlattener(const SourceManager &SM, const LangOptions &LO,
                  std::uint64_t Seed, unsigned FnIndex)
      : SM_(SM), LO_(LO), Rng_(Seed ^ (0x9E3779B97F4A7C15ULL * (FnIndex + 1))),
        Mask_((std::uint32_t)(Seed ^ 0xA5A5A5A5u ^ (FnIndex * 0x10001u)) |
              1u) {}

  /// Flatten function body, or leave Body empty with SkipReason set.
  FlattenResult flattenFunction(const FunctionDecl *Fn) {
    FlattenResult Result;
    const auto *Body = dyn_cast<CompoundStmt>(Fn->getBody());
    if (!Body) {
      Result.SkipReason = "function body is not a compound statement";
      return Result;
    }

    std::vector<const VarDecl *> Vars;
    HoistCollector HC(Vars);
    HC.TraverseStmt(Fn->getBody());
    if (!HC.ok()) {
      Result.SkipReason = hoistRejectMessage(HC.rejectKind());
      Result.Culprit = HC.culprit();
      return Result;
    }

    // Unique names for collisions across scopes.
    std::set<std::string> UsedNames;
    for (const VarDecl *VD : Vars) {
      std::string Base = VD->getNameAsString();
      if (Base.empty()) {
        Result.SkipReason = "anonymous local variable cannot be hoisted";
        Result.Culprit = VD;
        return Result;
      }
      std::string Name = Base;
      unsigned Suffix = 0;
      while (!UsedNames.insert(Name).second) {
        Name = Base + "_fev" + std::to_string(++Suffix);
      }
      if (Name != Base)
        Renames_[VD] = Name;
    }

    unsigned Entry = uniqueNumber();
    unsigned Exit = uniqueNumber();
    std::string SwVar = freshVar();
    std::string WhileLab = freshLabel();
    Result.Body = buildFinalBody(Fn, Vars, SwVar, WhileLab, Entry, Exit, Body);
    if (Result.Body.empty())
      Result.SkipReason =
          "failed to lower control flow (unsupported construct or rewrite "
          "error)";
    return Result;
  }

private:
  const SourceManager &SM_;
  const LangOptions &LO_;
  std::mt19937_64 Rng_;
  std::uint32_t Mask_;

  std::vector<LevelInfo> Levels_;
  std::vector<BreakContInfo> Breaks_;
  std::vector<BreakContInfo> Continues_;

  /// Logical state id → case body (inner statements only, no `case`/`break`
  /// wrapper trailer beyond what transform emits).
  struct CaseBlock {
    unsigned Id = 0;
    std::string Body;
    std::vector<std::string> LeadLabels; // labels before case content
  };
  std::vector<CaseBlock> Cases_;

  std::map<const VarDecl *, std::string> Renames_;
  std::map<const Stmt *, std::vector<std::string>> ExtraLabels_;
  std::set<unsigned> UsedIds_;
  unsigned VarCounter_ = 0;
  unsigned LabelCounter_ = 0;
  bool Failed_ = false;

  unsigned uniqueNumber() {
    for (int Attempt = 0; Attempt < 64; ++Attempt) {
      unsigned Id = (unsigned)(Rng_() & 0x0fffffffu);
      if (Id == 0)
        Id = 1;
      if (UsedIds_.insert(Id).second)
        return Id;
    }
    unsigned Id = (unsigned)UsedIds_.size() + 1u;
    while (!UsedIds_.insert(Id).second)
      ++Id;
    return Id;
  }

  std::string freshVar() {
    return "_fev_sw" + std::to_string(VarCounter_++);
  }

  std::string freshLabel() {
    return "_fev_L" + std::to_string(LabelCounter_++);
  }

  std::string encLit(unsigned LogicalId) const {
    std::string S;
    llvm::raw_string_ostream OS(S);
    OS << llvm::format("0x%x", (LogicalId ^ Mask_)) << "u";
    return OS.str();
  }

  std::string topVar() const { return Levels_.back().Var; }
  std::string topLabel() const { return Levels_.back().Label; }

  std::string setState(unsigned LogicalNext) const {
    return topVar() + " = " + encLit(LogicalNext) + " + _fev_mod";
  }

  void emitCase(unsigned Id, const std::string &Inner,
                const std::vector<std::string> &Labs = {}) {
    CaseBlock CB;
    CB.Id = Id;
    CB.Body = Inner;
    CB.LeadLabels = Labs;
    Cases_.push_back(std::move(CB));
  }

  std::string buildFinalBody(const FunctionDecl *Fn,
                             const std::vector<const VarDecl *> &Vars,
                             const std::string &SwVar,
                             const std::string &WhileLab, unsigned Entry,
                             unsigned Exit, const Stmt *Body) {
    // Reset and re-run transform into Cases_ with known SwVar/WhileLab.
    Cases_.clear();
    Levels_.clear();
    Breaks_.clear();
    Continues_.clear();
    ExtraLabels_.clear();
    Failed_ = false;
    // Keep Renames_, Mask_, UsedIds_ for Entry/Exit already allocated.
    // Re-seed UsedIds_ to include Entry/Exit only — uniqueNumber during
    // transform needs free ids. Entry/Exit already in UsedIds_.

    Levels_.push_back({SwVar, WhileLab});
    if (!transformBlock(Body, Entry, Exit))
      return {};
    Levels_.pop_back();

    // Permute case order (László §5).
    std::shuffle(Cases_.begin(), Cases_.end(), Rng_);

    std::string Out;
    llvm::raw_string_ostream OS(Out);
    OS << "{\n";
    for (const VarDecl *VD : Vars) {
      std::string Name =
          Renames_.count(VD) ? Renames_[VD] : VD->getNameAsString();
      OS << "  " << VD->getType().getAsString() << " " << Name << ";\n";
    }
    OS << "  /* László-style CFF: XOR-encoded volatile dispatcher */\n";
    OS << "  volatile unsigned " << SwVar << " = " << encLit(Entry) << ";\n";
    OS << "  volatile unsigned _fev_mod = 0u;\n";
    // Always reference the level label so cross-level gotos compile cleanly
    // even when no break/continue actually jumps here.
    OS << "  goto " << WhileLab << ";\n";
    OS << WhileLab << ":\n";
    OS << "  while (" << SwVar << " != " << encLit(Exit) << ") {\n";
    OS << "    switch (" << SwVar << " ^ " << llvm::format("0x%x", Mask_)
       << "u) {\n";

    for (const CaseBlock &CB : Cases_) {
      for (const std::string &Lab : CB.LeadLabels)
        OS << "    " << Lab << ":\n";
      OS << "    case " << CB.Id << "u: {\n";
      OS << CB.Body;
      if (!CB.Body.empty() && CB.Body.back() != '\n')
        OS << "\n";
      OS << "    }\n";
    }

    OS << "    default: {\n";
    OS << "      volatile unsigned _fev_trap = " << SwVar
       << "; (void)_fev_trap;\n";
    OS << "      " << SwVar << " = " << encLit(Exit) << ";\n";
    OS << "      break;\n";
    OS << "    }\n";
    OS << "    }\n";
    OS << "  }\n";
    if (!Fn->getReturnType()->isVoidType())
      OS << "  __builtin_unreachable();\n";
    OS << "}\n";
    return OS.str();
  }

  bool transformBlock(const Stmt *Block, unsigned Entry, unsigned Exit) {
    auto Parts = splitBlock(Block);
    if (Parts.empty()) {
      // Empty block: still need a case that jumps to exit.
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      IOS << "      " << setState(Exit) << ";\n";
      IOS << "      break;\n";
      emitCase(Entry, IOS.str());
      return true;
    }

    unsigned Cur = Entry;
    for (size_t I = 0, E = Parts.size(); I != E; ++I) {
      unsigned PartExit = (I + 1 == E) ? Exit : uniqueNumber();
      if (!transformPart(Parts[I], Cur, PartExit))
        return false;
      Cur = PartExit;
    }
    return !Failed_;
  }

  bool transformPart(const BlockPart &Part, unsigned Entry, unsigned Exit) {
    switch (Part.Kind) {
    case PartKind::Block:
      return transformBlock(Part.Node, Entry, Exit);
    case PartKind::If:
      return transformIf(cast<IfStmt>(Part.Node), Entry, Exit);
    case PartKind::Switch:
      return transformSwitch(cast<SwitchStmt>(Part.Node), Entry, Exit);
    case PartKind::While:
      return transformWhile(cast<WhileStmt>(Part.Node), Entry, Exit);
    case PartKind::Do:
      return transformDo(cast<DoStmt>(Part.Node), Entry, Exit);
    case PartKind::For:
      return transformFor(cast<ForStmt>(Part.Node), Entry, Exit);
    case PartKind::Try:
      return transformTry(cast<CXXTryStmt>(Part.Node), Entry, Exit);
    case PartKind::Sequence:
      return transformSequence(Part.Sequence, Entry, Exit);
    }
    return false;
  }

  std::vector<std::string> labelsFor(const Stmt *S) {
    std::vector<std::string> Labs;
    auto It = ExtraLabels_.find(S);
    if (It != ExtraLabels_.end())
      Labs = It->second;
    return Labs;
  }

  bool transformIf(const IfStmt *If, unsigned Entry, unsigned Exit) {
    unsigned ThenEntry = uniqueNumber();
    unsigned ElseEntry = If->getElse() ? uniqueNumber() : Exit;

    std::string Cond = srcRange(If->getCond(), SM_, LO_);
    if (Cond.empty())
      return false;

    std::string Inner;
    llvm::raw_string_ostream IOS(Inner);
    for (const std::string &Lab : labelsFor(If))
      IOS << "      " << Lab << ":\n";
    IOS << "      if (" << Cond << ")\n";
    IOS << "        " << setState(ThenEntry) << ";\n";
    IOS << "      else\n";
    IOS << "        " << setState(ElseEntry) << ";\n";
    IOS << "      break;\n";
    emitCase(Entry, IOS.str());

    if (!transformBlock(If->getThen(), ThenEntry, Exit))
      return false;
    if (If->getElse()) {
      if (!transformBlock(If->getElse(), ElseEntry, Exit))
        return false;
    }
    return true;
  }

  bool transformWhile(const WhileStmt *W, unsigned Entry, unsigned Exit) {
    unsigned BodyEntry = uniqueNumber();
    std::string Cond = srcRange(W->getCond(), SM_, LO_);
    if (Cond.empty())
      return false;

    std::string Inner;
    llvm::raw_string_ostream IOS(Inner);
    for (const std::string &Lab : labelsFor(W))
      IOS << "      " << Lab << ":\n";
    IOS << "      if (" << Cond << ")\n";
    IOS << "        " << setState(BodyEntry) << ";\n";
    IOS << "      else\n";
    IOS << "        " << setState(Exit) << ";\n";
    IOS << "      break;\n";
    emitCase(Entry, IOS.str());

    Breaks_.push_back({Levels_.size(), Exit});
    Continues_.push_back({Levels_.size(), Entry});
    bool Ok = transformBlock(W->getBody(), BodyEntry, Entry);
    Continues_.pop_back();
    Breaks_.pop_back();
    return Ok;
  }

  bool transformDo(const DoStmt *D, unsigned Entry, unsigned Exit) {
    unsigned TestEntry = uniqueNumber();
    unsigned BodyEntry = uniqueNumber();
    std::string Cond = srcRange(D->getCond(), SM_, LO_);
    if (Cond.empty())
      return false;

    // Entry case jumps into body first (do-while).
    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      for (const std::string &Lab : labelsFor(D))
        IOS << "      " << Lab << ":\n";
      IOS << "      " << setState(BodyEntry) << ";\n";
      IOS << "      break;\n";
      emitCase(Entry, IOS.str());
    }
    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      IOS << "      if (" << Cond << ")\n";
      IOS << "        " << setState(BodyEntry) << ";\n";
      IOS << "      else\n";
      IOS << "        " << setState(Exit) << ";\n";
      IOS << "      break;\n";
      emitCase(TestEntry, IOS.str());
    }

    Breaks_.push_back({Levels_.size(), Exit});
    Continues_.push_back({Levels_.size(), TestEntry});
    bool Ok = transformBlock(D->getBody(), BodyEntry, TestEntry);
    Continues_.pop_back();
    Breaks_.pop_back();
    return Ok;
  }

  bool transformFor(const ForStmt *F, unsigned Entry, unsigned Exit) {
    unsigned TestEntry = uniqueNumber();
    unsigned IncEntry = uniqueNumber();
    unsigned BodyEntry = uniqueNumber();

    // Init case.
    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      for (const std::string &Lab : labelsFor(F))
        IOS << "      " << Lab << ":\n";
      if (const Stmt *Init = F->getInit()) {
        if (const auto *DS = dyn_cast<DeclStmt>(Init)) {
          IOS << emitDeclInits(DS);
        } else {
          std::string T = stmtWithSemi(Init, SM_, LO_);
          if (T.empty())
            return false;
          IOS << "      " << T << "\n";
        }
      }
      IOS << "      " << setState(TestEntry) << ";\n";
      IOS << "      break;\n";
      emitCase(Entry, IOS.str());
    }

    // Test case.
    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      if (const Expr *Cond = F->getCond()) {
        std::string C = srcRange(Cond, SM_, LO_);
        if (C.empty())
          return false;
        IOS << "      if (" << C << ")\n";
        IOS << "        " << setState(BodyEntry) << ";\n";
        IOS << "      else\n";
        IOS << "        " << setState(Exit) << ";\n";
      } else {
        IOS << "      " << setState(BodyEntry) << ";\n";
      }
      IOS << "      break;\n";
      emitCase(TestEntry, IOS.str());
    }

    // Increment case.
    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      if (const Expr *Inc = F->getInc()) {
        std::string T = srcRange(Inc, SM_, LO_);
        if (T.empty())
          return false;
        IOS << "      " << T << ";\n";
      }
      IOS << "      " << setState(TestEntry) << ";\n";
      IOS << "      break;\n";
      emitCase(IncEntry, IOS.str());
    }

    Breaks_.push_back({Levels_.size(), Exit});
    Continues_.push_back({Levels_.size(), IncEntry});
    bool Ok = transformBlock(F->getBody(), BodyEntry, IncEntry);
    Continues_.pop_back();
    Breaks_.pop_back();
    return Ok;
  }

  bool transformSwitch(const SwitchStmt *Sw, unsigned Entry, unsigned Exit) {
    std::string Cond = srcRange(Sw->getCond(), SM_, LO_);
    if (Cond.empty())
      return false;

    // Collect case/default targets and attach goto labels.
    struct CaseArm {
      std::string CaseLabelSrc; // "case 1" or "default"
      const Stmt *Target = nullptr;
      std::string GotoLab;
    };
    std::vector<CaseArm> Arms;

    const Stmt *Body = Sw->getBody();
    std::vector<const Stmt *> FlatBody;
    std::function<void(const Stmt *)> walk = [&](const Stmt *S) {
      if (!S)
        return;
      if (const auto *CS = dyn_cast<CompoundStmt>(S)) {
        for (const Stmt *C : CS->body())
          walk(C);
        return;
      }
      if (const auto *C = dyn_cast<CaseStmt>(S)) {
        CaseArm Arm;
        Arm.CaseLabelSrc = "case " + srcRange(C->getLHS(), SM_, LO_);
        if (C->getRHS())
          Arm.CaseLabelSrc += " ... " + srcRange(C->getRHS(), SM_, LO_);
        Arm.GotoLab = freshLabel();
        const Stmt *Sub = C->getSubStmt();
        // Nested case labels fall through to ultimate stmt.
        while (const auto *Inner = dyn_cast<CaseStmt>(Sub)) {
          CaseArm Nest;
          Nest.CaseLabelSrc = "case " + srcRange(Inner->getLHS(), SM_, LO_);
          Nest.GotoLab = Arm.GotoLab; // same target until real stmt
          // Will fix targets below.
          Sub = Inner->getSubStmt();
          Arms.push_back(Nest);
        }
        if (const auto *Def = dyn_cast<DefaultStmt>(Sub)) {
          CaseArm Nest;
          Nest.CaseLabelSrc = "default";
          Nest.GotoLab = Arm.GotoLab;
          Sub = Def->getSubStmt();
          Arms.push_back(Nest);
        }
        Arm.Target = Sub;
        Arms.push_back(Arm);
        ExtraLabels_[Sub].push_back(Arm.GotoLab);
        FlatBody.push_back(Sub);
        return;
      }
      if (const auto *D = dyn_cast<DefaultStmt>(S)) {
        CaseArm Arm;
        Arm.CaseLabelSrc = "default";
        Arm.GotoLab = freshLabel();
        Arm.Target = D->getSubStmt();
        Arms.push_back(Arm);
        ExtraLabels_[Arm.Target].push_back(Arm.GotoLab);
        FlatBody.push_back(Arm.Target);
        return;
      }
      FlatBody.push_back(S);
    };
    walk(Body);

    // Fix nested case arms that share goto but need own labels pointing to
    // same target — already share GotoLab.

    {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      for (const std::string &Lab : labelsFor(Sw))
        IOS << "      " << Lab << ":\n";
      IOS << "      switch (" << Cond << ") {\n";
      for (const CaseArm &A : Arms) {
        IOS << "        " << A.CaseLabelSrc << ": goto " << A.GotoLab << ";\n";
      }
      IOS << "      }\n";
      IOS << "      " << setState(Exit) << ";\n";
      IOS << "      break;\n";
      emitCase(Entry, IOS.str());
    }

    Breaks_.push_back({Levels_.size(), Exit});
    unsigned BodyEntry = uniqueNumber();

    BlockPart SeqAccum;
    SeqAccum.Kind = PartKind::Sequence;
    std::vector<BlockPart> Parts;
    auto flush = [&]() {
      if (!SeqAccum.Sequence.empty()) {
        Parts.push_back(SeqAccum);
        SeqAccum.Sequence.clear();
      }
    };
    for (const Stmt *S : FlatBody) {
      BlockPart Tmp;
      // Reuse split logic via a one-element compound simulation:
      if (isControlOrCompound(S) && !isa<DeclStmt>(S)) {
        flush();
        if (isa<CompoundStmt>(S))
          Parts.push_back({PartKind::Block, S, {}});
        else if (isa<IfStmt>(S))
          Parts.push_back({PartKind::If, S, {}});
        else if (isa<WhileStmt>(S))
          Parts.push_back({PartKind::While, S, {}});
        else if (isa<DoStmt>(S))
          Parts.push_back({PartKind::Do, S, {}});
        else if (isa<ForStmt>(S))
          Parts.push_back({PartKind::For, S, {}});
        else if (isa<SwitchStmt>(S))
          Parts.push_back({PartKind::Switch, S, {}});
        else if (isa<CXXTryStmt>(S))
          Parts.push_back({PartKind::Try, S, {}});
        else {
          SeqAccum.Sequence.push_back(S);
        }
      } else if (isSequenceBreaker(S)) {
        flush();
        Parts.push_back({PartKind::Sequence, nullptr, {S}});
      } else {
        SeqAccum.Sequence.push_back(S);
      }
    }
    flush();

    unsigned Cur = BodyEntry;
    // Dispatcher falls into body via goto labels on cases; also set BodyEntry
    // unused as direct entry — gotos land on labels inside cases. Emit a
    // trampoline case BodyEntry that just goes to Exit if somehow entered.
    if (Parts.empty()) {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      IOS << "      " << setState(Exit) << ";\n";
      IOS << "      break;\n";
      emitCase(BodyEntry, IOS.str());
    } else {
      for (size_t I = 0, N = Parts.size(); I != N; ++I) {
        unsigned PartExit = (I + 1 == N) ? Exit : uniqueNumber();
        // Attach ExtraLabels from first stmt onto the case via transformSequence
        if (!transformPart(Parts[I], Cur, PartExit)) {
          Breaks_.pop_back();
          return false;
        }
        Cur = PartExit;
      }
    }

    Breaks_.pop_back();
    (void)BodyEntry;
    return true;
  }

  bool transformTry(const CXXTryStmt *Try, unsigned Entry, unsigned Exit) {
    // Nested flatten level under try (László Fig. 4).
    std::string InnerVar = freshVar();
    std::string InnerLab = freshLabel();
    unsigned InnerEntry = uniqueNumber();
    unsigned InnerExit = uniqueNumber();

    std::string Inner;
    llvm::raw_string_ostream IOS(Inner);
    for (const std::string &Lab : labelsFor(Try))
      IOS << "      " << Lab << ":\n";
    IOS << "      try {\n";
    IOS << "        volatile unsigned " << InnerVar << " = "
        << encLit(InnerEntry) << ";\n";
    IOS << "        goto " << InnerLab << ";\n";
    IOS << InnerLab << ":\n";
    IOS << "        while (" << InnerVar << " != " << encLit(InnerExit)
        << ") {\n";
    IOS << "          switch (" << InnerVar << " ^ "
        << llvm::format("0x%x", Mask_) << "u) {\n";
    IOS << "          /* nested cases spliced below */\n";
    IOS << "__FEV_TRY_CASES__\n";
    IOS << "          default: " << InnerVar << " = " << encLit(InnerExit)
        << "; break;\n";
    IOS << "          }\n";
    IOS << "        }\n";
    IOS << "        " << setState(Exit) << ";\n";
    IOS << "      }";

    // Handlers: each gets its own nested flatten, then continue outer.
    for (unsigned H = 0; H < Try->getNumHandlers(); ++H) {
      const CXXCatchStmt *Catch = Try->getHandler(H);
      IOS << " catch (";
      if (Catch->getExceptionDecl()) {
        IOS << Catch->getExceptionDecl()->getType().getAsString() << " "
            << Catch->getExceptionDecl()->getNameAsString();
      } else {
        IOS << "...";
      }
      IOS << ") {\n";
      IOS << "__FEV_CATCH_" << H << "__\n";
      IOS << "        " << setState(Exit) << ";\n";
      IOS << "      }";
    }
    IOS << "\n      break;\n";

    // Generate nested cases for try body.
    std::vector<CaseBlock> Saved = std::move(Cases_);
    Cases_.clear();
    Levels_.push_back({InnerVar, InnerLab});
    bool Ok = transformBlock(Try->getTryBlock(), InnerEntry, InnerExit);
    Levels_.pop_back();
    std::vector<CaseBlock> TryCases = std::move(Cases_);

    std::vector<std::vector<CaseBlock>> CatchCases(Try->getNumHandlers());
    for (unsigned H = 0; H < Try->getNumHandlers(); ++H) {
      Cases_.clear();
      std::string CVar = freshVar();
      std::string CLab = freshLabel();
      unsigned CE = uniqueNumber();
      unsigned CX = uniqueNumber();
      Levels_.push_back({CVar, CLab});
      const CXXCatchStmt *Catch = Try->getHandler(H);
      Ok = Ok && transformBlock(Catch->getHandlerBlock(), CE, CX);
      Levels_.pop_back();
      CatchCases[H] = std::move(Cases_);

      // Wrap catch cases into a mini-dispatcher string for placeholder.
      std::string CatchDisp;
      llvm::raw_string_ostream CDS(CatchDisp);
      CDS << "        volatile unsigned " << CVar << " = " << encLit(CE)
          << ";\n";
      CDS << "        goto " << CLab << ";\n";
      CDS << CLab << ":\n";
      CDS << "        while (" << CVar << " != " << encLit(CX) << ") {\n";
      CDS << "          switch (" << CVar << " ^ " << llvm::format("0x%x", Mask_)
          << "u) {\n";
      std::shuffle(CatchCases[H].begin(), CatchCases[H].end(), Rng_);
      for (const CaseBlock &CB : CatchCases[H]) {
        for (const std::string &Lab : CB.LeadLabels)
          CDS << "          " << Lab << ":\n";
        CDS << "          case " << CB.Id << "u: {\n" << CB.Body << "          }\n";
      }
      CDS << "          default: " << CVar << " = " << encLit(CX)
          << "; break;\n";
      CDS << "          }\n";
      CDS << "        }\n";
      CatchCases[H].clear();
      CatchCases[H].push_back({0, CDS.str(), {}}); // stash as single blob
    }

    Cases_ = std::move(Saved);

    // Splice try cases into placeholder.
    std::string TryCaseText;
    {
      llvm::raw_string_ostream TCS(TryCaseText);
      std::shuffle(TryCases.begin(), TryCases.end(), Rng_);
      for (const CaseBlock &CB : TryCases) {
        for (const std::string &Lab : CB.LeadLabels)
          TCS << "          " << Lab << ":\n";
        TCS << "          case " << CB.Id << "u: {\n"
            << CB.Body << "          }\n";
      }
    }

    std::string FinalInner = Inner;
    auto replaceAll = [](std::string &S, const std::string &A,
                         const std::string &B) {
      size_t Pos = 0;
      while ((Pos = S.find(A, Pos)) != std::string::npos) {
        S.replace(Pos, A.size(), B);
        Pos += B.size();
      }
    };
    replaceAll(FinalInner, "__FEV_TRY_CASES__", TryCaseText);
    for (unsigned H = 0; H < Try->getNumHandlers(); ++H) {
      std::string Key = "__FEV_CATCH_" + std::to_string(H) + "__";
      std::string Val =
          CatchCases[H].empty() ? std::string() : CatchCases[H][0].Body;
      replaceAll(FinalInner, Key, Val);
    }

    emitCase(Entry, FinalInner);
    return Ok;
  }

  std::string emitDeclInits(const DeclStmt *DS) {
    std::string Out;
    llvm::raw_string_ostream OS(Out);
    for (const Decl *D : DS->decls()) {
      const auto *VD = dyn_cast<VarDecl>(D);
      if (!VD || !VD->hasInit())
        continue;
      std::string Name =
          Renames_.count(VD) ? Renames_[VD] : VD->getNameAsString();
      std::string Init = srcRange(VD->getInit(), SM_, LO_);
      if (Init.empty()) {
        Failed_ = true;
        return {};
      }
      OS << "      " << Name << " = " << Init << ";\n";
    }
    return OS.str();
  }

  bool transformSequence(const std::vector<const Stmt *> &Stmts,
                         unsigned Entry, unsigned Exit) {
    if (Stmts.empty()) {
      std::string Inner;
      llvm::raw_string_ostream IOS(Inner);
      IOS << "      " << setState(Exit) << ";\n";
      IOS << "      break;\n";
      emitCase(Entry, IOS.str());
      return true;
    }

    std::string Inner;
    llvm::raw_string_ostream IOS(Inner);

    // Lead labels attached to the first real statement.
    for (const std::string &Lab : labelsFor(Stmts.front()))
      IOS << "      " << Lab << ":\n";

    bool EndsWithTransfer = false;
    for (const Stmt *S : Stmts) {
      // LabelStmt wrapper.
      if (const auto *LS = dyn_cast<LabelStmt>(S)) {
        IOS << "      " << LS->getName() << ":\n";
        S = LS->getSubStmt();
      }

      if (isa<NullStmt>(S))
        continue;

      if (isa<BreakStmt>(S)) {
        if (Breaks_.empty())
          return false;
        const BreakContInfo &B = Breaks_.back();
        IOS << "      " << Levels_[B.Level - 1].Var << " = "
            << encLit(B.Entry) << " + _fev_mod;\n";
        if (B.Level != Levels_.size()) {
          IOS << "      goto " << Levels_[B.Level - 1].Label << ";\n";
        } else {
          IOS << "      break;\n";
        }
        EndsWithTransfer = true;
        continue;
      }

      if (isa<ContinueStmt>(S)) {
        if (Continues_.empty())
          return false;
        const BreakContInfo &C = Continues_.back();
        IOS << "      " << Levels_[C.Level - 1].Var << " = "
            << encLit(C.Entry) << " + _fev_mod;\n";
        if (C.Level != Levels_.size()) {
          IOS << "      goto " << Levels_[C.Level - 1].Label << ";\n";
        } else {
          IOS << "      break;\n";
        }
        EndsWithTransfer = true;
        continue;
      }

      if (isa<ReturnStmt>(S) || isa<GotoStmt>(S)) {
        std::string T = stmtWithSemi(S, SM_, LO_);
        if (T.empty())
          return false;
        IOS << "      " << T << "\n";
        EndsWithTransfer = true;
        continue;
      }

      if (const auto *DS = dyn_cast<DeclStmt>(S)) {
        std::string Inits = emitDeclInits(DS);
        if (Failed_)
          return false;
        IOS << Inits;
        continue;
      }

      std::string T = stmtWithSemi(S, SM_, LO_);
      if (T.empty()) {
        // Expr without semi (rare) — pretty-print via range.
        T = srcRange(S, SM_, LO_);
        if (T.empty())
          return false;
        T += ";";
      }
      // Apply renames for simple identifier uses is hard; decls already renamed
      // at hoist. Inits use renamed LHS. Body text keeps original names — only
      // renamed when collision; ensure collision renames are substituted.
      if (!Renames_.empty()) {
        // Best-effort: replace whole-word original names. Skip if none needed
        // in this stmt — names only change on collision.
        for (const auto &KV : Renames_) {
          const std::string &From = KV.first->getNameAsString();
          const std::string &To = KV.second;
          // crude replace
          size_t Pos = 0;
          while ((Pos = T.find(From, Pos)) != std::string::npos) {
            bool LeftOk =
                Pos == 0 || (!std::isalnum((unsigned char)T[Pos - 1]) &&
                             T[Pos - 1] != '_');
            size_t End = Pos + From.size();
            bool RightOk =
                End >= T.size() || (!std::isalnum((unsigned char)T[End]) &&
                                    T[End] != '_');
            if (LeftOk && RightOk) {
              T.replace(Pos, From.size(), To);
              Pos += To.size();
            } else {
              Pos = End;
            }
          }
        }
      }
      IOS << "      " << T << "\n";
    }

    if (!EndsWithTransfer) {
      IOS << "      " << setState(Exit) << ";\n";
      IOS << "      break;\n";
    }
    emitCase(Entry, IOS.str());
    return true;
  }
};

class FlattenCFGPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "flatten-cfg"; }

  llvm::StringRef description() const override {
    return "László-style control-flow flattening (if/while/do/for/switch/try, "
           "break/continue rewrite, permuted XOR+volatile dispatcher)";
  }

  bool run(fev::PassContext &Ctx) override {
    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO, std::uint64_t Seed,
              unsigned MinStmts)
          : Rewriter_(R), LangOpts_(LO), Seed_(Seed), MinStmts_(MinStmts) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn");
        if (!Fn || !Fn->hasBody())
          return;
        auto *Body = dyn_cast<CompoundStmt>(Fn->getBody());
        if (!Body)
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Body->getLBracLoc(), SM))
          return;
        if (countStmts(Body) < MinStmts_)
          return;

        LaszloFlattener Fl(SM, LangOpts_, Seed_, FnIndex_++);
        FlattenResult Flat = Fl.flattenFunction(Fn);
        if (Flat.Body.empty()) {
          if (!Flat.SkipReason.empty())
            warnFlattenSkip(Fn, SM, Flat.SkipReason, Flat.Culprit);
          return;
        }

        const CharSourceRange Range = CharSourceRange::getTokenRange(
            Body->getBeginLoc(), Body->getEndLoc());
        if (Range.isInvalid()) {
          warnFlattenSkip(Fn, SM, "invalid source range for function body",
                          nullptr);
          return;
        }
        (void)Rewriter_.ReplaceText(Range, Flat.Body);
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
      std::uint64_t Seed_;
      unsigned MinStmts_;
      unsigned FnIndex_ = 0;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts(), Ctx.Config.Seed,
              Ctx.Config.FlattenMinStmts);
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &H);
    Finder.matchAST(Ctx.AST);
    return true;
  }
};

FEV_REGISTER_PASS(FlattenCFGPass);

} // namespace
