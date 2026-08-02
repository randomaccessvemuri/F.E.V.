#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/TypeLoc.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

/// Built-in benign-looking C identifiers (used when --name-dict is omitted).
const char *const kBuiltinDict[] = {
    "alpha",    "anchor",   "answer",   "apple",    "april",    "area",
    "arena",    "array",    "arrow",    "aside",    "asset",    "atlas",
    "audio",    "autumn",   "avenue",   "badge",    "baker",    "balance",
    "bamboo",   "banner",   "barrel",   "basin",    "beacon",   "beaver",
    "bench",    "berry",    "binary",   "blade",    "blank",    "blend",
    "bliss",    "block",    "bloom",    "board",    "bonus",    "boost",
    "border",   "bottle",   "branch",   "brave",    "bread",    "bridge",
    "brief",    "bright",   "bronze",   "brook",    "brush",    "bucket",
    "budget",   "buffer",   "build",    "bundle",   "bureau",   "button",
    "cable",    "cache",    "cafe",     "cake",     "calendar", "camera",
    "campus",   "canal",    "candle",   "canvas",   "canyon",   "carbon",
    "career",   "cargo",    "carpet",   "castle",   "catalog",  "cedar",
    "celery",   "center",   "cereal",   "chain",    "chair",    "chalk",
    "chapel",   "charge",   "chart",    "chase",    "check",    "cheese",
    "cherry",   "chest",    "chief",    "child",    "chord",    "chrome",
    "cipher",   "circle",   "circus",   "citizen",  "civic",    "claim",
    "clamp",    "clause",   "clean",    "clear",    "clerk",    "click",
    "client",   "cliff",    "climb",    "clock",    "clone",    "cloud",
    "coach",    "coast",    "cocoa",    "coffee",   "collar",   "colony",
    "column",   "combat",   "comedy",   "comic",    "comma",    "common",
    "copper",   "coral",    "corner",   "cotton",   "couch",    "county",
    "couple",   "course",   "cover",    "craft",    "crane",    "crash",
    "crate",    "crayon",   "cream",    "credit",   "creek",    "crest",
    "crime",    "crisis",   "critic",   "cross",    "crowd",    "crown",
    "crude",    "cruise",   "crush",    "crystal",  "cubic",    "culture",
    "cupboard", "curtain",  "curve",    "custom",   "cycle",    "daily",
    "dairy",    "dance",    "dealer",   "debate",   "decade",   "decimal",
    "deck",     "decor",    "deed",     "degree",   "delay",    "delta",
    "demand",   "denim",    "dental",   "depot",    "depth",    "deputy",
    "desert",   "design",   "desk",     "detail",   "device",   "diary",
    "digit",    "dinner",   "direct",   "disk",     "divide",   "doctor",
    "domain",   "donor",    "door",     "draft",    "dragon",   "drama",
    "dream",    "dress",    "drift",    "drill",    "drink",    "drive",
    "drop",     "drum",     "dryer",    "duck",     "dusk",     "dust",
    "duty",     "eagle",    "earth",    "east",     "easy",     "echo",
    "edge",     "editor",   "effect",   "effort",   "eight",    "elbow",
    "elder",    "elect",    "element",  "elite",    "email",    "empire",
    "empty",    "enable",   "ending",   "enemy",    "energy",   "engine",
    "enough",   "entry",    "envoy",    "equal",    "error",    "escape",
    "essay",    "estate",   "event",    "every",    "exact",    "exam",
    "excel",    "except",   "excess",   "exchange", "excuse",   "execute",
    "exempt",   "exercise", "exhaust",  "exhibit",  "exile",    "exist",
    "exit",     "expand",   "expect",   "expert",   "expire",   "explain",
    "explore",  "export",   "expose",   "express",  "extend",   "extra",
    "fabric",   "face",     "factor",    "factory",  "faculty",  "fade",
    "fail",     "fair",     "faith",    "fall",     "fame",     "family",
    "famous",   "fancy",    "farm",     "fashion",  "fast",     "fate",
    "father",   "fault",    "favor",    "fear",     "feast",    "feat",
    "federal",  "feed",     "feel",     "fence",    "ferry",    "fever",
    "fiber",    "fiction",  "field",    "fifteen",  "fifth",    "fifty",
    "fight",    "figure",   "file",     "fill",     "film",     "filter",
    "final",    "finance",  "find",     "fine",     "finger",   "finish",
    "fire",     "firm",     "first",    "fiscal",   "fish",     "fit",
    "five",     "fix",     "flag",     "flame",    "flash",    "flat",
    "flavor",   "flee",     "fleet",    "flesh",    "flight",   "float",
    "flood",    "floor",    "flour",    "flow",     "flower",   "fluid",
    "flush",    "foam",     "focus",    "fold",     "folk",     "follow",
    "food",     "foot",     "force",    "forest",   "forget",   "fork",
    "form",     "formal",   "format",   "former",   "formula",  "fort",
    "forth",    "forty",    "forum",    "forward",  "found",    "four",
    "frame",    "frank",    "fraud",    "free",     "fresh",    "friend",
    "front",    "frost",    "fruit",    "fuel",     "full",     "function",
    "fund",     "funeral",  "funny",    "furnace",  "furniture","further",
    "future",   "gain",     "galaxy",   "gallery",  "game",     "gang",
    "garage",   "garden",   "garlic",   "gate",     "gather",   "gauge",
    "gear",     "gender",   "gene",     "general",  "gift",     "glass",
    "global",   "glory",    "glove",    "goal",     "gold",     "golf",
    "good",     "govern",   "grab",     "grade",    "grain",    "grand",
    "grant",    "grape",    "graph",    "grasp",    "grass",    "grave",
    "gray",     "great",    "green",    "greet",    "grid",     "grief",
    "grill",    "grind",    "grip",     "grocery",  "ground",   "group",
    "grow",     "growth",   "guard",    "guess",    "guest",    "guide",
    "guilt",    "guitar",   "habit",    "hair",     "half",     "hall",
    "hand",     "handle",   "hang",     "happen",   "happy",    "harbor",
    "hard",     "harm",     "harvest",  "haven",    "hazard",   "header",
    "health",   "heart",    "heat",     "heaven",   "heavy",    "height",
    "hello",    "helmet",   "help",     "herald",   "hero",     "hidden",
    "highland", "highway",  "hill",     "history",  "hobby",    "holder",
    "holiday",  "hollow",   "home",     "honey",    "honor",    "hook",
    "hope",     "horizon",  "horse",    "host",     "hotel",    "hour",
    "house",    "human",    "humor",    "hunter",   "hurry",    "hybrid",
    "image",    "impact",   "import",   "impose",   "improve",  "impulse",
    "inch",     "income",   "index",    "indoor",   "infant",   "infer",
    "inform",   "initial",  "inject",   "injury",   "ink",      "inmate",
    "inner",    "input",    "inquiry",  "insane",   "insect",   "insert",
    "inside",   "insight",  "insist",   "inspect",  "inspire",  "install",
    "instance", "instead",  "insult",   "insure",   "intact",   "intake",
    "integer",  "intend",   "intent",   "inter",    "interest", "interior",
    "internal", "internet", "interpret","interval", "interview","intimate",
    "into",     "introduce","invade",   "invent",   "invest",   "invite",
    "involve",  "iron",     "island",   "issue",    "item",     "jacket",
    "jaguar",   "jail",     "jazz",     "jeans",    "jelly",    "jewel",
    "job",      "join",     "joint",    "joke",     "journal",  "journey",
    "judge",    "juice",    "jump",     "jungle",   "junior",   "jury",
    "justice",  "keen",     "keep",     "kernel",   "kettle",   "key",
    "kick",     "kid",      "kill",     "kind",     "king",     "kiss",
    "kit",      "kitchen",  "knee",     "knife",    "knock",    "knot",
    "know",     "label",    "labor",    "lack",     "ladder",   "lady",
    "lake",     "lamp",     "land",     "lane",     "language", "lap",
    "large",    "laser",    "last",     "late",     "later",    "laugh",
    "launch",   "law",      "lawn",     "lawsuit",  "layer",    "lead",
    "leader",   "leaf",     "league",   "lean",     "learn",    "lease",
    "least",    "leather",  "leave",    "lecture",  "left",     "leg",
    "legal",    "legend",   "leisure",  "lemon",    "lend",     "length",
    "lens",     "lesson",   "letter",   "level",    "liar",     "liberty",
    "library",  "license",  "lick",     "lie",      "life",     "lift",
    "light",    "like",     "limb",     "limit",    "line",     "linear",
    "link",     "lion",     "lip",      "liquid",   "list",     "listen",
    "literal",  "little",   "live",     "liver",    "living",   "load",
    "loan",     "local",    "locate",   "lock",     "locus",    "log",
    "logic",    "logo",     "lonely",   "long",     "look",     "loop",
    "lord",     "lose",     "loss",     "lost",     "lot",      "loud",
    "lounge",   "love",     "lover",    "low",      "lower",    "loyal",
    "luck",     "lucky",    "luggage",  "lumber",   "lunar",    "lunch",
    "lung",     "lure",     "luxury",   "lyric",
};

bool isReservedIdent(llvm::StringRef N) {
  static const llvm::StringSet<> Kws = {
      "auto",     "break",    "case",     "char",     "const",    "continue",
      "default",  "do",       "double",   "else",     "enum",     "extern",
      "float",    "for",      "goto",     "if",       "inline",   "int",
      "long",     "register", "restrict", "return",   "short",    "signed",
      "sizeof",   "static",   "struct",   "switch",   "typedef",  "union",
      "unsigned", "void",     "volatile", "while",    "_Alignas", "_Alignof",
      "_Atomic",  "_Bool",    "_Complex", "_Generic", "_Imaginary",
      "_Noreturn","_Static_assert", "_Thread_local", "bool", "true", "false",
      "nullptr",  "alignof",  "alignas",  "main",     "WinMain",  "wWinMain",
      "DllMain",  "wDllMain"};
  return Kws.contains(N);
}

bool isEntryPointName(llvm::StringRef N) {
  return N == "main" || N == "WinMain" || N == "wWinMain" || N == "DllMain" ||
         N == "wDllMain";
}

bool isValidCIdent(llvm::StringRef S) {
  if (S.empty() || isReservedIdent(S))
    return false;
  if (!(std::isalpha((unsigned char)S[0]) || S[0] == '_'))
    return false;
  for (char C : S) {
    if (!(std::isalnum((unsigned char)C) || C == '_'))
      return false;
  }
  return true;
}

class XorShift64 {
public:
  explicit XorShift64(std::uint64_t Seed)
      : S_(Seed ? Seed : 0x9E3779B97F4A7C15ULL) {}
  std::uint64_t next() {
    std::uint64_t X = S_;
    X ^= X >> 12;
    X ^= X << 25;
    X ^= X >> 27;
    S_ = X;
    return X * 0x2545F4914F6CDD1DULL;
  }
  std::uint32_t nextBounded(std::uint32_t Bound) {
    return (std::uint32_t)(next() % Bound);
  }

private:
  std::uint64_t S_;
};

std::vector<std::string> loadDictionary(const std::string &Path,
                                        std::uint64_t Seed) {
  std::vector<std::string> Words;
  llvm::StringSet<> Seen;

  auto addWord = [&](llvm::StringRef W) {
    W = W.trim();
    if (W.empty() || W.starts_with("#"))
      return;
    if (!isValidCIdent(W))
      return;
    if (!Seen.insert(W).second)
      return;
    Words.emplace_back(W.str());
  };

  if (!Path.empty()) {
    auto MB = llvm::MemoryBuffer::getFile(Path);
    if (!MB) {
      fev::logWarn() << "dict-rename: cannot read --name-dict '" << Path
                     << "'; falling back to built-in dictionary";
    } else {
      llvm::StringRef Buf = MB.get()->getBuffer();
      while (!Buf.empty()) {
        auto Split = Buf.split('\n');
        addWord(Split.first);
        Buf = Split.second;
      }
    }
  }

  if (Words.empty()) {
    for (const char *W : kBuiltinDict)
      addWord(W);
  }

  XorShift64 Rng(Seed);
  for (unsigned I = (unsigned)Words.size(); I > 1; --I) {
    unsigned J = Rng.nextBounded(I);
    std::swap(Words[I - 1], Words[J]);
  }
  return Words;
}

std::string allocName(llvm::StringSet<> &Used, std::vector<std::string> &Words,
                      unsigned &WordIdx, llvm::StringRef Old) {
  // Two dictionary words joined (e.g. apple + zebra → applezebra).
  while (WordIdx + 1 < Words.size()) {
    const std::string Cand = Words[WordIdx] + Words[WordIdx + 1];
    WordIdx += 2;
    if (!isValidCIdent(Cand) || Used.contains(Cand) || Cand == Old)
      continue;
    Used.insert(Cand);
    return Cand;
  }
  unsigned N = 0;
  std::string Synth;
  if (Words.size() >= 2) {
    do {
      const std::string &A = Words[N % Words.size()];
      const std::string &B = Words[(N * 7u + 1u) % Words.size()];
      Synth = A + B + std::to_string(N);
      ++N;
    } while ((!isValidCIdent(Synth) || Used.contains(Synth) || Synth == Old) &&
             N < 100000u);
    if (isValidCIdent(Synth) && !Used.contains(Synth) && Synth != Old) {
      Used.insert(Synth);
      return Synth;
    }
  }
  N = 0;
  do {
    Synth = "sym_" + std::to_string(N++);
  } while (Used.contains(Synth) || Synth == Old);
  Used.insert(Synth);
  return Synth;
}

struct Edit {
  CharSourceRange Range;
  std::string Text;
  unsigned Offset = 0;
};

void enqueueName(std::vector<Edit> &Edits, SourceLocation Loc,
                 const std::string &Text, SourceManager &SM,
                 const LangOptions &LO) {
  if (Loc.isInvalid())
    return;
  // Macro args (e.g. offsetof) need the spelling location in the main file.
  SourceLocation Spell = SM.getSpellingLoc(Loc);
  if (!Spell.isValid() || !SM.isInMainFile(Spell))
    return;
  CharSourceRange R = Lexer::makeFileCharRange(
      CharSourceRange::getTokenRange(SourceRange(Spell, Spell)), SM, LO);
  if (R.isInvalid())
    return;
  Edits.push_back(Edit{R, Text, SM.getFileOffset(R.getBegin())});
}

class DictRenamePass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "dict-rename"; }

  llvm::StringRef description() const override {
    return "Final layout scrub: rename functions, variables, typedefs, structs, "
           "and fields to two-word dictionary identifiers (including _fev_*); "
           "--name-dict, --seed";
  }

  bool run(fev::PassContext &Ctx) override {
    auto Words = loadDictionary(Ctx.Config.NameDictPath, Ctx.Config.Seed);
    if (Words.empty()) {
      fev::logError() << "dict-rename: empty dictionary";
      return false;
    }

    llvm::StringSet<> Used;
    class CollectNames : public MatchFinder::MatchCallback {
    public:
      explicit CollectNames(llvm::StringSet<> &Used) : Used_(Used) {}
      void run(const MatchFinder::MatchResult &Result) override {
        if (const auto *ND = Result.Nodes.getNodeAs<NamedDecl>("n"))
          if (!ND->getName().empty())
            Used_.insert(ND->getName());
      }
      llvm::StringSet<> &Used_;
    };
    CollectNames CN(Used);
    MatchFinder CollectFinder;
    CollectFinder.addMatcher(namedDecl().bind("n"), &CN);
    CollectFinder.matchAST(Ctx.AST);

    llvm::DenseMap<const NamedDecl *, std::string> Rename;
    unsigned WordIdx = 0;
    unsigned FnCount = 0, VarCount = 0, TypeCount = 0, FieldCount = 0;

    auto consider = [&](const NamedDecl *ND, const char *Kind, unsigned &Ctr) {
      if (!ND || ND->getName().empty())
        return;
      if (isEntryPointName(ND->getName()) || isReservedIdent(ND->getName()))
        return;
      SourceManager &SM = Ctx.AST.getSourceManager();
      if (!fev::isInMainFile(ND->getLocation(), SM))
        return;
      const NamedDecl *Key = ND;
      if (const auto *FD = dyn_cast<FunctionDecl>(ND))
        Key = FD->getCanonicalDecl();
      else if (const auto *VD = dyn_cast<VarDecl>(ND))
        Key = VD->getCanonicalDecl();
      else if (const auto *TD = dyn_cast<TypedefNameDecl>(ND))
        Key = TD->getCanonicalDecl();
      else if (const auto *RD = dyn_cast<RecordDecl>(ND))
        if (const RecordDecl *Def = RD->getDefinition())
          Key = Def;
      if (Rename.count(Key))
        return;
      std::string New =
          allocName(Used, Words, WordIdx, ND->getName());
      Rename[Key] = New;
      ++Ctr;
      fev::logDebug() << "dict-rename: " << Kind << " " << ND->getName()
                      << " → " << New;
    };

    class CollectDecls : public MatchFinder::MatchCallback {
    public:
      CollectDecls(llvm::function_ref<void(const NamedDecl *, const char *,
                                           unsigned &)>
                       Consider,
                   unsigned &Fn, unsigned &Var, unsigned &Ty, unsigned &Fld)
          : Consider_(Consider), Fn_(Fn), Var_(Var), Ty_(Ty), Fld_(Fld) {}

      void run(const MatchFinder::MatchResult &Result) override {
        if (const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn")) {
          // Rename defs in the main file (includes injected _fev_* helpers).
          if (!Fn->isThisDeclarationADefinition())
            return;
          Consider_(Fn, "fn", Fn_);
          return;
        }
        if (const auto *VD = Result.Nodes.getNodeAs<VarDecl>("var")) {
          Consider_(VD, "var", Var_);
          return;
        }
        if (const auto *TD = Result.Nodes.getNodeAs<TypedefNameDecl>("td")) {
          Consider_(TD, "typedef", Ty_);
          return;
        }
        if (const auto *RD = Result.Nodes.getNodeAs<RecordDecl>("rec")) {
          if (!RD->isThisDeclarationADefinition() || !RD->getIdentifier())
            return;
          Consider_(RD, "struct", Ty_);
          return;
        }
        if (const auto *FD = Result.Nodes.getNodeAs<FieldDecl>("field")) {
          Consider_(FD, "field", Fld_);
        }
      }

      llvm::function_ref<void(const NamedDecl *, const char *, unsigned &)>
          Consider_;
      unsigned &Fn_, &Var_, &Ty_, &Fld_;
    };

    CollectDecls CD(consider, FnCount, VarCount, TypeCount, FieldCount);
    MatchFinder DeclFinder;
    DeclFinder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &CD);
    DeclFinder.addMatcher(
        varDecl(unless(isExpansionInSystemHeader())).bind("var"), &CD);
    DeclFinder.addMatcher(
        typedefDecl(unless(isExpansionInSystemHeader())).bind("td"), &CD);
    DeclFinder.addMatcher(
        recordDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("rec"),
        &CD);
    DeclFinder.addMatcher(
        fieldDecl(unless(isExpansionInSystemHeader())).bind("field"), &CD);
    DeclFinder.matchAST(Ctx.AST);

    if (Rename.empty()) {
      fev::logDebug() << "dict-rename: nothing to rename";
      return true;
    }

    auto lookup = [&](const NamedDecl *ND) -> const std::string * {
      if (!ND)
        return nullptr;
      const NamedDecl *Key = ND;
      if (const auto *FD = dyn_cast<FunctionDecl>(ND))
        Key = FD->getCanonicalDecl();
      else if (const auto *VD = dyn_cast<VarDecl>(ND))
        Key = VD->getCanonicalDecl();
      else if (const auto *TD = dyn_cast<TypedefNameDecl>(ND))
        Key = TD->getCanonicalDecl();
      else if (const auto *RD = dyn_cast<RecordDecl>(ND))
        if (const RecordDecl *Def = RD->getDefinition())
          Key = Def;
      auto It = Rename.find(Key);
      return It == Rename.end() ? nullptr : &It->second;
    };

    std::vector<Edit> Edits;

    class RewriteHandler : public MatchFinder::MatchCallback {
    public:
      RewriteHandler(
          llvm::function_ref<const std::string *(const NamedDecl *)> Lookup,
          std::vector<Edit> &Edits)
          : Lookup_(Lookup), Edits_(Edits) {}

      void run(const MatchFinder::MatchResult &Result) override {
        SourceManager &SM = *Result.SourceManager;
        const LangOptions &LO = Result.Context->getLangOpts();

        if (const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn")) {
          if (const std::string *N = Lookup_(Fn))
            enqueueName(Edits_, Fn->getNameInfo().getLoc(), *N, SM, LO);
          return;
        }
        if (const auto *VD = Result.Nodes.getNodeAs<VarDecl>("var")) {
          if (const std::string *N = Lookup_(VD))
            enqueueName(Edits_, VD->getLocation(), *N, SM, LO);
          return;
        }
        if (const auto *TD = Result.Nodes.getNodeAs<TypedefNameDecl>("td")) {
          if (const std::string *N = Lookup_(TD))
            enqueueName(Edits_, TD->getLocation(), *N, SM, LO);
          return;
        }
        if (const auto *RD = Result.Nodes.getNodeAs<RecordDecl>("rec")) {
          if (const std::string *N = Lookup_(RD))
            enqueueName(Edits_, RD->getLocation(), *N, SM, LO);
          return;
        }
        if (const auto *FD = Result.Nodes.getNodeAs<FieldDecl>("field")) {
          if (const std::string *N = Lookup_(FD))
            enqueueName(Edits_, FD->getLocation(), *N, SM, LO);
          return;
        }
        if (const auto *DRE = Result.Nodes.getNodeAs<DeclRefExpr>("ref")) {
          if (const std::string *N = Lookup_(DRE->getDecl()))
            enqueueName(Edits_, DRE->getLocation(), *N, SM, LO);
          return;
        }
        if (const auto *ME = Result.Nodes.getNodeAs<MemberExpr>("mem")) {
          if (const std::string *N =
                  Lookup_(dyn_cast_or_null<NamedDecl>(ME->getMemberDecl())))
            enqueueName(Edits_, ME->getMemberLoc(), *N, SM, LO);
          return;
        }
        if (const auto *TL = Result.Nodes.getNodeAs<TypeLoc>("tl")) {
          if (auto TTL = TL->getAs<TypedefTypeLoc>()) {
            if (const TypedefNameDecl *TD = TTL.getDecl())
              if (const std::string *N = Lookup_(TD))
                enqueueName(Edits_, TTL.getNameLoc(), *N, SM, LO);
          } else if (auto RTL = TL->getAs<RecordTypeLoc>()) {
            if (const RecordDecl *RD = RTL.getDecl())
              if (const std::string *N = Lookup_(RD))
                enqueueName(Edits_, RTL.getNameLoc(), *N, SM, LO);
          }
        }
      }

      llvm::function_ref<const std::string *(const NamedDecl *)> Lookup_;
      std::vector<Edit> &Edits_;
    };

    RewriteHandler RH(lookup, Edits);
    MatchFinder RF;
    RF.addMatcher(functionDecl(unless(isExpansionInSystemHeader())).bind("fn"),
                  &RH);
    RF.addMatcher(varDecl(unless(isExpansionInSystemHeader())).bind("var"), &RH);
    RF.addMatcher(typedefDecl(unless(isExpansionInSystemHeader())).bind("td"),
                  &RH);
    RF.addMatcher(recordDecl(unless(isExpansionInSystemHeader())).bind("rec"),
                  &RH);
    RF.addMatcher(fieldDecl(unless(isExpansionInSystemHeader())).bind("field"),
                  &RH);
    RF.addMatcher(declRefExpr(unless(isExpansionInSystemHeader())).bind("ref"),
                  &RH);
    RF.addMatcher(memberExpr(unless(isExpansionInSystemHeader())).bind("mem"),
                  &RH);
    RF.addMatcher(typeLoc(loc(qualType(anyOf(
                               typedefType(),
                               recordType()))))
                      .bind("tl"),
                  &RH);
    RF.matchAST(Ctx.AST);

    // OffsetOfExpr has no dedicated AST matcher in this Clang; visit directly.
    class OffVisitor : public RecursiveASTVisitor<OffVisitor> {
    public:
      OffVisitor(
          llvm::function_ref<const std::string *(const NamedDecl *)> Lookup,
          std::vector<Edit> &Edits, SourceManager &SM, const LangOptions &LO)
          : Lookup_(Lookup), Edits_(Edits), SM_(SM), LO_(LO) {}
      bool VisitOffsetOfExpr(OffsetOfExpr *E) {
        for (unsigned I = 0, N = E->getNumComponents(); I != N; ++I) {
          const OffsetOfNode &C = E->getComponent(I);
          if (C.getKind() != OffsetOfNode::Field)
            continue;
          if (const std::string *Name = Lookup_(C.getField()))
            enqueueName(Edits_, C.getEndLoc(), *Name, SM_, LO_);
        }
        return true;
      }
      llvm::function_ref<const std::string *(const NamedDecl *)> Lookup_;
      std::vector<Edit> &Edits_;
      SourceManager &SM_;
      const LangOptions &LO_;
    };
    OffVisitor OV(lookup, Edits, Ctx.AST.getSourceManager(),
                  Ctx.AST.getLangOpts());
    OV.TraverseAST(Ctx.AST);

    std::sort(Edits.begin(), Edits.end(),
              [](const Edit &A, const Edit &B) { return A.Offset > B.Offset; });
    llvm::DenseSet<unsigned> SeenOff;
    unsigned Applied = 0;
    for (const Edit &E : Edits) {
      if (!SeenOff.insert(E.Offset).second)
        continue;
      if (Ctx.Rewriter.ReplaceText(E.Range, E.Text))
        continue;
      ++Applied;
    }

    // Scrub FEV watermarks BEFORE residual whole-file renames so comment-body
    // renames cannot overlap deletions (that ate "static const u" → "nsigned").
    SourceManager &SM = Ctx.Rewriter.getSourceMgr();
    const FileID MainID = SM.getMainFileID();
    StringRef Buf = SM.getBufferData(MainID);
    const SourceLocation FileStart = SM.getLocForStartOfFile(MainID);

    struct MarkerEdit {
      unsigned Off;
      unsigned Len;
      std::string Repl;
    };
    std::vector<MarkerEdit> MarkerEdits;
    std::vector<std::pair<unsigned, unsigned>> DeletedCommentSpans;

    auto enqueueMarker = [&](unsigned Off, unsigned Len, std::string Repl) {
      MarkerEdits.push_back(MarkerEdit{Off, Len, std::move(Repl)});
    };

    static const char *const CommentMarkers[] = {
        "/* FEV_WINAPI_HASH */",
        "/* FEV_SCRAMBLE_RUNTIME */",
        "/* FEV_OPAQUE_RUNTIME */",
        "/* FEV_SANDBOX_SLEEP */",
        "/* FEV_JUNK_CODE */",
        "/* FEV_DICT_BYTES */",
        "/* FEV_VALIDATE_RUNTIME */",
    };
    for (const char *M : CommentMarkers) {
      const size_t MLen = std::strlen(M);
      size_t Pos = 0;
      while ((Pos = Buf.find(M, Pos)) != StringRef::npos) {
        enqueueMarker((unsigned)Pos, (unsigned)MLen, "");
        DeletedCommentSpans.emplace_back((unsigned)Pos,
                                         (unsigned)Pos + (unsigned)MLen);
        Pos += MLen;
      }
    }

    {
      const char *OldGuard = "FEV_CHACHA_RUNTIME_H";
      const size_t OldLen = std::strlen(OldGuard);
      size_t Pos = 0;
      while ((Pos = Buf.find(OldGuard, Pos)) != StringRef::npos) {
        enqueueMarker((unsigned)Pos, (unsigned)OldLen, "OBF_RUNTIME_H");
        Pos += OldLen;
      }
    }

    {
      size_t Pos = 0;
      while (Pos < Buf.size()) {
        size_t Start = Buf.find("/*", Pos);
        if (Start == StringRef::npos)
          break;
        size_t End = Buf.find("*/", Start + 2);
        if (End == StringRef::npos)
          break;
        StringRef Trimmed = Buf.substr(Start + 2, End - (Start + 2)).ltrim();
        if (Trimmed.starts_with("fev ") || Trimmed.starts_with("fev:") ||
            Trimmed.starts_with("fev-") || Trimmed.starts_with("[fev]") ||
            Trimmed.starts_with("FEV_WINAPI") ||
            Trimmed.starts_with("FEV_SCRAMBLE") ||
            Trimmed.starts_with("FEV_OPAQUE") ||
            Trimmed.starts_with("FEV_SANDBOX") ||
            Trimmed.starts_with("FEV_JUNK") ||
            Trimmed.starts_with("FEV_DICT") ||
            Trimmed.starts_with("FEV_VALIDATE")) {
          const unsigned Len = (unsigned)(End + 2 - Start);
          enqueueMarker((unsigned)Start, Len, "");
          DeletedCommentSpans.emplace_back((unsigned)Start,
                                           (unsigned)Start + Len);
        }
        Pos = End + 2;
      }
    }

    std::sort(MarkerEdits.begin(), MarkerEdits.end(),
              [](const MarkerEdit &A, const MarkerEdit &B) {
                return A.Off > B.Off;
              });
    llvm::DenseSet<unsigned> SeenMarkerOff;
    for (const MarkerEdit &ME : MarkerEdits) {
      if (!SeenMarkerOff.insert(ME.Off).second)
        continue;
      Ctx.Rewriter.ReplaceText(FileStart.getLocWithOffset(ME.Off), ME.Len,
                               ME.Repl);
      SeenOff.insert(ME.Off);
    }

    // Residual scrub for inactive PP branches: FEV-flavored names only, and
    // never inside watermark comments we just deleted.
    {
      std::vector<std::pair<std::string, std::string>> Pairs;
      for (const auto &KV : Rename) {
        const std::string Old = KV.first->getNameAsString();
        if (Old.size() < 4)
          continue;
        if (!(llvm::StringRef(Old).starts_with("_fev") ||
              llvm::StringRef(Old).starts_with("fev_") ||
              llvm::StringRef(Old).starts_with("FEV_")))
          continue;
        Pairs.emplace_back(Old, KV.second);
      }
      std::sort(Pairs.begin(), Pairs.end(),
                [](const auto &A, const auto &B) {
                  return A.first.size() > B.first.size();
                });
      auto isIdentChar = [](char C) {
        return std::isalnum((unsigned char)C) || C == '_';
      };
      auto inDeletedComment = [&](unsigned Off) {
        for (const auto &Span : DeletedCommentSpans)
          if (Off >= Span.first && Off < Span.second)
            return true;
        return false;
      };
      for (const auto &Pr : Pairs) {
        const std::string &Old = Pr.first;
        const std::string &New = Pr.second;
        size_t Pos = 0;
        while ((Pos = Buf.find(Old, Pos)) != StringRef::npos) {
          const bool LeftOk = Pos == 0 || !isIdentChar(Buf[Pos - 1]);
          const size_t End = Pos + Old.size();
          const bool RightOk = End >= Buf.size() || !isIdentChar(Buf[End]);
          const unsigned Off = (unsigned)Pos;
          if (LeftOk && RightOk && !inDeletedComment(Off) &&
              SeenOff.insert(Off).second) {
            if (!Ctx.Rewriter.ReplaceText(FileStart.getLocWithOffset(Off),
                                          Old.size(), New))
              ++Applied;
          }
          Pos = End;
        }
      }
    }

    fev::logInfo() << "dict-rename: fn=" << FnCount << " var=" << VarCount
                   << " type/struct=" << TypeCount << " field=" << FieldCount
                   << " tokens=" << Applied;
    return true;
  }
};

FEV_REGISTER_PASS(DictRenamePass);

} // namespace
