#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"
#include "fev/ByteArrayUtils.h"
#include "fev/Validate.h"
#include "fev/ChaCha20.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Type.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/raw_ostream.h"

#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

/// Built-in fallback when --name-dict is omitted (same pool spirit as dict-rename).
const char *const kBuiltinDict[] = {
    "alpha",   "anchor",  "answer",  "apple",   "april",   "area",    "arena",
    "array",   "arrow",   "aside",   "asset",   "atlas",   "audio",   "autumn",
    "avenue",  "badge",   "baker",   "balance", "bamboo",  "banner",  "barrel",
    "basin",   "beacon",  "beaver",  "bench",   "berry",   "binary",  "blade",
    "blank",   "blend",   "bliss",   "block",   "bloom",   "board",   "bonus",
    "boost",   "border",  "bottle",  "branch",  "brave",   "bread",   "bridge",
    "brief",   "bright",  "bronze",  "brook",   "brush",   "bucket",  "budget",
    "buffer",  "build",   "bundle",  "bureau",  "button",  "cable",   "cache",
    "cafe",    "cake",    "camera",  "campus",  "canal",   "candle",  "canvas",
    "canyon",  "carbon",  "career",  "cargo",   "carpet",  "castle",  "catalog",
    "cedar",   "celery",  "center",  "cereal",  "chain",   "chair",   "chalk",
    "chapel",  "charge",  "chart",   "chase",   "check",   "cheese",  "cherry",
    "chest",   "chief",   "child",   "chord",   "chrome",  "cipher",  "circle",
    "circus",  "citizen", "civic",   "claim",   "clamp",   "clause",  "clean",
    "clear",   "clerk",   "click",   "client",  "cliff",   "climb",   "clock",
    "clone",   "cloud",   "coach",   "coast",   "cocoa",   "coffee",  "collar",
    "colony",  "column",  "combat",  "comedy",  "comic",   "comma",   "common",
    "copper",  "coral",   "corner",  "cotton",  "couch",   "county",  "couple",
    "course",  "cover",   "craft",   "crane",   "crash",   "crate",   "crayon",
    "cream",   "credit",  "creek",   "crest",   "crime",   "crisis",  "critic",
    "cross",   "crowd",   "crown",   "crude",   "cruise",  "crush",   "crystal",
    "cubic",   "culture", "curtain", "curve",   "custom",  "cycle",   "daily",
    "dairy",   "dance",   "dealer",  "debate",  "decade",  "decimal", "deck",
    "decor",   "deed",    "degree",  "delay",   "delta",   "demand",  "denim",
    "dental",  "depot",   "depth",   "deputy",  "desert",  "design",  "desk",
    "detail",  "device",  "diary",   "digit",   "dinner",  "direct",  "disk",
    "divide",  "doctor",  "domain",  "donor",   "door",    "draft",   "dragon",
    "drama",   "dream",   "dress",   "drift",   "drill",   "drink",   "drive",
    "drop",    "drum",    "dryer",   "duck",    "dusk",    "dust",    "duty",
    "eagle",   "earth",   "east",    "easy",    "echo",    "edge",    "editor",
    "effect",  "effort",  "eight",   "elbow",   "elder",   "elect",   "element",
    "elite",   "email",   "empire",  "empty",   "enable",  "ending",  "enemy",
    "energy",  "engine",  "enough",  "entry",   "envoy",   "equal",   "error",
    "escape",  "essay",   "estate",  "event",   "every",   "exact",   "exam",
    "excel",   "except",  "excess",  "excuse",  "execute", "exempt",  "exile",
    "exist",   "exit",    "expand",  "expect",  "expert",  "expire",  "explain",
    "explore", "export",  "expose",  "express", "extend",  "extra",   "fabric",
    "face",    "factor",   "factory", "faculty", "fade",    "fail",    "fair",
    "faith",   "fall",    "fame",    "family",  "famous",  "fancy",   "farm",
    "fashion", "fast",    "fate",    "father",  "fault",   "favor",   "fear",
    "feast",   "feat",    "federal", "feed",    "feel",    "fence",   "ferry",
    "fever",   "fiber",   "fiction", "field",   "fifteen", "fifth",   "fifty",
    "fight",   "figure",  "file",    "fill",    "film",    "filter",  "final",
    "finance", "find",    "fine",    "finger",  "finish",  "fire",    "firm",
    "first",   "fiscal",  "fish",    "fit",     "five",    "fix",    "flag",
    "flame",   "flash",   "flat",    "flavor",  "flee",    "fleet",   "flesh",
    "flight",  "float",   "flood",   "floor",   "flour",   "flow",    "flower",
    "fluid",   "flush",   "foam",    "focus",   "fold",    "folk",    "follow",
    "food",    "foot",    "force",   "forest",  "forget",  "fork",    "form",
    "formal",  "format",  "former",  "formula", "fort",    "forth",   "forty",
    "forum",   "forward", "found",   "four",    "frame",   "frank",   "fraud",
    "free",    "fresh",   "friend",  "front",   "frost",   "fruit",   "fuel",
    "full",    "fund",    "funeral", "funny",   "furnace", "future",  "gain",
    "galaxy",  "gallery", "game",    "gang",    "garage",  "garden",  "garlic",
    "gate",    "gather",  "gauge",   "gear",    "gender",  "gene",    "general",
    "gift",    "glass",   "global",  "glory",   "glove",   "goal",    "gold",
    "golf",    "good",    "govern",  "grab",    "grade",   "grain",   "grand",
    "grant",   "grape",   "graph",   "grasp",   "grass",   "grave",   "gray",
    "great",   "green",   "greet",   "grid",    "grief",   "grill",   "grind",
    "grip",    "grocery", "ground",  "group",   "grow",    "growth",  "guard",
    "guess",   "guest",   "guide",   "guilt",   "guitar",  "habit",   "hair",
    "half",    "hall",    "hand",    "handle",  "hang",    "happen",  "happy",
    "harbor",  "hard",    "harm",    "harvest", "haven",   "hazard",  "header",
    "health",  "heart",   "heat",    "heaven",  "heavy",   "height",  "hello",
    "helmet",  "help",    "herald",  "hero",    "hidden",  "highland","highway",
    "hill",    "history", "hobby",   "holder",  "holiday", "hollow",  "home",
    "honey",   "honor",   "hook",    "hope",    "horizon", "horse",   "host",
    "hotel",   "hour",    "house",   "human",   "humor",   "hunter",  "hurry",
    "hybrid",  "image",   "impact",  "import",  "impose",  "improve", "impulse",
    "inch",    "income",  "index",   "indoor",  "infant",  "infer",   "inform",
    "initial", "inject",  "injury",  "ink",     "inmate",  "inner",   "input",
    "inquiry", "insane",  "insect",  "insert",  "inside",  "insight", "insist",
    "inspect", "inspire", "install", "instance","instead", "insult",  "insure",
    "intact",  "intake",  "integer", "intend",  "intent",  "inter",   "interest",
    "interior","internal","internet","interval","interview","intimate","into",
    "invent",  "invest",  "invite",  "involve", "iron",    "island",  "issue",
    "item",    "jacket",  "jaguar",  "jail",    "jazz",    "jeans",   "jelly",
    "jewel",   "job",     "join",    "joint",   "joke",    "journal", "journey",
    "judge",   "juice",   "jump",    "jungle",  "junior",  "jury",    "justice",
    "keen",    "keep",    "kernel",  "kettle",  "key",     "kick",    "kid",
    "kind",    "king",    "kiss",    "kit",     "kitchen", "knee",    "knife",
    "knock",   "knot",    "know",    "label",   "labor",   "lack",    "ladder",
    "lady",    "lake",    "lamp",    "land",    "lane",    "language","lap",
    "large",   "laser",   "last",    "late",    "later",   "laugh",   "launch",
    "law",     "lawn",    "layer",   "lead",    "leader",  "leaf",    "league",
    "lean",    "learn",   "lease",   "least",   "leather", "leave",   "lecture",
    "left",    "leg",     "legal",   "legend",  "leisure", "lemon",   "lend",
    "length",  "lens",    "lesson",  "letter",  "level",   "liar",    "liberty",
    "library", "license", "lick",    "lie",     "life",    "lift",    "light",
    "like",    "limb",    "limit",   "line",    "linear",  "link",    "lion",
    "lip",     "liquid",  "list",    "listen",  "literal", "little",  "live",
    "liver",   "living",  "load",    "loan",    "local",   "locate",  "lock",
    "locus",   "log",     "logic",   "logo",    "lonely",  "long",    "look",
    "loop",    "lord",    "lose",    "loss",    "lost",    "lot",     "loud",
    "lounge",  "love",    "lover",   "low",     "lower",   "loyal",   "luck",
    "lucky",   "luggage", "lumber",  "lunar",   "lunch",   "lung",    "lure",
    "luxury",  "lyric",
};

bool isReservedIdent(llvm::StringRef N) {
  static const llvm::StringSet<> Kws = {
      "auto",     "break",   "case",    "char",   "const",   "continue",
      "default",  "do",      "double",  "else",   "enum",    "extern",
      "float",    "for",     "goto",    "if",     "inline",  "int",
      "long",     "register","restrict","return", "short",   "signed",
      "sizeof",   "static",  "struct",  "switch", "typedef", "union",
      "unsigned", "void",    "volatile","while",  "bool",    "true",
      "false",    "main"};
  return Kws.contains(N);
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

std::vector<std::string> loadDictionary(const std::string &Path) {
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
      fev::logWarn() << "dict-bytes: cannot read --name-dict '" << Path
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
  return Words;
}

/// Build 256 unique two-word compounds keyed by *slot* (not plaintext byte).
bool buildWordTable(const std::vector<std::string> &Words, std::uint64_t Seed,
                    std::vector<std::string> &Out) {
  Out.assign(256, {});
  if (Words.size() < 2)
    return false;

  llvm::StringSet<> Used;
  XorShift64 Rng(Seed ^ 0xD1C7B17E5C001DULL);
  for (unsigned I = 0; I < 256; ++I) {
    bool Ok = false;
    for (unsigned Attempt = 0; Attempt < 100000; ++Attempt) {
      const std::string &A = Words[Rng.nextBounded((unsigned)Words.size())];
      const std::string &B = Words[Rng.nextBounded((unsigned)Words.size())];
      if (A == B)
        continue;
      std::string Cand = A + B;
      if (!isValidCIdent(Cand) || Used.contains(Cand))
        continue;
      Used.insert(Cand);
      Out[I] = std::move(Cand);
      Ok = true;
      break;
    }
    if (!Ok)
      return false;
  }
  return true;
}

/// Seed-random bijection: SlotForByte[b] = slot, ByteForSlot[slot] = b.
void buildSlotPermutation(std::uint64_t Seed, std::uint8_t SlotForByte[256],
                          std::uint8_t ByteForSlot[256]) {
  for (unsigned I = 0; I < 256; ++I)
    SlotForByte[I] = (std::uint8_t)I;
  XorShift64 Rng(Seed ^ 0xA5A5DEADBEEF42ULL);
  for (unsigned I = 256; I > 1; --I) {
    unsigned J = Rng.nextBounded(I);
    std::swap(SlotForByte[I - 1], SlotForByte[J]);
  }
  for (unsigned B = 0; B < 256; ++B)
    ByteForSlot[SlotForByte[B]] = (std::uint8_t)B;
}

std::string formatU8Table(const std::uint8_t *Bytes, unsigned N) {
  std::string Out = "{";
  llvm::raw_string_ostream OS(Out);
  for (unsigned I = 0; I < N; ++I) {
    if (I)
      OS << ", ";
    if (I && (I % 16) == 0)
      OS << "\n  ";
    OS << (unsigned)Bytes[I];
  }
  OS << "}";
  return OS.str();
}

std::string formatIntIndices(const std::vector<std::uint8_t> &Bytes) {
  return formatU8Table(Bytes.data(), (unsigned)Bytes.size());
}

std::string formatWordTable(const std::vector<std::string> &Tab) {
  std::string Out = "{\n";
  llvm::raw_string_ostream OS(Out);
  for (unsigned I = 0; I < Tab.size(); ++I) {
    OS << "  \"" << Tab[I] << "\"";
    if (I + 1 < Tab.size())
      OS << ",";
    if ((I % 4) == 3 || I + 1 == Tab.size())
      OS << "\n";
    else
      OS << " ";
  }
  OS << "}";
  return OS.str();
}

class DictBytesPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "dict-bytes"; }

  llvm::StringRef description() const override {
    return "Encode global/static byte arrays via seed-random 256 two-word "
           "slots (shuffled integer indices + inverse map); restore at main "
           "(--name-dict, --seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    auto Words = loadDictionary(Ctx.Config.NameDictPath);
    if (Words.size() < 2) {
      fev::logError() << "dict-bytes: dictionary needs at least 2 words";
      return false;
    }

    std::vector<std::string> Table;
    if (!buildWordTable(Words, Ctx.Config.Seed, Table)) {
      fev::logError() << "dict-bytes: failed to build unique 256 representations";
      return false;
    }

    std::uint8_t SlotForByte[256];
    std::uint8_t ByteForSlot[256];
    buildSlotPermutation(Ctx.Config.Seed, SlotForByte, ByteForSlot);

    // Validate the bijection itself before touching the AST.
    {
      bool PermOk = true;
      bool Seen[256] = {};
      for (unsigned B = 0; B < 256; ++B) {
        const std::uint8_t S = SlotForByte[B];
        if (Seen[S] || ByteForSlot[S] != (std::uint8_t)B) {
          PermOk = false;
          break;
        }
        Seen[S] = true;
      }
      if (!fev::validateExpect(Ctx.Config, PermOk,
                               "dict-bytes slot↔byte bijection"))
        return false;
    }

    bool Edited = false;
    bool NeedTable = false;
    bool NeedValidateRuntime = false;
    bool Failed = false;
    std::vector<std::string> EnsureCalls;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, const LangOptions &LO, const std::uint8_t *SlotForByte,
              const std::uint8_t *ByteForSlot, fev::ValidateMode VMode,
              bool &Edited, bool &NeedTable, bool &NeedValidateRuntime,
              bool &Failed, std::vector<std::string> &Calls)
          : Rewriter_(R), LangOpts_(LO), SlotForByte_(SlotForByte),
            ByteForSlot_(ByteForSlot), VMode_(VMode), Edited_(Edited),
            NeedTable_(NeedTable), NeedValidateRuntime_(NeedValidateRuntime),
            Failed_(Failed), Calls_(Calls) {}

      void run(const MatchFinder::MatchResult &Result) override {
        if (Failed_)
          return;
        const auto *VD = Result.Nodes.getNodeAs<VarDecl>("buf");
        if (!VD || !VD->hasInit() || VD->getName().empty())
          return;
        if (VD->isLocalVarDecl())
          return;

        StringRef NameRef = VD->getName();
        if (fev::isFeVArtifactName(NameRef))
          return;

        if (!fev::isByteOrientedArray(VD->getType()))
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(VD->getLocation(), SM))
          return;

        std::vector<std::uint8_t> Plain;
        if (!fev::collectVarInitBytes(VD->getInit(), Plain))
          return;
        if (Plain.size() < 8)
          return;

        // Cross-check against the declared array size when known (catches
        // truncated string-literal reads, etc.).
        if (const auto *CAT =
                dyn_cast<ConstantArrayType>(VD->getType().getCanonicalType())) {
          const uint64_t DeclN = CAT->getSize().getZExtValue();
          if (DeclN != Plain.size()) {
            std::string Msg;
            llvm::raw_string_ostream OS(Msg);
            OS << "dict-bytes " << VD->getName() << " size mismatch: collected "
               << Plain.size() << "B vs type " << DeclN << "B";
            if (!fev::validateExpect(VMode_, false, Msg)) {
              Failed_ = true;
              return;
            }
            if (DeclN < Plain.size())
              Plain.resize((size_t)DeclN);
            else if (DeclN > Plain.size())
              Plain.resize((size_t)DeclN, 0);
          }
        }

        std::vector<std::uint8_t> Encoded(Plain.size());
        std::vector<std::uint8_t> RoundTrip(Plain.size());
        for (size_t I = 0; I < Plain.size(); ++I) {
          Encoded[I] = SlotForByte_[Plain[I]];
          RoundTrip[I] = ByteForSlot_[Encoded[I]];
        }
        const std::string BufLabel =
            "dict-bytes " + VD->getNameAsString();
        if (!fev::validateRoundTrip(VMode_, BufLabel, Plain, RoundTrip)) {
          Failed_ = true;
          return;
        }

        const std::uint32_t Tag =
            fev::fnv1a32(Plain.data(), Plain.size());
        const std::string Name = VD->getNameAsString();
        const std::string IdxName = "_fev_db_idx_" + Name;
        const std::string Ensure = "_fev_dictbytes_" + Name;

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
        OS << "/* fev dict-bytes: " << Name
           << " (shuffled slot → word → inv; fnv="
           << llvm::format("0x%08x", Tag) << ") */\n"
           << "static const unsigned " << IdxName << "[" << Encoded.size()
           << "] = " << formatIntIndices(Encoded) << ";\n"
           << "unsigned char " << Name << "[" << Encoded.size() << "];\n"
           << "static void " << Ensure << "(void) {\n"
           << "  static int ready;\n"
           << "  if (!ready) {\n"
           << "    for (unsigned i = 0; i < " << Encoded.size()
           << "u; ++i) {\n"
           << "      unsigned slot = " << IdxName << "[i];\n"
           << "      (void)_fev_db_words[slot];\n"
           << "      " << Name << "[i] = _fev_db_inv[slot];\n"
           << "    }\n";
        if (VMode_ != fev::ValidateMode::Off) {
          OS << fev::emitBufferIntegrityCheck(Name, (unsigned)Encoded.size(),
                                              Tag);
          NeedValidateRuntime_ = true;
        }
        OS << "    ready = 1;\n"
           << "  }\n"
           << "}\n";

        if (Rewriter_.ReplaceText(Range, OS.str()))
          return;

        Calls_.push_back(Ensure + "();");
        Edited_ = true;
        NeedTable_ = true;
        fev::logDebug() << "dict-bytes: " << Name << " (" << Encoded.size()
                        << "B, first_slot=" << (unsigned)Encoded.front()
                        << ", fnv=" << llvm::format("0x%08x", Tag) << ")";
      }

    private:
      Rewriter &Rewriter_;
      const LangOptions &LangOpts_;
      const std::uint8_t *SlotForByte_;
      const std::uint8_t *ByteForSlot_;
      fev::ValidateMode VMode_;
      bool &Edited_;
      bool &NeedTable_;
      bool &NeedValidateRuntime_;
      bool &Failed_;
      std::vector<std::string> &Calls_;
    };

    Handler H(Ctx.Rewriter, Ctx.AST.getLangOpts(), SlotForByte, ByteForSlot,
              Ctx.Config.Validate, Edited, NeedTable, NeedValidateRuntime,
              Failed, EnsureCalls);
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
      fev::logInfo() << "dict-bytes: rewrote 0 buffer(s)";
      return true;
    }

    {
      SourceManager &SM = Ctx.Rewriter.getSourceMgr();
      StringRef Buf = SM.getBufferData(SM.getMainFileID());
      if (NeedValidateRuntime &&
          Buf.find("FEV_VALIDATE_RUNTIME") == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, fev::buildValidateRuntimeC());
      if (NeedTable && Buf.find("FEV_DICT_BYTES") == StringRef::npos) {
        std::string TableC;
        llvm::raw_string_ostream OS(TableC);
        OS << "/* FEV_DICT_BYTES */\n"
           << "static const char *_fev_db_words[256] = "
           << formatWordTable(Table) << ";\n"
           << "static const unsigned char _fev_db_inv[256] = "
           << formatU8Table(ByteForSlot, 256) << ";\n";
        fev::insertAtFileStart(Ctx.Rewriter, OS.str());
      }
    }

    class MainHandler : public MatchFinder::MatchCallback {
    public:
      MainHandler(Rewriter &R, std::vector<std::string> InCalls)
          : Rewriter_(R), Calls_(std::move(InCalls)) {}
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

    MainHandler MH(Ctx.Rewriter, EnsureCalls);
    MatchFinder MF;
    MF.addMatcher(
        functionDecl(isDefinition(), hasName("main")).bind("mainfn"), &MH);
    MF.matchAST(Ctx.AST);

    fev::logInfo() << "dict-bytes: rewrote " << EnsureCalls.size()
                   << " buffer(s)";
    return true;
  }
};

FEV_REGISTER_PASS(DictBytesPass);

} // namespace
