#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Stmt.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- CityHash64 (short keys), mirrored in emitted runtime -----------------
// Subset of Google CityHash sufficient for 0..16-byte inputs. Used both to
// precompute constants in the pass and as the single-way wrapper from
// Cao et al., CMC 2025 (anti-DSE opaque predicates).

constexpr std::uint64_t k0 = 0xc3a5c85c97cb3127ULL;
constexpr std::uint64_t k2 = 0x9ae16a3b2f90404fULL;
constexpr std::uint64_t kMul = 0x9ddfea08eb382d69ULL;

std::uint64_t rot64(std::uint64_t Val, int Shift) {
  return Shift == 0 ? Val : ((Val >> Shift) | (Val << (64 - Shift)));
}

std::uint64_t shiftMix(std::uint64_t Val) { return Val ^ (Val >> 47); }

std::uint64_t fetch32(const unsigned char *P) {
  return (std::uint64_t)P[0] | ((std::uint64_t)P[1] << 8) |
         ((std::uint64_t)P[2] << 16) | ((std::uint64_t)P[3] << 24);
}

std::uint64_t fetch64(const unsigned char *P) {
  return fetch32(P) | (fetch32(P + 4) << 32);
}

std::uint64_t hashLen16(std::uint64_t U, std::uint64_t V) {
  std::uint64_t A = (U ^ V) * kMul;
  A ^= (A >> 47);
  std::uint64_t B = (V ^ A) * kMul;
  B ^= (B >> 47);
  B *= kMul;
  return B;
}

std::uint64_t hashLen0to16(const unsigned char *S, std::size_t Len) {
  if (Len >= 8) {
    std::uint64_t Mul = k2 + Len * 2;
    std::uint64_t A = fetch64(S) + k2;
    std::uint64_t B = fetch64(S + Len - 8);
    std::uint64_t C = rot64(B, 37) * Mul + A;
    std::uint64_t D = (rot64(A, 25) + B) * Mul;
    return hashLen16(C, D) * Mul;
  }
  if (Len >= 4) {
    std::uint64_t Mul = k2 + Len * 2;
    std::uint64_t A = fetch32(S);
    return hashLen16(Len + (A << 3), fetch32(S + Len - 4)) * Mul;
  }
  if (Len > 0) {
    std::uint8_t A = S[0];
    std::uint8_t B = S[Len >> 1];
    std::uint8_t C = S[Len - 1];
    std::uint32_t Y = (std::uint32_t)A + ((std::uint32_t)B << 8);
    std::uint32_t Z = (std::uint32_t)Len + ((std::uint32_t)C << 2);
    return shiftMix(Y * k2 ^ Z * k0) * k2;
  }
  return k2;
}

std::uint64_t cityHash64(const void *Data, std::size_t Len) {
  const auto *S = static_cast<const unsigned char *>(Data);
  if (Len <= 16)
    return hashLen0to16(S, Len);
  // Longer keys unused by this pass; fold via 16-byte window.
  return hashLen0to16(S, 16) ^ hashLen0to16(S + Len - 16, 16);
}

std::uint64_t cityHashU32(std::uint32_t V) {
  unsigned char Buf[4] = {
      (unsigned char)(V & 0xff), (unsigned char)((V >> 8) & 0xff),
      (unsigned char)((V >> 16) & 0xff), (unsigned char)((V >> 24) & 0xff)};
  return cityHash64(Buf, 4);
}

double unitFloat(std::uint64_t Seed, unsigned Salt) {
  std::uint64_t X = Seed ^ (0x9E3779B97F4A7C15ULL * (Salt + 1));
  X ^= X >> 30;
  X *= 0xBF58476D1CE4E5B9ULL;
  X ^= X >> 27;
  return (double)(X >> 11) / (double)(1ULL << 53);
}

unsigned pickKind(std::uint64_t Seed, unsigned Salt, unsigned NKinds) {
  std::uint64_t X = Seed ^ (0xD1B54A32D192ED03ULL * (Salt + 1));
  X ^= X >> 33;
  X *= 0xFF51AFD7ED558CCDULL;
  return (unsigned)(X % NKinds);
}

enum class OpaqueKind : unsigned {
  Hash = 0,    // CityHash single-way wrapper (paper §3.1)
  Fermat = 1,  // modular exponentiation / Fermat (paper §3.2)
  Fib = 2,     // recursive Fibonacci path explosion (paper §3.3.1)
  Collatz = 3, // Collatz path explosion (paper §3.3.2)
  Volatile = 4 // opt-resistant always-true (baseline mix-in)
};

constexpr unsigned kFermatPrime = 10007;
constexpr const char *kRuntimeMarker = "/* FEV_OPAQUE_RUNTIME */";

std::string runtimeHelpers() {
  // Emitted once per TU. CityHash path matches the C++ precompute above.
  // unused attrs: a given TU may not exercise every predicate family.
  return std::string(kRuntimeMarker) + R"C(
#include <stddef.h>
#include <stdint.h>
static uint64_t _fev_rot64(uint64_t v, int s) {
  return s == 0 ? v : ((v >> s) | (v << (64 - s)));
}
static uint64_t _fev_shift_mix(uint64_t v) { return v ^ (v >> 47); }
static uint64_t _fev_fetch32(const unsigned char *p) {
  return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
         ((uint64_t)p[3] << 24);
}
static uint64_t _fev_fetch64(const unsigned char *p) {
  return _fev_fetch32(p) | (_fev_fetch32(p + 4) << 32);
}
static uint64_t _fev_hash_len_16(uint64_t u, uint64_t v) {
  const uint64_t kMul = 0x9ddfea08eb382d69ULL;
  uint64_t a = (u ^ v) * kMul;
  a ^= (a >> 47);
  uint64_t b = (v ^ a) * kMul;
  b ^= (b >> 47);
  b *= kMul;
  return b;
}
__attribute__((unused)) static uint64_t _fev_cityhash64(const void *data,
                                                       size_t len) {
  const unsigned char *s = (const unsigned char *)data;
  const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
  const uint64_t k2 = 0x9ae16a3b2f90404fULL;
  if (len <= 16) {
    if (len >= 8) {
      uint64_t mul = k2 + len * 2;
      uint64_t a = _fev_fetch64(s) + k2;
      uint64_t b = _fev_fetch64(s + len - 8);
      uint64_t c = _fev_rot64(b, 37) * mul + a;
      uint64_t d = (_fev_rot64(a, 25) + b) * mul;
      return _fev_hash_len_16(c, d) * mul;
    }
    if (len >= 4) {
      uint64_t mul = k2 + len * 2;
      uint64_t a = _fev_fetch32(s);
      return _fev_hash_len_16(len + (a << 3), _fev_fetch32(s + len - 4)) * mul;
    }
    if (len > 0) {
      uint8_t a = s[0];
      uint8_t b = s[len >> 1];
      uint8_t c = s[len - 1];
      uint32_t y = (uint32_t)a + ((uint32_t)b << 8);
      uint32_t z = (uint32_t)len + ((uint32_t)c << 2);
      return _fev_shift_mix(y * k2 ^ z * k0) * k2;
    }
    return k2;
  }
  return _fev_cityhash64(s, 16) ^ _fev_cityhash64(s + len - 16, 16);
}
__attribute__((unused)) static uint64_t _fev_modexp(uint64_t base, uint64_t exp,
                                                   uint64_t mod) {
  uint64_t result = 1;
  base %= mod;
  while (exp > 0) {
    if (exp & 1u)
      result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1;
  }
  return result;
}
__attribute__((unused)) static unsigned _fev_fib(unsigned n) {
  static unsigned memo[48];
  static int ready = 0;
  if (!ready) {
    memo[0] = 0;
    memo[1] = 1;
    for (unsigned i = 2; i < 48; ++i)
      memo[i] = memo[i - 1] + memo[i - 2];
    ready = 1;
  }
  return n < 48 ? memo[n] : memo[47];
}
__attribute__((unused)) static int _fev_collatz_ok(unsigned n) {
  if (n == 0)
    return 0;
  unsigned guard = 0;
  while (n != 1u && guard < 100000u) {
    n = (n & 1u) ? (3u * n + 1u) : (n >> 1);
    ++guard;
  }
  return n == 1u;
}
)C";
}

std::string junkArm(const std::string &XName) {
  // Always-true opaques: mark the dead arm unreachable so clang's uninit
  // analysis does not treat gated assignments as maybe-skipped.
  return "    volatile unsigned _fev_junk = " + XName +
         ";\n"
         "    _fev_junk ^= 0xBADC0DEU;\n"
         "    _fev_junk = (_fev_junk << 3) | (_fev_junk >> 29);\n"
         "    (void)_fev_junk;\n"
         "    __builtin_unreachable();\n";
}

std::string wrapStmt(const std::string &BodyText, OpaqueKind Kind,
                     std::uint64_t Seed, unsigned Salt, unsigned FibN) {
  const std::string X = "_fev_ox_" + std::to_string(Salt);
  // Tie the opaque input to a stack address (ASLR / local identity) xor a
  // per-site seed — not a foldable literal zero (paper §3: input/local-tied).
  std::string Setup = "  volatile unsigned " + X + "_anchor = " +
                      std::to_string((unsigned)(Seed & 0xffffffffu)) +
                      "U;\n"
                      "  unsigned " +
                      X + " = (unsigned)((uintptr_t)&" + X + "_anchor ^ " +
                      std::to_string((unsigned)((Seed >> 32) ^ Salt)) + "U);\n";

  std::string Cond;
  switch (Kind) {
  case OpaqueKind::Hash: {
    // Traditional evenness opaque, single-way wrapped: hash(x(x-1)%2)==hash(0).
    const std::uint64_t H0 = cityHashU32(0);
    Cond = "({ unsigned _fev_t = (" + X + " * (" + X +
           " - 1u)) % 2u; _fev_cityhash64(&_fev_t, sizeof(_fev_t)) == " +
           std::to_string(H0) + "ULL; })";
    break;
  }
  case OpaqueKind::Fermat: {
    // a^p ≡ a (mod p) for prime p (Fermat); a derived from local x.
    Cond = "({ unsigned long long _fev_a = (unsigned long long)" + X +
           " * (unsigned long long)" + X +
           "; _fev_modexp(_fev_a % " + std::to_string(kFermatPrime) + "ULL, " +
           std::to_string(kFermatPrime) + "ULL, " +
           std::to_string(kFermatPrime) + "ULL) == (_fev_a % " +
           std::to_string(kFermatPrime) + "ULL); })";
    break;
  }
  case OpaqueKind::Fib: {
    unsigned N = FibN < 3 ? 3 : (FibN > 40 ? 40 : FibN);
    Cond = "({ unsigned _fev_n = " + std::to_string(N) + "U + (" + X +
           " % 3U); _fev_fib(_fev_n) == _fev_fib(_fev_n - 1U) + "
           "_fev_fib(_fev_n - 2U); })";
    break;
  }
  case OpaqueKind::Collatz: {
    Cond = "({ unsigned _fev_n = 7U + (" + X +
           " % 25U); _fev_collatz_ok(_fev_n); })";
    break;
  }
  case OpaqueKind::Volatile:
  default: {
    // Always true at runtime; volatile keeps -O2 from deleting the branch.
    Cond = "({ volatile int _fev_z = 0; volatile int _fev_s = (int)" + X +
           "; (_fev_z == 0) && ((_fev_s ^ _fev_s) == 0); })";
    break;
  }
  }

  std::string Out;
  Out += "{\n";
  Out += Setup;
  Out += "  if (" + Cond + ") {\n";
  Out += "    " + BodyText;
  if (!BodyText.empty() && BodyText.back() != ';' && BodyText.back() != '}')
    Out += ";";
  Out += "\n  } else {\n";
  Out += junkArm(X);
  Out += "  }\n";
  Out += "}\n";
  return Out;
}

bool isSkippableStmt(const Stmt *S) {
  if (!S)
    return true;
  if (isa<DeclStmt>(S) || isa<NullStmt>(S) || isa<LabelStmt>(S) ||
      isa<AttributedStmt>(S) || isa<SwitchCase>(S) || isa<CapturedStmt>(S))
    return true;
  // Never wrap transfers — wrapping `return` leaves a non-returning else arm.
  if (isa<ReturnStmt>(S) || isa<BreakStmt>(S) || isa<ContinueStmt>(S) ||
      isa<GotoStmt>(S) || isa<IndirectGotoStmt>(S) || isa<CXXThrowExpr>(S))
    return true;
  // Leave compounds and structured CF intact; wrap *leaf* children only so
  // nested edits never overlap (if/while bodies still get leaf wraps).
  if (isa<CompoundStmt>(S) || isa<IfStmt>(S) || isa<WhileStmt>(S) ||
      isa<DoStmt>(S) || isa<ForStmt>(S) || isa<SwitchStmt>(S) ||
      isa<CXXTryStmt>(S) || isa<CXXForRangeStmt>(S))
    return true;
  return false;
}

class CollectCandidates : public RecursiveASTVisitor<CollectCandidates> {
public:
  CollectCandidates(SourceManager &SM, const LangOptions &LO)
      : SM_(SM), LangOpts_(LO) {}

  bool VisitCompoundStmt(CompoundStmt *CS) {
    if (!fev::isInMainFile(CS->getLBracLoc(), SM_))
      return true;
    for (Stmt *Child : CS->body()) {
      if (isSkippableStmt(Child))
        continue;
      SourceLocation B = Child->getBeginLoc();
      if (B.isInvalid() || !fev::isInMainFile(B, SM_))
        continue;
      std::string Text = fev::stmtText(Child, SM_, LangOpts_);
      if (Text.find("_fev_ox_") != std::string::npos ||
          Text.find("_fev_cityhash64") != std::string::npos ||
          Text.find("_fev_fib") != std::string::npos)
        continue;
      Candidates_.push_back(Child);
    }
    return true;
  }

  std::vector<Stmt *> take() { return std::move(Candidates_); }

private:
  SourceManager &SM_;
  const LangOptions &LangOpts_;
  std::vector<Stmt *> Candidates_;
};

class OpaquePredicatesPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "opaque-predicates"; }

  llvm::StringRef description() const override {
    return "Anti-DSE opaque predicates (CityHash/Fermat/Fib/Collatz) as bogus "
           "control flow (--opaque-density, --opaque-fib-n, --seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const double Density = Ctx.Config.OpaqueDensity;
    const unsigned FibN = Ctx.Config.OpaqueFibN;
    const std::uint64_t Seed = Ctx.Config.Seed;
    bool NeedRuntime = false;
    unsigned Salt = 0;

    class Handler : public MatchFinder::MatchCallback {
    public:
      Handler(Rewriter &R, double Density, unsigned FibN, std::uint64_t Seed,
              bool &NeedRuntime, unsigned &Salt)
          : Rewriter_(R), Density_(Density), FibN_(FibN), Seed_(Seed),
            NeedRuntime_(NeedRuntime), Salt_(Salt) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *Fn = Result.Nodes.getNodeAs<FunctionDecl>("fn");
        if (!Fn || !Fn->hasBody())
          return;

        SourceManager &SM = *Result.SourceManager;
        if (!fev::isInMainFile(Fn->getLocation(), SM))
          return;

        // Never inject opaques into FEV runtime helpers (ChaCha, ensure_*, …).
        StringRef FnName = Fn->getName();
        if (FnName.starts_with("fev_") || FnName.starts_with("_fev_"))
          return;

        const LangOptions &LO = Result.Context->getLangOpts();
        CollectCandidates Collector(SM, LO);
        Collector.TraverseStmt(Fn->getBody());
        std::vector<Stmt *> Cands = Collector.take();

        struct Edit {
          SourceRange Range;
          std::string Text;
          unsigned BeginOff;
        };
        std::vector<Edit> Edits;

        for (Stmt *S : Cands) {
          unsigned MySalt = Salt_++;
          if (unitFloat(Seed_, MySalt) > Density_)
            continue;

          std::string Body = fev::stmtText(S, SM, LO);
          if (Body.empty())
            continue;

          OpaqueKind Kind = static_cast<OpaqueKind>(
              pickKind(Seed_, MySalt, /*NKinds=*/5));
          if (Kind != OpaqueKind::Volatile)
            NeedRuntime_ = true;

          std::string Wrapped =
              wrapStmt(Body, Kind, Seed_, MySalt, FibN_);
          SourceLocation Begin = S->getBeginLoc();
          SourceLocation End =
              Lexer::getLocForEndOfToken(S->getEndLoc(), 0, SM, LO);
          if (Begin.isInvalid() || End.isInvalid())
            continue;
          Edits.push_back(Edit{SourceRange(Begin, End), std::move(Wrapped),
                               SM.getFileOffset(Begin)});
        }

        std::sort(Edits.begin(), Edits.end(),
                  [](const Edit &A, const Edit &B) {
                    return A.BeginOff > B.BeginOff;
                  });
        for (const Edit &E : Edits)
          Rewriter_.ReplaceText(E.Range, E.Text);
      }

    private:
      Rewriter &Rewriter_;
      double Density_;
      unsigned FibN_;
      std::uint64_t Seed_;
      bool &NeedRuntime_;
      unsigned &Salt_;
    };

    Handler H(Ctx.Rewriter, Density, FibN, Seed, NeedRuntime, Salt);
    MatchFinder Finder;
    Finder.addMatcher(
        functionDecl(isDefinition(), unless(isExpansionInSystemHeader()))
            .bind("fn"),
        &H);
    Finder.matchAST(Ctx.AST);

    if (NeedRuntime) {
      SourceManager &SM = Ctx.Rewriter.getSourceMgr();
      StringRef Buf = SM.getBufferData(SM.getMainFileID());
      if (Buf.find(kRuntimeMarker) == StringRef::npos)
        fev::insertAtFileStart(Ctx.Rewriter, runtimeHelpers());
    }

    fev::logDebug() << "opaque-predicates: density=" << Density
                    << " fib-n=" << FibN << " sites~" << Salt;
    return true;
  }
};

FEV_REGISTER_PASS(OpaquePredicatesPass);

} // namespace
