#include "fev/Log.h"
#include "fev/Pass.h"
#include "fev/RewriteUtils.h"

#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Lex/Lexer.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

constexpr const char *kMarker = "/* FEV_WINAPI_HASH */";

std::uint32_t djb2(llvm::StringRef S, std::uint32_t Seed) {
  std::uint32_t H = 5381u ^ Seed;
  for (char C : S) {
    unsigned char U = (unsigned char)C;
    if (U >= 'A' && U <= 'Z')
      U = (unsigned char)(U - 'A' + 'a');
    H = ((H << 5) + H) + U;
  }
  return H;
}

struct ApiSpec {
  const char *CalleeName;
  const char *ExportName;
  const char *Module;
  const char *TypedefSig;
  const char *RetTy;
  const char *Params;
  const char *Args;
};

const ApiSpec kApis[] = {
    {"VirtualAlloc", "VirtualAlloc", "kernel32.dll",
     "LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD)", "LPVOID",
     "LPVOID a, SIZE_T b, DWORD c, DWORD d", "a, b, c, d"},
    {"VirtualProtect", "VirtualProtect", "kernel32.dll",
     "BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD, PDWORD)", "BOOL",
     "LPVOID a, SIZE_T b, DWORD c, PDWORD d", "a, b, c, d"},
    {"VirtualFree", "VirtualFree", "kernel32.dll",
     "BOOL (WINAPI *)(LPVOID, SIZE_T, DWORD)", "BOOL",
     "LPVOID a, SIZE_T b, DWORD c", "a, b, c"},
    {"CreateThread", "CreateThread", "kernel32.dll",
     "HANDLE (WINAPI *)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, "
     "LPVOID, DWORD, LPDWORD)",
     "HANDLE",
     "LPSECURITY_ATTRIBUTES a, SIZE_T b, LPTHREAD_START_ROUTINE c, LPVOID d, "
     "DWORD e, LPDWORD f",
     "a, b, c, d, e, f"},
    {"WaitForSingleObject", "WaitForSingleObject", "kernel32.dll",
     "DWORD (WINAPI *)(HANDLE, DWORD)", "DWORD", "HANDLE a, DWORD b", "a, b"},
    {"CloseHandle", "CloseHandle", "kernel32.dll", "BOOL (WINAPI *)(HANDLE)",
     "BOOL", "HANDLE a", "a"},
    {"LoadLibraryA", "LoadLibraryA", "kernel32.dll", "HMODULE (WINAPI *)(LPCSTR)",
     "HMODULE", "LPCSTR a", "a"},
    {"GetProcAddress", "GetProcAddress", "kernel32.dll",
     "FARPROC (WINAPI *)(HMODULE, LPCSTR)", "FARPROC", "HMODULE a, LPCSTR b",
     "a, b"},
    {"GetModuleHandleA", "GetModuleHandleA", "kernel32.dll",
     "HMODULE (WINAPI *)(LPCSTR)", "HMODULE", "LPCSTR a", "a"},
    {"Sleep", "Sleep", "kernel32.dll", "void (WINAPI *)(DWORD)", "void",
     "DWORD a", "a"},
    {"GetTickCount", "GetTickCount", "kernel32.dll",
     "DWORD (WINAPI *)(void)", "DWORD", "void", ""},
    {"GetCurrentProcessId", "GetCurrentProcessId", "kernel32.dll",
     "DWORD (WINAPI *)(void)", "DWORD", "void", ""},
    {"GetCurrentThreadId", "GetCurrentThreadId", "kernel32.dll",
     "DWORD (WINAPI *)(void)", "DWORD", "void", ""},
    {"IsDebuggerPresent", "IsDebuggerPresent", "kernel32.dll",
     "BOOL (WINAPI *)(void)", "BOOL", "void", ""},
    {"QueryPerformanceCounter", "QueryPerformanceCounter", "kernel32.dll",
     "BOOL (WINAPI *)(LARGE_INTEGER *)", "BOOL", "LARGE_INTEGER *a", "a"},
    {"GetSystemTimeAsFileTime", "GetSystemTimeAsFileTime", "kernel32.dll",
     "void (WINAPI *)(LPFILETIME)", "void", "LPFILETIME a", "a"},
    {"ExitProcess", "ExitProcess", "kernel32.dll", "void (WINAPI *)(UINT)",
     "void", "UINT a", "a"},
    {"CreateFileA", "CreateFileA", "kernel32.dll",
     "HANDLE (WINAPI *)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, "
     "DWORD, HANDLE)",
     "HANDLE",
     "LPCSTR a, DWORD b, DWORD c, LPSECURITY_ATTRIBUTES d, DWORD e, DWORD f, "
     "HANDLE g",
     "a, b, c, d, e, f, g"},
    {"ReadFile", "ReadFile", "kernel32.dll",
     "BOOL (WINAPI *)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)", "BOOL",
     "HANDLE a, LPVOID b, DWORD c, LPDWORD d, LPOVERLAPPED e", "a, b, c, d, e"},
    {"WriteFile", "WriteFile", "kernel32.dll",
     "BOOL (WINAPI *)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)", "BOOL",
     "HANDLE a, LPCVOID b, DWORD c, LPDWORD d, LPOVERLAPPED e", "a, b, c, d, e"},
    {"RtlMoveMemory", "RtlMoveMemory", "ntdll.dll",
     "void (WINAPI *)(PVOID, const void *, SIZE_T)", "void",
     "PVOID a, const void *b, SIZE_T c", "a, b, c"},
    {"memmove", "RtlMoveMemory", "ntdll.dll",
     "void (WINAPI *)(PVOID, const void *, SIZE_T)", "void",
     "PVOID a, const void *b, SIZE_T c", "a, b, c"},
    {"memcpy", "RtlMoveMemory", "ntdll.dll",
     "void (WINAPI *)(PVOID, const void *, SIZE_T)", "void",
     "PVOID a, const void *b, SIZE_T c", "a, b, c"},
};

const ApiSpec *findApi(llvm::StringRef Name) {
  for (const ApiSpec &A : kApis) {
    if (Name == A.CalleeName)
      return &A;
  }
  return nullptr;
}

std::string runtimeResolver(std::uint32_t Seed) {
  std::string Out = kMarker;
  Out += R"C(
#if defined(_WIN32)
#include <stdint.h>
#include <stddef.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef struct _FEV_UNICODE_STR {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} FEV_UNICODE_STR;

typedef struct _FEV_LDR_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  FEV_UNICODE_STR FullDllName;
  FEV_UNICODE_STR BaseDllName;
} FEV_LDR_ENTRY;

static uint32_t _fev_djb2_ascii(const char *s, uint32_t seed) {
  uint32_t h = 5381u ^ seed;
  for (; s && *s; ++s) {
    unsigned char c = (unsigned char)*s;
    if (c >= 'A' && c <= 'Z')
      c = (unsigned char)(c - 'A' + 'a');
    h = ((h << 5) + h) + c;
  }
  return h;
}

static uint32_t _fev_djb2_wide(const WCHAR *s, USHORT nBytes, uint32_t seed) {
  uint32_t h = 5381u ^ seed;
  USHORT n = (USHORT)(nBytes / sizeof(WCHAR));
  for (USHORT i = 0; i < n && s; ++i) {
    unsigned char c = (unsigned char)(s[i] & 0xff);
    if (c >= 'A' && c <= 'Z')
      c = (unsigned char)(c - 'A' + 'a');
    h = ((h << 5) + h) + c;
  }
  return h;
}

static void *_fev_peb(void) {
  void *p = NULL;
#if defined(_M_X64) || defined(__x86_64__)
  __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(p));
#elif defined(_M_IX86) || defined(__i386__)
  __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(p));
#endif
  return p;
}

static HMODULE _fev_mod_by_hash(uint32_t modHash, uint32_t seed) {
  uint8_t *peb = (uint8_t *)_fev_peb();
  if (!peb)
    return NULL;
  uint8_t *ldr = *(uint8_t **)(peb + 0x18);
  if (!ldr)
    return NULL;
#if defined(_M_X64) || defined(__x86_64__)
  LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x20);
#else
  LIST_ENTRY *head = (LIST_ENTRY *)(ldr + 0x14);
#endif
  for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
    FEV_LDR_ENTRY *ent = (FEV_LDR_ENTRY *)((uint8_t *)e -
        offsetof(FEV_LDR_ENTRY, InMemoryOrderLinks));
    if (!ent->BaseDllName.Buffer)
      continue;
    uint32_t h =
        _fev_djb2_wide(ent->BaseDllName.Buffer, ent->BaseDllName.Length, seed);
    if (h == modHash)
      return (HMODULE)ent->DllBase;
  }
  return NULL;
}

static FARPROC _fev_export_by_hash(HMODULE mod, uint32_t apiHash,
                                   uint32_t seed) {
  if (!mod)
    return NULL;
  uint8_t *base = (uint8_t *)mod;
  IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    return NULL;
  IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE)
    return NULL;
  IMAGE_DATA_DIRECTORY dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (!dir.VirtualAddress)
    return NULL;
  IMAGE_EXPORT_DIRECTORY *exp =
      (IMAGE_EXPORT_DIRECTORY *)(base + dir.VirtualAddress);
  DWORD *names = (DWORD *)(base + exp->AddressOfNames);
  WORD *ords = (WORD *)(base + exp->AddressOfNameOrdinals);
  DWORD *funcs = (DWORD *)(base + exp->AddressOfFunctions);
  for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
    const char *nm = (const char *)(base + names[i]);
    if (_fev_djb2_ascii(nm, seed) != apiHash)
      continue;
    return (FARPROC)(base + funcs[ords[i]]);
  }
  return NULL;
}

static FARPROC _fev_get_api(uint32_t modHash, uint32_t apiHash, uint32_t seed) {
  return _fev_export_by_hash(_fev_mod_by_hash(modHash, seed), apiHash, seed);
}

static const uint32_t _fev_api_seed = )C";
  Out += std::to_string(Seed);
  Out += "u;\n#endif /* _WIN32 */\n";
  return Out;
}

std::string emitWrapper(const ApiSpec &A, std::uint32_t Seed) {
  const std::uint32_t ModH = djb2(A.Module, Seed);
  const std::uint32_t ApiH = djb2(A.ExportName, Seed);
  const std::string Wrap = std::string("_fev_") + A.ExportName;
  const std::string Ptr = std::string("_fev_p_") + A.ExportName;
  const std::string Ty = std::string("_fev_t_") + A.ExportName;

  // TypedefSig is like "LPVOID (WINAPI *)(LPVOID, SIZE_T, DWORD, DWORD)" —
  // splice the typedef name before the final parameter list's "*".
  std::string TypedefLine = A.TypedefSig;
  const auto Star = TypedefLine.find("(WINAPI *)");
  if (Star != std::string::npos)
    TypedefLine.replace(Star, std::strlen("(WINAPI *)"),
                        "(WINAPI *" + Ty + ")");
  else {
    const auto Star2 = TypedefLine.find("(*)");
    if (Star2 != std::string::npos)
      TypedefLine.replace(Star2, 3, "(*" + Ty + ")");
  }

  std::string S;
  llvm::raw_string_ostream OS(S);
  OS << "#if defined(_WIN32)\n"
     << "typedef " << TypedefLine << ";\n"
     << "static FARPROC " << Ptr << ";\n";
  if (llvm::StringRef(A.RetTy) == "void") {
    OS << "static void " << Wrap << "(" << A.Params << ") {\n"
       << "  if (!" << Ptr << ")\n"
       << "    " << Ptr << " = _fev_get_api(" << ModH << "u, " << ApiH
       << "u, _fev_api_seed);\n"
       << "  if (" << Ptr << ")\n"
       << "    ((" << Ty << ")(void *)" << Ptr << ")(" << A.Args << ");\n"
       << "}\n";
  } else {
    OS << "static " << A.RetTy << " " << Wrap << "(" << A.Params << ") {\n"
       << "  if (!" << Ptr << ")\n"
       << "    " << Ptr << " = _fev_get_api(" << ModH << "u, " << ApiH
       << "u, _fev_api_seed);\n"
       << "  if (!" << Ptr << ")\n"
       << "    return (" << A.RetTy << ")0;\n"
       << "  return ((" << Ty << ")(void *)" << Ptr << ")(" << A.Args
       << ");\n"
       << "}\n";
  }
  OS << "#endif\n";
  return OS.str();
}

struct Edit {
  CharSourceRange Range;
  std::string Wrap;
  std::string Export;
};

class WinApiHashPass final : public fev::Pass {
public:
  llvm::StringRef name() const override { return "winapi-hash"; }

  llvm::StringRef description() const override {
    return "Replace Windows API calls with DJB2-hashed PEB/export resolution "
           "(--seed)";
  }

  bool run(fev::PassContext &Ctx) override {
    const std::uint32_t Seed = (std::uint32_t)Ctx.Config.Seed;
    std::set<std::string> UsedExports;
    std::vector<Edit> Edits;

    class CallHandler : public MatchFinder::MatchCallback {
    public:
      CallHandler(std::vector<Edit> &Edits, std::set<std::string> &Used)
          : Edits_(Edits), Used_(Used) {}

      void run(const MatchFinder::MatchResult &Result) override {
        const auto *CE = Result.Nodes.getNodeAs<CallExpr>("call");
        if (!CE)
          return;
        const FunctionDecl *FD = CE->getDirectCallee();
        if (!FD)
          return;
        StringRef Name = FD->getName();
        if (Name.starts_with("_fev_") || Name.starts_with("fev_"))
          return;
        const ApiSpec *Spec = findApi(Name);
        if (!Spec)
          return;

        SourceManager &SM = *Result.SourceManager;
        const LangOptions &LO = Result.Context->getLangOpts();

        // Use expansion locations so macro wrappers (RtlMoveMemory→memmove)
        // still rewrite the token written in the main file.
        SourceLocation ExpCallee =
            SM.getExpansionLoc(CE->getCallee()->getExprLoc());
        if (ExpCallee.isInvalid() || !SM.isInMainFile(ExpCallee))
          return;

        CharSourceRange NameRange = Lexer::makeFileCharRange(
            CharSourceRange::getTokenRange(SourceRange(ExpCallee, ExpCallee)),
            SM, LO);
        if (NameRange.isInvalid())
          return;

        std::string Spell = Lexer::getSourceText(NameRange, SM, LO).str();
        if (llvm::StringRef(Spell).starts_with("_fev_"))
          return;
        if (const ApiSpec *BySpell = findApi(Spell))
          Spec = BySpell;

        Used_.insert(Spec->ExportName);
        Edits_.push_back(
            Edit{NameRange, std::string("_fev_") + Spec->ExportName,
                 Spec->ExportName});
      }

    private:
      std::vector<Edit> &Edits_;
      std::set<std::string> &Used_;
    };

    CallHandler CH(Edits, UsedExports);
    MatchFinder Finder;
    Finder.addMatcher(callExpr(callee(functionDecl())).bind("call"), &CH);
    Finder.matchAST(Ctx.AST);

    if (Edits.empty()) {
      fev::logDebug() << "winapi-hash: no matching Windows API calls";
      return true;
    }

    SourceManager &SM = Ctx.Rewriter.getSourceMgr();
    std::sort(Edits.begin(), Edits.end(), [&](const Edit &A, const Edit &B) {
      return SM.getFileOffset(A.Range.getBegin()) >
             SM.getFileOffset(B.Range.getBegin());
    });
    for (const Edit &E : Edits)
      (void)Ctx.Rewriter.ReplaceText(E.Range, E.Wrap);

    std::string Preamble = runtimeResolver(Seed);
    std::set<std::string> Emitted;
    for (const ApiSpec &A : kApis) {
      if (!UsedExports.count(A.ExportName) || Emitted.count(A.ExportName))
        continue;
      Emitted.insert(A.ExportName);
      Preamble += emitWrapper(A, Seed);
    }

    StringRef Buf = SM.getBufferData(SM.getMainFileID());
    if (Buf.find(kMarker) == StringRef::npos)
      fev::insertAtFileStart(Ctx.Rewriter, Preamble);
    else {
      for (const std::string &Exp : Emitted) {
        const std::string Needle = std::string("static ") + /*any*/ "";
        (void)Needle;
        const std::string WrapName = std::string("_fev_") + Exp + "(";
        // Definition uses "static … _fev_Export("
        const std::string DefNeedle = std::string("_fev_") + Exp + "(";
        // Check for wrapper typedef/pointer already emitted
        const std::string PtrNeedle = std::string("_fev_p_") + Exp;
        if (Buf.find(PtrNeedle) == StringRef::npos) {
          for (const ApiSpec &A : kApis) {
            if (A.ExportName == Exp) {
              fev::insertAtFileStart(Ctx.Rewriter, emitWrapper(A, Seed));
              break;
            }
          }
        }
        (void)DefNeedle;
        (void)WrapName;
      }
    }

    fev::logInfo() << "winapi-hash: rewrote " << Edits.size()
                   << " call(s), " << Emitted.size() << " export wrapper(s)";
    return true;
  }
};

FEV_REGISTER_PASS(WinApiHashPass);

} // namespace
