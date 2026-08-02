#include "fev/Log.h"

#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"

#include <cstdlib>
#include <memory>
#include <string>
#include <unistd.h>

namespace fev {
namespace {

LogLevel gMinLevel = LogLevel::Info;
LogColorMode gColorMode = LogColorMode::Auto;
std::unique_ptr<llvm::raw_fd_ostream> gLogFile;
std::string gLogFilePath;
std::string gCurrentPass;

constexpr const char *kReset = "\033[0m";
constexpr const char *kBold = "\033[1m";
constexpr const char *kDim = "\033[2m";
constexpr const char *kRed = "\033[31m";
constexpr const char *kGreen = "\033[32m";
constexpr const char *kYellow = "\033[33m";
constexpr const char *kCyan = "\033[36m";

const char *levelName(LogLevel Level) {
  switch (Level) {
  case LogLevel::Debug:
    return "debug";
  case LogLevel::Info:
    return "info";
  case LogLevel::Warn:
    return "warn";
  case LogLevel::Error:
    return "error";
  }
  return "info";
}

const char *levelColor(LogLevel Level) {
  switch (Level) {
  case LogLevel::Debug:
    return kDim;
  case LogLevel::Info:
    return kGreen;
  case LogLevel::Warn:
    return kYellow;
  case LogLevel::Error:
    return kRed;
  }
  return kReset;
}

bool envTruthy(const char *Value) {
  if (!Value || !*Value)
    return false;
  return !(Value[0] == '0' && Value[1] == '\0');
}

/// File always records info+debug; warn/error included so failures are complete.
bool fileWantsLevel(LogLevel Level) {
  switch (Level) {
  case LogLevel::Debug:
  case LogLevel::Info:
  case LogLevel::Warn:
  case LogLevel::Error:
    return true;
  }
  return false;
}

void appendPassTag(llvm::raw_ostream &OS) {
  if (gCurrentPass.empty())
    return;
  OS << '[' << gCurrentPass << "] ";
}

} // namespace

void setLogLevel(LogLevel Min) { gMinLevel = Min; }
LogLevel getLogLevel() { return gMinLevel; }
void setLogColorMode(LogColorMode Mode) { gColorMode = Mode; }

bool logColorEnabled() {
  switch (gColorMode) {
  case LogColorMode::Always:
    return true;
  case LogColorMode::Never:
    return false;
  case LogColorMode::Auto:
    break;
  }
  if (envTruthy(std::getenv("NO_COLOR")))
    return false;
  if (envTruthy(std::getenv("FORCE_COLOR")))
    return true;
  const char *Term = std::getenv("TERM");
  if (Term && Term[0] == '\0')
    return false;
  if (Term && std::string(Term) == "dumb")
    return false;
  return ::isatty(STDERR_FILENO) == 1;
}

void initLogFromEnvironment() {
  if (envTruthy(std::getenv("FEV_VERBOSE")) ||
      envTruthy(std::getenv("FEV_DEBUG")))
    gMinLevel = LogLevel::Debug;
  if (envTruthy(std::getenv("NO_COLOR")))
    gColorMode = LogColorMode::Never;
  else if (envTruthy(std::getenv("FORCE_COLOR")))
    gColorMode = LogColorMode::Always;
}

bool logEnabled(LogLevel Level) {
  return static_cast<int>(Level) >= static_cast<int>(gMinLevel);
}

bool setLogFile(llvm::StringRef Path) {
  if (Path.empty()) {
    closeLogFile();
    return true;
  }

  std::error_code EC;
  auto Out = std::make_unique<llvm::raw_fd_ostream>(
      Path, EC,
      llvm::sys::fs::OF_Append | llvm::sys::fs::OF_TextWithCRLF);
  if (EC) {
    llvm::errs() << "fev: error: cannot open log file '" << Path
                 << "': " << EC.message() << '\n';
    return false;
  }

  gLogFile = std::move(Out);
  gLogFilePath = Path.str();
  *gLogFile << "----- fev session -----\n";
  gLogFile->flush();
  return true;
}

void closeLogFile() {
  if (!gLogFile)
    return;
  gLogFile->flush();
  gLogFile.reset();
  gLogFilePath.clear();
}

bool hasLogFile() { return gLogFile != nullptr; }

llvm::StringRef getLogFilePath() { return gLogFilePath; }

void setCurrentPass(llvm::StringRef Name) { gCurrentPass = Name.str(); }

llvm::StringRef getCurrentPass() { return gCurrentPass; }

LogMessage::LogMessage(LogLevel Level)
    : Level_(Level), ActiveConsole_(logEnabled(Level)),
      ActiveFile_(gLogFile && fileWantsLevel(Level)),
      Active_(ActiveConsole_ || ActiveFile_) {}

LogMessage::~LogMessage() { finish(); }

void LogMessage::finish() {
  if (Finished_ || !Active_)
    return;
  Finished_ = true;

  if (ActiveConsole_) {
    const bool Color = logColorEnabled();
    llvm::raw_ostream &OS = llvm::errs();

    if (Color) {
      OS << kBold << kCyan << "fev" << kReset << ": ";
      OS << levelColor(Level_) << levelName(Level_) << kReset << ": ";
      if (!gCurrentPass.empty())
        OS << kCyan << '[' << gCurrentPass << ']' << kReset << ' ';
      if (Level_ == LogLevel::Warn)
        OS << kYellow;
      else if (Level_ == LogLevel::Error)
        OS << kRed;
      else if (Level_ == LogLevel::Debug)
        OS << kDim;
    } else {
      OS << "fev: " << levelName(Level_) << ": ";
      appendPassTag(OS);
    }

    OS << Text_;
    if (Color)
      OS << kReset;
    OS << '\n';
  }

  if (ActiveFile_ && gLogFile) {
    *gLogFile << "fev: " << levelName(Level_) << ": ";
    appendPassTag(*gLogFile);
    *gLogFile << Text_ << '\n';
    gLogFile->flush();
  }
}

void printBanner(llvm::raw_ostream &OS) {
  const bool Color = logColorEnabled();
  const char *Art = Color ? kCyan : "";
  const char *Credit = Color ? kDim : "";
  const char *Reset = Color ? kReset : "";

  OS << Art << R"(
  █████▒     ▓█████       ██▒   █▓
▓██   ▒      ▓█   ▀      ▓██░   █▒
▒████ ░      ▒███         ▓██  █▒░
░▓█▒  ░      ▒▓█  ▄        ▒██ █░░
░▒█░     ██▓ ░▒████▒ ██▓    ▒▀█░
 ▒ ░     ▒▓▒ ░░ ▒░ ░ ▒▓▒    ░ ▐░
 ░       ░▒   ░ ░  ░ ░▒     ░ ░░
 ░ ░     ░      ░    ░        ░░
          ░     ░  ░  ░        ░
          ░           ░       ░
)" << Reset;

  OS << Credit
     << "  FEV — source-to-source obfuscator (ClangTooling)\n"
     << "  Made by @tmajik\n"
     << Reset << '\n';
}

} // namespace fev
