#pragma once

#include "llvm/ADT/StringRef.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <utility>

namespace fev {

enum class LogLevel {
  Debug = 0,
  Info = 1,
  Warn = 2,
  Error = 3,
};

enum class LogColorMode {
  Auto,
  Always,
  Never,
};

void setLogLevel(LogLevel Min);
LogLevel getLogLevel();
void setLogColorMode(LogColorMode Mode);
bool logColorEnabled();

/// Apply NO_COLOR / FORCE_COLOR / TERM / FEV_LOG_FILE heuristics before CLI.
void initLogFromEnvironment();

bool logEnabled(LogLevel Level);

/// Append all info/debug (and warn/error) lines to one shared log file.
/// Returns false if the path cannot be opened. Empty Path closes the file.
bool setLogFile(llvm::StringRef Path);
void closeLogFile();
bool hasLogFile();
llvm::StringRef getLogFilePath();

/// Tag subsequent log lines with the active pass name (empty = none).
void setCurrentPass(llvm::StringRef Name);
llvm::StringRef getCurrentPass();

/// RAII: sets the current pass for the duration of a pass run.
class PassLogScope {
public:
  explicit PassLogScope(llvm::StringRef Name) { setCurrentPass(Name); }
  ~PassLogScope() { setCurrentPass({}); }
  PassLogScope(const PassLogScope &) = delete;
  PassLogScope &operator=(const PassLogScope &) = delete;
};

/// FEV ASCII banner + credit line (stderr when TTY-colored, else stdout-safe).
void printBanner(llvm::raw_ostream &OS);

/// Buffered log line. Flushes a single colored `fev: <level> …` line on
/// destruction (or explicit finish()). When a log file is open, info/debug
/// (plus warn/error) are also appended there without ANSI colors.
class LogMessage {
public:
  explicit LogMessage(LogLevel Level);
  ~LogMessage();

  LogMessage(const LogMessage &) = delete;
  LogMessage &operator=(const LogMessage &) = delete;

  LogMessage(LogMessage &&Other) noexcept
      : Level_(Other.Level_), ActiveConsole_(Other.ActiveConsole_),
        ActiveFile_(Other.ActiveFile_), Active_(Other.Active_),
        Finished_(Other.Finished_), Text_(std::move(Other.Text_)) {
    Other.Active_ = false;
    Other.ActiveConsole_ = false;
    Other.ActiveFile_ = false;
    Other.Finished_ = true;
  }

  LogMessage &operator=(LogMessage &&Other) noexcept {
    if (this != &Other) {
      finish();
      Level_ = Other.Level_;
      ActiveConsole_ = Other.ActiveConsole_;
      ActiveFile_ = Other.ActiveFile_;
      Active_ = Other.Active_;
      Finished_ = Other.Finished_;
      Text_ = std::move(Other.Text_);
      Other.Active_ = false;
      Other.ActiveConsole_ = false;
      Other.ActiveFile_ = false;
      Other.Finished_ = true;
    }
    return *this;
  }

  template <typename T> LogMessage &operator<<(const T &Value) {
    if (Active_) {
      llvm::raw_string_ostream OS(Text_);
      OS << Value;
    }
    return *this;
  }

  void finish();

private:
  LogLevel Level_;
  bool ActiveConsole_ = false;
  bool ActiveFile_ = false;
  bool Active_ = false;
  bool Finished_ = false;
  std::string Text_;
};

inline LogMessage logDebug() { return LogMessage(LogLevel::Debug); }
inline LogMessage logInfo() { return LogMessage(LogLevel::Info); }
inline LogMessage logWarn() { return LogMessage(LogLevel::Warn); }
inline LogMessage logError() { return LogMessage(LogLevel::Error); }

} // namespace fev
