# FEV — source-to-source compiler (ClangTooling)
#
# Build:
#   make
#   make list / list-targets / clean / help
#
# Obfuscate / compare:
#   make FILE=examples/sample.c BINARY=1
#   make FILE=examples/sample.c PASSES=none BINARY=1              # → sample_orig.c
#   make FILE=examples/sample.c PASSES=all SUFFIX=_obf BINARY=1
#   make FILE=examples/sample2.c PASSES=none SUFFIX=_orig BINARY=1
#   make FILE=examples/sample_cff.c PASSES=flatten-cfg BINARY=1 SEED=1
#
# PASSES=all (default) applies each pass in turn. PASSES=none copies the
# source unchanged (baseline for A/B). SUFFIX defaults to _obf, or _orig
# when PASSES=none.
#
# Extra fev flags: FEV_FLAGS='--opaque-density=0.5 -v'
# Shared pass log: LOG_FILE=fev.log (appended across sequential steps)

BUILD_DIR ?= build
JOBS      ?= $(shell nproc 2>/dev/null || echo 4)
CMAKE     ?= cmake
FEV       := $(BUILD_DIR)/fev

FILE        ?=
PASSES      ?= all
SEED        ?= 0xC0FFEE
OUT         ?=
BINARY      ?= 0
TARGET      ?= host
BINARY_OUT  ?=
CLANG_FLAGS ?=
FEV_FLAGS   ?=
SEQUENTIAL  ?=
LOG_FILE    ?=
VALIDATE    ?= warn
# Output name stem: sample$(SUFFIX).c  (e.g. _obf, _orig, _test)
SUFFIX      ?=

ifneq ($(LOG_FILE),)
FEV_LOG_ARGS := --log-file=$(LOG_FILE)
else
FEV_LOG_ARGS :=
endif

FEV_VALIDATE_ARGS := --validate=$(VALIDATE)

MINGW_FLAGS ?= --target=x86_64-w64-mingw32 \
	-isystem /usr/x86_64-w64-mingw32/include \
	-isystem /usr/lib/clang/22/include
# Direct gcc (PASSES=none): cross-compiler already knows its sysroot.
MINGW_GCC_FLAGS ?=

# Default suffix: _orig for baseline, otherwise _obf.
ifeq ($(SUFFIX),)
  ifeq ($(PASSES),none)
    SUFFIX := _orig
  else
    SUFFIX := _obf
  endif
endif

ifneq ($(FILE),)
_FILE_DIR  := $(dir $(FILE))
_FILE_BASE := $(basename $(notdir $(FILE)))
_FILE_EXT  := $(suffix $(FILE))
_OUT_DEF   := $(_FILE_DIR)$(_FILE_BASE)$(SUFFIX)$(_FILE_EXT)
_BIN_EXT   := $(if $(filter mingw-x64,$(TARGET)),.exe,)
_BIN_DEF   := $(_FILE_DIR)$(_FILE_BASE)$(SUFFIX)$(_BIN_EXT)
endif

OUT        := $(if $(OUT),$(OUT),$(_OUT_DEF))
BINARY_OUT := $(if $(BINARY_OUT),$(BINARY_OUT),$(_BIN_DEF))

# PASSES=all always pipelines; explicit lists are one-shot unless SEQUENTIAL=1.
ifeq ($(PASSES),all)
SEQUENTIAL := 1
endif

ifneq ($(FILE),)
.DEFAULT_GOAL := run
else
.DEFAULT_GOAL := build
endif

.PHONY: all configure build run obfuscate list list-targets clean help \
	test test-sample2 test-cff test-opaque

all: build

help:
	@echo ""
	@echo "  █████▒     ▓█████       ██▒   █▓"
	@echo "▓██   ▒      ▓█   ▀      ▓██░   █▒"
	@echo "▒████ ░      ▒███         ▓██  █▒░"
	@echo "░▓█▒  ░      ▒▓█  ▄        ▒██ █░░"
	@echo "░▒█░     ██▓ ░▒████▒ ██▓    ▒▀█░"
	@echo " ▒ ░     ▒▓▒ ░░ ▒░ ░ ▒▓▒    ░ ▐░"
	@echo " ░       ░▒   ░ ░  ░ ░▒     ░ ░░"
	@echo " ░ ░     ░      ░    ░        ░░"
	@echo "          ░     ░  ░  ░        ░"
	@echo "          ░           ░       ░"
	@echo ""
	@echo "  FEV — source-to-source obfuscator"
	@echo "  Made by @tmajik"
	@echo ""
	@echo "  make                         build fev"
	@echo "  make FILE=<src>              apply PASSES (default PASSES=all, SUFFIX=_obf)"
	@echo "  make FILE=<src> BINARY=1     also compile output"
	@echo "  make FILE=<src> PASSES=none  copy original → <stem>_orig.<ext>"
	@echo "  make list / list-targets / clean"
	@echo ""
	@echo "Knobs: FILE PASSES SEED SUFFIX OUT BINARY TARGET BINARY_OUT"
	@echo "       CLANG_FLAGS FEV_FLAGS SEQUENTIAL LOG_FILE VALIDATE"
	@echo ""
	@echo "  PASSES=all   → sequential pipeline of every pass"
	@echo "  PASSES=none  → no obfuscation (baseline copy for comparison)"
	@echo "  PASSES=a,b   → one fev invocation (SEQUENTIAL=1 to pipeline)"
	@echo "  SUFFIX=_obf  → output stem (default _obf; _orig when PASSES=none)"
	@echo ""
	@echo "Examples:"
	@echo "  make FILE=examples/sample.c BINARY=1"
	@echo "  make FILE=examples/sample.c PASSES=none BINARY=1"
	@echo "  make FILE=examples/sample.c PASSES=all SUFFIX=_obf BINARY=1"
	@echo "  make FILE=examples/sample2.c PASSES=none SUFFIX=_orig BINARY=1"
	@echo "  make FILE=examples/sample2.c BINARY=1"
	@echo ""
	@echo "Smoke: make test | test-sample2 | test-cff | test-opaque"

configure: $(BUILD_DIR)/CMakeCache.txt

$(BUILD_DIR)/CMakeCache.txt: CMakeLists.txt cmake/DiscoverPasses.cmake cmake/GeneratedPassNames.h.in
	$(CMAKE) -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release

build: configure
	$(CMAKE) --build $(BUILD_DIR) -j$(JOBS)

$(FEV): build

list: $(FEV)
	$(FEV) --list-passes

list-targets: $(FEV)
	$(FEV) --list-targets

run obfuscate: $(FEV)
	@if [ -z "$(FILE)" ]; then \
	  echo "usage: make FILE=<source.c> [PASSES=all|none|a,b] [SUFFIX=_obf] [BINARY=1] …" >&2; \
	  echo "       make help" >&2; \
	  exit 1; \
	fi
	@if [ ! -f "$(FILE)" ]; then \
	  echo "error: FILE not found: $(FILE)" >&2; \
	  exit 1; \
	fi
	@set -e; \
	EFF_TARGET="$(TARGET)"; \
	EFF_CLANG="$(CLANG_FLAGS)"; \
	EFF_BINOUT="$(BINARY_OUT)"; \
	if grep -qE '^[ 	]*#[ 	]*include[ 	]*[<\"]windows\.h[>\"]' "$(FILE)"; then \
	  if [ "$$EFF_TARGET" = "host" ]; then \
	    echo "note: windows.h in $(FILE) → TARGET=mingw-x64"; \
	    EFF_TARGET=mingw-x64; \
	  fi; \
	  if [ -z "$$EFF_CLANG" ]; then \
	    EFF_CLANG="$(MINGW_FLAGS)"; \
	  fi; \
	  case "$$EFF_BINOUT" in \
	    *.exe) ;; \
	    *) EFF_BINOUT="$${EFF_BINOUT}.exe" ;; \
	  esac; \
	fi; \
	rm -f "$(OUT)" $$( [ "$(BINARY)" = "1" ] || [ "$(BINARY)" = "yes" ] || [ "$(BINARY)" = "true" ] || [ "$(BINARY)" = "ON" ] && echo "$$EFF_BINOUT" ); \
	WANT_BIN=0; \
	case "$(BINARY)" in 1|yes|true|ON) WANT_BIN=1 ;; esac; \
	\
	if [ "$(PASSES)" = "none" ]; then \
	  echo "passes: none (baseline copy → $(OUT), SUFFIX=$(SUFFIX))"; \
	  cp -f "$(FILE)" "$(OUT)"; \
	  if [ "$$WANT_BIN" = "1" ]; then \
	    if [ "$$EFF_TARGET" = "mingw-x64" ]; then \
	      echo "compiling [mingw-x64] $$EFF_BINOUT"; \
	      x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -o "$$EFF_BINOUT" "$(OUT)" $(MINGW_GCC_FLAGS); \
	    else \
	      echo "compiling [host] $$EFF_BINOUT"; \
	      clang -std=c11 -Wall -Wextra -o "$$EFF_BINOUT" "$(OUT)" $$EFF_CLANG; \
	    fi; \
	  fi; \
	  echo "wrote $(OUT)" $$( [ "$$WANT_BIN" = "1" ] && echo "+ $$EFF_BINOUT" ); \
	  exit 0; \
	fi; \
	\
	EMIT_BIN=""; \
	if [ "$$WANT_BIN" = "1" ]; then \
	  EMIT_BIN="--emit-binary --binary-target=$$EFF_TARGET --binary-output=$$EFF_BINOUT"; \
	fi; \
	PASS_LIST_OUT=$$($(FEV) --no-banner --list-passes 2>/dev/null); \
	pass_desc() { \
	  printf '%s\n' "$$PASS_LIST_OUT" | awk -v n="$$1" \
	    '$$0 == "  " n { getline; sub(/^[[:space:]]+/, ""); print; exit }'; \
	}; \
	if [ "$(PASSES)" = "all" ]; then \
	  RAW=$$(printf '%s\n' "$$PASS_LIST_OUT" | sed -n 's/^  \([a-z0-9][-a-z0-9]*\)$$/\1/p'); \
	else \
	  RAW=$$(printf '%s' "$(PASSES)" | tr ',' ' '); \
	fi; \
	if [ -z "$$RAW" ]; then \
	  echo "error: no passes to run (PASSES=$(PASSES))" >&2; \
	  exit 1; \
	fi; \
	if [ "$(SEQUENTIAL)" = "1" ]; then \
	  STEPS=""; \
	  PENDING=""; \
	  for P in $$RAW; do \
	    if [ "$$P" = "encrypt-strings" ]; then \
	      PENDING="encrypt-strings"; \
	    elif [ "$$P" = "encrypt-buffers" ] && [ "$$PENDING" = "encrypt-strings" ]; then \
	      STEPS="$$STEPS encrypt-strings,encrypt-buffers"; \
	      PENDING=""; \
	    elif [ "$$P" = "encrypt-buffers" ]; then \
	      STEPS="$$STEPS encrypt-buffers"; \
	    else \
	      if [ -n "$$PENDING" ]; then STEPS="$$STEPS $$PENDING"; PENDING=""; fi; \
	      STEPS="$$STEPS $$P"; \
	    fi; \
	  done; \
	  if [ -n "$$PENDING" ]; then STEPS="$$STEPS $$PENDING"; fi; \
	  STEPS=$$(echo $$STEPS); \
	  # dict-bytes before scramble-arrays / array-split (encode plain bytes first). \
	  STEPS_NO_DB=""; \
	  HAS_DB=0; \
	  for S in $$STEPS; do \
	    if [ "$$S" = "dict-bytes" ]; then HAS_DB=1; \
	    else STEPS_NO_DB="$$STEPS_NO_DB $$S"; fi; \
	  done; \
	  if [ "$$HAS_DB" = "1" ]; then \
	    STEPS_WITH_DB=""; \
	    INSERTED=0; \
	    for S in $$STEPS_NO_DB; do \
	      if [ "$$INSERTED" = "0" ] && { [ "$$S" = "array-split" ] || [ "$$S" = "scramble-arrays" ]; }; then \
	        STEPS_WITH_DB="$$STEPS_WITH_DB dict-bytes $$S"; \
	        INSERTED=1; \
	      else \
	        STEPS_WITH_DB="$$STEPS_WITH_DB $$S"; \
	      fi; \
	    done; \
	    if [ "$$INSERTED" = "0" ]; then STEPS_WITH_DB="$$STEPS_WITH_DB dict-bytes"; fi; \
	    STEPS=$$STEPS_WITH_DB; \
	  else \
	    STEPS=$$STEPS_NO_DB; \
	  fi; \
	  STEPS=$$(echo $$STEPS); \
	  # dict-rename last so _fev_* names from earlier passes get scrubbed. \
	  STEPS_NO_DICT=""; \
	  HAS_DICT=0; \
	  for S in $$STEPS; do \
	    if [ "$$S" = "dict-rename" ]; then HAS_DICT=1; \
	    else STEPS_NO_DICT="$$STEPS_NO_DICT $$S"; fi; \
	  done; \
	  if [ "$$HAS_DICT" = "1" ]; then STEPS="$$STEPS_NO_DICT dict-rename"; \
	  else STEPS="$$STEPS_NO_DICT"; fi; \
	  STEPS=$$(echo $$STEPS); \
	  echo "pipeline: $$STEPS  (SUFFIX=$(SUFFIX))"; \
	  LAST=$$(printf '%s\n' $$STEPS | tail -n1); \
	  CUR="$(FILE)"; \
	  FIRST=1; \
	  for STEP in $$STEPS; do \
	    DESC=""; \
	    for PN in $$(printf '%s' "$$STEP" | tr ',' ' '); do \
	      PD=$$(pass_desc "$$PN"); \
	      if [ -n "$$PD" ]; then \
	        if [ -n "$$DESC" ]; then DESC="$$DESC | $$PD"; else DESC="$$PD"; fi; \
	      fi; \
	    done; \
	    if [ -n "$$DESC" ]; then echo "→ $$STEP — $$DESC"; else echo "→ $$STEP"; fi; \
	    EMIT=""; \
	    if [ "$$WANT_BIN" = "1" ] && [ "$$STEP" = "$$LAST" ]; then EMIT="$$EMIT_BIN"; fi; \
	    BANNER_FLAG=""; \
	    if [ "$$FIRST" = "0" ]; then BANNER_FLAG="--no-banner"; fi; \
	    FIRST=0; \
	    $(FEV) $$BANNER_FLAG --passes=$$STEP --seed=$(SEED) -o "$(OUT)" $$EMIT $(FEV_LOG_ARGS) $(FEV_VALIDATE_ARGS) $(FEV_FLAGS) \
	      "$$CUR" -- $$EFF_CLANG; \
	    CUR="$(OUT)"; \
	  done; \
	else \
	  echo "passes: $$RAW (single invocation, SUFFIX=$(SUFFIX))"; \
	  for PN in $$RAW; do \
	    PD=$$(pass_desc "$$PN"); \
	    if [ -n "$$PD" ]; then echo "  $$PN — $$PD"; else echo "  $$PN"; fi; \
	  done; \
	  $(FEV) --passes=$(PASSES) --seed=$(SEED) -o "$(OUT)" $$EMIT_BIN $(FEV_LOG_ARGS) $(FEV_VALIDATE_ARGS) $(FEV_FLAGS) \
	    "$(FILE)" -- $$EFF_CLANG; \
	fi; \
	echo "wrote $(OUT)" $$( [ "$$WANT_BIN" = "1" ] && echo "+ $$EFF_BINOUT" )

# --- smoke tests ----------------------------------------------------------

test: $(FEV)
	$(MAKE) --no-print-directory FILE=examples/sample.c \
		PASSES=encrypt-strings,encrypt-buffers BINARY=1 TARGET=host SEED=0xC0FFEE
	@test -f examples/sample_obf.c && test -f examples/sample_obf
	@OUT=$$(examples/sample_obf); echo "$$OUT"; \
	  echo "$$OUT" | grep -qx 'hello from fev: sum=5' \
	  || (echo "FAIL: unexpected program output" >&2; exit 1)
	@! grep -F 'hello from fev' examples/sample_obf.c >/dev/null \
	  || (echo "FAIL: cleartext format string still present" >&2; exit 1)
	@echo "PASS: examples/sample_obf.c + examples/sample_obf"

test-sample2: $(FEV)
	$(MAKE) --no-print-directory FILE=examples/sample2.c \
		PASSES=mba-substitute,flatten-cfg,opaque-predicates,encrypt-buffers \
		SEQUENTIAL=1 BINARY=1 TARGET=mingw-x64 SEED=0xC0FFEE \
		CLANG_FLAGS="$(MINGW_FLAGS)"
	@test -f examples/sample2_obf.c && test -f examples/sample2_obf.exe
	@! grep -q '0xfc, 0x48, 0x83' examples/sample2_obf.c \
	  || (echo "FAIL: cleartext payload prefix still present" >&2; exit 1)
	@grep -q '_fev_ct_my_payload' examples/sample2_obf.c
	@grep -q '_fev_sw' examples/sample2_obf.c
	@file examples/sample2_obf.exe | grep -qi 'PE32+' \
	  || (echo "FAIL: expected PE32+ binary" >&2; file examples/sample2_obf.exe; exit 1)
	@echo "PASS: examples/sample2_obf.c + examples/sample2_obf.exe"

test-cff: $(FEV)
	$(MAKE) --no-print-directory FILE=examples/sample_cff.c \
		PASSES=flatten-cfg BINARY=1 TARGET=host SEED=1
	@test -f examples/sample_cff_obf.c && test -f examples/sample_cff_obf
	@grep -q '_fev_sw' examples/sample_cff_obf.c
	@grep -q 'while' examples/sample_cff_obf.c
	@OUT=$$(examples/sample_cff_obf); echo "$$OUT"; \
	  echo "$$OUT" | grep -qx 'laszlo cff: x=12' \
	  || (echo "FAIL: unexpected program output" >&2; exit 1)
	@echo "PASS: examples/sample_cff_obf.c + examples/sample_cff_obf"

test-opaque: $(FEV)
	$(MAKE) --no-print-directory FILE=examples/sample_opaque.c \
		PASSES=opaque-predicates BINARY=1 TARGET=host SEED=0xC0FFEE \
		FEV_FLAGS="--opaque-density=1.0 --opaque-fib-n=12"
	@test -f examples/sample_opaque_obf.c && test -f examples/sample_opaque_obf
	@grep -q 'FEV_OPAQUE_RUNTIME' examples/sample_opaque_obf.c
	@grep -qE '_fev_cityhash64|_fev_modexp|_fev_fib|_fev_collatz_ok' examples/sample_opaque_obf.c
	@grep -q '_fev_ox_' examples/sample_opaque_obf.c
	@OUT=$$(examples/sample_opaque_obf); echo "$$OUT"; \
	  echo "$$OUT" | grep -qx 'opaque demo: 49' \
	  || (echo "FAIL: unexpected program output" >&2; exit 1)
	@echo "PASS: examples/sample_opaque_obf.c + examples/sample_opaque_obf"

clean:
	rm -rf $(BUILD_DIR) out
	rm -f examples/*_obf.c examples/*_obf.h examples/*_obf examples/*_obf.exe
	rm -f examples/*_orig.c examples/*_orig.h examples/*_orig examples/*_orig.exe
