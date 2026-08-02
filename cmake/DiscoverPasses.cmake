# Discovers pass string names from src/passes/*.cpp and emits a header.
# Looks for:  llvm::StringRef name() const override { return "pass-id"; }

set(FEV_PASSES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/passes")
file(GLOB FEV_PASS_SOURCES CONFIGURE_DEPENDS "${FEV_PASSES_DIR}/*.cpp")
list(SORT FEV_PASS_SOURCES)

set(FEV_PASS_NAME_LIST "")
set(_fev_names_acc "")

foreach(_fev_src ${FEV_PASS_SOURCES})
  get_filename_component(_fev_base "${_fev_src}" NAME)
  file(READ "${_fev_src}" _fev_contents)

  string(REGEX MATCH
    "name\\(\\)[ \t\r\n]*const[ \t\r\n]*override[ \t\r\n]*\\{[ \t\r\n]*return[ \t\r\n]*\"([^\"]+)\""
    _fev_match "${_fev_contents}")

  if(CMAKE_MATCH_1)
    set(_fev_pass_name "${CMAKE_MATCH_1}")
    list(APPEND FEV_PASS_NAME_LIST "${_fev_pass_name}")
    string(APPEND _fev_names_acc "  \"${_fev_pass_name}\",\n")
    message(STATUS "FEV pass: ${_fev_pass_name}  (${_fev_base})")
  else()
    message(WARNING "FEV: could not extract pass name() from ${_fev_base} — "
                    "expected: name() const override { return \"id\"; }")
  endif()
endforeach()

list(LENGTH FEV_PASS_NAME_LIST FEV_PASS_NAME_COUNT)

set(_fev_gen_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${_fev_gen_dir}")
set(FEV_GENERATED_PASS_NAMES_H "${_fev_gen_dir}/GeneratedPassNames.h")

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/GeneratedPassNames.h.in"
  "${FEV_GENERATED_PASS_NAMES_H}"
  @ONLY
)
