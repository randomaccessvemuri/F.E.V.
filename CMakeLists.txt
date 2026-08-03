cmake_minimum_required(VERSION 3.20)
project(fev LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(LLVM REQUIRED CONFIG)
find_package(Clang REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "Using ClangConfig.cmake in: ${Clang_DIR}")

execute_process(
  COMMAND clang -print-resource-dir
  OUTPUT_VARIABLE FEV_CLANG_RESOURCE_DIR
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE FEV_RESOURCE_DIR_RC
)
if(NOT FEV_RESOURCE_DIR_RC EQUAL 0 OR FEV_CLANG_RESOURCE_DIR STREQUAL "")
  message(FATAL_ERROR "Failed to resolve Clang resource directory via 'clang -print-resource-dir'")
endif()
message(STATUS "Clang resource dir: ${FEV_CLANG_RESOURCE_DIR}")

# Auto-discover every pass translation unit under src/passes/.
file(GLOB FEV_PASS_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/passes/*.cpp")
list(SORT FEV_PASS_SOURCES)
list(LENGTH FEV_PASS_SOURCES _fev_pass_src_count)
message(STATUS "FEV pass sources: ${_fev_pass_src_count}")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/DiscoverPasses.cmake")

set(FEV_SOURCES
  src/main.cpp
  src/Compiler.cpp
  src/Config.cpp
  src/PassRegistry.cpp
  src/TargetSupport.cpp
  src/support/ChaCha20.cpp
  src/support/Log.cpp
  ${FEV_PASS_SOURCES}
)

add_executable(fev ${FEV_SOURCES})

target_include_directories(fev PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/generated
  ${LLVM_INCLUDE_DIRS}
  ${CLANG_INCLUDE_DIRS}
)

target_compile_definitions(fev PRIVATE
  ${LLVM_DEFINITIONS}
  FEV_CLANG_RESOURCE_DIR="${FEV_CLANG_RESOURCE_DIR}"
)

target_compile_options(fev PRIVATE -fno-exceptions -Wall -Wextra -Wno-unused-parameter)
target_link_options(fev PRIVATE -Wl,--no-as-needed)
target_link_libraries(fev PRIVATE clang-cpp LLVM)

install(TARGETS fev RUNTIME DESTINATION bin)
