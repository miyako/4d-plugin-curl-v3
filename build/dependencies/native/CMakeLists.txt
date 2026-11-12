cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0091 NEW)
project(native_source_prerequisites LANGUAGES C)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
enable_testing()

if(NOT NATIVE_LIBRARY STREQUAL "zlib")
  message(FATAL_ERROR "Unsupported source prerequisite")
endif()
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(ZLIB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(ZLIB_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(ZLIB_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZLIB_INSTALL OFF CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)
add_subdirectory("${NATIVE_SOURCE}" upstream EXCLUDE_FROM_ALL)
if(WIN32)
  set_target_properties(zlibstatic PROPERTIES OUTPUT_NAME zlib)
endif()

foreach(kind candidate baseline)
  add_executable(zlib_${kind}_probe zlib-probe.c)
  target_include_directories(zlib_${kind}_probe PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/upstream" "${NATIVE_SOURCE}")
  target_compile_definitions(zlib_${kind}_probe PRIVATE
    EXPECTED_ZLIB_VERSION="${EXPECTED_VERSION}")
  if(WIN32)
    target_link_options(zlib_${kind}_probe PRIVATE
      "/MAP:${CMAKE_CURRENT_BINARY_DIR}/${kind}.map" /VERBOSE:LIB)
  else()
    target_link_options(zlib_${kind}_probe PRIVATE
      "LINKER:-map,${CMAKE_CURRENT_BINARY_DIR}/${kind}.map")
  endif()
  if(kind STREQUAL "candidate")
    target_link_libraries(zlib_${kind}_probe PRIVATE zlibstatic)
  else()
    target_link_libraries(zlib_${kind}_probe PRIVATE "${BASELINE_ARCHIVE}")
  endif()
  add_test(NAME zlib_${kind}_write COMMAND zlib_${kind}_probe write
    "${CMAKE_CURRENT_BINARY_DIR}/${kind}-streams")
endforeach()
add_test(NAME zlib_candidate_read COMMAND zlib_candidate_probe read
  "${CMAKE_CURRENT_BINARY_DIR}/baseline-streams")
add_test(NAME zlib_baseline_read COMMAND zlib_baseline_probe read
  "${CMAKE_CURRENT_BINARY_DIR}/candidate-streams")
set_tests_properties(zlib_candidate_read PROPERTIES DEPENDS zlib_baseline_write)
set_tests_properties(zlib_baseline_read PROPERTIES DEPENDS zlib_candidate_write)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME zlib_configuration COMMAND "${Python3_EXECUTABLE}" "${NATIVE_DRIVER}"
  compare-zlib "${CMAKE_CURRENT_BINARY_DIR}/candidate-streams/version-info.json"
  "${CMAKE_CURRENT_BINARY_DIR}/baseline-streams/version-info.json")
set_tests_properties(zlib_configuration PROPERTIES
  DEPENDS "zlib_candidate_write;zlib_baseline_write")
set_tests_properties(zlib_candidate_write zlib_baseline_write zlib_candidate_read
  zlib_baseline_read zlib_configuration PROPERTIES TIMEOUT 30)

install(FILES "$<TARGET_FILE:zlibstatic>" DESTINATION lib)
install(FILES "${NATIVE_SOURCE}/zlib.h" "${CMAKE_CURRENT_BINARY_DIR}/upstream/zconf.h"
  DESTINATION include)
install(FILES "${NATIVE_SOURCE}/LICENSE" DESTINATION share/licenses/zlib)
