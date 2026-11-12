cmake_minimum_required(VERSION 3.20)
cmake_policy(SET CMP0091 NEW)
project(proxy_provenance_candidate LANGUAGES CXX)

if(NOT IS_DIRECTORY "${PROXY_SOURCE}/libmodman")
  message(FATAL_ERROR "PROXY_SOURCE must be the verified upstream checkout")
endif()
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY MultiThreaded)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(modman STATIC "${PROXY_SOURCE}/libmodman/module_manager.cpp")
add_library(proxy STATIC
  "${PROXY_SOURCE}/libproxy/extension_config.cpp"
  "${PROXY_SOURCE}/libproxy/extension_pacrunner.cpp"
  "${PROXY_SOURCE}/libproxy/extension_wpad.cpp"
  "${PROXY_SOURCE}/libproxy/proxy.cpp"
  "${PROXY_SOURCE}/libproxy/url.cpp")

foreach(module IN LISTS PROXY_MODULES)
  target_sources(proxy PRIVATE "${PROXY_SOURCE}/libproxy/modules/${module}.cpp")
  set_source_files_properties("${PROXY_SOURCE}/libproxy/modules/${module}.cpp"
    PROPERTIES COMPILE_DEFINITIONS "MM_MODULE_BUILTIN=${module}")
  string(APPEND builtins "X(${module})")
endforeach()
string(REPLACE "\\" "\\\\" module_directory "${PROXY_MODULE_DIRECTORY}")
set_source_files_properties("${PROXY_SOURCE}/libproxy/proxy.cpp" PROPERTIES
  COMPILE_DEFINITIONS "BUILTIN_MODULES=${builtins};MODULEDIR=\"${module_directory}\"")

foreach(target modman proxy)
  target_include_directories(${target} PUBLIC "${PROXY_SOURCE}" "${PROXY_SOURCE}/libproxy")
  if(WIN32)
    target_compile_definitions(${target} PRIVATE WIN32 _CRT_SECURE_NO_WARNINGS)
  else()
    target_compile_definitions(${target} PRIVATE _POSIX_C_SOURCE=200112L)
    target_compile_options(${target} PRIVATE -fvisibility=hidden -fPIC)
  endif()
endforeach()
target_link_libraries(proxy PUBLIC modman)
if(WIN32)
  set_target_properties(proxy PROPERTIES OUTPUT_NAME libproxy)
  target_link_libraries(proxy PUBLIC ws2_32 advapi32)
elseif(APPLE)
  target_link_libraries(proxy PUBLIC "-framework CoreFoundation"
    "-framework SystemConfiguration" "-framework JavaScriptCore")
else()
  message(FATAL_ERROR "Only the plugin's macOS and Windows targets are supported")
endif()

enable_testing()
add_executable(proxy_behavior behavior.cpp)
target_link_libraries(proxy_behavior PRIVATE proxy)
add_executable(proxy_file_url file-url.cpp)
target_link_libraries(proxy_file_url PRIVATE proxy)
add_executable(proxy_url_test "${PROXY_SOURCE}/libproxy/test/url-test.cpp")
target_link_libraries(proxy_url_test PRIVATE proxy)
add_executable(proxy_url_encode "${PROXY_SOURCE}/libproxy/test/url-encode.cpp")
target_link_libraries(proxy_url_encode PRIVATE proxy)
if(WIN32)
  foreach(target proxy_behavior proxy_file_url proxy_url_test proxy_url_encode)
    target_compile_definitions(${target} PRIVATE WIN32 _CRT_SECURE_NO_WARNINGS)
  endforeach()
endif()
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/empty-modules")
configure_file(test.pac "${CMAKE_CURRENT_BINARY_DIR}/test.pac" COPYONLY)
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/test.pac" pac)
string(REPLACE "\r\n" "\n" pac "${pac}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test-lf.pac" "${pac}")
string(REPLACE "\n" "\r\n" pac "${pac}")
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/test-crlf.pac" "${pac}")
foreach(target proxy_behavior proxy_file_url proxy_url_test proxy_url_encode)
  if(target STREQUAL "proxy_file_url")
    add_test(NAME ${target} COMMAND ${target} "${CMAKE_CURRENT_BINARY_DIR}/test-lf.pac"
      "${CMAKE_CURRENT_BINARY_DIR}/test-crlf.pac")
  else()
    add_test(NAME ${target} COMMAND ${target} "${CMAKE_CURRENT_BINARY_DIR}/test.pac")
  endif()
  set_tests_properties(${target} PROPERTIES TIMEOUT 30
    ENVIRONMENT "PX_MODULE_PATH=${CMAKE_CURRENT_BINARY_DIR}/empty-modules")
endforeach()

# The same public-API fixture exercises the exact old archives without assigning
# them the candidate source identity or changing the plugin's linker inputs.
if(BASELINE_PROXY AND BASELINE_MODMAN)
  add_executable(proxy_baseline_behavior behavior.cpp)
  target_compile_definitions(proxy_baseline_behavior PRIVATE PROXY_BASELINE_OBSERVATION=1)
  target_include_directories(proxy_baseline_behavior PRIVATE "${PROXY_SOURCE}/libproxy")
  target_link_libraries(proxy_baseline_behavior PRIVATE "${BASELINE_PROXY}" "${BASELINE_MODMAN}")
  if(WIN32)
    target_compile_definitions(proxy_baseline_behavior PRIVATE WIN32 _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(proxy_baseline_behavior PRIVATE ws2_32 advapi32)
  else()
    target_link_libraries(proxy_baseline_behavior PRIVATE "-framework CoreFoundation"
      "-framework SystemConfiguration" "-framework JavaScriptCore")
  endif()
  add_test(NAME proxy_baseline_behavior COMMAND proxy_baseline_behavior
    "${CMAKE_CURRENT_BINARY_DIR}/test.pac")
  set_tests_properties(proxy_baseline_behavior PROPERTIES TIMEOUT 30
    ENVIRONMENT "PX_MODULE_PATH=${CMAKE_CURRENT_BINARY_DIR}/empty-modules")
endif()

if(PROXY_RELINK_PROBE)
  add_executable(proxy_user_relink relink-probe.cpp)
  target_link_libraries(proxy_user_relink PRIVATE proxy)
  add_test(NAME proxy_user_relink COMMAND proxy_user_relink)
endif()

install(TARGETS proxy modman ARCHIVE DESTINATION lib)
install(FILES "${PROXY_SOURCE}/libproxy/proxy.h" DESTINATION include)
install(FILES "${PROXY_SOURCE}/COPYING" DESTINATION share/licenses/libproxy)
