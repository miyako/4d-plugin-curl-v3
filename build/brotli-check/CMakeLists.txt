cmake_minimum_required(VERSION 3.15)
project(brotli_check C)

if(NOT BROTLI_ROOT)
  message(FATAL_ERROR "BROTLI_ROOT must point to the patched Brotli installation")
endif()

enable_testing()
add_executable(brotli-check check.c)
target_include_directories(brotli-check PRIVATE "${BROTLI_ROOT}/include")
foreach(component enc dec common)
  find_library(BROTLI_${component} NAMES brotli${component}
    PATHS "${BROTLI_ROOT}/lib" NO_DEFAULT_PATH REQUIRED)
  target_link_libraries(brotli-check PRIVATE "${BROTLI_${component}}")
endforeach()
if(NOT WIN32)
  target_link_libraries(brotli-check PRIVATE m)
endif()
add_test(NAME patched-brotli COMMAND brotli-check)
