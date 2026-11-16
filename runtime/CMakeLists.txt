cmake_minimum_required(VERSION 3.15)
project(apkbridge_runtime LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_options(/W3 /EHsc)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# zlib is required by the ZIP/APK reader (ships on iOS/macOS/Linux/Windows).
find_package(ZLIB REQUIRED)

# Core C++ (DEX parse/interp + ZIP + AXML) behind the C ABI.
add_library(apkbridge_core STATIC src/bridge.cpp)
target_include_directories(apkbridge_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(apkbridge_core PUBLIC ZLIB::ZLIB)

# CLI driver — calls the SAME C ABI the iOS host uses.
add_executable(apkbridge_run src/main.cpp)
target_link_libraries(apkbridge_run PRIVATE apkbridge_core)

enable_testing()
add_executable(runtime_tests ${CMAKE_CURRENT_SOURCE_DIR}/../tests/runtime/runtime_tests.cpp)
target_link_libraries(runtime_tests PRIVATE apkbridge_core ZLIB::ZLIB)
add_test(NAME runtime_tests COMMAND runtime_tests)
