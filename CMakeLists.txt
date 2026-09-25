cmake_minimum_required(VERSION 3.20)

project(webdavd
  VERSION 0.1.0
  DESCRIPTION "Lightweight WebDAV (RFC 4918 class 1) server"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

option(WEBDAV_BUILD_TESTS "Build unit tests" ON)

set(WEBDAV_WARNINGS -Wall -Wextra -Wpedantic -Werror)

find_package(Threads REQUIRED)
find_library(CRYPT_LIBRARY crypt REQUIRED)

include(FetchContent)

# ---------------------------------------------------------------- nlohmann/json
set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
FetchContent_Declare(nlohmann_json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(nlohmann_json)

# ---------------------------------------------------------------- Boost (headers)
# Boost.Asio + Boost.Beast are header-only for this project; we only need the
# include tree, so the superproject is fetched without being configured.
FetchContent_Declare(boost
  URL https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.tar.xz
  SOURCE_SUBDIR webdav-no-subdir
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(boost)

# The CMake release tarball ships modular headers under libs/*/include (there is
# no merged boost/ tree), so collect every library's include directory.
file(GLOB _webdav_boost_includes LIST_DIRECTORIES true
  "${boost_SOURCE_DIR}/libs/*/include"
  "${boost_SOURCE_DIR}/libs/*/*/include")
add_library(webdav_boost INTERFACE)
target_include_directories(webdav_boost SYSTEM INTERFACE ${_webdav_boost_includes})
target_compile_definitions(webdav_boost INTERFACE
  BOOST_ASIO_NO_DEPRECATED
  BOOST_SYSTEM_NO_DEPRECATED)

# Mark third-party include trees as SYSTEM so -Werror only applies to our code.
add_library(webdav_json INTERFACE)
target_include_directories(webdav_json SYSTEM INTERFACE "${nlohmann_json_SOURCE_DIR}/include")

# ---------------------------------------------------------------- core library
add_library(webdav_core STATIC
  src/auth.cpp
  src/bcrypt.cpp
  src/cli.cpp
  src/config.cpp
  src/dav.cpp
  src/fault.cpp
  src/fsutil.cpp
  src/http.cpp
  src/log.cpp
  src/server.cpp)

target_include_directories(webdav_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(webdav_core
  PUBLIC
    webdav_json
    webdav_boost
    Threads::Threads
  PRIVATE
    "${CRYPT_LIBRARY}")
target_compile_options(webdav_core PRIVATE ${WEBDAV_WARNINGS})

# ---------------------------------------------------------------- daemon
add_executable(webdavd src/main.cpp)
target_link_libraries(webdavd PRIVATE webdav_core)
target_compile_options(webdavd PRIVATE ${WEBDAV_WARNINGS})

# ---------------------------------------------------------------- tests
if(WEBDAV_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
