include(FetchContent)

FetchContent_Declare(googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(webdav_tests
  test_auth.cpp
  test_bcrypt.cpp
  test_cli.cpp
  test_config.cpp
  test_dav.cpp
  test_fault.cpp
  test_fsutil.cpp
  test_http.cpp
  test_log.cpp)

target_link_libraries(webdav_tests PRIVATE webdav_core GTest::gtest_main "${CRYPT_LIBRARY}")
target_compile_options(webdav_tests PRIVATE ${WEBDAV_WARNINGS})
target_compile_definitions(webdav_tests PRIVATE
  WEBDAV_TEST_TMPDIR="${CMAKE_BINARY_DIR}/tmp")

include(GoogleTest)
gtest_discover_tests(webdav_tests)

# Runs the real binary; keeps main() and the CLI error-exit paths covered.
add_test(NAME cli_version COMMAND webdavd --version)
