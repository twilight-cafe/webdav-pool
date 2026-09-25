#include <gtest/gtest.h>

#include <cstring>
#include <string>

#include "webdav/fault.hpp"
#include "webdav/log.hpp"

TEST(LogTest, WritesEveryLevel) {
  webdav::log_write(webdav::LogLevel::kInfo, "info");
  webdav::log_write(webdav::LogLevel::kWarning, "warning");
  webdav::log_write(webdav::LogLevel::kError, "error");
}

TEST(LogTest, TruncatesOverlongLines) {
  webdav::log_write(webdav::LogLevel::kInfo, std::string(2000, 'x'));
}

TEST(LogTest, FallsBackWhenTimeConversionFails) {
  webdav::set_fault_hook([](const char* operation) {
    return std::strcmp(operation, "gmtime_r") == 0 ? EINVAL : 0;
  });
  webdav::log_write(webdav::LogLevel::kWarning, "fallback");
  webdav::set_fault_hook(nullptr);
}
