#include "webdav/log.hpp"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "webdav/fault.hpp"

namespace webdav {

namespace {

const char* level_tag(LogLevel level) {
  if (level == LogLevel::kWarning) {
    return "WARN";
  }
  if (level == LogLevel::kError) {
    return "ERROR";
  }
  return "INFO";
}

}  // namespace

void log_write(LogLevel level, std::string_view message) {
  char stamp[32];
  const std::time_t now = std::time(nullptr);
  std::tm tm_buf{};
  if (fs_gmtime_r(&now, &tm_buf) != nullptr) {
    std::strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm_buf);
  } else {
    std::strcpy(stamp, "-");
  }

  char line[kMaxLogLine];
  const int written = std::snprintf(line, sizeof(line), "%s [%s] %.*s\n", stamp, level_tag(level),
                                    static_cast<int>(message.size()), message.data());
  std::size_t length = static_cast<std::size_t>(written);
  if (length >= sizeof(line)) {
    length = sizeof(line) - 1;  // snprintf truncated the line
  }
  std::FILE* out = (level == LogLevel::kError) ? stderr : stdout;
  std::fwrite(line, 1, length, out);
  std::fflush(out);
}

}  // namespace webdav
