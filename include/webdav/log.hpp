#pragma once

#include <cstddef>
#include <string_view>

namespace webdav {

enum class LogLevel { kInfo, kWarning, kError };

// Maximum length of a emitted log line, including prefix and newline.
inline constexpr std::size_t kMaxLogLine = 512;

// Writes a single line to stdout (info/warning) or stderr (error).
// The message is truncated so a log line never exceeds kMaxLogLine bytes.
void log_write(LogLevel level, std::string_view message);

}  // namespace webdav
