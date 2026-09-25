#include "webdav/http.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "webdav/fault.hpp"

namespace webdav {

namespace {

constexpr std::size_t kMaxChunkLine = 128;

int hex_digit(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

bool extract_header(const http::request_header<>& head, std::string_view name, std::string& out) {
  const auto field = head.find(name);
  if (field == head.end()) {
    return false;
  }
  out.assign(field->value().data(), field->value().size());
  return true;
}

std::string normalise(std::string value) {
  std::string out;
  out.reserve(value.size());
  for (const char c : value) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}  // LCOV_EXCL_LINE

}  // namespace

std::string format_http_date(std::time_t when) {
  std::tm parts{};
  if (fs_gmtime_r(&when, &parts) == nullptr) {
    return "Thu, 01 Jan 1970 00:00:00 GMT";
  }
  char buffer[64];
  std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &parts);
  return buffer;
}

std::string format_iso8601(std::time_t when) {
  std::tm parts{};
  if (fs_gmtime_r(&when, &parts) == nullptr) {
    return "1970-01-01T00:00:00Z";
  }
  char buffer[64];
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &parts);
  return buffer;
}

std::string format_etag(std::uint64_t size, const struct timespec& modified) {
  const long long nanos = static_cast<long long>(modified.tv_sec) * 1000000000LL +
                          static_cast<long long>(modified.tv_nsec);
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "\"%llu-%lld\"",
                static_cast<unsigned long long>(size), nanos);
  return buffer;
}

const char* reason_phrase(http::status status) {
  switch (status) {
    case http::status::ok:
      return "OK";
    case http::status::created:
      return "Created";
    case http::status::no_content:
      return "No Content";
    case http::status::partial_content:
      return "Partial Content";
    case http::status::multi_status:
      return "Multi-Status";
    case http::status::bad_request:
      return "Bad Request";
    case http::status::unauthorized:
      return "Unauthorized";
    case http::status::forbidden:
      return "Forbidden";
    case http::status::not_found:
      return "Not Found";
    case http::status::method_not_allowed:
      return "Method Not Allowed";
    case http::status::length_required:
      return "Length Required";
    case http::status::conflict:
      return "Conflict";
    case http::status::precondition_failed:
      return "Precondition Failed";
    case http::status::unsupported_media_type:
      return "Unsupported Media Type";
    case http::status::range_not_satisfiable:
      return "Range Not Satisfiable";
    case http::status::internal_server_error:
      return "Internal Server Error";
    case http::status::not_implemented:
      return "Not Implemented";
    case http::status::bad_gateway:
      return "Bad Gateway";
    case http::status::service_unavailable:
      return "Service Unavailable";
    case http::status::insufficient_storage:
      return "Insufficient Storage";
    default:
      break;
  }
  return "Unknown";
}

bool Reader::read_some(char* out, std::size_t length, std::size_t& got) {
  got = 0;
  if (length == 0) {
    return true;
  }
  for (;;) {
    if (buffer_.size() > 0) {
      const std::size_t n = std::min<std::size_t>(length, buffer_.size());
      const auto data = buffer_.data();
      std::memcpy(out, data.data(), n);
      buffer_.consume(n);
      got = n;
      return true;
    }
    std::size_t read = socket_.read_some(buffer_.prepare(kIoBufferSize), error_);
    if (error_) {
      return false;
    }
    buffer_.commit(read);
  }
}

bool Reader::read_exact(char* out, std::size_t length) {
  std::size_t total = 0;
  while (total < length) {
    std::size_t got = 0;
    if (!read_some(out + total, length - total, got)) {
      return false;
    }
    total += got;
  }
  return true;
}

BodyReader::BodyReader(Reader& reader, const http::request_header<>& head) : reader_(reader) {
  const std::size_t transfer_encoding_count = head.count("transfer-encoding");
  std::string encoding;
  if (transfer_encoding_count != 0) {
    if (transfer_encoding_count != 1 || head.count("content-length") != 0 ||
        !extract_header(head, "transfer-encoding", encoding) ||
        normalise(encoding) != "chunked") {
      (void)fail();
      return;
    }
    state_ = State::kChunkSize;
    return;
  }
  if (head.count("content-length") > 1) {
    (void)fail();
    return;
  }
  std::string length;
  if (!extract_header(head, "content-length", length)) {
    state_ = State::kDone;
    return;
  }
  if (length.empty()) {
    (void)fail();
    return;
  }
  std::uint64_t value = 0;
  for (const char c : length) {
    if (c < '0' || c > '9') {
      (void)fail();
      return;
    }
    if (value > (UINT64_MAX - static_cast<std::uint64_t>(c - '0')) / 10) {
      (void)fail();
      return;
    }
    value = value * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (value == 0) {
    state_ = State::kDone;
    return;
  }
  remaining_ = value;
  state_ = State::kLength;
}

bool BodyReader::fail() {
  failed_ = true;
  state_ = State::kDone;
  return false;
}

bool BodyReader::read_line(std::string& line) {
  line.clear();
  for (;;) {
    char c = 0;
    if (!reader_.read_exact(&c, 1)) {
      return false;
    }
    if (c == '\n') {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      return true;
    }
    if (line.size() >= kMaxChunkLine) {
      return false;
    }
    line.push_back(c);
  }
}

bool BodyReader::read(char* out, std::size_t capacity, std::size_t& got) {
  got = 0;
  if (failed_) {
    return false;
  }
  while (state_ != State::kDone) {
    switch (state_) {
      case State::kLength: {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(capacity, remaining_));
        std::size_t n = 0;
        if (!reader_.read_some(out, want, n)) {
          return fail();
        }
        remaining_ -= n;
        total_ += n;
        got = n;
        if (remaining_ == 0) {
          state_ = State::kDone;
        }
        return true;
      }
      case State::kChunkSize: {
        if (!read_line(line_)) {
          return fail();
        }
        const std::size_t semicolon = line_.find(';');
        const std::string size_text = semicolon == std::string::npos ? line_ : line_.substr(0, semicolon);
        if (size_text.empty()) {
          return fail();
        }
        std::uint64_t size = 0;
        for (const char c : size_text) {
          const int digit = hex_digit(c);
          if (digit < 0) {
            return fail();
          }
          if (size > (UINT64_MAX >> 4)) {
            return fail();
          }
          size = (size << 4) | static_cast<std::uint64_t>(digit);
        }
        if (size == 0) {
          state_ = State::kTrailer;
          break;
        }
        remaining_ = size;
        state_ = State::kChunkData;
        break;
      }
      case State::kChunkData: {
        const std::size_t want =
            static_cast<std::size_t>(std::min<std::uint64_t>(capacity, remaining_));
        std::size_t n = 0;
        if (!reader_.read_some(out, want, n)) {
          return fail();
        }
        remaining_ -= n;
        total_ += n;
        got = n;
        if (remaining_ == 0) {
          state_ = State::kChunkCrlf;
        }
        return true;
      }
      case State::kChunkCrlf: {
        if (!read_line(line_) || !line_.empty()) {
          return fail();
        }
        state_ = State::kChunkSize;
        break;
      }
      case State::kTrailer: {
        if (!read_line(line_)) {
          return fail();
        }
        if (line_.empty()) {
          state_ = State::kDone;
        }
        break;
      }
      case State::kDone:  // LCOV_EXCL_LINE
        break;  // LCOV_EXCL_LINE
    }
  }
  got = 0;
  return !failed_;
}

bool read_body_limited(BodyReader& body, std::string& out, std::size_t limit) {
  out.clear();
  char buffer[4096];
  for (;;) {
    std::size_t got = 0;
    if (!body.read(buffer, sizeof(buffer), got)) {
      return false;
    }
    if (got == 0) {
      return true;
    }
    if (out.size() + got > limit) {
      return false;
    }
    out.append(buffer, got);
  }
}

bool Response::has(std::string_view name) const {
  for (const auto& field : fields_) {
    if (normalise(field.first) == normalise(std::string(name))) {
      return true;
    }
  }
  return false;
}

bool Response::write_head() {
  if (wrote_head_) {
    return true;
  }
  wrote_head_ = true;
  std::string head;
  head.reserve(256);
  head.append(version_ == 10 ? "HTTP/1.0 " : "HTTP/1.1 ");
  head.append(std::to_string(static_cast<int>(status_)));
  head.push_back(' ');
  head.append(reason_phrase(status_));
  head.append("\r\n");
  if (!has("Server")) {
    head.append("Server: webdavd\r\n");
  }
  if (!has("Date")) {
    head.append("Date: ");
    head.append(format_http_date(std::time(nullptr)));
    head.append("\r\n");
  }
  if (!has("Connection")) {
    head.append(keep_alive_ ? "Connection: keep-alive\r\n" : "Connection: close\r\n");
  }
  for (const auto& field : fields_) {
    head.append(field.first);
    head.append(": ");
    head.append(field.second);
    head.append("\r\n");
  }
  head.append("\r\n");
  if (error_) {
    return false;
  }
  if (const int injected = fault_inject("http_write"); injected != 0) {
    error_ = ErrorCode(injected, boost::system::system_category());
    return false;
  }
  // The head must go out even for bodyless (HEAD) responses, so bypass the
  // body-suppression check in write().
  asio::write(socket_, asio::buffer(head), error_);
  return !error_;
}

bool Response::write(const char* data, std::size_t size) {
  if (error_) {
    return false;
  }
  if (bodyless_) {
    return true;
  }
  if (size == 0) {
    return true;
  }
  if (const int injected = fault_inject("http_write"); injected != 0) {
    error_ = ErrorCode(injected, boost::system::system_category());
    return false;
  }
  asio::write(socket_, asio::buffer(data, size), error_);
  return !error_;
}

bool Response::write_chunk(const char* data, std::size_t size) {
  if (bodyless_) {
    return !error_;
  }
  if (size == 0) {
    return !error_;
  }
  char header[32];
  const int written = std::snprintf(header, sizeof(header), "%zx\r\n", size);
  if (!write(header, static_cast<std::size_t>(written)) || !write(data, size)) {
    return false;
  }
  return write("\r\n", 2);
}

bool Response::finish_chunked() { return write("0\r\n\r\n", 5); }

bool Response::send_text(http::status status, std::string_view body) {
  result(status);
  set("Content-Type", "text/plain; charset=utf-8");
  set("Content-Length", std::to_string(body.size()));
  if (!write_head()) {
    return false;
  }
  return write(body);
}

}  // namespace webdav
