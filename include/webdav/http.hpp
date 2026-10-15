#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webdav {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using TcpSocket = asio::ip::tcp::socket;
using ErrorCode = boost::system::error_code;

// Every buffer in the request path is one of these fixed sizes.
inline constexpr std::size_t kIoBufferSize = 16 * 1024;
inline constexpr std::size_t kMaxHeaderBytes = 16 * 1024;
inline constexpr std::size_t kMaxControlBody = 64 * 1024;
// Upper bound for chunked trailer bytes; trailers are outside the data body
// and must not be allowed to pin a worker indefinitely.
inline constexpr std::size_t kMaxTrailerBytes = 8 * 1024;

std::string format_http_date(std::time_t when);
std::string format_iso8601(std::time_t when);
std::string format_etag(std::uint64_t size, const struct timespec& modified);
const char* reason_phrase(http::status status);

// Pull-based reader over the parser leftover buffer and the socket.
class Reader {
 public:
  Reader(TcpSocket& socket, beast::flat_buffer& buffer) : socket_(socket), buffer_(buffer) {}

  bool read_some(char* out, std::size_t length, std::size_t& got);
  bool read_exact(char* out, std::size_t length);
  const ErrorCode& error() const { return error_; }

 private:
  TcpSocket& socket_;
  beast::flat_buffer& buffer_;
  ErrorCode error_;
};

// Incremental body decoder for one request. Handles Content-Length and
// chunked transfer encoding without ever buffering the whole body.
class BodyReader {
 public:
  BodyReader(Reader& reader, const http::request_header<>& head);

  bool has_body() const { return state_ != State::kDone; }
  bool complete() const { return state_ == State::kDone && !failed_; }
  bool failed() const { return failed_; }
  std::uint64_t total() const { return total_; }

  // Fills up to `capacity` bytes; returns false on a protocol or I/O error.
  bool read(char* out, std::size_t capacity, std::size_t& got);

 private:
  enum class State { kDone, kLength, kChunkSize, kChunkData, kChunkCrlf, kTrailer };

  bool read_line(std::string& line);
  bool fail();

  Reader& reader_;
  State state_{State::kDone};
  std::uint64_t remaining_{0};
  std::uint64_t total_{0};
  bool failed_{false};
  std::size_t trailer_bytes_{0};
  std::string line_;
};

// Reads a control body (PROPFIND/PROPPATCH) up to `limit` bytes.
bool read_body_limited(BodyReader& body, std::string& out, std::size_t limit);

// Builds and writes one response; owns keep-alive bookkeeping for it.
class Response {
 public:
  Response(TcpSocket& socket, unsigned version, bool keep_alive)
      : socket_(socket), version_(version), keep_alive_(keep_alive) {}

  void result(http::status status) { status_ = status; }
  http::status result() const { return status_; }
  void set(std::string name, std::string value) {
    fields_.emplace_back(std::move(name), std::move(value));
  }
  bool has(std::string_view name) const;
  void set_keep_alive(bool value) { keep_alive_ = value; }
  bool keep_alive() const { return keep_alive_; }
  // HEAD responses must carry the headers of the entity but no body bytes.
  void set_bodyless(bool value) { bodyless_ = value; }

  bool write_head();
  bool write(const char* data, std::size_t size);
  bool write(std::string_view text) { return write(text.data(), text.size()); }
  bool write_chunk(const char* data, std::size_t size);
  bool write_chunk(std::string_view text) { return write_chunk(text.data(), text.size()); }
  bool finish_chunked();
  bool send_text(http::status status, std::string_view body);

  const ErrorCode& error() const { return error_; }

 private:
  TcpSocket& socket_;
  unsigned version_;
  http::status status_{http::status::ok};
  std::vector<std::pair<std::string, std::string>> fields_;
  bool keep_alive_{false};
  bool bodyless_{false};
  bool wrote_head_{false};
  ErrorCode error_;
};

}  // namespace webdav
