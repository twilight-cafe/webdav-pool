#include <gtest/gtest.h>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "webdav/fault.hpp"
#include "webdav/http.hpp"

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;

const bool kIgnoreSigpipe = [] {
  ::signal(SIGPIPE, SIG_IGN);
  return true;
}();

class ScopedFaultHook {
 public:
  explicit ScopedFaultHook(webdav::FaultHook hook) { webdav::set_fault_hook(std::move(hook)); }
  ~ScopedFaultHook() { webdav::set_fault_hook(nullptr); }
  ScopedFaultHook(const ScopedFaultHook&) = delete;
  ScopedFaultHook& operator=(const ScopedFaultHook&) = delete;
};

class SocketPair {
 public:
  SocketPair() {
    int fds[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
      throw std::runtime_error("socketpair failed");
    }
    boost::system::error_code ec;
    a_.assign(asio::ip::tcp::v4(), fds[0], ec);
    if (ec) {
      ::close(fds[0]);
      ::close(fds[1]);
      throw std::runtime_error("assign a failed: " + ec.message());
    }
    b_.assign(asio::ip::tcp::v4(), fds[1], ec);
    if (ec) {
      ::close(fds[1]);
      throw std::runtime_error("assign b failed: " + ec.message());
    }
  }

  webdav::TcpSocket& a() { return a_; }
  webdav::TcpSocket& b() { return b_; }

 private:
  asio::io_context ioc_;
  webdav::TcpSocket a_{ioc_};
  webdav::TcpSocket b_{ioc_};
};

bool write_some(webdav::TcpSocket& socket, std::string_view data) {
  boost::system::error_code ec;
  asio::write(socket, asio::buffer(data.data(), data.size()), ec);
  return !ec;
}


void shutdown_send(webdav::TcpSocket& socket) {
  boost::system::error_code ec;
  socket.shutdown(webdav::TcpSocket::shutdown_send, ec);
}


}  // namespace

TEST(HttpTest, DatesAndEtags) {
  EXPECT_EQ(webdav::format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
  EXPECT_EQ(webdav::format_iso8601(0), "1970-01-01T00:00:00Z");
  struct timespec modified {};
  modified.tv_sec = 1;
  modified.tv_nsec = 2;
  EXPECT_EQ(webdav::format_etag(3, modified), "\"3-1000000002\"");
}

TEST(HttpTest, DateFallbacksAreReachable) {
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "gmtime_r") == 0 ? EINVAL : 0;
  });
  EXPECT_EQ(webdav::format_http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
  EXPECT_EQ(webdav::format_iso8601(0), "1970-01-01T00:00:00Z");
}

TEST(HttpTest, ReasonPhrases) {
  EXPECT_STREQ(webdav::reason_phrase(http::status::ok), "OK");
  EXPECT_STREQ(webdav::reason_phrase(http::status::created), "Created");
  EXPECT_STREQ(webdav::reason_phrase(http::status::no_content), "No Content");
  EXPECT_STREQ(webdav::reason_phrase(http::status::partial_content), "Partial Content");
  EXPECT_STREQ(webdav::reason_phrase(http::status::multi_status), "Multi-Status");
  EXPECT_STREQ(webdav::reason_phrase(http::status::bad_request), "Bad Request");
  EXPECT_STREQ(webdav::reason_phrase(http::status::unauthorized), "Unauthorized");
  EXPECT_STREQ(webdav::reason_phrase(http::status::forbidden), "Forbidden");
  EXPECT_STREQ(webdav::reason_phrase(http::status::not_found), "Not Found");
  EXPECT_STREQ(webdav::reason_phrase(http::status::method_not_allowed), "Method Not Allowed");
  EXPECT_STREQ(webdav::reason_phrase(http::status::length_required), "Length Required");
  EXPECT_STREQ(webdav::reason_phrase(http::status::conflict), "Conflict");
  EXPECT_STREQ(webdav::reason_phrase(http::status::precondition_failed), "Precondition Failed");
  EXPECT_STREQ(webdav::reason_phrase(http::status::unsupported_media_type),
               "Unsupported Media Type");
  EXPECT_STREQ(webdav::reason_phrase(http::status::range_not_satisfiable),
               "Range Not Satisfiable");
  EXPECT_STREQ(webdav::reason_phrase(http::status::internal_server_error),
               "Internal Server Error");
  EXPECT_STREQ(webdav::reason_phrase(http::status::not_implemented), "Not Implemented");
  EXPECT_STREQ(webdav::reason_phrase(http::status::bad_gateway), "Bad Gateway");
  EXPECT_STREQ(webdav::reason_phrase(http::status::service_unavailable), "Service Unavailable");
  EXPECT_STREQ(webdav::reason_phrase(http::status::insufficient_storage), "Insufficient Storage");
  EXPECT_STREQ(webdav::reason_phrase(static_cast<http::status>(599)), "Unknown");
}

TEST(HttpTest, ReaderZeroLengthAndBufferPath) {
  SocketPair pair;
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  char byte = 0;
  std::size_t got = 99;
  EXPECT_TRUE(reader.read_some(&byte, 0, got));
  EXPECT_EQ(got, 0u);

  const std::string data = "abc";
  auto out = buffer.prepare(data.size());
  std::memcpy(out.data(), data.data(), data.size());
  buffer.commit(data.size());
  char target[4] = {};
  EXPECT_TRUE(reader.read_some(target, sizeof(target), got));
  EXPECT_EQ(got, data.size());
  EXPECT_EQ(std::string(target, got), data);
}

TEST(HttpTest, ReaderSocketEofAndError) {
  {
    SocketPair pair;
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    shutdown_send(pair.b());
    char byte = 0;
    std::size_t got = 0;
    EXPECT_FALSE(reader.read_some(&byte, 1, got));
    EXPECT_EQ(reader.error(), asio::error::eof);
  }
  {
    SocketPair pair;
    beast::flat_buffer buffer;
    pair.a().close();
    webdav::Reader reader(pair.a(), buffer);
    char byte = 0;
    std::size_t got = 0;
    EXPECT_FALSE(reader.read_some(&byte, 1, got));
    EXPECT_TRUE(reader.error());
  }
}

TEST(HttpTest, ReaderReadExactRoundTrip) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "abcdef"));
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  char target[6] = {};
  EXPECT_TRUE(reader.read_exact(target, sizeof(target)));
  EXPECT_EQ(std::string(target, sizeof(target)), "abcdef");
}

TEST(HttpTest, BodyReaderContentLength) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "hello"));
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  http::request_header<> head;
  head.set(http::field::content_length, "5");
  webdav::BodyReader body(reader, head);
  EXPECT_TRUE(body.has_body());
  EXPECT_FALSE(body.complete());

  char out[3] = {};
  std::size_t got = 0;
  EXPECT_TRUE(body.read(out, 2, got));
  EXPECT_EQ(got, 2u);
  EXPECT_EQ(std::string(out, got), "he");
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 3u);
  EXPECT_EQ(std::string(out, got), "llo");
  EXPECT_TRUE(body.complete());
  EXPECT_EQ(body.total(), 5u);
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 0u);
}

TEST(HttpTest, BodyReaderMissingAndZeroLength) {
  SocketPair pair;
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  {
    http::request_header<> head;
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.complete());
    EXPECT_FALSE(body.has_body());
    char out = 0;
    std::size_t got = 1;
    EXPECT_TRUE(body.read(&out, 1, got));
    EXPECT_EQ(got, 0u);
  }
  {
    http::request_header<> head;
    head.set(http::field::content_length, "0");
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.complete());
    EXPECT_FALSE(body.has_body());
  }
}

TEST(HttpTest, BodyReaderRejectsBadContentLengths) {
  SocketPair pair;
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  for (const char* value : {"", "abc", "18446744073709551616"}) {
    http::request_header<> head;
    head.set(http::field::content_length, value);
    webdav::BodyReader body(reader, head);
    EXPECT_FALSE(body.complete()) << value;
    EXPECT_TRUE(body.failed()) << value;
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got)) << value;
  }
}

TEST(HttpTest, BodyReaderTruncatedContentLength) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "he"));
  shutdown_send(pair.b());
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  http::request_header<> head;
  head.set(http::field::content_length, "5");
  webdav::BodyReader body(reader, head);
  char out[5] = {};
  std::size_t got = 0;
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 2u);
  EXPECT_FALSE(body.read(out, sizeof(out), got));
  EXPECT_TRUE(body.failed());
}

TEST(HttpTest, BodyReaderChunkedLowercaseAndExtension) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "a;name=value\r\n0123456789\r\n0\r\nX-Trailer: y\r\n\r\n"));
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  http::request_header<> head;
  head.set(http::field::transfer_encoding, "chunked");
  webdav::BodyReader body(reader, head);
  char out[16] = {};
  std::size_t got = 0;
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 10u);
  EXPECT_EQ(std::string(out, got), "0123456789");
  EXPECT_FALSE(body.complete());
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 0u);
  EXPECT_TRUE(body.complete());
}

TEST(HttpTest, BodyReaderChunkedUppercase) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "A\r\nABCDEFGHIJ\r\n0\r\n\r\n"));
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  http::request_header<> head;
  head.set(http::field::transfer_encoding, "chunked");
  webdav::BodyReader body(reader, head);
  char out[16] = {};
  std::size_t got = 0;
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 10u);
  EXPECT_EQ(std::string(out, got), "ABCDEFGHIJ");
  EXPECT_TRUE(body.read(out, sizeof(out), got));
  EXPECT_EQ(got, 0u);
  EXPECT_TRUE(body.complete());
}

TEST(HttpTest, BodyReaderRejectsMalformedChunks) {
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got));
    EXPECT_TRUE(body.failed());
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "z\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), std::string(20, 'F') + "\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "1\r\nxBAD\r\n0\r\n\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_TRUE(body.read(&out, 1, got));
    EXPECT_EQ(out, 'x');
    EXPECT_FALSE(body.read(&out, 1, got));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), std::string(129, 'a') + "\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "0\r\n" + std::string(129, 'a') + "\r\n"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out = 0;
    std::size_t got = 0;
    EXPECT_FALSE(body.read(&out, 1, got));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "5\r\nhe"));
    shutdown_send(pair.b());
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    char out[5] = {};
    std::size_t got = 0;
    EXPECT_TRUE(body.read(out, sizeof(out), got));
    EXPECT_FALSE(body.read(out, sizeof(out), got));
  }
}

TEST(HttpTest, ReadBodyLimited) {
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "abc"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::content_length, "3");
    webdav::BodyReader body(reader, head);
    std::string out;
    EXPECT_TRUE(webdav::read_body_limited(body, out, 5));
    EXPECT_EQ(out, "abc");
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "abcdefghij"));
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::content_length, "10");
    webdav::BodyReader body(reader, head);
    std::string out;
    EXPECT_FALSE(webdav::read_body_limited(body, out, 5));
  }
  {
    SocketPair pair;
    ASSERT_TRUE(write_some(pair.b(), "he"));
    shutdown_send(pair.b());
    beast::flat_buffer buffer;
    webdav::Reader reader(pair.a(), buffer);
    http::request_header<> head;
    head.set(http::field::content_length, "5");
    webdav::BodyReader body(reader, head);
    std::string out;
    EXPECT_FALSE(webdav::read_body_limited(body, out, 64));
  }
}

TEST(HttpTest, ResponseWritesHeadFieldsAndBodies) {
  SocketPair pair;
  webdav::Response response(pair.a(), 11, true);
  response.set("X-Test", "yes");
  EXPECT_TRUE(response.has("x-test"));
  EXPECT_TRUE(response.write_head());
  EXPECT_TRUE(response.write_head());
  EXPECT_TRUE(response.write("ab", 2));
  EXPECT_TRUE(response.write("", 0));
  EXPECT_TRUE(response.write_chunk("cd", 2));
  EXPECT_TRUE(response.write_chunk("", 0));
  EXPECT_TRUE(response.finish_chunked());

  webdav::Response text(pair.b(), 10, false);
  EXPECT_TRUE(text.send_text(http::status::ok, "hello"));
}

TEST(HttpTest, ResponseBodylessSkipsBodyBytes) {
  SocketPair pair;
  webdav::Response response(pair.a(), 11, true);
  response.set_bodyless(true);
  EXPECT_TRUE(response.write("ignored", 7));
  EXPECT_TRUE(response.write_chunk("ignored", 7));
  EXPECT_TRUE(response.write_head());
}

TEST(HttpTest, ResponsePropagatesSocketFailures) {
  SocketPair pair;
  pair.a().close();
  webdav::Response response(pair.a(), 11, false);
  EXPECT_FALSE(response.write("x", 1));
  EXPECT_FALSE(response.write_head());
  EXPECT_FALSE(response.write("x", 1));
  EXPECT_FALSE(response.write_chunk("x", 1));

  webdav::Response text(pair.a(), 11, false);
  EXPECT_FALSE(text.send_text(http::status::ok, "body"));
}

TEST(HttpTest, InjectedWriteFailures) {
  SocketPair pair;
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "http_write") == 0 ? EIO : 0;
  });
  webdav::Response head(pair.a(), 11, false);
  EXPECT_FALSE(head.write_head());

  webdav::Response body(pair.a(), 11, false);
  EXPECT_FALSE(body.write("x", 1));
}

TEST(HttpTest, BodyReaderChunkSizeLineTruncationFails) {
  SocketPair pair;
  ASSERT_TRUE(write_some(pair.b(), "5"));
  shutdown_send(pair.b());
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);
  http::request_header<> head;
  head.set(http::field::transfer_encoding, "chunked");
  webdav::BodyReader body(reader, head);
  char out = 0;
  std::size_t got = 0;
  EXPECT_FALSE(body.read(&out, 1, got));
}

TEST(HttpTest, BodyReaderRejectsAmbiguousTransferEncoding) {
  SocketPair pair;
  beast::flat_buffer buffer;
  webdav::Reader reader(pair.a(), buffer);

  {
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "identity");
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.failed());
  }
  {
    http::request_header<> head;
    head.insert(http::field::transfer_encoding, "identity");
    head.insert(http::field::transfer_encoding, "chunked");
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.failed());
  }
  {
    http::request_header<> head;
    head.set(http::field::transfer_encoding, "chunked");
    head.set(http::field::content_length, "5");
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.failed());
  }
  {
    http::request_header<> head;
    head.set(http::field::content_length, "1");
    head.insert(http::field::content_length, "2");
    webdav::BodyReader body(reader, head);
    EXPECT_TRUE(body.failed());
  }
}
