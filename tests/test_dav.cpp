#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <crypt.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "webdav/auth.hpp"
#include "webdav/config.hpp"
#include "webdav/fsutil.hpp"
#include "webdav/fault.hpp"
#include "webdav/server.hpp"

namespace {

namespace fs = std::filesystem;

const char* kPassword = "s3cret";

std::string bcrypt_hash(const std::string& password, const std::string& setting) {
  crypt_data data{};
  std::memset(&data, 0, sizeof(data));
  char* result = crypt_r(password.c_str(), setting.c_str(), &data);
  return result != nullptr ? std::string(result) : std::string();
}

std::string tmp_base() {
  static const std::string base = [] {
    const std::string dir = std::string(WEBDAV_TEST_TMPDIR) + "/dav";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
  }();
  return base;
}

std::string make_root(const std::string& name) {
  const fs::path path = fs::path(tmp_base()) / name;
  std::error_code ec;
  fs::remove_all(path, ec);
  fs::create_directories(path, ec);
  return fs::canonical(path).string();
}

void write_file(const std::string& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << content;
}

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

bool has_temporary_file(const std::string& directory) {
  std::error_code ec;
  for (const auto& entry : fs::directory_iterator(directory, ec)) {
    if (entry.path().filename().string().rfind(".webdav-tmp-", 0) == 0) {
      return true;
    }
  }
  return false;
}

std::size_t open_fd_count() {
  std::error_code ec;
  std::size_t count = 0;
  for (const auto& entry : fs::directory_iterator("/proc/self/fd", ec)) {
    (void)entry;
    ++count;
  }
  return count;
}

std::string basic_auth(const std::string& user, const std::string& password) {
  return "Basic " + webdav::base64_encode(user + ":" + password);
}

struct Response {
  int status{0};
  std::string reason;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  std::string header(const std::string& name) const {
    for (const auto& field : headers) {
      if (field.first.size() == name.size() &&
          std::equal(field.first.begin(), field.first.end(), name.begin(), [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
          })) {
        return field.second;
      }
    }
    return std::string();
  }
};

class Client {
 public:
  explicit Client(std::uint16_t port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
      throw std::runtime_error("socket() failed");
    }
    struct timeval timeout {};
    timeout.tv_sec = 10;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
      ::close(fd_);
      fd_ = -1;
      throw std::runtime_error("connect() failed");
    }
  }

  ~Client() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  Response request(const std::string& method, const std::string& target,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   const std::string& body, bool head = false, bool close = true) {
    std::string raw;
    raw.append(method).append(" ").append(target).append(" HTTP/1.1\r\n");
    raw.append("Host: 127.0.0.1\r\n");
    raw.append("Authorization: ").append(basic_auth("alice", kPassword)).append("\r\n");
    if (!headers.empty()) {
      for (const auto& field : headers) {
        raw.append(field.first).append(": ").append(field.second).append("\r\n");
      }
    }
    if (!body.empty() || method == "PUT" || method == "PROPFIND" || method == "PROPPATCH" ||
        method == "MKCOL") {
      if (header_present(headers, "Content-Length") == false &&
          header_present(headers, "Transfer-Encoding") == false) {
        raw.append("Content-Length: ").append(std::to_string(body.size())).append("\r\n");
      }
    }
    if (close) {
      raw.append("Connection: close\r\n");
    }
    raw.append("\r\n");
    raw.append(body);
    return send_raw(raw, head);
  }

  Response request_as(const std::string& method, const std::string& target,
                      const std::string& user, const std::string& password,
                      const std::string& auth_override) {
    std::string raw;
    raw.append(method).append(" ").append(target).append(" HTTP/1.1\r\n");
    raw.append("Host: 127.0.0.1\r\n");
    if (!auth_override.empty()) {
      raw.append("Authorization: ").append(auth_override).append("\r\n");
    } else {
      raw.append("Authorization: ").append(basic_auth(user, password)).append("\r\n");
    }
    raw.append("Connection: close\r\n\r\n");
    return send_raw(raw, false);
  }

  // Sends as much of `raw` as the peer accepts, then tears the connection down
  // without waiting for a response.  Used by interruption tests.
  void send_partial_and_close(const std::string& raw) {
    if (fd_ < 0) {
      throw std::runtime_error("bad socket");
    }
    std::size_t sent = 0;
    while (sent < raw.size()) {
      const ssize_t n = ::send(fd_, raw.data() + sent, raw.size() - sent, MSG_NOSIGNAL);
      if (n <= 0) {
        break;
      }
      sent += static_cast<std::size_t>(n);
    }
    (void)::shutdown(fd_, SHUT_WR);
    (void)::close(fd_);
    fd_ = -1;
  }

  Response send_raw(const std::string& raw, bool head) {
    if (fd_ < 0) {
      throw std::runtime_error("bad socket");
    }
    std::size_t sent = 0;
    while (sent < raw.size()) {
      const ssize_t n = ::send(fd_, raw.data() + sent, raw.size() - sent, 0);
      if (n <= 0) {
        throw std::runtime_error("send failed");
      }
      sent += static_cast<std::size_t>(n);
    }
    return read_response(head);
  }

 private:
  static bool header_present(const std::vector<std::pair<std::string, std::string>>& headers,
                             const std::string& name) {
    for (const auto& field : headers) {
      if (field.first == name) {
        return true;
      }
    }
    return false;
  }

  bool fill() {
    char buffer[4096];
    const ssize_t n = ::recv(fd_, buffer, sizeof(buffer), 0);
    if (n <= 0) {
      return false;
    }
    pending_.append(buffer, static_cast<std::size_t>(n));
    return true;
  }

  std::string take_line() {
    for (;;) {
      const std::size_t end = pending_.find("\r\n");
      if (end != std::string::npos) {
        std::string line = pending_.substr(0, end);
        pending_.erase(0, end + 2);
        return line;
      }
      if (!fill()) {
        return std::string();
      }
    }
  }

  void take_exactly(std::size_t count, std::string& out) {
    while (pending_.size() < count) {
      if (!fill()) {
        break;
      }
    }
    const std::size_t available = std::min(count, pending_.size());
    out.append(pending_, 0, available);
    pending_.erase(0, available);
  }

  Response read_response(bool head) {
    Response response;
    const std::string status_line = take_line();
    if (status_line.empty()) {
      return response;
    }
    const std::size_t first_space = status_line.find(' ');
    const std::size_t second_space = status_line.find(' ', first_space + 1);
    response.status = std::stoi(status_line.substr(first_space + 1, second_space - first_space - 1));
    response.reason = status_line.substr(second_space + 1);
    for (;;) {
      const std::string line = take_line();
      if (line.empty()) {
        break;
      }
      const std::size_t colon = line.find(':');
      if (colon == std::string::npos) {
        continue;
      }
      std::string value = line.substr(colon + 1);
      while (!value.empty() && value.front() == ' ') {
        value.erase(value.begin());
      }
      response.headers.emplace_back(line.substr(0, colon), value);
    }
    if (head || response.status == 204 || response.status == 304) {
      return response;
    }
    if (!response.header("Transfer-Encoding").empty()) {
      for (;;) {
        const std::string size_line = take_line();
        const std::size_t size = std::stoul(size_line, nullptr, 16);
        if (size == 0) {
          (void)take_line();
          break;
        }
        take_exactly(size, response.body);
        (void)take_line();
      }
      return response;
    }
    const std::string length = response.header("Content-Length");
    if (!length.empty()) {
      take_exactly(static_cast<std::size_t>(std::stoul(length)), response.body);
    }
    return response;
  }

  int fd_{-1};
  std::string pending_;
};

class DavTest : public ::testing::Test {
 protected:
  void SetUp() override {
    root_alice_ = make_root("alice");
    root_bob_ = make_root("bob");

    write_file(root_alice_ + "/hello.txt", "hello world");
    write_file(root_alice_ + "/page.html", "<html/>");
    fs::create_directories(root_alice_ + "/dir/sub");
    write_file(root_alice_ + "/dir/a.bin", "abc");
    write_file(root_alice_ + "/dir/sub/deep.txt", "deep");
    write_file(root_bob_ + "/secret.txt", "bob-secret");

    webdav::Config config;
    config.host = "127.0.0.1";
    config.port = 0;
    config.max_connections = 4;
    config.auth_backoff_base_ms = 1;
    config.auth_backoff_max_ms = 1;
    const std::string hash = bcrypt_hash(kPassword, "$2b$10$abcdefghijklmnopqrstuu");
    config.users.push_back(webdav::User{"alice", hash, root_alice_});
    config.users.push_back(webdav::User{"bob", hash, root_bob_});

    auto authenticator = std::make_shared<webdav::Authenticator>(
        config.users, config.auth_max_concurrent, config.auth_backoff_base_ms,
        config.auth_backoff_max_ms, webdav::default_verify(), webdav::default_sleep());
    server_ = std::make_unique<webdav::Server>(config, authenticator);
    server_->bind();
    port_ = server_->port();
    thread_ = std::thread([this] { server_->serve(); });
  }

  void TearDown() override {
    server_->stop();
    if (thread_.joinable()) {
      thread_.join();
    }
  }

  Response send(const std::string& method, const std::string& target,
                const std::vector<std::pair<std::string, std::string>>& headers = {},
                const std::string& body = "", bool head = false) {
    Client client(port_);
    return client.request(method, target, headers, body, head);
  }

  std::uint16_t port_{0};
  std::string root_alice_;
  std::string root_bob_;
  std::unique_ptr<webdav::Server> server_;
  std::thread thread_;
};

}  // namespace

namespace {

class ScopedFaultHook {
 public:
  explicit ScopedFaultHook(webdav::FaultHook hook) { webdav::set_fault_hook(std::move(hook)); }
  ~ScopedFaultHook() { webdav::set_fault_hook(nullptr); }
  ScopedFaultHook(const ScopedFaultHook&) = delete;
  ScopedFaultHook& operator=(const ScopedFaultHook&) = delete;
};

}  // namespace

TEST_F(DavTest, OptionsAdvertisesClassOne) {
  const Response response = send("OPTIONS", "/");
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.header("DAV"), "1");
  EXPECT_EQ(response.header("MS-Author-Via"), "DAV");
  EXPECT_NE(response.header("Allow").find("PROPFIND"), std::string::npos);
}

TEST_F(DavTest, RejectsMissingCredentials) {
  Client client(port_);
  const Response response = client.request_as("OPTIONS", "/", "", "", "");
  EXPECT_EQ(response.status, 401);
  EXPECT_NE(response.header("WWW-Authenticate").find("Basic realm=\"webdav\""), std::string::npos);
}

TEST_F(DavTest, RejectsWrongPasswordAndUnknownUser) {
  // Each request carries `Connection: close`, so a fresh connection is needed
  // for the second attempt.
  Client wrong_password(port_);
  EXPECT_EQ(wrong_password.request_as("OPTIONS", "/", "alice", "nope", "").status, 401);
  Client unknown_user(port_);
  EXPECT_EQ(unknown_user.request_as("OPTIONS", "/", "nobody", "nope", "").status, 401);
}

TEST_F(DavTest, GetReturnsFileWithMetadata) {
  const Response response = send("GET", "/hello.txt");
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.body, "hello world");
  EXPECT_EQ(response.header("Content-Type"), "text/plain");
  EXPECT_EQ(response.header("Content-Length"), "11");
  EXPECT_FALSE(response.header("ETag").empty());
  EXPECT_FALSE(response.header("Last-Modified").empty());
  EXPECT_EQ(response.header("Accept-Ranges"), "bytes");
}

TEST_F(DavTest, HeadOmitsBodyButKeepsLength) {
  const Response response = send("HEAD", "/hello.txt", {}, "", true);
  EXPECT_EQ(response.status, 200);
  EXPECT_EQ(response.header("Content-Length"), "11");
  EXPECT_TRUE(response.body.empty());
}

TEST_F(DavTest, GetOnCollectionIsMethodNotAllowed) {
  const Response response = send("GET", "/dir");
  EXPECT_EQ(response.status, 405);
  EXPECT_NE(response.header("Allow").find("GET"), std::string::npos);
}

TEST_F(DavTest, GetMissingFileIsNotFound) {
  EXPECT_EQ(send("GET", "/nope.txt").status, 404);
}

TEST_F(DavTest, GetSupportsRanges) {
  const Response prefix = send("GET", "/hello.txt", {{"Range", "bytes=0-4"}});
  EXPECT_EQ(prefix.status, 206);
  EXPECT_EQ(prefix.body, "hello");
  EXPECT_EQ(prefix.header("Content-Range"), "bytes 0-4/11");

  const Response open_ended = send("GET", "/hello.txt", {{"Range", "bytes=6-"}});
  EXPECT_EQ(open_ended.status, 206);
  EXPECT_EQ(open_ended.body, "world");

  const Response suffix = send("GET", "/hello.txt", {{"Range", "bytes=-5"}});
  EXPECT_EQ(suffix.status, 206);
  EXPECT_EQ(suffix.body, "world");
}

TEST_F(DavTest, GetFallsBackToFullBodyForInvalidRanges) {
  for (const char* value : {"bytes=99-200", "bytes=5-2", "items=0-1", "bytes=0-1,3-4"}) {
    const Response response = send("GET", "/hello.txt", {{"Range", value}});
    EXPECT_EQ(response.status, 200) << value;
    EXPECT_EQ(response.body, "hello world") << value;
  }
}

TEST_F(DavTest, PutCreatesAndOverwrites) {
  const Response created = send("PUT", "/new.txt", {}, "fresh");
  EXPECT_EQ(created.status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/new.txt"), "fresh");

  const Response replaced = send("PUT", "/new.txt", {}, "updated");
  EXPECT_EQ(replaced.status, 204);
  EXPECT_EQ(read_file(root_alice_ + "/new.txt"), "updated");
}

TEST_F(DavTest, PutChunkedBody) {
  Client client(port_);
  std::string raw =
      "PUT /chunked.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
      basic_auth("alice", kPassword) + "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
  raw.append("5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");
  const Response response = client.send_raw(raw, false);
  EXPECT_EQ(response.status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/chunked.txt"), "hello world");
}

TEST_F(DavTest, PutErrors) {
  EXPECT_EQ(send("PUT", "/missing/parent.txt", {}, "x").status, 409);
  EXPECT_EQ(send("PUT", "/dir", {}, "x").status, 405);
  EXPECT_EQ(send("PUT", "/no-length.txt", {}, "").status, 411);
}

TEST_F(DavTest, MkcolBehaviours) {
  EXPECT_EQ(send("MKCOL", "/fresh").status, 201);
  EXPECT_TRUE(fs::is_directory(root_alice_ + "/fresh"));
  EXPECT_EQ(send("MKCOL", "/fresh").status, 405);
  EXPECT_EQ(send("MKCOL", "/absent/child").status, 409);
  EXPECT_EQ(send("MKCOL", "/withbody", {}, "data").status, 415);
}

TEST_F(DavTest, DeleteRemovesFilesAndTrees) {
  EXPECT_EQ(send("DELETE", "/hello.txt").status, 204);
  EXPECT_FALSE(fs::exists(root_alice_ + "/hello.txt"));
  EXPECT_EQ(send("DELETE", "/hello.txt").status, 404);
  EXPECT_EQ(send("DELETE", "/dir").status, 204);
  EXPECT_FALSE(fs::exists(root_alice_ + "/dir"));
  EXPECT_EQ(send("DELETE", "/").status, 403);
}

TEST_F(DavTest, PropfindDepthZeroDescribesResource) {
  const Response response = send("PROPFIND", "/hello.txt", {{"Depth", "0"}});
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.header("Content-Type").find("application/xml"), std::string::npos);
  EXPECT_NE(response.body.find("<D:href>/hello.txt</D:href>"), std::string::npos);
  EXPECT_NE(response.body.find("getcontentlength"), std::string::npos);
  EXPECT_NE(response.body.find("getetag"), std::string::npos);
}

TEST_F(DavTest, PropfindDepthOneListsChildren) {
  const Response response = send("PROPFIND", "/dir", {{"Depth", "1"}});
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("<D:href>/dir/</D:href>"), std::string::npos);
  EXPECT_NE(response.body.find("<D:href>/dir/a.bin</D:href>"), std::string::npos);
  EXPECT_NE(response.body.find("<D:href>/dir/sub/</D:href>"), std::string::npos);
  EXPECT_NE(response.body.find("<D:collection/>"), std::string::npos);
}

TEST_F(DavTest, PropfindDepthInfinityIsForbidden) {
  EXPECT_EQ(send("PROPFIND", "/", {{"Depth", "infinity"}}).status, 403);
  EXPECT_EQ(send("PROPFIND", "/").status, 403);
  EXPECT_EQ(send("PROPFIND", "/", {{"Depth", "0"}}).status, 207);
}

TEST_F(DavTest, PropfindUnknownPropertyIsReportedMissing) {
  const std::string body =
      "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:getetag/>"
      "<D:resourcetype/><D:getcontentlength/><D:mystery/></D:prop></D:propfind>";
  const Response response = send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, body);
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("<D:getetag>"), std::string::npos);
  EXPECT_NE(response.body.find("404 Not Found"), std::string::npos);
  EXPECT_NE(response.body.find("mystery"), std::string::npos);
}

TEST_F(DavTest, PropfindAllpropAndPropname) {
  const Response allprop =
      send("PROPFIND", "/dir", {{"Depth", "0"}},
           "<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:allprop/></D:propfind>");
  EXPECT_EQ(allprop.status, 207);
  EXPECT_NE(allprop.body.find("<D:resourcetype><D:collection/></D:resourcetype>"),
            std::string::npos);

  const Response propname =
      send("PROPFIND", "/hello.txt", {{"Depth", "0"}},
           "<D:propfind xmlns:D=\"DAV:\"><D:propname/></D:propfind>");
  EXPECT_EQ(propname.status, 207);
  EXPECT_NE(propname.body.find("<D:getetag/>"), std::string::npos);
}

TEST_F(DavTest, PropfindMalformedBodies) {
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, "not xml").status, 400);
  EXPECT_EQ(send("PROPFIND", "/absent", {{"Depth", "0"}}).status, 404);
}

TEST_F(DavTest, ProppatchAlwaysForbids) {
  const std::string body =
      "<?xml version=\"1.0\"?><D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop>"
      "<D:displayname>x</D:displayname></D:prop></D:set></D:propertyupdate>";
  const Response response = send("PROPPATCH", "/hello.txt", {}, body);
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("403 Forbidden"), std::string::npos);
  EXPECT_NE(response.body.find("displayname"), std::string::npos);
  EXPECT_EQ(send("PROPPATCH", "/absent", {}, body).status, 404);
  EXPECT_EQ(send("PROPPATCH", "/hello.txt", {}, "garbage").status, 400);
}

TEST_F(DavTest, CopyFileAndDirectory) {
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/copy.txt"}}).status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/copy.txt"), "hello world");

  EXPECT_EQ(send("COPY", "/dir", {{"Destination", "/dir2"}}).status, 201);
  EXPECT_TRUE(fs::exists(root_alice_ + "/dir2/sub/deep.txt"));

  EXPECT_EQ(send("COPY", "/dir", {{"Destination", "/dir3"}, {"Depth", "0"}}).status, 201);
  EXPECT_TRUE(fs::is_directory(root_alice_ + "/dir3"));
  EXPECT_FALSE(fs::exists(root_alice_ + "/dir3/sub"));
}

TEST_F(DavTest, CopyErrors) {
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/copy.txt"}}).status, 201);
  EXPECT_EQ(
      send("COPY", "/hello.txt", {{"Destination", "/copy.txt"}, {"Overwrite", "F"}}).status, 412);
  EXPECT_EQ(
      send("COPY", "/hello.txt", {{"Destination", "/copy.txt"}, {"Overwrite", "T"}}).status, 204);
  EXPECT_EQ(send("COPY", "/absent.txt", {{"Destination", "/x.txt"}}).status, 404);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/nope/x.txt"}}).status, 409);
  EXPECT_EQ(send("COPY", "/hello.txt", {}).status, 400);
  EXPECT_EQ(send("COPY", "/dir", {{"Destination", "/dir/sub"}}).status, 403);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/"}}).status, 403);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "http://other/x.txt"}}).status, 502);
  // Overwriting a collection with a file mirrors the destination DELETE rule.
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/dir"}}).status, 204);
  EXPECT_TRUE(fs::is_regular_file(root_alice_ + "/dir"));
}

TEST_F(DavTest, MoveFileAndDirectory) {
  EXPECT_EQ(send("MOVE", "/hello.txt", {{"Destination", "/moved.txt"}}).status, 201);
  EXPECT_FALSE(fs::exists(root_alice_ + "/hello.txt"));
  EXPECT_TRUE(fs::exists(root_alice_ + "/moved.txt"));

  EXPECT_EQ(send("MOVE", "/dir", {{"Destination", "/moved-dir"}}).status, 201);
  EXPECT_TRUE(fs::exists(root_alice_ + "/moved-dir/sub/deep.txt"));

  EXPECT_EQ(send("MOVE", "/moved.txt", {{"Destination", "/page.html"}}).status, 204);
}

TEST_F(DavTest, UnsupportedMethodsAreRejected) {
  for (const char* method : {"LOCK", "UNLOCK", "SEARCH", "PATCH", "TRACE"}) {
    const Response response = send(method, "/hello.txt");
    EXPECT_EQ(response.status, 405) << method;
    EXPECT_NE(response.header("Allow").find("OPTIONS"), std::string::npos);
  }
}

TEST_F(DavTest, RejectsPathEscapes) {
  const char* targets[] = {
      "/../etc/passwd", "%2e%2e%2fetc", "/%2e%2e/", "/../", "/%2e%2e/etc/passwd",
      "/dir/../../etc", "/a/./b", "/a//b",
  };
  for (const char* target : targets) {
    const Response response = send("GET", target);
    EXPECT_EQ(response.status, 403) << target;
  }
  EXPECT_EQ(send("GET", "/%00").status, 403);
  EXPECT_EQ(send("GET", "/%252e%252e%252fetc").status, 403);
}

TEST_F(DavTest, RejectsSymlinksAndDoesNotFollowThem) {
  const std::string link = root_alice_ + "/escape";
  ASSERT_EQ(::symlink(root_bob_.c_str(), link.c_str()), 0);
  EXPECT_EQ(send("GET", "/escape/secret.txt").status, 403);
  EXPECT_EQ(send("GET", "/escape").status, 403);
  EXPECT_EQ(send("PROPFIND", "/escape", {{"Depth", "0"}}).status, 403);
  EXPECT_EQ(send("PUT", "/escape/evil.txt", {}, "x").status, 403);
  EXPECT_EQ(send("DELETE", "/escape").status, 403);
  EXPECT_EQ(send("COPY", "/escape", {{"Destination", "/copied"}}).status, 403);

  // Depth 1 listings must not expose symlinked entries.
  const Response listing = send("PROPFIND", "/", {{"Depth", "1"}});
  EXPECT_EQ(listing.body.find("escape"), std::string::npos);
}

TEST_F(DavTest, CannotReachAnotherUsersTree) {
  Client client(port_);
  const Response response = client.request_as("GET", "/secret.txt", "alice", kPassword, "");
  EXPECT_EQ(response.status, 404);
  EXPECT_EQ(response.body.find("bob"), std::string::npos);
  EXPECT_EQ(response.body.find(root_bob_), std::string::npos);
  EXPECT_EQ(response.body.find(root_alice_), std::string::npos);
}

TEST_F(DavTest, KeepAliveServesSeveralRequests) {
  Client client(port_);
  const Response first = client.request("GET", "/hello.txt", {}, "", false, false);
  EXPECT_EQ(first.status, 200);
  EXPECT_EQ(first.body, "hello world");
  const Response second = client.request("GET", "/page.html", {}, "", false, false);
  EXPECT_EQ(second.status, 200);
  EXPECT_EQ(second.body, "<html/>");
}

TEST_F(DavTest, LargeFileStreamsBothWays) {
  std::string payload;
  payload.reserve(300 * 1024);
  for (int i = 0; i < 300 * 1024; ++i) {
    payload.push_back(static_cast<char>('a' + (i % 26)));
  }
  EXPECT_EQ(send("PUT", "/big.bin", {}, payload).status, 201);
  const Response fetched = send("GET", "/big.bin");
  EXPECT_EQ(fetched.status, 200);
  EXPECT_EQ(fetched.body.size(), payload.size());
  EXPECT_TRUE(fetched.body == payload);
}

TEST(DavServer, UnknownAuthenticatedRootIsInternalError) {
  webdav::Config config;
  config.host = "127.0.0.1";
  config.port = 0;
  config.max_connections = 2;
  const std::string hash = bcrypt_hash(kPassword, "$2b$10$abcdefghijklmnopqrstuu");
  std::vector<webdav::User> auth_users{webdav::User{"alice", hash, "/unused"}};
  auto authenticator = std::make_shared<webdav::Authenticator>(
      auth_users, config.auth_max_concurrent, 1, 1, webdav::default_verify(),
      [](std::chrono::milliseconds) {});
  webdav::Server server(config, authenticator);
  server.bind();
  std::thread thread([&server] { server.serve(); });
  Client client(server.port());
  const Response response = client.request_as("OPTIONS", "/", "alice", kPassword, "");
  EXPECT_EQ(response.status, 500);
  server.stop();
  thread.join();
}

TEST(DavServer, PortIsZeroBeforeBind) {
  webdav::Config config;
  config.host = "127.0.0.1";
  config.port = 0;
  auto authenticator = std::make_shared<webdav::Authenticator>(
      std::vector<webdav::User>{}, 1, 1, 1,
      [](const std::string&, const std::string&) { return true; },
      [](std::chrono::milliseconds) {});
  webdav::Server server(config, authenticator);
  EXPECT_EQ(server.port(), 0);
}

TEST(DavServer, BindReportsResolveFailure) {
  webdav::Config config;
  config.host = "no.such.host.invalid";
  config.port = 1;
  auto authenticator = std::make_shared<webdav::Authenticator>(
      std::vector<webdav::User>{}, 1, 1, 1,
      [](const std::string&, const std::string&) { return true; },
      [](std::chrono::milliseconds) {});
  webdav::Server server(config, authenticator);
  EXPECT_THROW(server.bind(), std::runtime_error);
}

TEST_F(DavTest, ExpectContinueSendsInterimResponse) {
  std::string raw =
      "OPTIONS / HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
      basic_auth("alice", kPassword) +
      "\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n";
  Client client(port_);
  const Response interim = client.send_raw(raw, false);
  EXPECT_EQ(interim.status, 100);
}

TEST_F(DavTest, GetRejectsNonRegularFiles) {
  const std::string fifo = root_alice_ + "/fifo";
  ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
  const Response response = send("GET", "/fifo");
  EXPECT_EQ(response.status, 403);
}

TEST_F(DavTest, GetOpenAndStatFailures) {
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("GET", "/hello.txt").status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("GET", "/hello.txt").status, 403);
  }
}

TEST_F(DavTest, GetHandlesPreadErrorsAndInterrupts) {
  {
    bool first = true;
    ScopedFaultHook guard([&first](const char* operation) {
      if (std::strcmp(operation, "pread") != 0 || !first) {
        return 0;
      }
      first = false;
      return EINTR;
    });
    const Response response = send("GET", "/hello.txt");
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, "hello world");
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "pread") == 0 ? EIO : 0;
    });
    const Response response = send("GET", "/hello.txt");
    EXPECT_EQ(response.status, 200);
    EXPECT_TRUE(response.body.empty());
  }
}

TEST_F(DavTest, GetHandlesEarlyEofFromFile) {
  const std::string path = root_alice_ + "/shrink.txt";
  write_file(path, "hello");
  bool first = true;
  ScopedFaultHook guard([&first, &path](const char* operation) {
    if (std::strcmp(operation, "pread") != 0 || !first) {
      return 0;
    }
    first = false;
    if (::truncate(path.c_str(), 0) != 0) {
      // The hook only needs to make the subsequent read observe EOF.
    }
    return 0;
  });
  const Response response = send("GET", "/shrink.txt");
  EXPECT_EQ(response.status, 200);
  EXPECT_TRUE(response.body.empty());
}

TEST_F(DavTest, GetRejectsMalformedRangeSyntax) {
  for (const char* value : {"bytes=1", "bytes=-", "bytes=-x", "bytes=-0", "bytes=x-1", "bytes=0-x"}) {
    const Response response = send("GET", "/hello.txt", {{"Range", value}});
    EXPECT_EQ(response.status, 200) << value;
    EXPECT_EQ(response.body, "hello world") << value;
  }
}

TEST_F(DavTest, PutRejectsExistingNonRegularTarget) {
  const std::string fifo = root_alice_ + "/put-fifo";
  ASSERT_EQ(::mkfifo(fifo.c_str(), 0600), 0);
  EXPECT_EQ(send("PUT", "/put-fifo", {}, "x").status, 403);
}

TEST_F(DavTest, PutFaultPaths) {
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? ENOSPC : 0;
    });
    EXPECT_EQ(send("PUT", "/tempfail.txt", {}, "data").status, 507);
    EXPECT_FALSE(fs::exists(root_alice_ + "/tempfail.txt"));
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "write") == 0 ? ENOSPC : 0;
    });
    EXPECT_EQ(send("PUT", "/writefail.txt", {}, "data").status, 507);
    EXPECT_FALSE(fs::exists(root_alice_ + "/writefail.txt"));
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "write") == 0 ? EIO : 0;
    });
    EXPECT_EQ(send("PUT", "/writeio.txt", {}, "data").status, 400);
    EXPECT_FALSE(fs::exists(root_alice_ + "/writeio.txt"));
  }
  {
    bool first = true;
    ScopedFaultHook guard([&first](const char* operation) {
      if (std::strcmp(operation, "write") != 0 || !first) {
        return 0;
      }
      first = false;
      return EINTR;
    });
    EXPECT_EQ(send("PUT", "/writeintr.txt", {}, "data").status, 201);
    EXPECT_EQ(read_file(root_alice_ + "/writeintr.txt"), "data");
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "renameat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("PUT", "/renamefail.txt", {}, "data").status, 403);
    EXPECT_FALSE(fs::exists(root_alice_ + "/renamefail.txt"));
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "renameat") == 0 ? EEXIST : 0;
    });
    EXPECT_EQ(send("PUT", "/renameexists.txt", {}, "data").status, 405);
  }
  {
    Client client(port_);
    std::string raw =
        "PUT /badchunk.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
        basic_auth("alice", kPassword) +
        "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nz\r\n";
    EXPECT_EQ(client.send_raw(raw, false).status, 400);
    EXPECT_FALSE(fs::exists(root_alice_ + "/badchunk.txt"));
  }
}

TEST_F(DavTest, DeleteWithBodyAndFaults) {
  EXPECT_EQ(send("DELETE", "/hello.txt", {}, "ignored").status, 204);
  EXPECT_FALSE(fs::exists(root_alice_ + "/hello.txt"));
  write_file(root_alice_ + "/hello.txt", "hello world");

  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EPERM : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? ENOSPC : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 507);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EDQUOT : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 507);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EIO : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 500);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? ENOENT : 0;
    });
    EXPECT_EQ(send("DELETE", "/hello.txt").status, 404);
  }

  fs::create_directories(root_alice_ + "/linkparent");
  ASSERT_EQ(::symlink("hello.txt", (root_alice_ + "/linkparent/link").c_str()), 0);
  EXPECT_EQ(send("DELETE", "/linkparent").status, 403);

  std::string deep;
  for (int i = 0; i < webdav::kMaxTreeDepth + 2; ++i) {
    deep += "/d";
  }
  ASSERT_TRUE(fs::create_directories(root_alice_ + "/deeptree" + deep));
  EXPECT_EQ(send("DELETE", "/deeptree").status, 403);
}

TEST_F(DavTest, MkcolFaultPaths) {
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("MKCOL", "/mkcol-eacces").status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? EPERM : 0;
    });
    EXPECT_EQ(send("MKCOL", "/mkcol-eperm").status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? EEXIST : 0;
    });
    EXPECT_EQ(send("MKCOL", "/mkcol-exists").status, 409);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? ENOTEMPTY : 0;
    });
    EXPECT_EQ(send("MKCOL", "/mkcol-notempty").status, 409);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? ENOSPC : 0;
    });
    EXPECT_EQ(send("MKCOL", "/mkcol-enospc").status, 507);
  }
}

TEST_F(DavTest, PropfindEmptyChunkedBodyUsesAllprop) {
  Client client(port_);
  std::string raw =
      "PROPFIND /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
      basic_auth("alice", kPassword) +
      "\r\nDepth: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n";
  const Response response = client.send_raw(raw, false);
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("getcontentlength"), std::string::npos);
}

TEST_F(DavTest, PropfindMalformedChunkedBodyIsBadRequest) {
  Client client(port_);
  std::string raw =
      "PROPFIND /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
      basic_auth("alice", kPassword) +
      "\r\nDepth: 0\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nz\r\n";
  EXPECT_EQ(client.send_raw(raw, false).status, 400);
}

TEST_F(DavTest, PropfindOversizedBodyIsRejected) {
  const std::string body(70 * 1024, 'x');
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, body).status, 400);
}

TEST_F(DavTest, PropfindMalformedXmlShapes) {
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, "<").status, 400);
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, "<a").status, 400);
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, "<D:propfind><D:prop>").status, 400);
  EXPECT_EQ(send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, "<D:prop").status, 400);
}

TEST_F(DavTest, PropfindUnknownUnprefixedPropertyAddsNamespace) {
  const std::string body =
      "<D:propfind xmlns:D=\"DAV:\"><D:prop><mystery/></D:prop></D:propfind>";
  const Response response = send("PROPFIND", "/hello.txt", {{"Depth", "0"}}, body);
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("xmlns=\"DAV:\""), std::string::npos);
  EXPECT_NE(response.body.find("404 Not Found"), std::string::npos);
}

TEST_F(DavTest, PropfindEscapesXmlSpecialCharacters) {
  const std::string name = "weird&<>'\".txt";
  write_file(root_alice_ + "/" + name, "x");
  const Response response = send("PROPFIND", "/", {{"Depth", "1"}});
  EXPECT_EQ(response.status, 207);
  EXPECT_NE(response.body.find("&amp;"), std::string::npos);
  EXPECT_NE(response.body.find("&lt;"), std::string::npos);
  EXPECT_NE(response.body.find("&gt;"), std::string::npos);
  EXPECT_NE(response.body.find("&quot;"), std::string::npos);
  EXPECT_NE(response.body.find("&apos;"), std::string::npos);
}

TEST_F(DavTest, ProppatchInvalidTargetUsesBadRequest) {
  const std::string body =
      "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>x</D:displayname>"
      "</D:prop></D:set></D:propertyupdate>";
  EXPECT_EQ(send("PROPPATCH", "/%", {}, body).status, 400);
}

TEST_F(DavTest, ProppatchMalformedChunkedBodyIsBadRequest) {
  Client client(port_);
  std::string raw =
      "PROPPATCH /hello.txt HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: " +
      basic_auth("alice", kPassword) +
      "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nz\r\n";
  EXPECT_EQ(client.send_raw(raw, false).status, 400);
}

TEST_F(DavTest, PathStatusBadRequestAndNotDirectory) {
  EXPECT_EQ(send("GET", "/%").status, 400);
  EXPECT_EQ(send("GET", "/hello.txt/child").status, 404);
  EXPECT_EQ(send("PUT", "/hello.txt/child", {}, "x").status, 409);
}

TEST_F(DavTest, CopyDestinationParsingAndIdentity) {
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "http://127.0.0.1"}}).status, 403);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "relative"}}).status, 400);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/hello.txt"}}).status, 403);
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/copy-body.txt"}}, "ignored").status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/copy-body.txt"), "hello world");
}

TEST_F(DavTest, CopyOverwriteFailurePaths) {
  EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/overwrite.txt"}}).status, 201);
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/overwrite.txt"}}).status, 403);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? ENOTEMPTY : 0;
    });
    EXPECT_EQ(send("COPY", "/hello.txt", {{"Destination", "/overwrite.txt"}}).status, 409);
  }
}

TEST_F(DavTest, MoveFaultAndCrossDeviceFallback) {
  write_file(root_alice_ + "/move-src.txt", "move me");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "renameat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(send("MOVE", "/move-src.txt", {{"Destination", "/move-fail.txt"}}).status, 403);
    EXPECT_TRUE(fs::exists(root_alice_ + "/move-src.txt"));
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "renameat") == 0 ? EXDEV : 0;
    });
    EXPECT_EQ(send("MOVE", "/move-src.txt", {{"Destination", "/move-fallback.txt"}}).status, 201);
    EXPECT_FALSE(fs::exists(root_alice_ + "/move-src.txt"));
    EXPECT_EQ(read_file(root_alice_ + "/move-fallback.txt"), "move me");
  }
}

TEST_F(DavTest, GetBodyWriteFailureStopsStreaming) {
  int writes = 0;
  ScopedFaultHook guard([&writes](const char* operation) {
    if (std::strcmp(operation, "http_write") != 0) {
      return 0;
    }
    ++writes;
    return writes == 2 ? EIO : 0;
  });
  const Response response = send("GET", "/hello.txt");
  EXPECT_EQ(response.status, 200);
  EXPECT_TRUE(response.body.empty());
}

TEST_F(DavTest, PropfindWriteHeadFailureIsHandled) {
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "http_write") == 0 ? EIO : 0;
  });
  const Response response = send("PROPFIND", "/hello.txt", {{"Depth", "0"}});
  EXPECT_EQ(response.status, 0);
}

TEST_F(DavTest, ProppatchWriteHeadFailureIsHandled) {
  const std::string body =
      "<D:propertyupdate xmlns:D=\"DAV:\"><D:set><D:prop><D:displayname>x</D:displayname>"
      "</D:prop></D:set></D:propertyupdate>";
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "http_write") == 0 ? EIO : 0;
  });
  const Response response = send("PROPPATCH", "/hello.txt", {}, body);
  EXPECT_EQ(response.status, 0);
}

TEST(DavServer, BindReportsAcceptorOpenFailure) {
  webdav::Config config;
  config.host = "127.0.0.1";
  config.port = 0;
  auto authenticator = std::make_shared<webdav::Authenticator>(
      std::vector<webdav::User>{}, 1, 1, 1,
      [](const std::string&, const std::string&) { return true; },
      [](std::chrono::milliseconds) {});
  webdav::Server server(config, authenticator);
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "acceptor_open") == 0 ? EACCES : 0;
  });
  EXPECT_THROW(server.bind(), std::runtime_error);
}

TEST(DavServer, BindReportsAcceptorListenFailure) {
  webdav::Config config;
  config.host = "127.0.0.1";
  config.port = 0;
  auto authenticator = std::make_shared<webdav::Authenticator>(
      std::vector<webdav::User>{}, 1, 1, 1,
      [](const std::string&, const std::string&) { return true; },
      [](std::chrono::milliseconds) {});
  webdav::Server server(config, authenticator);
  ScopedFaultHook guard([](const char* operation) {
    return std::strcmp(operation, "acceptor_listen") == 0 ? EACCES : 0;
  });
  EXPECT_THROW(server.bind(), std::runtime_error);
}

TEST_F(DavTest, PutLargerThanBeastDefaultBodyLimit) {
  // Beast's request_parser defaults to a 1 MiB body limit.  The server must
  // raise that limit or large streaming PUTs fail before the body is read.
  std::string payload(2 * 1024 * 1024, 'x');
  const Response response = send("PUT", "/large-2m.bin", {}, payload);
  EXPECT_EQ(response.status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/large-2m.bin").size(), payload.size());
}

TEST_F(DavTest, ConcurrentPutsToSamePathAreAtomic) {
  constexpr int kThreads = 4;
  std::vector<std::string> payloads;
  for (int i = 0; i < kThreads; ++i) {
    payloads.emplace_back(8192, static_cast<char>('a' + i));
  }
  std::vector<int> statuses(kThreads, -1);
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    workers.emplace_back([&, i] {
      try {
        Client client(port_);
        statuses[i] = client.request("PUT", "/concurrent-put.bin", {}, payloads[i]).status;
      } catch (...) {
        statuses[i] = -1;
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  for (const int status : statuses) {
    EXPECT_TRUE(status == 201 || status == 204) << status;
  }
  const std::string final_body = read_file(root_alice_ + "/concurrent-put.bin");
  bool matched = false;
  for (const std::string& payload : payloads) {
    matched = matched || final_body == payload;
  }
  EXPECT_TRUE(matched);
  EXPECT_FALSE(has_temporary_file(root_alice_));
}

TEST_F(DavTest, ConcurrentPutAndGetStayConsistent) {
  constexpr int kIterations = 40;
  std::vector<std::string> payloads;
  for (int i = 0; i < 5; ++i) {
    payloads.emplace_back(4096, static_cast<char>('a' + i));
  }
  write_file(root_alice_ + "/concurrent-rw.bin", payloads[0]);

  std::atomic<int> failures{0};
  std::thread writer([&] {
    for (int i = 0; i < kIterations; ++i) {
      try {
        Client client(port_);
        const Response response = client.request("PUT", "/concurrent-rw.bin", {},
                                                 payloads[static_cast<std::size_t>(i) % payloads.size()]);
        if (response.status != 201 && response.status != 204) {
          ++failures;
        }
      } catch (...) {
        ++failures;
      }
    }
  });
  std::thread reader([&] {
    for (int i = 0; i < kIterations; ++i) {
      try {
        Client client(port_);
        const Response response = client.request("GET", "/concurrent-rw.bin", {}, "");
        if (response.status != 200) {
          ++failures;
          continue;
        }
        bool matched = false;
        for (const std::string& payload : payloads) {
          matched = matched || response.body == payload;
        }
        if (!matched) {
          ++failures;
        }
      } catch (...) {
        ++failures;
      }
    }
  });
  writer.join();
  reader.join();
  EXPECT_EQ(failures.load(), 0);
  EXPECT_FALSE(has_temporary_file(root_alice_));
}

TEST_F(DavTest, ConcurrentAuthenticationRequests) {
  constexpr int kThreads = 8;
  std::vector<int> statuses(kThreads, -1);
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int i = 0; i < kThreads; ++i) {
    workers.emplace_back([&, i] {
      try {
        Client client(port_);
        statuses[i] = client
                          .request_as("OPTIONS", "/", "alice",
                                      i == 0 ? std::string("wrong-password") : std::string(kPassword),
                                      "")
                          .status;
      } catch (...) {
        statuses[i] = -1;
      }
    });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }
  EXPECT_EQ(statuses[0], 401);
  for (int i = 1; i < kThreads; ++i) {
    EXPECT_EQ(statuses[i], 200) << i;
  }
}

TEST_F(DavTest, InterruptedUploadCleansTemporaryFileAndFds) {
  const std::size_t fds_before = open_fd_count();
  std::string raw = "PUT /interrupted.bin HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: ";
  raw.append(basic_auth("alice", kPassword));
  raw.append("\r\nContent-Length: 1048576\r\nConnection: close\r\n\r\n");
  raw.append(65536, 'x');

  Client client(port_);
  client.send_partial_and_close(raw);

  // Give the detached worker a moment to observe the EOF and unlink its temp
  // file, then require both the temp file and the extra descriptor to be gone.
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  bool clean = false;
  for (int i = 0; i < 200; ++i) {
    if (!has_temporary_file(root_alice_) && !fs::exists(root_alice_ + "/interrupted.bin") &&
        open_fd_count() <= fds_before + 2) {
      clean = true;
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  EXPECT_TRUE(clean);
}

TEST_F(DavTest, ConcurrentIntermediateSymlinkSwapCannotEscape) {
  const std::string original = root_alice_ + "/race-dir";
  const std::string moved = root_alice_ + "/race-real";
  const std::string outside = root_bob_ + "/race-outside";
  std::error_code ec;
  fs::remove_all(original, ec);
  fs::remove_all(moved, ec);
  fs::remove_all(outside, ec);
  fs::create_directories(original, ec);
  fs::create_directories(outside, ec);

  std::atomic<bool> stop{false};
  std::atomic<int> errors{0};
  std::thread swapper([&] {
    while (!stop.load(std::memory_order_relaxed)) {
      std::error_code swap_ec;
      fs::rename(original, moved, swap_ec);
      if (swap_ec) {
        std::this_thread::yield();
        continue;
      }
      fs::create_directory_symlink(outside, original, swap_ec);
      if (swap_ec) {
        fs::rename(moved, original, swap_ec);
        std::this_thread::yield();
        continue;
      }
      fs::remove(original, swap_ec);
      fs::rename(moved, original, swap_ec);
      std::this_thread::yield();
    }
  });

  for (int i = 0; i < 200; ++i) {
    try {
      Client client(port_);
      const Response response = client.request("PUT", "/race-dir/pwn.txt", {}, "pwn");
      if (response.status >= 500) {
        ++errors;
      }
    } catch (...) {
      ++errors;
    }
  }
  stop.store(true);
  swapper.join();

  if (fs::is_symlink(original)) {
    fs::remove(original, ec);
  }
  for (int i = 0; i < 20 && fs::exists(moved); ++i) {
    fs::remove_all(original, ec);
    fs::rename(moved, original, ec);
    if (!ec) {
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  EXPECT_EQ(errors.load(), 0);
  EXPECT_FALSE(fs::exists(outside + "/pwn.txt"));
  EXPECT_TRUE(fs::is_directory(original));
}

TEST_F(DavTest, EncodedLegalNamesRemainAccessible) {
  const std::vector<std::string> names = {"space name.txt", "中文.txt", "plus+name.txt",
                                          "a#b?c.txt"};
  for (const std::string& name : names) {
    write_file(root_alice_ + "/" + name, "ok:" + name);
  }
  for (const std::string& name : names) {
    const Response response = send("GET", "/" + webdav::percent_encode(name));
    EXPECT_EQ(response.status, 200) << name;
    EXPECT_EQ(response.body, "ok:" + name) << name;
  }
  const std::string new_name = "new file 名字.txt";
  const Response put =
      send("PUT", "/" + webdav::percent_encode(new_name), {}, "encoded-put");
  EXPECT_EQ(put.status, 201);
  EXPECT_EQ(read_file(root_alice_ + "/" + new_name), "encoded-put");
}

TEST_F(DavTest, RejectsOverlongAndAbsoluteStyleTargets) {
  EXPECT_EQ(send("GET", "/" + std::string(5000, 'a')).status, 403);
  EXPECT_EQ(send("GET", "//etc/passwd").status, 403);
  EXPECT_EQ(send("GET", "/%2fetc/passwd").status, 403);
  EXPECT_EQ(send("GET", "/%252fetc/passwd").status, 403);
}

TEST_F(DavTest, CopyAndMoveRejectAncestorDestination) {
  const Response copy = send("COPY", "/dir/sub", {{"Destination", "/dir"}});
  EXPECT_EQ(copy.status, 403);
  EXPECT_TRUE(fs::exists(root_alice_ + "/dir/sub/deep.txt"));

  const Response move = send("MOVE", "/dir/sub", {{"Destination", "/dir"}});
  EXPECT_EQ(move.status, 403);
  EXPECT_TRUE(fs::exists(root_alice_ + "/dir/sub/deep.txt"));
}

TEST_F(DavTest, ForwardedClientIpHeaderIsAcceptedForAuthBookkeeping) {
  EXPECT_EQ(send("OPTIONS", "/", {{"X-Real-IP", "203.0.113.9"}}).status, 200);
}
