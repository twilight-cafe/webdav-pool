#include "webdav/server.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <sys/socket.h>
#include <sys/time.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "webdav/dav.hpp"
#include "webdav/fault.hpp"
#include "webdav/fsutil.hpp"
#include "webdav/http.hpp"
#include "webdav/log.hpp"

namespace webdav {

using tcp = asio::ip::tcp;

namespace {

// Browser CORS policy.  `Origin` only decides whether the browser may *read* a
// response: the server answers every request normally and merely omits the
// `Access-Control-*` headers for an Origin outside the allowlist, leaving the
// blocking to the browser.  An unlisted Origin must therefore never become a
// 403 - that would be both non-conforming and indistinguishable, in the
// browser, from a wrong server address.
constexpr std::string_view kCorsAllowMethods = "GET, PUT, DELETE, OPTIONS, PROPFIND, MKCOL";
constexpr std::string_view kCorsAllowHeaders =
    "Authorization, Content-Type, Depth, If-Match, If-None-Match";
// Browser scripts only see CORS-safelisted response headers plus the ones listed
// here. A scripted WebDAV capability probe reads `DAV` and `Allow`, so both must
// be exposed or the client concludes the server is not a WebDAV server.
constexpr std::string_view kCorsExposeHeaders = "ETag, DAV, MS-Author-Via, Allow";

// True when any configured user lists `origin`.  Used whenever no user is known
// yet: a credential-less preflight and a 401 must be readable by the browser
// even though the follow-up, authenticated request is what names the user.
bool any_user_allows_origin(const Config& config, std::string_view origin) {
  for (const User& user : config.users) {
    if (cors_allows_origin(user, origin)) {
      return true;
    }
  }
  return false;
}

void set_cors_headers(Response& response, std::string_view origin) {
  response.set("Access-Control-Allow-Origin", std::string(origin));
  response.set("Access-Control-Allow-Credentials", "true");
  response.set("Access-Control-Allow-Methods", std::string(kCorsAllowMethods));
  response.set("Access-Control-Allow-Headers", std::string(kCorsAllowHeaders));
  response.set("Access-Control-Expose-Headers", std::string(kCorsExposeHeaders));
  response.set("Vary", "Origin");
}

void set_preflight_headers(Response& response, std::string_view origin) {
  set_cors_headers(response, origin);
  response.set("Access-Control-Max-Age", "86400");
}

}  // namespace

struct Server::Impl {
  struct UserRoot {
    std::string name;
    Fd fd;
  };

  Impl(Config cfg, std::shared_ptr<Authenticator> authenticator)
      : config(std::move(cfg)), auth(std::move(authenticator)), slots(config.max_connections) {
    for (const User& user : config.users) {
      UserRoot entry;
      entry.name = user.name;
      entry.fd = open_root_directory(user.root);
      roots.push_back(std::move(entry));
    }
  }

  void handle_connection(tcp::socket socket);
  void run_worker(tcp::socket socket);

  const Fd* root_for(const std::string& name) const {
    for (const UserRoot& entry : roots) {
      if (entry.name == name) {
        return &entry.fd;
      }
    }
    return nullptr;
  }

  const User* user_for(const std::string& name) const {
    for (const User& user : config.users) {
      if (user.name == name) {
        return &user;
      }
    }
    return nullptr;
  }

  // Adds the CORS response headers when `origin` is allowed to read the answer,
  // and `Vary: Origin` either way so a shared cache cannot hand one Origin's
  // answer to another. `user` is null while no user is known (401/500, or a
  // credential-less preflight); any configured allowlist then counts.
  void apply_cors_headers(Response& response, const User* user, std::string_view origin) const {
    const bool allowed = user != nullptr ? cors_allows_origin(*user, origin)
                                         : any_user_allows_origin(config, origin);
    if (allowed) {
      set_cors_headers(response, origin);
    } else {
      response.set("Vary", "Origin");
    }
  }

  Config config;
  std::shared_ptr<Authenticator> auth;
  asio::io_context ioc;
  std::unique_ptr<tcp::acceptor> acceptor;
  std::atomic<bool> stopping{false};
  Semaphore slots;
  std::mutex drain_mutex;
  std::condition_variable drain_cv;
  int active{0};
  std::vector<UserRoot> roots;
};

void Server::Impl::handle_connection(tcp::socket socket) {
  beast::flat_buffer buffer(kMaxHeaderBytes);
  while (!stopping.load(std::memory_order_relaxed)) {
    http::request_parser<http::empty_body> parser;
    parser.body_limit(std::numeric_limits<std::uint64_t>::max());
    ErrorCode ec;
    http::read_header(socket, buffer, parser, ec);
    if (ec) {
      break;
    }
    const auto& head = parser.get();

    std::string client_key;
    {
      beast::error_code endpoint_ec;
      const auto endpoint = socket.remote_endpoint(endpoint_ec);
      client_key = endpoint_ec ? std::string("unknown") : endpoint.address().to_string();
      const auto forwarded = head.find("x-real-ip");
      if (forwarded != head.end()) {
        const std::string_view forwarded_value(forwarded->value().data(), forwarded->value().size());
        boost::system::error_code address_ec;
        const auto forwarded_address = asio::ip::make_address(forwarded_value, address_ec);
        if (!address_ec && !endpoint_ec && endpoint.address().is_loopback()) {
          client_key = forwarded_address.to_string();
        }
      }
    }

    Reader reader(socket, buffer);
    BodyReader body(reader, head);
    Response response(socket, head.version(), head.keep_alive());
    if (head.method() == http::verb::head) {
      response.set_bodyless(true);
    }

    // A browser CORS preflight is an OPTIONS request carrying both Origin and
    // Access-Control-Request-Method.  Browsers never attach credentials to it,
    // so it must be answered before authentication: requiring credentials here
    // would make every cross-origin request impossible.  The preflight does not
    // identify a user, so the Origin is checked against every configured
    // allowlist; the follow-up request is still authenticated and judged by
    // that user's own list.
    const auto origin_field = head.find("origin");
    const bool has_origin = origin_field != head.end();
    std::string origin;
    if (has_origin) {
      origin.assign(origin_field->value().data(), origin_field->value().size());
    }
    if (head.method() == http::verb::options && has_origin &&
        head.find("access-control-request-method") != head.end()) {
      // A preflight is answered normally whether or not the Origin is listed;
      // without the CORS headers the browser blocks the follow-up request.
      response.result(http::status::no_content);
      response.set("DAV", "1");
      response.set("MS-Author-Via", "DAV");
      response.set("Allow", std::string(kAllowMethods));
      if (any_user_allows_origin(config, origin)) {
        set_preflight_headers(response, origin);
      } else {
        response.set("Vary", "Origin");
      }
      if (!response.write_head()) {
        break;
      }
      if (!response.keep_alive() || !body.complete()) {
        break;
      }
      continue;
    }

    const auto authorization = head[http::field::authorization];
    const AuthResult auth_result = auth->authenticate(
        client_key, std::string_view(authorization.data(), authorization.size()));
    const bool authenticated = auth_result.status == AuthStatus::kOk;
    const Fd* root = authenticated ? root_for(auth_result.user->name) : nullptr;
    const User* configured_user = authenticated ? user_for(auth_result.user->name) : nullptr;
    if (has_origin) {
      apply_cors_headers(response, configured_user, origin);
    }
    if (!authenticated) {
      response.set("WWW-Authenticate", "Basic realm=\"webdav\", charset=\"UTF-8\"");
      (void)response.send_text(http::status::unauthorized, "Unauthorized\n");
    } else if (root == nullptr || configured_user == nullptr) {
      (void)response.send_text(http::status::internal_server_error, "Unknown root\n");
    } else {
      if (head.version() == 11) {
        const auto expect = head[http::field::expect];
        const std::string_view expect_view(expect.data(), expect.size());
        if (expect_view.find("100-continue") != std::string_view::npos) {
          ErrorCode write_ec;
          const char interim[] = "HTTP/1.1 100 Continue\r\n\r\n";
          asio::write(socket, asio::buffer(interim, sizeof(interim) - 1), write_ec);
        }
      }
      // DAV handlers receive only the authenticated user's pre-opened root;
      // they never receive or look up the configured `name` as an OS account.
      DavContext context{socket, head, body, *root};
      handle_dav_request(context, response);
    }

    if (!response.keep_alive() || !body.complete()) {
      break;
    }
  }
  beast::error_code ec;
  socket.shutdown(tcp::socket::shutdown_send, ec);
}

void Server::Impl::run_worker(tcp::socket socket) {
  timeval timeout{};
  timeout.tv_sec = 30;
  (void)::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  (void)::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
  handle_connection(std::move(socket));
  slots.release();
  {
    std::lock_guard<std::mutex> lock(drain_mutex);
    --active;
  }
  drain_cv.notify_all();
}

Server::Server(Config config, std::shared_ptr<Authenticator> authenticator)
    : impl_(std::make_unique<Impl>(std::move(config), std::move(authenticator))) {}

Server::~Server() { stop(); }

void Server::bind() {
  beast::error_code ec;
  tcp::resolver resolver(impl_->ioc);
  const auto results = resolver.resolve(impl_->config.host, std::to_string(impl_->config.port), ec);
  if (ec) {
    throw std::runtime_error("cannot resolve '" + impl_->config.host + "': " + ec.message());
  }
  impl_->acceptor = std::make_unique<tcp::acceptor>(impl_->ioc);
  if (const int injected = fault_inject("acceptor_open"); injected != 0) {
    ec = beast::error_code(injected, boost::system::system_category());
  } else {
    impl_->acceptor->open(results.begin()->endpoint().protocol(), ec);
  }
  if (ec) {
    throw std::runtime_error("cannot open listening socket: " + ec.message());
  }
  impl_->acceptor->set_option(asio::socket_base::reuse_address(true), ec);
  impl_->acceptor->bind(*results.begin(), ec);
  if (ec) {
    throw std::runtime_error("cannot bind " + impl_->config.host + ":" +
                             std::to_string(impl_->config.port) + ": " + ec.message());
  }
  if (const int injected = fault_inject("acceptor_listen"); injected != 0) {
    ec = beast::error_code(injected, boost::system::system_category());
  } else {
    impl_->acceptor->listen(asio::socket_base::max_listen_connections, ec);
  }
  if (ec) {
    throw std::runtime_error("cannot listen: " + ec.message());
  }
}

std::uint16_t Server::port() const {
  beast::error_code ec;
  if (!impl_->acceptor) {
    return 0;
  }
  const tcp::endpoint endpoint = impl_->acceptor->local_endpoint(ec);
  return ec ? 0 : endpoint.port();
}

void Server::serve() {
  while (!impl_->stopping.load()) {
    impl_->slots.acquire();
    beast::error_code ec;
    tcp::socket socket(impl_->ioc);
    impl_->acceptor->accept(socket, ec);
    if (ec) {
      impl_->slots.release();
      break;
    }
    {
      std::lock_guard<std::mutex> lock(impl_->drain_mutex);
      ++impl_->active;
    }
    Impl* impl = impl_.get();
    std::thread([impl, socket = std::move(socket)]() mutable {
      impl->run_worker(std::move(socket));
    }).detach();
  }
}

void Server::stop() {
  impl_->stopping.store(true);
  beast::error_code ec;
  if (impl_->acceptor) {
    // On Linux close() alone does not wake a thread that is blocked inside
    // accept(); shutting the listening socket down first makes accept() return
    // immediately, so serve() can observe `stopping` and the worker can be
    // joined instead of hanging forever.
    ::shutdown(impl_->acceptor->native_handle(), SHUT_RDWR);
    impl_->acceptor->close(ec);
  }
  std::unique_lock<std::mutex> lock(impl_->drain_mutex);
  impl_->drain_cv.wait(lock, [this] { return impl_->active == 0; });
}

}  // namespace webdav
