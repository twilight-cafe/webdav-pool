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

    const auto authorization = head[http::field::authorization];
    const AuthResult auth_result = auth->authenticate(
        client_key, std::string_view(authorization.data(), authorization.size()));
    if (auth_result.status != AuthStatus::kOk) {
      response.set("WWW-Authenticate", "Basic realm=\"webdav\", charset=\"UTF-8\"");
      (void)response.send_text(http::status::unauthorized, "Unauthorized\n");
    } else {
      const Fd* root = root_for(auth_result.user->name);
      if (root == nullptr) {
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
        DavContext context{socket, head, body, *root, *auth_result.user};
        handle_dav_request(context, response);
      }
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
