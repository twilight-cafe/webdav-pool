#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "webdav/auth.hpp"
#include "webdav/config.hpp"

namespace webdav {

// Interface used by the CLI so the server can be replaced in tests.
class ServerLike {
 public:
  virtual ~ServerLike() = default;
  virtual void bind() = 0;
  virtual std::uint16_t port() const = 0;
  virtual void serve() = 0;
  virtual void stop() = 0;
};

// Minimal HTTP/1.1 front end. Phase 1 wires authentication and OPTIONS; the
// remaining DAV methods are added in later phases.
class Server : public ServerLike {
 public:
  Server(Config config, std::shared_ptr<Authenticator> authenticator);
  ~Server() override;

  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  // Creates and binds the listening socket. Throws std::runtime_error on
  // failure. A port of 0 lets the OS choose one (useful for tests).
  void bind() override;

  // Actual port the listening socket is bound to.
  std::uint16_t port() const override;

  // Serves until stop() is called. Never throws.
  void serve() override;

  // Requests the accept loop to stop and waits for in-flight workers.
  void stop() override;

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace webdav
