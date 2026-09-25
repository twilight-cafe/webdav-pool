#pragma once

#include <functional>
#include <memory>

#include "webdav/auth.hpp"
#include "webdav/config.hpp"
#include "webdav/server.hpp"

namespace webdav {

using ServerFactory =
    std::function<std::unique_ptr<ServerLike>(const Config&, std::shared_ptr<Authenticator>)>;

// Builds the real server; used as the default factory.
std::unique_ptr<ServerLike> make_server(const Config& config, std::shared_ptr<Authenticator> auth);

// Full command line handling. Returns the process exit code.
int run_cli(int argc, char** argv, const ServerFactory& factory);
int run_cli(int argc, char** argv);

}  // namespace webdav
