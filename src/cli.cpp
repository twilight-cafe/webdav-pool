#include "webdav/cli.hpp"

#include <cstdio>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "webdav/log.hpp"
#include "webdav/server.hpp"
#include "webdav/version.hpp"

namespace webdav {

namespace {

void print_usage() {
  std::printf("usage: %s [--config PATH] [--version] [--help]\n", kProgramName);
}

}  // namespace

std::unique_ptr<ServerLike> make_server(const Config& config,
                                        std::shared_ptr<Authenticator> auth) {
  return std::make_unique<Server>(config, std::move(auth));
}

int run_cli(int argc, char** argv, const ServerFactory& factory) {
  std::string config_path = "config.json";
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument = argv[i];
    if (argument == "--version") {
      std::printf("%s %s\n", kProgramName, kVersion);
      return 0;
    }
    if (argument == "--help" || argument == "-h") {
      print_usage();
      return 0;
    }
    if (argument == "--config") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "%s: --config requires a path argument\n", kProgramName);
        return 2;
      }
      config_path = argv[++i];
      continue;
    }
    std::fprintf(stderr, "%s: unknown argument '%s'\n", kProgramName, argv[i]);
    return 2;
  }

  Config config;
  try {
    config = load_config(config_path);
  } catch (const ConfigError& error) {
    std::fprintf(stderr, "%s: configuration error: %s\n", kProgramName, error.what());
    return 1;
  }

  try {
    auto authenticator =
        std::make_shared<Authenticator>(config.users, config.auth_max_concurrent,
                                        config.auth_backoff_base_ms, config.auth_backoff_max_ms,
                                        default_verify(), default_sleep());
    std::unique_ptr<ServerLike> server = factory(config, std::move(authenticator));
    server->bind();
    log_write(LogLevel::kInfo,
              "listening on " + config.host + ":" + std::to_string(server->port()));
    server->serve();
  } catch (const std::exception& error) {
    log_write(LogLevel::kError, std::string("fatal: ") + error.what());
    return 1;
  }
  log_write(LogLevel::kInfo, "shutdown complete");
  return 0;
}

int run_cli(int argc, char** argv) { return run_cli(argc, argv, make_server); }

}  // namespace webdav
