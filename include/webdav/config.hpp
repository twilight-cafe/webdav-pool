#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace webdav {

// A single configured user. `root` is stored canonicalised (realpath) so that
// later path confinement can compare components without resolving again.
struct User {
  std::string name;
  std::string password_bcrypt;
  std::string root;
};

struct Config {
  std::string host{"127.0.0.1"};
  std::uint16_t port{8080};
  std::vector<User> users;
  int max_connections{16};
  int auth_max_concurrent{2};
  int auth_backoff_base_ms{250};
  int auth_backoff_max_ms{5000};
};

// Thrown for every configuration problem; the message carries the reason.
class ConfigError : public std::runtime_error {
 public:
  explicit ConfigError(const std::string& message) : std::runtime_error(message) {}
};

// Parses and fully validates JSON configuration text.
Config parse_config(const std::string& json_text);

// Reads a configuration file (bounded size) and parses it.
Config load_config(const std::string& path);

}  // namespace webdav
