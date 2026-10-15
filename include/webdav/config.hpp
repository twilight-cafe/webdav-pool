#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webdav {

// A single configured WebDAV identity. `name` is an application-level login
// name only: it is never looked up as an OS account and the process never
// switches credentials to it. All filesystem operations run as the user that
// launched webdavd and are confined to the pre-opened `root`. `root` is stored
// canonicalised (realpath) so later path confinement can compare components
// without resolving again.
struct User {
  User() = default;
  User(std::string user_name, std::string password, std::string user_root)
      : name(std::move(user_name)),
        password_bcrypt(std::move(password)),
        root(std::move(user_root)) {}
  User(std::string user_name, std::string password, std::string user_root,
       std::vector<std::string> domains)
      : name(std::move(user_name)),
        password_bcrypt(std::move(password)),
        root(std::move(user_root)),
        cors_domains(std::move(domains)),
        cors_configured(true) {}
  User(std::string user_name, std::string password, std::string user_root,
       std::vector<std::string> domains, bool configured)
      : name(std::move(user_name)),
        password_bcrypt(std::move(password)),
        root(std::move(user_root)),
        cors_domains(std::move(domains)),
        cors_configured(configured) {}

  std::string name;
  std::string password_bcrypt;
  std::string root;
  // CORS allowlist. Each entry is either a complete origin
  // ("https://app.example.com"), a bare host ("app.example.com"), or a
  // wildcard host ("*.app.example.com"). `cors_configured` distinguishes an
  // omitted key from an explicitly supplied list; both keep the CORS response
  // headers away from every browser Origin unless a configured rule matches.
  // Requests that do not carry an Origin header are not browser CORS requests
  // and are not subject to this list.
  std::vector<std::string> cors_domains;
  bool cors_configured{false};
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

// Returns true when `origin` may read a response produced for `user`, i.e. when
// it matches one of the user's `cors_domains` rules. This is a response-sharing
// decision only: a mismatch must never reject the request, it merely omits the
// Access-Control-* headers so that the browser blocks the response itself. A
// user with no `cors_domains` entry has an empty allowlist, so no browser Origin
// is allowed; requests without Origin are not browser CORS requests at all.
bool cors_allows_origin(const User& user, std::string_view origin);

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
