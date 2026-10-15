#include "webdav/config.hpp"

#include <algorithm>
#include <cctype>
#include <climits>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <nlohmann/json.hpp>

#include "webdav/bcrypt.hpp"
#include "webdav/fault.hpp"

namespace webdav {

namespace {

using json = nlohmann::json;

constexpr std::size_t kMaxConfigBytes = 4u * 1024u * 1024u;

[[noreturn]] void fail(const std::string& message) { throw ConfigError(message); }

bool is_known_top_key(const std::string& key) {
  return key == "host" || key == "port" || key == "users" || key == "max_connections" ||
         key == "auth_max_concurrent" || key == "auth_backoff_base_ms" ||
         key == "auth_backoff_max_ms";
}

int require_int(const json& object, const std::string& key, int low, int high) {
  const json& value = object.at(key);
  if (!value.is_number_integer()) {
    fail("'" + key + "' must be an integer");
  }
  const long long number = value.get<long long>();
  if (number < low || number > high) {
    fail("'" + key + "' must be in [" + std::to_string(low) + "," + std::to_string(high) + "]");
  }
  return static_cast<int>(number);
}

std::string canonical_directory(const std::string& path, const std::string& user) {
  if (path.empty()) {
    fail("user '" + user + "': 'root' must not be empty");
  }
  if (path[0] != '/') {
    fail("user '" + user + "': 'root' must be an absolute path");
  }
  char resolved[PATH_MAX];
  errno = 0;
  if (::realpath(path.c_str(), resolved) == nullptr) {
    fail("user '" + user + "': 'root' is not accessible: " + std::strerror(errno));
  }
  const std::string result(resolved);
  struct stat info {};
  if (fs_stat(result.c_str(), &info) != 0) {
    fail("user '" + user + "': cannot stat 'root'");
  }
  if (!S_ISDIR(info.st_mode)) {
    fail("user '" + user + "': 'root' is not a directory");
  }
  return result;
}

bool path_within(const std::string& child, const std::string& parent) {
  if (parent == "/") {
    return true;
  }
  if (child.size() < parent.size() || child.compare(0, parent.size(), parent) != 0) {
    return false;
  }
  return child.size() == parent.size() || child[parent.size()] == '/';
}

std::string ascii_lower(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const char c : input) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}  // LCOV_EXCL_LINE

std::string_view trim_ascii_ws(std::string_view text) {
  while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
    text.remove_prefix(1);
  }
  while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
    text.remove_suffix(1);
  }
  return text;
}

// Compares a lower-cased Origin header value against one configured rule.
// Full origins must match exactly (modulo a trailing slash convenience);
// bare hosts match the origin host; a leading "*." enables subdomain matching.
bool origin_matches_rule(std::string_view origin, std::string_view raw_rule) {
  const std::string rule = ascii_lower(trim_ascii_ws(raw_rule));
  if (rule.empty()) {
    return false;
  }

  if (rule.find("://") != std::string::npos) {
    if (rule.back() == '/') {
      return origin == std::string_view(rule).substr(0, rule.size() - 1);
    }
    return origin == rule;
  }

  const std::size_t scheme_end = origin.find("://");
  if (scheme_end == std::string_view::npos || scheme_end == 0) {
    return false;
  }
  const std::string_view authority = origin.substr(scheme_end + 3);
  if (authority.empty() || authority.find_first_of("/?#@") != std::string_view::npos) {
    return false;
  }

  std::string_view host = authority;
  if (host.front() == '[') {
    const std::size_t close = host.find(']');
    if (close == std::string_view::npos) {
      return false;
    }
    host = host.substr(0, close + 1);
  } else {
    const std::size_t colon = host.rfind(':');
    if (colon != std::string_view::npos) {
      host = host.substr(0, colon);
    }
  }
  if (host.empty()) {
    return false;
  }

  if (rule.size() > 2 && rule[0] == '*' && rule[1] == '.') {
    const std::string_view suffix(rule.data() + 2, rule.size() - 2);
    return host.size() > suffix.size() &&
           host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0 &&
           host[host.size() - suffix.size() - 1] == '.';
  }
  if (!rule.empty() && rule.front() == '[') {
    if (rule.find("]:") == std::string::npos) {
      return host == rule;
    }
    return authority == rule;
  }
  if (rule.find(':') != std::string::npos) {
    return authority == rule;
  }
  return host == rule;
}

void parse_cors_domains(const json& entry, User& user) {
  const json& value = entry.at("cors_domains");
  if (!value.is_array()) {
    fail("user '" + user.name + "': 'cors_domains' must be an array");
  }
  user.cors_configured = true;
  for (const json& item : value) {
    if (!item.is_string()) {
      fail("user '" + user.name + "': 'cors_domains' entries must be strings");
    }
    std::string domain = item.get<std::string>();
    if (domain.empty()) {
      fail("user '" + user.name + "': 'cors_domains' entries must not be empty");
    }
    for (const char c : domain) {
      if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) {
        fail("user '" + user.name +
             "': 'cors_domains' entries must not contain control characters");
      }
    }
    user.cors_domains.push_back(std::move(domain));
  }
}

}  // namespace

bool cors_allows_origin(const User& user, std::string_view origin) {
  const std::string lower_origin = ascii_lower(origin);
  if (lower_origin.empty()) {
    return false;
  }
  return std::any_of(user.cors_domains.begin(), user.cors_domains.end(),
                     [&lower_origin](const std::string& rule) {
                       return origin_matches_rule(lower_origin, rule);
                     });
}

Config parse_config(const std::string& json_text) {
  const json doc = json::parse(json_text, nullptr, false);
  if (doc.is_discarded()) {
    fail("invalid JSON syntax");
  }
  if (!doc.is_object()) {
    fail("top-level JSON value must be an object");
  }
  for (auto it = doc.begin(); it != doc.end(); ++it) {
    if (!is_known_top_key(it.key())) {
      fail("unknown configuration key '" + it.key() + "'");
    }
  }

  Config config;

  if (!doc.contains("host")) {
    fail("missing required key 'host'");
  }
  if (!doc.at("host").is_string()) {
    fail("'host' must be a string");
  }
  config.host = doc.at("host").get<std::string>();
  if (config.host.empty()) {
    fail("'host' must not be empty");
  }
  {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    const int rc = ::getaddrinfo(config.host.c_str(), nullptr, &hints, &result);
    if (rc != 0) {
      fail("'host' is not resolvable: " + std::string(::gai_strerror(rc)));
    }
    ::freeaddrinfo(result);
  }

  if (!doc.contains("port")) {
    fail("missing required key 'port'");
  }
  config.port = static_cast<std::uint16_t>(require_int(doc, "port", 1, 65535));

  if (!doc.contains("users")) {
    fail("missing required key 'users'");
  }
  if (!doc.at("users").is_array()) {
    fail("'users' must be an array");
  }
  for (const json& entry : doc.at("users")) {
    if (!entry.is_object()) {
      fail("every entry of 'users' must be an object");
    }
    for (auto it = entry.begin(); it != entry.end(); ++it) {
      const std::string& key = it.key();
      if (key != "name" && key != "password_bcrypt" && key != "root" &&
          key != "cors_domains") {
        fail("unknown user key '" + key + "'");
      }
    }
    if (!entry.contains("name") || !entry.at("name").is_string()) {
      fail("user entry is missing string 'name'");
    }
    if (!entry.contains("password_bcrypt") || !entry.at("password_bcrypt").is_string()) {
      fail("user entry is missing string 'password_bcrypt'");
    }
    if (!entry.contains("root") || !entry.at("root").is_string()) {
      fail("user entry is missing string 'root'");
    }

    User user;
    user.name = entry.at("name").get<std::string>();
    if (user.name.empty()) {
      fail("user 'name' must not be empty");
    }
    user.password_bcrypt = entry.at("password_bcrypt").get<std::string>();
    if (!is_valid_bcrypt_hash(user.password_bcrypt, 10)) {
      fail("user '" + user.name + "': 'password_bcrypt' must be a bcrypt hash with cost >= 10");
    }
    user.root = canonical_directory(entry.at("root").get<std::string>(), user.name);
    if (entry.contains("cors_domains")) {
      parse_cors_domains(entry, user);
    }
    for (const User& existing : config.users) {
      if (existing.name == user.name) {
        fail("duplicate user name '" + user.name + "'");
      }
      if (path_within(existing.root, user.root) || path_within(user.root, existing.root)) {
        fail("user roots must not overlap: '" + existing.name + "' and '" + user.name + "'");
      }
    }
    config.users.push_back(std::move(user));
  }

  if (doc.contains("max_connections")) {
    config.max_connections = require_int(doc, "max_connections", 1, 1024);
  }
  if (doc.contains("auth_max_concurrent")) {
    config.auth_max_concurrent = require_int(doc, "auth_max_concurrent", 1, 64);
  }
  if (doc.contains("auth_backoff_base_ms")) {
    config.auth_backoff_base_ms = require_int(doc, "auth_backoff_base_ms", 1, 60000);
  }
  if (doc.contains("auth_backoff_max_ms")) {
    config.auth_backoff_max_ms = require_int(doc, "auth_backoff_max_ms", 1, 600000);
  }
  if (config.auth_backoff_max_ms < config.auth_backoff_base_ms) {
    fail("'auth_backoff_max_ms' must be >= 'auth_backoff_base_ms'");
  }

  return config;
}

Config load_config(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    fail("cannot open config file '" + path + "': " + std::strerror(errno));
  }
  std::string data;
  char buffer[4096];
  std::size_t read = 0;
  while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0) {
    if (data.size() + read > kMaxConfigBytes) {
      std::fclose(file);
      fail("config file '" + path + "' exceeds " + std::to_string(kMaxConfigBytes) + " bytes");
    }
    data.append(buffer, read);
  }
  const bool failed = std::ferror(file) != 0;
  std::fclose(file);
  if (failed) {
    fail("error while reading config file '" + path + "'");
  }
  return parse_config(data);
}

}  // namespace webdav
