#include <gtest/gtest.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "webdav/config.hpp"
#include "webdav/fault.hpp"

namespace {

namespace fs = std::filesystem;

constexpr const char* kHash =
    "$2b$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c";

std::string tmp_root() {
  static const std::string root = [] {
    const std::string dir = std::string(WEBDAV_TEST_TMPDIR) + "/config";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
  }();
  return root;
}

std::string make_dir(const std::string& name) {
  const fs::path path = fs::path(tmp_root()) / name;
  std::error_code ec;
  fs::create_directories(path, ec);
  return fs::canonical(path).string();
}

std::string user_entry(const std::string& name, const std::string& hash, const std::string& root) {
  return "{\"name\":\"" + name + "\",\"password_bcrypt\":\"" + hash + "\",\"root\":\"" + root +
         "\"}";
}

std::string config_json(const std::string& users, const std::string& extra = "") {
  return "{\"host\":\"127.0.0.1\",\"port\":8080,\"users\":[" + users + "]" + extra + "}";
}

std::string user_entry_with_cors(const std::string& name, const std::string& hash,
                                 const std::string& root, const std::string& cors_json) {
  return "{\"name\":\"" + name + "\",\"password_bcrypt\":\"" + hash + "\",\"root\":\"" +
         root + "\",\"cors_domains\":" + cors_json + "}";
}

void expect_error(const std::string& json, const std::string& needle) {
  try {
    (void)webdav::parse_config(json);
    FAIL() << "expected ConfigError for: " << json;
  } catch (const webdav::ConfigError& error) {
    EXPECT_NE(std::string(error.what()).find(needle), std::string::npos)
        << "message was: " << error.what();
  }
}

}  // namespace

TEST(Config, ParsesValidConfiguration) {
  const std::string alice = make_dir("ok_alice");
  const std::string bob = make_dir("ok_bob");
  const webdav::Config config = webdav::parse_config(
      config_json(user_entry("alice", kHash, alice) + "," + user_entry("bob", kHash, bob)));
  ASSERT_EQ(config.users.size(), 2u);
  EXPECT_EQ(config.host, "127.0.0.1");
  EXPECT_EQ(config.port, 8080);
  EXPECT_EQ(config.users[0].name, "alice");
  EXPECT_EQ(config.users[0].root, alice);
  EXPECT_FALSE(config.users[0].cors_configured);
  EXPECT_TRUE(config.users[0].cors_domains.empty());
  EXPECT_EQ(config.max_connections, 16);
  EXPECT_EQ(config.auth_max_concurrent, 2);
  EXPECT_EQ(config.auth_backoff_base_ms, 250);
  EXPECT_EQ(config.auth_backoff_max_ms, 5000);
}

TEST(Config, UserNameNeedNotBeAnOsAccount) {
  // `name` is an application-level WebDAV login. The parser must not call
  // getpwnam()/initgroups() or require a matching system account.
  const std::string root = make_dir("app_level_user");
  const std::string name = "webdav-no-such-os-account-314159";
  const webdav::Config config = webdav::parse_config(config_json(user_entry(name, kHash, root)));
  ASSERT_EQ(config.users.size(), 1u);
  EXPECT_EQ(config.users[0].name, name);
  EXPECT_EQ(config.users[0].root, root);
}

TEST(Config, AcceptsEmptyUserList) {
  const webdav::Config config = webdav::parse_config(config_json(""));
  EXPECT_TRUE(config.users.empty());
}

TEST(Config, ParsesOptionalTuningKeys) {
  const std::string alice = make_dir("tuned_alice");
  const webdav::Config config = webdav::parse_config(
      config_json(user_entry("alice", kHash, alice),
                  ",\"max_connections\":32,\"auth_max_concurrent\":4,"
                  "\"auth_backoff_base_ms\":100,\"auth_backoff_max_ms\":2000"));
  EXPECT_EQ(config.max_connections, 32);
  EXPECT_EQ(config.auth_max_concurrent, 4);
  EXPECT_EQ(config.auth_backoff_base_ms, 100);
  EXPECT_EQ(config.auth_backoff_max_ms, 2000);
}

TEST(Config, ParsesCorsDomains) {
  const std::string alice = make_dir("cors_alice");
  const std::string entry = user_entry_with_cors(
      "alice", kHash, alice,
      "[\"https://app.example.com\",\"*.internal.example\",\"api.example.com:8443\"]");
  const webdav::Config config = webdav::parse_config(config_json(entry));
  ASSERT_EQ(config.users.size(), 1u);
  const webdav::User& user = config.users[0];
  EXPECT_TRUE(user.cors_configured);
  ASSERT_EQ(user.cors_domains.size(), 3u);
  EXPECT_EQ(user.cors_domains[0], "https://app.example.com");
  EXPECT_EQ(user.cors_domains[1], "*.internal.example");
  EXPECT_EQ(user.cors_domains[2], "api.example.com:8443");
  EXPECT_TRUE(webdav::cors_allows_origin(user, "https://app.example.com"));
  EXPECT_TRUE(webdav::cors_allows_origin(user, "HTTPS://APP.EXAMPLE.COM"));
  EXPECT_TRUE(webdav::cors_allows_origin(user, "https://x.internal.example"));
  EXPECT_TRUE(webdav::cors_allows_origin(user, "https://api.example.com:8443"));
  EXPECT_FALSE(webdav::cors_allows_origin(user, "https://api.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(user, "https://evil.example"));
}

TEST(Config, EmptyCorsDomainsDeniesEveryOrigin) {
  const std::string alice = make_dir("cors_empty_alice");
  const std::string entry = user_entry_with_cors("alice", kHash, alice, "[]");
  const webdav::Config config = webdav::parse_config(config_json(entry));
  ASSERT_EQ(config.users.size(), 1u);
  const webdav::User& user = config.users[0];
  EXPECT_TRUE(user.cors_configured);
  EXPECT_TRUE(user.cors_domains.empty());
  EXPECT_FALSE(webdav::cors_allows_origin(user, "https://app.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(user, ""));
}

TEST(Config, CorsMatchingSemantics) {
  const webdav::User no_policy{"alice", "hash", "/tmp"};
  EXPECT_FALSE(webdav::cors_allows_origin(no_policy, "https://anything.example"));
  EXPECT_FALSE(webdav::cors_allows_origin(no_policy, ""));

  const webdav::User implicit_policy{"alice", "hash", "/tmp", {"app.example.com"}, false};
  EXPECT_TRUE(webdav::cors_allows_origin(implicit_policy, "https://app.example.com"));

  const webdav::User full_origin{"alice", "hash", "/tmp", {"https://app.example.com/"}};
  EXPECT_TRUE(webdav::cors_allows_origin(full_origin, "https://app.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(full_origin, "http://app.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(full_origin, "https://app.example.com/"));

  const webdav::User empty_rule{"alice", "hash", "/tmp", {""}};
  EXPECT_FALSE(webdav::cors_allows_origin(empty_rule, "https://app.example.com"));

  const webdav::User bare{"alice", "hash", "/tmp", {"app.example.com"}};
  EXPECT_TRUE(webdav::cors_allows_origin(bare, "https://app.example.com:8443"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "https://other.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "app.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "://app.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "https://"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "https://app.example.com/path"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "https://[::1"));
  EXPECT_FALSE(webdav::cors_allows_origin(bare, "https://:8080"));

  const webdav::User wildcard{"alice", "hash", "/tmp", {"*.example.com"}};
  EXPECT_TRUE(webdav::cors_allows_origin(wildcard, "https://a.example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(wildcard, "https://example.com"));
  EXPECT_FALSE(webdav::cors_allows_origin(wildcard, "https://badexample.com"));

  const webdav::User port{"alice", "hash", "/tmp", {"app.example.com:8443"}};
  EXPECT_TRUE(webdav::cors_allows_origin(port, "https://app.example.com:8443"));
  EXPECT_FALSE(webdav::cors_allows_origin(port, "https://app.example.com:9999"));

  const webdav::User ipv6{"alice", "hash", "/tmp", {"[::1]"}};
  EXPECT_TRUE(webdav::cors_allows_origin(ipv6, "http://[::1]:8080"));
  EXPECT_FALSE(webdav::cors_allows_origin(ipv6, "http://[::1"));

  const webdav::User ipv6_port{"alice", "hash", "/tmp", {"[::1]:8080"}};
  EXPECT_TRUE(webdav::cors_allows_origin(ipv6_port, "http://[::1]:8080"));
  EXPECT_FALSE(webdav::cors_allows_origin(ipv6_port, "http://[::1]:9090"));

  const webdav::User whitespace{"alice", "hash", "/tmp", {"  app.example.com\t"}};
  EXPECT_TRUE(webdav::cors_allows_origin(whitespace, "https://app.example.com"));
}

TEST(Config, RejectsInvalidJson) {
  expect_error("{not json", "invalid JSON syntax");
}

TEST(Config, RejectsNonObjectTopLevel) {
  expect_error("[1,2,3]", "top-level JSON value must be an object");
}

TEST(Config, RejectsUnknownTopLevelKey) {
  expect_error("{\"host\":\"127.0.0.1\",\"port\":1,\"users\":[],\"nope\":1}", "unknown configuration key");
}

TEST(Config, RequiresHost) {
  expect_error("{\"port\":1,\"users\":[]}", "missing required key 'host'");
  expect_error("{\"host\":5,\"port\":1,\"users\":[]}", "'host' must be a string");
  expect_error("{\"host\":\"\",\"port\":1,\"users\":[]}", "'host' must not be empty");
}

TEST(Config, RejectsUnresolvableHost) {
  expect_error("{\"host\":\"no.such.host.invalid\",\"port\":1,\"users\":[]}",
               "'host' is not resolvable");
}

TEST(Config, RequiresPort) {
  expect_error("{\"host\":\"127.0.0.1\",\"users\":[]}", "missing required key 'port'");
  expect_error("{\"host\":\"127.0.0.1\",\"port\":\"x\",\"users\":[]}", "'port' must be an integer");
  expect_error("{\"host\":\"127.0.0.1\",\"port\":0,\"users\":[]}", "'port' must be in");
  expect_error("{\"host\":\"127.0.0.1\",\"port\":70000,\"users\":[]}", "'port' must be in");
}

TEST(Config, RequiresUsers) {
  expect_error("{\"host\":\"127.0.0.1\",\"port\":1}", "missing required key 'users'");
  expect_error("{\"host\":\"127.0.0.1\",\"port\":1,\"users\":{}}", "'users' must be an array");
  expect_error("{\"host\":\"127.0.0.1\",\"port\":1,\"users\":[7]}",
               "every entry of 'users' must be an object");
}

TEST(Config, ValidatesUserFields) {
  expect_error(config_json("{\"password_bcrypt\":\"" + std::string(kHash) +
                           "\",\"root\":\"/tmp\"}"),
               "missing string 'name'");
  expect_error(config_json("{\"name\":\"alice\",\"root\":\"/tmp\"}"),
               "missing string 'password_bcrypt'");
  expect_error(config_json("{\"name\":\"alice\",\"password_bcrypt\":\"" + std::string(kHash) + "\"}"),
               "missing string 'root'");
  expect_error(config_json("{\"name\":\"\",\"password_bcrypt\":\"" + std::string(kHash) +
                           "\",\"root\":\"/tmp\"}"),
               "user 'name' must not be empty");
}

TEST(Config, RejectsUnknownUserKey) {
  expect_error(config_json("{\"name\":\"a\",\"password_bcrypt\":\"" + std::string(kHash) +
                           "\",\"root\":\"/tmp\",\"extra\":1}"),
               "unknown user key 'extra'");
}

TEST(Config, RejectsInvalidCorsDomains) {
  const std::string alice = make_dir("cors_invalid_alice");
  expect_error(config_json(user_entry_with_cors("alice", kHash, alice, "\"x\"")),
               "'cors_domains' must be an array");
  expect_error(config_json(user_entry_with_cors("alice", kHash, alice, "[1]")),
               "'cors_domains' entries must be strings");
  expect_error(config_json(user_entry_with_cors("alice", kHash, alice, "[\"\"]")),
               "'cors_domains' entries must not be empty");
  expect_error(config_json(user_entry_with_cors("alice", kHash, alice, "[\"line\\nfeed\"]")),
               "must not contain control characters");
}

TEST(Config, RejectsBadBcrypt) {
  const std::string alice = make_dir("badhash_alice");
  expect_error(config_json(user_entry("alice", "plaintext", alice)), "bcrypt hash with cost >= 10");
  expect_error(config_json(user_entry(
                   "alice", "$2b$09$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", alice)),
               "bcrypt hash with cost >= 10");
}

TEST(Config, ValidatesRootPath) {
  expect_error(config_json(user_entry("alice", kHash, "relative/path")),
               "'root' must be an absolute path");
  expect_error(config_json(user_entry("alice", kHash, "")), "'root' must not be empty");
  expect_error(config_json(user_entry("alice", kHash, "/definitely/not/here")),
               "'root' is not accessible");

  const fs::path file = fs::path(tmp_root()) / "a_file";
  {
    std::ofstream out(file, std::ios::binary);
    out << "x";
  }
  expect_error(config_json(user_entry("alice", kHash, file.string())),
               "'root' is not a directory");
}

TEST(Config, RejectsDuplicateUserNames) {
  const std::string first = make_dir("dup_a");
  const std::string second = make_dir("dup_b");
  expect_error(config_json(user_entry("alice", kHash, first) + "," +
                           user_entry("alice", kHash, second)),
               "duplicate user name 'alice'");
}

TEST(Config, RejectsNestedRoots) {
  const std::string parent = make_dir("nest_parent");
  const std::string child = make_dir("nest_parent/child");
  expect_error(config_json(user_entry("alice", kHash, parent) + "," +
                           user_entry("bob", kHash, child)),
               "must not overlap");
  expect_error(config_json(user_entry("alice", kHash, child) + "," +
                           user_entry("bob", kHash, parent)),
               "must not overlap");
}

TEST(Config, RejectsEqualRoots) {
  const std::string shared = make_dir("nest_shared");
  expect_error(config_json(user_entry("alice", kHash, shared) + "," +
                           user_entry("bob", kHash, shared)),
               "must not overlap");
}

TEST(Config, ValidatesOptionalRanges) {
  expect_error(config_json("", ",\"max_connections\":0"), "'max_connections' must be in");
  expect_error(config_json("", ",\"max_connections\":\"x\""), "'max_connections' must be an integer");
  expect_error(config_json("", ",\"auth_max_concurrent\":0"), "'auth_max_concurrent' must be in");
  expect_error(config_json("", ",\"auth_backoff_base_ms\":0"), "'auth_backoff_base_ms' must be in");
  expect_error(config_json("", ",\"auth_backoff_max_ms\":0"), "'auth_backoff_max_ms' must be in");
  expect_error(config_json("", ",\"auth_backoff_max_ms\":50,\"auth_backoff_base_ms\":100"),
               "must be >= 'auth_backoff_base_ms'");
}

TEST(Config, LoadsFileFromDisk) {
  const std::string alice = make_dir("file_alice");
  const fs::path path = fs::path(tmp_root()) / "good.json";
  {
    std::ofstream out(path);
    out << config_json(user_entry("alice", kHash, alice));
  }
  const webdav::Config config = webdav::load_config(path.string());
  ASSERT_EQ(config.users.size(), 1u);
  EXPECT_EQ(config.users[0].name, "alice");
}

TEST(Config, ReportsMissingFile) {
  const fs::path missing = fs::path(tmp_root()) / "does-not-exist.json";
  EXPECT_THROW(webdav::load_config(missing.string()), webdav::ConfigError);
}

TEST(Config, RejectsOversizedFile) {
  const fs::path path = fs::path(tmp_root()) / "huge.json";
  {
    std::ofstream out(path, std::ios::binary);
    const std::string filler(4u * 1024u * 1024u + 1, ' ');
    out << filler;
  }
  try {
    (void)webdav::load_config(path.string());
    FAIL() << "expected ConfigError";
  } catch (const webdav::ConfigError& error) {
    EXPECT_NE(std::string(error.what()).find("exceeds"), std::string::npos);
  }
}

TEST(Config, ReportsStatFailureDuringRootValidation) {
  const std::string alice = make_dir("stat_alice");
  webdav::set_fault_hook([](const char* operation) {
    return std::strcmp(operation, "stat") == 0 ? EACCES : 0;
  });
  try {
    (void)webdav::parse_config(config_json(user_entry("alice", kHash, alice)));
    FAIL() << "expected ConfigError";
  } catch (const webdav::ConfigError& error) {
    EXPECT_NE(std::string(error.what()).find("cannot stat 'root'"), std::string::npos);
  }
  webdav::set_fault_hook(nullptr);
}

TEST(Config, RejectsRootThatIsParentOfEveryOtherRoot) {
  const std::string child = make_dir("root_parent_child");
  expect_error(config_json(user_entry("root", kHash, "/") + "," +
                           user_entry("alice", kHash, child)),
               "must not overlap");
}

TEST(Config, ReportsReadFailure) {
  const std::string directory = make_dir("read_failure_directory");
  try {
    (void)webdav::load_config(directory);
    FAIL() << "expected ConfigError";
  } catch (const webdav::ConfigError& error) {
    EXPECT_NE(std::string(error.what()).find("error while reading config file"),
              std::string::npos);
  }
}
