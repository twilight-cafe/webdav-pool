#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "webdav/cli.hpp"

namespace {

namespace fs = std::filesystem;

constexpr const char* kHash =
    "$2b$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c";

struct Flags {
  bool bound{false};
  bool served{false};
  bool fail_bind{false};
};

class FakeServer : public webdav::ServerLike {
 public:
  explicit FakeServer(std::shared_ptr<Flags> flags) : flags_(std::move(flags)) {}

  void bind() override {
    flags_->bound = true;
    if (flags_->fail_bind) {
      throw std::runtime_error("bind failed");
    }
  }
  std::uint16_t port() const override { return 4321; }
  void serve() override { flags_->served = true; }
  void stop() override {}

 private:
  std::shared_ptr<Flags> flags_;
};

webdav::ServerFactory fake_factory(const std::shared_ptr<Flags>& flags) {
  return [flags](const webdav::Config&, std::shared_ptr<webdav::Authenticator>) {
    return std::unique_ptr<webdav::ServerLike>(std::make_unique<FakeServer>(flags));
  };
}

int run(const std::vector<std::string>& args, const webdav::ServerFactory& factory) {
  std::vector<std::string> owned;
  owned.emplace_back("webdavd");
  owned.insert(owned.end(), args.begin(), args.end());
  std::vector<char*> argv;
  argv.reserve(owned.size());
  for (std::string& value : owned) {
    argv.push_back(value.data());
  }
  return webdav::run_cli(static_cast<int>(argv.size()), argv.data(), factory);
}

std::string write_config(const std::string& name) {
  const fs::path base = fs::path(WEBDAV_TEST_TMPDIR) / "cli";
  const fs::path root = base / (name + "_root");
  std::error_code ec;
  fs::create_directories(root, ec);
  const fs::path path = base / (name + ".json");
  std::ofstream out(path);
  out << "{\"host\":\"127.0.0.1\",\"port\":8080,\"users\":[{\"name\":\"alice\","
      << "\"password_bcrypt\":\"" << kHash << "\",\"root\":\"" << fs::canonical(root).string()
      << "\"}]}";
  out.close();
  return path.string();
}

}  // namespace

TEST(Cli, VersionExitsZero) {
  auto flags = std::make_shared<Flags>();
  EXPECT_EQ(run({"--version"}, fake_factory(flags)), 0);
  EXPECT_FALSE(flags->bound);
}

TEST(Cli, HelpVariantsExitZero) {
  auto flags = std::make_shared<Flags>();
  EXPECT_EQ(run({"--help"}, fake_factory(flags)), 0);
  EXPECT_EQ(run({"-h"}, fake_factory(flags)), 0);
}

TEST(Cli, RejectsUnknownArgument) {
  auto flags = std::make_shared<Flags>();
  EXPECT_EQ(run({"--bogus"}, fake_factory(flags)), 2);
}

TEST(Cli, RejectsConfigWithoutPath) {
  auto flags = std::make_shared<Flags>();
  EXPECT_EQ(run({"--config"}, fake_factory(flags)), 2);
}

TEST(Cli, ReportsConfigurationError) {
  auto flags = std::make_shared<Flags>();
  const std::string missing = (fs::path(WEBDAV_TEST_TMPDIR) / "cli" / "absent.json").string();
  EXPECT_EQ(run({"--config", missing}, fake_factory(flags)), 1);
  EXPECT_FALSE(flags->bound);
}

TEST(Cli, ServesWithValidConfiguration) {
  auto flags = std::make_shared<Flags>();
  const std::string config = write_config("good");
  EXPECT_EQ(run({"--config", config}, fake_factory(flags)), 0);
  EXPECT_TRUE(flags->bound);
  EXPECT_TRUE(flags->served);
}

TEST(Cli, ReportsBindFailure) {
  auto flags = std::make_shared<Flags>();
  flags->fail_bind = true;
  const std::string config = write_config("bindfail");
  EXPECT_EQ(run({"--config", config}, fake_factory(flags)), 1);
  EXPECT_TRUE(flags->bound);
  EXPECT_FALSE(flags->served);
}

namespace {

int reserve_port() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return -1;
  }
  sockaddr_in address {};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::close(fd);
    return -1;
  }
  socklen_t length = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
    ::close(fd);
    return -1;
  }
  return fd;
}

std::string write_config_with_port(const std::string& name, int port) {
  const fs::path base = fs::path(WEBDAV_TEST_TMPDIR) / "cli";
  const fs::path root = base / (name + "_root");
  std::error_code ec;
  fs::create_directories(root, ec);
  const fs::path path = base / (name + ".json");
  std::ofstream out(path);
  out << "{\"host\":\"127.0.0.1\",\"port\":" << port
      << ",\"users\":[{\"name\":\"alice\",\"password_bcrypt\":\"" << kHash
      << "\",\"root\":\"" << fs::canonical(root).string() << "\"}]}";
  out.close();
  return path.string();
}

int run_default(const std::vector<std::string>& args) {
  std::vector<std::string> owned;
  owned.emplace_back("webdavd");
  owned.insert(owned.end(), args.begin(), args.end());
  std::vector<char*> argv;
  argv.reserve(owned.size());
  for (std::string& value : owned) {
    argv.push_back(value.data());
  }
  return webdav::run_cli(static_cast<int>(argv.size()), argv.data());
}

}  // namespace

TEST(Cli, DefaultFactoryExercisesRealServerBindFailure) {
  const int fd = reserve_port();
  ASSERT_GE(fd, 0);
  sockaddr_in address {};
  socklen_t length = sizeof(address);
  ASSERT_EQ(::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length), 0);
  const int port = ntohs(address.sin_port);
  const std::string config = write_config_with_port("default_bind_failure", port);
  const int rc = run_default({"--config", config});
  ::close(fd);
  EXPECT_EQ(rc, 1);
}
