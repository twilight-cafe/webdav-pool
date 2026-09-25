#include <gtest/gtest.h>

#include <cerrno>
#include <ctime>
#include <cstring>

#include "webdav/fault.hpp"

namespace {

class ScopedFaultHook {
 public:
  explicit ScopedFaultHook(webdav::FaultHook hook) { webdav::set_fault_hook(std::move(hook)); }
  ~ScopedFaultHook() { webdav::set_fault_hook(nullptr); }

  ScopedFaultHook(const ScopedFaultHook&) = delete;
  ScopedFaultHook& operator=(const ScopedFaultHook&) = delete;
};

}  // namespace

TEST(FaultTest, ClearHookPassesThrough) {
  ScopedFaultHook guard([](const char*) { return 0; });
  EXPECT_EQ(webdav::fault_inject("anything"), 0);
}

TEST(FaultTest, EveryWrapperPropagatesInjectedErrno) {
  ScopedFaultHook guard([](const char*) { return EACCES; });

  struct stat info {};
  std::time_t now = 0;
  std::tm tm_value {};
  crypt_data crypt_value {};

  EXPECT_EQ(webdav::fs_stat(".", &info), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_open(".", O_RDONLY, 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_openat(-1, ".", O_RDONLY, 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_fstat(-1, &info), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_fstatat(-1, ".", &info, 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_unlinkat(-1, "x", 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_mkdirat(-1, "x", 0700), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_renameat(-1, "x", -1, "y"), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_read(-1, &info, 1), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_write(-1, &info, 1), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_pread(-1, &info, 1, 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_fchmod(-1, 0600), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_fcntl(-1, F_GETFD, 0), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_close(-1), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_fdopendir(-1), nullptr);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_readdir(nullptr), nullptr);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_closedir(nullptr), -1);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_gmtime_r(&now, &tm_value), nullptr);
  EXPECT_EQ(errno, EACCES);
  EXPECT_EQ(webdav::fs_crypt_r("key", "salt", &crypt_value), nullptr);
  EXPECT_EQ(errno, EACCES);
}
