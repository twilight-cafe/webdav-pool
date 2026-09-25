#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "webdav/fault.hpp"
#include "webdav/fsutil.hpp"

namespace {

namespace fs = std::filesystem;

constexpr int kTreeSymlink = webdav::kTreeSymlink;
constexpr int kTreeDepthExceeded = webdav::kTreeDepthExceeded;

class ScopedFaultHook {
 public:
  explicit ScopedFaultHook(webdav::FaultHook hook) { webdav::set_fault_hook(std::move(hook)); }
  ~ScopedFaultHook() { webdav::set_fault_hook(nullptr); }
  ScopedFaultHook(const ScopedFaultHook&) = delete;
  ScopedFaultHook& operator=(const ScopedFaultHook&) = delete;
};

std::string tmp_base() {
  static const std::string base = [] {
    const std::string dir = std::string(WEBDAV_TEST_TMPDIR) + "/fsutil";
    std::error_code ec;
    fs::create_directories(dir, ec);
    return dir;
  }();
  return base;
}

std::string fresh_dir(const std::string& name) {
  const fs::path path = fs::path(tmp_base()) / name;
  std::error_code ec;
  fs::remove_all(path, ec);
  fs::create_directories(path, ec);
  return fs::canonical(path).string();
}

void write_file(const std::string& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  out << content;
}

std::string read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

TEST(Fsutil, FdLifecycle) {
  webdav::Fd invalid;
  EXPECT_FALSE(invalid.valid());
  EXPECT_EQ(invalid.get(), -1);
  EXPECT_EQ(invalid.release(), -1);
  EXPECT_FALSE(invalid.duplicate().valid());

  const std::string path = fresh_dir("fd_lifecycle") + "/file";
  write_file(path, "data");
  int raw = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  ASSERT_GE(raw, 0);
  webdav::Fd first(raw);
  EXPECT_TRUE(first.valid());
  EXPECT_EQ(first.get(), raw);

  webdav::Fd second(std::move(first));
  EXPECT_FALSE(first.valid());
  EXPECT_EQ(second.get(), raw);

  webdav::Fd third;
  third = std::move(second);
  EXPECT_FALSE(second.valid());
  EXPECT_EQ(third.get(), raw);

  webdav::Fd duplicate = third.duplicate();
  EXPECT_TRUE(duplicate.valid());
  ASSERT_NE(duplicate.get(), third.get());
  const int duplicate_raw = duplicate.release();
  EXPECT_GE(duplicate_raw, 0);
  EXPECT_FALSE(duplicate.valid());
  ::close(duplicate_raw);
  third.reset();
  EXPECT_FALSE(third.valid());
}

TEST(Fsutil, OpenLeafRejectsInvalidParent) {
  webdav::Fd out = webdav::open_leaf(webdav::Fd{}, "x", O_RDONLY);
  EXPECT_FALSE(out.valid());
}

TEST(Fsutil, DirStreamBehaviours) {
  webdav::DirStream empty;
  EXPECT_FALSE(empty.valid());
  EXPECT_EQ(empty.fd(), -1);
  std::string name;
  struct stat info {};
  EXPECT_FALSE(empty.next(name, info));

  webdav::DirStream from_invalid(webdav::Fd{});
  EXPECT_FALSE(from_invalid.valid());

  const std::string dir = fresh_dir("dirstream");
  write_file(dir + "/child.txt", "x");
  webdav::Fd raw(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  ASSERT_TRUE(raw.valid());

  webdav::DirStream stream(std::move(raw));
  ASSERT_TRUE(stream.valid());
  EXPECT_GE(stream.fd(), 0);

  webdav::DirStream moved(std::move(stream));
  EXPECT_FALSE(stream.valid());
  ASSERT_TRUE(moved.valid());
  EXPECT_TRUE(moved.next(name, info));
  EXPECT_EQ(name, "child.txt");
  EXPECT_TRUE(S_ISREG(info.st_mode));
  EXPECT_FALSE(moved.next(name, info));

  webdav::DirStream assigned;
  assigned = std::move(moved);
  EXPECT_TRUE(assigned.valid());
  EXPECT_FALSE(moved.valid());

  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstatat") == 0 ? EACCES : 0;
    });
    webdav::DirStream stream2(
        webdav::Fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)));
    ASSERT_TRUE(stream2.valid());
    EXPECT_FALSE(stream2.next(name, info));
  }

  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fdopendir") == 0 ? EACCES : 0;
    });
    webdav::DirStream failing(
        webdav::Fd(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC)));
    EXPECT_FALSE(failing.valid());
  }
}

TEST(Fsutil, PercentCodec) {
  std::string out;
  EXPECT_TRUE(webdav::percent_decode("%41%2f%7E", out));
  EXPECT_EQ(out, "A/~");
  EXPECT_TRUE(webdav::percent_decode("plain", out));
  EXPECT_EQ(out, "plain");
  EXPECT_FALSE(webdav::percent_decode("%", out));
  EXPECT_FALSE(webdav::percent_decode("%4", out));
  EXPECT_FALSE(webdav::percent_decode("%G0", out));

  EXPECT_EQ(webdav::percent_encode("a b/中文\n"), "a%20b/%E4%B8%AD%E6%96%87%0A");
  EXPECT_EQ(webdav::percent_encode("AZaz09-._~/"), "AZaz09-._~/");
}

TEST(Fsutil, ResolvePathStatuses) {
  const std::string dir = fresh_dir("resolve");
  fs::create_directories(fs::path(dir) / "sub");
  write_file(dir + "/file.txt", "x");
  write_file(dir + "/sub/child.txt", "y");
  ASSERT_EQ(::symlink("sub", (dir + "/linkdir").c_str()), 0);
  ASSERT_EQ(::symlink("file.txt", (dir + "/linkfile").c_str()), 0);
  const webdav::Fd root = webdav::open_root_directory(dir);
  ASSERT_TRUE(root.valid());

  {
    const webdav::Target target = webdav::resolve_path(webdav::Fd{}, "/");
    EXPECT_EQ(target.status, webdav::PathStatus::kNotFound);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/");
    ASSERT_TRUE(target.ok());
    EXPECT_TRUE(target.is_root);
    EXPECT_TRUE(target.exists);
    EXPECT_TRUE(target.decoded_path == "/");
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/sub/");
    ASSERT_TRUE(target.ok());
    EXPECT_EQ(target.leaf, "sub");
    EXPECT_TRUE(target.exists);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/sub/child.txt?download=1");
    ASSERT_TRUE(target.ok());
    EXPECT_TRUE(target.exists);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "http://example/sub/child.txt#x");
    ASSERT_TRUE(target.ok());
    EXPECT_TRUE(target.exists);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "http://example");
    ASSERT_TRUE(target.ok());
    EXPECT_TRUE(target.is_root);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/missing");
    ASSERT_TRUE(target.ok());
    EXPECT_FALSE(target.exists);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/missing/child");
    EXPECT_EQ(target.status, webdav::PathStatus::kNotFound);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/file.txt/child");
    EXPECT_EQ(target.status, webdav::PathStatus::kNotDirectory);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/linkdir/child.txt");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/linkfile");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/%");
    EXPECT_EQ(target.status, webdav::PathStatus::kBadRequest);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/%252e%252e");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/%00");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, std::string(4097, 'a'));
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    const webdav::Target target = webdav::resolve_path(root, "/a/./b");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }

  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstat") == 0 ? EACCES : 0;
    });
    const webdav::Target target = webdav::resolve_path(root, "/sub/child.txt");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstat") == 0 ? EACCES : 0;
    });
    const webdav::Target target = webdav::resolve_path(root, "/");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? EACCES : 0;
    });
    const webdav::Target target = webdav::resolve_path(root, "/sub/child.txt");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? ENOENT : 0;
    });
    const webdav::Target target = webdav::resolve_path(root, "/sub/child.txt");
    EXPECT_EQ(target.status, webdav::PathStatus::kNotFound);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstatat") == 0 ? EACCES : 0;
    });
    const webdav::Target target = webdav::resolve_path(root, "/sub/child.txt");
    EXPECT_EQ(target.status, webdav::PathStatus::kForbidden);
  }
}

TEST(Fsutil, RemoveTreeErrors) {
  const std::string dir = fresh_dir("remove_tree");
  write_file(dir + "/file.txt", "x");
  fs::create_directories(fs::path(dir) / "empty");
  fs::create_directories(fs::path(dir) / "tree/sub");
  write_file(dir + "/tree/sub/deep.txt", "deep");
  ASSERT_EQ(::symlink("file.txt", (dir + "/link").c_str()), 0);

  const webdav::Fd root = webdav::open_root_directory(dir);
  ASSERT_TRUE(root.valid());

  EXPECT_EQ(webdav::remove_tree(root, "file.txt"), 0);
  EXPECT_EQ(webdav::remove_tree(root, "empty"), 0);
  EXPECT_EQ(webdav::remove_tree(root, "tree"), 0);
  EXPECT_EQ(webdav::remove_tree(root, "link"), kTreeSymlink);
  EXPECT_EQ(webdav::remove_tree(root, "missing", webdav::kMaxTreeDepth + 1), kTreeDepthExceeded);

  write_file(dir + "/file.txt", "x");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstatat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::remove_tree(root, "file.txt"), EACCES);
  }

  fs::create_directories(fs::path(dir) / "d1");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::remove_tree(root, "d1"), EACCES);
  }

  fs::create_directories(fs::path(dir) / "d2");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fdopendir") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::remove_tree(root, "d2"), EACCES);
  }

  fs::create_directories(fs::path(dir) / "d3");
  write_file(dir + "/d3/child", "x");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::remove_tree(root, "d3"), EACCES);
  }

  fs::create_directories(fs::path(dir) / "d4");
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "unlinkat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::remove_tree(root, "d4"), EACCES);
  }
}

TEST(Fsutil, CopyTreeErrors) {
  const std::string dir = fresh_dir("copy_tree");
  write_file(dir + "/src.txt", "copy me");
  fs::create_directories(fs::path(dir) / "srcdir/sub");
  write_file(dir + "/srcdir/sub/deep.txt", "deep");
  write_file(dir + "/srcdir/top.txt", "top");

  const webdav::Fd root = webdav::open_root_directory(dir);
  ASSERT_TRUE(root.valid());

  EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "dst.txt", true), 0);
  EXPECT_EQ(read_file(dir + "/dst.txt"), "copy me");

  EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "shallow", false), 0);
  EXPECT_TRUE(fs::is_directory(fs::path(dir) / "shallow"));
  EXPECT_FALSE(fs::exists(fs::path(dir) / "shallow/sub"));

  EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "deepcopy", true), 0);
  EXPECT_EQ(read_file(dir + "/deepcopy/sub/deep.txt"), "deep");

  EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "depth", true, webdav::kMaxTreeDepth + 1),
            kTreeDepthExceeded);
  ASSERT_EQ(::symlink("src.txt", (dir + "/dangling").c_str()), 0);
  EXPECT_EQ(webdav::copy_tree(root, "dangling", root, "copied_link", true), kTreeSymlink);
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fstatat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "statfail", true), EACCES);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "openfail", true), EACCES);
  }
  {
    int opens = 0;
    ScopedFaultHook guard([&opens](const char* operation) {
      if (std::strcmp(operation, "openat") != 0) {
        return 0;
      }
      ++opens;
      return opens == 2 ? EEXIST : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "dstfail", true), EEXIST);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "read") == 0 ? EIO : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "readfail", true), EIO);
  }
  {
    bool first = true;
    ScopedFaultHook guard([&first](const char* operation) {
      if (std::strcmp(operation, "read") != 0 || !first) {
        return 0;
      }
      first = false;
      return EINTR;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "readintr", true), 0);
    EXPECT_EQ(read_file(dir + "/readintr"), "copy me");
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "write") == 0 ? EIO : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "writefail", true), EIO);
  }
  {
    bool first = true;
    ScopedFaultHook guard([&first](const char* operation) {
      if (std::strcmp(operation, "write") != 0 || !first) {
        return 0;
      }
      first = false;
      return EINTR;
    });
    EXPECT_EQ(webdav::copy_tree(root, "src.txt", root, "writeintr", true), 0);
    EXPECT_EQ(read_file(dir + "/writeintr"), "copy me");
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "mkdirat") == 0 ? EEXIST : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "mkdirfail", true), EEXIST);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "openat") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "sourceopenfail", true), EACCES);
  }
  {
    int opens = 0;
    ScopedFaultHook guard([&opens](const char* operation) {
      if (std::strcmp(operation, "openat") != 0) {
        return 0;
      }
      ++opens;
      return opens == 2 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "destopenfail", true), EACCES);
  }
  {
    ScopedFaultHook guard([](const char* operation) {
      return std::strcmp(operation, "fdopendir") == 0 ? EACCES : 0;
    });
    EXPECT_EQ(webdav::copy_tree(root, "srcdir", root, "streamfail", true), EACCES);
  }
  {
    fs::create_directories(fs::path(dir) / "withlink");
    ASSERT_EQ(::symlink("src.txt", (dir + "/withlink/link").c_str()), 0);
    const int rc = webdav::copy_tree(root, "withlink", root, "linkcopy", true);
    EXPECT_EQ(rc, kTreeSymlink);
  }
}
