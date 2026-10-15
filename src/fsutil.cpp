#include "webdav/fsutil.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "webdav/fault.hpp"

namespace webdav {

namespace {

constexpr std::size_t kMaxRequestPath = 4096;
constexpr std::size_t kCopyBufferSize = 16 * 1024;

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

Fd openat_path(const Fd& dir, const std::string& name) {
  return Fd{fs_openat(dir.get(), name.c_str(), O_PATH | O_NOFOLLOW | O_CLOEXEC, 0)};
}

// Decoded path split into segments, with the trailing slash recorded.
struct SplitPath {
  std::vector<std::string> segments;
  bool trailing_slash{false};
};

bool split_segments(const std::string& decoded, SplitPath& out) {
  std::string_view rest(decoded);
  rest.remove_prefix(1);  // caller checked the leading '/'
  if (!rest.empty() && rest.back() == '/') {
    out.trailing_slash = true;
    rest.remove_suffix(1);
  }
  std::size_t start = 0;
  while (start <= rest.size() && !rest.empty()) {
    const std::size_t slash = rest.find('/', start);
    const std::size_t end = slash == std::string_view::npos ? rest.size() : slash;
    const std::string_view segment = rest.substr(start, end - start);
    if (segment.empty() || segment == "." || segment == "..") {
      return false;
    }
    out.segments.emplace_back(segment);
    if (slash == std::string_view::npos) {
      break;
    }
    start = slash + 1;
  }
  return true;
}

}  // namespace

Fd::~Fd() { reset(); }

Fd::Fd(Fd&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }

Fd& Fd::operator=(Fd&& other) noexcept {
  if (this != &other) {
    reset();
    fd_ = other.fd_;
    other.fd_ = -1;
  }
  return *this;
}

int Fd::release() noexcept {
  const int fd = fd_;
  fd_ = -1;
  return fd;
}

void Fd::reset(int fd) noexcept {
  if (fd_ >= 0) {
    fs_close(fd_);
  }
  fd_ = fd;
}

Fd Fd::duplicate() const {
  if (fd_ < 0) {
    return Fd{};
  }
  return Fd{fs_fcntl(fd_, F_DUPFD_CLOEXEC, 3)};
}

DirStream::DirStream(Fd dir) {
  const int raw = dir.release();
  if (raw < 0) {
    return;
  }
  dir_ = fs_fdopendir(raw);
  if (dir_ == nullptr) {
    fs_close(raw);
  }
}

DirStream::~DirStream() {
  if (dir_ != nullptr) {
    fs_closedir(dir_);
  }
}

DirStream::DirStream(DirStream&& other) noexcept : dir_(other.dir_) { other.dir_ = nullptr; }

DirStream& DirStream::operator=(DirStream&& other) noexcept {
  if (this != &other) {
    if (dir_ != nullptr) {
      fs_closedir(dir_);
    }
    dir_ = other.dir_;
    other.dir_ = nullptr;
  }
  return *this;
}

int DirStream::fd() const noexcept { return dir_ != nullptr ? ::dirfd(dir_) : -1; }

bool DirStream::next(std::string& name, struct stat& info) {
  if (dir_ == nullptr) {
    return false;
  }
  for (;;) {
    errno = 0;
    struct dirent* entry = fs_readdir(dir_);
    if (entry == nullptr) {
      return false;
    }
    const char* raw = entry->d_name;
    if (raw[0] == '.' && (raw[1] == '\0' || (raw[1] == '.' && raw[2] == '\0'))) {
      continue;
    }
    if (fs_fstatat(::dirfd(dir_), raw, &info, AT_SYMLINK_NOFOLLOW) != 0) {
      continue;  // entry disappeared between readdir and stat
    }
    name.assign(raw);
    return true;
  }
}

bool percent_decode(std::string_view input, std::string& output) {
  output.clear();
  output.reserve(input.size());
  for (std::size_t i = 0; i < input.size(); ++i) {
    if (input[i] != '%') {
      output.push_back(input[i]);
      continue;
    }
    if (i + 2 >= input.size()) {
      return false;
    }
    const int high = hex_value(input[i + 1]);
    const int low = hex_value(input[i + 2]);
    if (high < 0 || low < 0) {
      return false;
    }
    output.push_back(static_cast<char>((high << 4) | low));
    i += 2;
  }
  return true;
}

std::string percent_encode(std::string_view input) {
  static constexpr char kHex[] = "0123456789ABCDEF";
  std::string output;
  output.reserve(input.size());
  for (const char c : input) {
    const auto byte = static_cast<unsigned char>(c);
    const bool unreserved = (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
                            (byte >= '0' && byte <= '9') || byte == '-' || byte == '.' ||
                            byte == '_' || byte == '~' || byte == '/';
    if (unreserved) {
      output.push_back(c);
    } else {
      output.push_back('%');
      output.push_back(kHex[byte >> 4]);
      output.push_back(kHex[byte & 0x0F]);
    }
  }
  return output;
}  // LCOV_EXCL_LINE

Fd open_root_directory(const std::string& path) {
  return Fd{fs_open(path.c_str(), O_PATH | O_DIRECTORY | O_CLOEXEC, 0)};
}

Fd open_leaf(const Fd& parent, const std::string& leaf, int flags, mode_t mode) {
  if (!parent.valid()) {
    return Fd{};
  }
  return Fd{fs_openat(parent.get(), leaf.c_str(), flags | O_NOFOLLOW | O_CLOEXEC, mode)};
}

Target resolve_path(const Fd& root, const std::string& request_target) {
  Target target;

  std::string path = request_target;
  const std::size_t cut = path.find_first_of("?#");
  if (cut != std::string::npos) {
    path.resize(cut);
  }

  // Absolute-form targets ("http://host/path") are reduced to their path.
  const std::size_t scheme = path.find("://");
  if (scheme != std::string::npos) {
    const std::size_t slash = path.find('/', scheme + 3);
    path = slash == std::string::npos ? std::string("/") : path.substr(slash);
  }

  // A second encoding pass would let "%252e%252e%252f" look like a plain name.
  if (path.find("%25") != std::string::npos || path.find("%2F") != std::string::npos ||
      path.find("%2f") != std::string::npos) {
    target.status = PathStatus::kForbidden;
    return target;
  }

  std::string decoded;
  if (!percent_decode(path, decoded)) {
    target.status = PathStatus::kBadRequest;
    return target;
  }
  if (decoded.find('\0') != std::string::npos) {
    target.status = PathStatus::kForbidden;
    return target;
  }
  if (decoded.size() > kMaxRequestPath || decoded.empty() || decoded[0] != '/') {
    target.status = PathStatus::kForbidden;
    return target;
  }

  SplitPath split;
  if (!split_segments(decoded, split)) {
    target.status = PathStatus::kForbidden;
    return target;
  }

  target.decoded_path = "/";
  for (const std::string& segment : split.segments) {
    if (target.decoded_path.size() > 1) {
      target.decoded_path.push_back('/');
    }
    target.decoded_path.append(segment);
  }

  Fd current = root.duplicate();
  if (!current.valid()) {
    target.status = PathStatus::kNotFound;
    return target;
  }

  for (std::size_t i = 0; i + 1 < split.segments.size(); ++i) {
    Fd next = openat_path(current, split.segments[i]);
    if (!next.valid()) {
      target.status = errno == ENOENT ? PathStatus::kNotFound : PathStatus::kForbidden;
      return target;
    }
    struct stat info {};
    if (fs_fstat(next.get(), &info) != 0) {
      target.status = PathStatus::kForbidden;
      return target;
    }
    if (S_ISLNK(info.st_mode)) {
      target.status = PathStatus::kForbidden;
      return target;
    }
    if (!S_ISDIR(info.st_mode)) {
      target.status = PathStatus::kNotDirectory;
      return target;
    }
    current = std::move(next);
  }

  target.parent = std::move(current);
  if (split.segments.empty()) {
    target.is_root = true;
    target.exists = true;
    if (fs_fstat(target.parent.get(), &target.info) != 0) {
      target.status = PathStatus::kForbidden;
    }
    return target;
  }

  target.leaf = split.segments.back();
  if (fs_fstatat(target.parent.get(), target.leaf.c_str(), &target.info, AT_SYMLINK_NOFOLLOW) == 0) {
    target.exists = true;
    if (S_ISLNK(target.info.st_mode)) {
      target.status = PathStatus::kForbidden;
      return target;
    }
    return target;
  }
  if (errno == ENOENT) {
    target.exists = false;
    return target;
  }
  target.status = PathStatus::kForbidden;
  return target;
}

int remove_tree(const Fd& parent, const std::string& leaf, int depth) {
  if (depth > kMaxTreeDepth) {
    return kTreeDepthExceeded;
  }
  struct stat info {};
  if (fs_fstatat(parent.get(), leaf.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
    return errno;
  }
  if (S_ISLNK(info.st_mode)) {
    return kTreeSymlink;
  }
  if (!S_ISDIR(info.st_mode)) {
    return fs_unlinkat(parent.get(), leaf.c_str(), 0) == 0 ? 0 : errno;
  }

  Fd dir = open_leaf(parent, leaf, O_RDONLY | O_DIRECTORY);
  if (!dir.valid()) {
    return errno;
  }
  DirStream stream(dir.duplicate());
  if (!stream.valid()) {
    return errno;
  }
  std::string name;
  struct stat entry_info {};
  while (stream.next(name, entry_info)) {
    const int rc = remove_tree(dir, name, depth + 1);
    if (rc != 0) {
      return rc;
    }
  }
  dir.reset();
  stream = DirStream();
  return fs_unlinkat(parent.get(), leaf.c_str(), AT_REMOVEDIR) == 0 ? 0 : errno;
}

int copy_tree(const Fd& src_parent, const std::string& src_leaf, const Fd& dst_parent,
              const std::string& dst_leaf, bool recursive, int depth) {
  if (depth > kMaxTreeDepth) {
    return kTreeDepthExceeded;
  }
  struct stat info {};
  if (fs_fstatat(src_parent.get(), src_leaf.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
    return errno;
  }
  if (S_ISLNK(info.st_mode)) {
    return kTreeSymlink;
  }
  if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode)) {
    return kTreeNotRegular;
  }

  if (!S_ISDIR(info.st_mode)) {
    Fd source = open_leaf(src_parent, src_leaf, O_RDONLY);
    if (!source.valid()) {
      return errno;
    }
    Fd destination = open_leaf(
        dst_parent, dst_leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW);
    if (!destination.valid()) {
      return errno;
    }
    std::vector<char> buffer(kCopyBufferSize);
    for (;;) {
      const ssize_t got = fs_read(source.get(), buffer.data(), buffer.size());
      if (got < 0) {
        if (errno == EINTR) {
          continue;
        }
        return errno;
      }
      if (got == 0) {
        break;
      }
      ssize_t written = 0;
      while (written < got) {
          const ssize_t n =
              fs_write(destination.get(), buffer.data() + written, static_cast<std::size_t>(got - written));
        if (n < 0) {
          if (errno == EINTR) {
            continue;
          }
          return errno;
        }
        written += n;
      }
    }
    fs_fchmod(destination.get(), info.st_mode & 0777);
    return 0;
  }

  const int mkdir_rc = fs_mkdirat(dst_parent.get(), dst_leaf.c_str(), 0700);
  if (mkdir_rc != 0) {
    return errno;
  }
  if (!recursive) {
    return 0;
  }

  Fd source = open_leaf(src_parent, src_leaf, O_RDONLY | O_DIRECTORY);
  if (!source.valid()) {
    return errno;
  }
  Fd destination = open_leaf(dst_parent, dst_leaf, O_RDONLY | O_DIRECTORY);
  if (!destination.valid()) {
    return errno;
  }
  DirStream stream(source.duplicate());
  if (!stream.valid()) {
    return errno;
  }
  std::string name;
  struct stat entry_info {};
  while (stream.next(name, entry_info)) {
    const int rc = copy_tree(source, name, destination, name, true, depth + 1);
    if (rc != 0) {
      return rc;
    }
  }
  fs_fchmod(destination.get(), info.st_mode & 0777);
  return 0;
}

}  // namespace webdav
