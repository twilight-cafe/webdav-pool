#pragma once

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webdav {

// Owns a file descriptor. Every filesystem operation in the project goes
// through these wrappers so descriptors can never leak.
class Fd {
 public:
  Fd() = default;
  explicit Fd(int fd) noexcept : fd_(fd) {}
  ~Fd();

  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  Fd(Fd&& other) noexcept;
  Fd& operator=(Fd&& other) noexcept;

  int get() const noexcept { return fd_; }
  bool valid() const noexcept { return fd_ >= 0; }
  int release() noexcept;
  void reset(int fd = -1) noexcept;
  Fd duplicate() const;

 private:
  int fd_{-1};
};

// RAII wrapper around a DIR* obtained from a duplicated descriptor.
class DirStream {
 public:
  DirStream() = default;
  explicit DirStream(Fd dir);
  ~DirStream();

  DirStream(const DirStream&) = delete;
  DirStream& operator=(const DirStream&) = delete;
  DirStream(DirStream&& other) noexcept;
  DirStream& operator=(DirStream&& other) noexcept;

  bool valid() const noexcept { return dir_ != nullptr; }
  int fd() const noexcept;

  // Yields the next non-"."/non-".." entry together with its lstat info.
  bool next(std::string& name, struct stat& info);

 private:
  DIR* dir_{nullptr};
};

enum class PathStatus {
  kOk,
  kBadRequest,    // malformed percent-encoding
  kForbidden,     // traversal, symlink, NUL, bad segment, over-long
  kNotFound,      // a parent component does not exist
  kNotDirectory,  // a parent component exists but is not a directory
};

// The outcome of resolving a request path against a user's root.
struct Target {
  PathStatus status{PathStatus::kOk};
  Fd parent;       // parent directory of `leaf`
  std::string leaf;
  std::string decoded_path;  // canonical, decoded path ("/" for the root)
  bool is_root{false};
  bool exists{false};
  struct stat info {};

  bool ok() const { return status == PathStatus::kOk; }
};

// Opens a directory as the confinement root.
Fd open_root_directory(const std::string& path);

// Strict RFC 3986 percent-decoding; returns false on malformed input.
bool percent_decode(std::string_view input, std::string& output);

// Percent-encodes everything outside the unreserved set (plus '/').
std::string percent_encode(std::string_view input);

// Decodes and validates the request target, then walks the root with
// openat(O_PATH|O_NOFOLLOW) so that no component can be replaced by a symlink
// between the check and the use.
Target resolve_path(const Fd& root, const std::string& request_target);

// Opens parent/leaf without following a final symlink. `mode` is only used
// when `flags` contains O_CREAT.
Fd open_leaf(const Fd& parent, const std::string& leaf, int flags, mode_t mode = 0);

// Maximum directory nesting handled by the recursive helpers.
inline constexpr int kMaxTreeDepth = 64;

// Signals used by the tree helpers, on top of plain errno values.
inline constexpr int kTreeDepthExceeded = E2BIG;
inline constexpr int kTreeSymlink = ELOOP;
inline constexpr int kTreeNotRegular = EINVAL;

// Removes `parent/leaf`, recursing into directories. Returns 0 or an errno.
int remove_tree(const Fd& parent, const std::string& leaf, int depth = 0);

// Copies `src_parent/src_leaf` to `dst_parent/dst_leaf`. `dst_leaf` must not
// exist. `recursive` mirrors a whole collection; otherwise only the collection
// itself is created. Returns 0 or an errno.
int copy_tree(const Fd& src_parent, const std::string& src_leaf, const Fd& dst_parent,
              const std::string& dst_leaf, bool recursive, int depth = 0);

}  // namespace webdav
