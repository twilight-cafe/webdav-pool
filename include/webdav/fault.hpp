#pragma once

#include <crypt.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cstddef>
#include <ctime>
#include <functional>
#include <utility>

namespace webdav {

// ---------------------------------------------------------------------------
// Test seam for filesystem fault injection.
//
// `set_fault_hook` installs a callback that every wrapped syscall consults
// before running. The hook receives a short operation name ("openat", "write",
// ...) and returns 0 to let the call proceed, or an errno value to make the
// call fail with that errno without touching the real filesystem. Production
// code never installs a hook, so each wrapper is a transparent pass-through.
// ---------------------------------------------------------------------------
using FaultHook = std::function<int(const char* operation)>;
void set_fault_hook(FaultHook hook);
int fault_inject(const char* operation);

// Thin wrappers around the libc calls used by the filesystem helpers. Going
// through these keeps every failure path reachable from a unit test.
int fs_stat(const char* path, struct stat* info);
int fs_open(const char* path, int flags, mode_t mode);
int fs_openat(int dirfd, const char* path, int flags, mode_t mode);
int fs_fstat(int fd, struct stat* info);
int fs_fstatat(int dirfd, const char* path, struct stat* info, int flags);
int fs_unlinkat(int dirfd, const char* path, int flags);
int fs_mkdirat(int dirfd, const char* path, mode_t mode);
int fs_renameat(int old_dirfd, const char* old_path, int new_dirfd, const char* new_path);
ssize_t fs_read(int fd, void* buffer, std::size_t count);
ssize_t fs_write(int fd, const void* buffer, std::size_t count);
ssize_t fs_pread(int fd, void* buffer, std::size_t count, off_t offset);
int fs_fchmod(int fd, mode_t mode);
int fs_fcntl(int fd, int command, int argument);
int fs_close(int fd);
DIR* fs_fdopendir(int fd);
struct dirent* fs_readdir(DIR* directory);
int fs_closedir(DIR* directory);

// Small non-filesystem seams used by config/log/http/bcrypt paths so their
// error branches are reachable under fault injection as well.
std::tm* fs_gmtime_r(const std::time_t* timep, std::tm* result);
char* fs_crypt_r(const char* key, const char* salt, struct crypt_data* data);

}  // namespace webdav