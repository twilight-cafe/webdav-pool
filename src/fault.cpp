#include "webdav/fault.hpp"

#include <cerrno>
#include <cstdio>
#include <ctime>
#include <unistd.h>

namespace webdav {

namespace {

FaultHook g_hook;

}  // namespace

void set_fault_hook(FaultHook hook) { g_hook = std::move(hook); }

int fault_inject(const char* operation) {
  if (!g_hook) {
    return 0;
  }
  return g_hook(operation);
}

int fs_stat(const char* path, struct stat* info) {
  if (const int injected = fault_inject("stat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::stat(path, info);
}

int fs_open(const char* path, int flags, mode_t mode) {
  if (const int injected = fault_inject("open"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::open(path, flags, mode);
}

int fs_openat(int dirfd, const char* path, int flags, mode_t mode) {
  if (const int injected = fault_inject("openat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::openat(dirfd, path, flags, mode);
}

int fs_fstat(int fd, struct stat* info) {
  if (const int injected = fault_inject("fstat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::fstat(fd, info);
}

int fs_fstatat(int dirfd, const char* path, struct stat* info, int flags) {
  if (const int injected = fault_inject("fstatat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::fstatat(dirfd, path, info, flags);
}

int fs_unlinkat(int dirfd, const char* path, int flags) {
  if (const int injected = fault_inject("unlinkat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::unlinkat(dirfd, path, flags);
}

int fs_mkdirat(int dirfd, const char* path, mode_t mode) {
  if (const int injected = fault_inject("mkdirat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::mkdirat(dirfd, path, mode);
}

int fs_renameat(int old_dirfd, const char* old_path, int new_dirfd, const char* new_path) {
  if (const int injected = fault_inject("renameat"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::renameat(old_dirfd, old_path, new_dirfd, new_path);
}

ssize_t fs_read(int fd, void* buffer, std::size_t count) {
  if (const int injected = fault_inject("read"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::read(fd, buffer, count);
}

ssize_t fs_write(int fd, const void* buffer, std::size_t count) {
  if (const int injected = fault_inject("write"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::write(fd, buffer, count);
}

ssize_t fs_pread(int fd, void* buffer, std::size_t count, off_t offset) {
  if (const int injected = fault_inject("pread"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::pread(fd, buffer, count, offset);
}

int fs_fchmod(int fd, mode_t mode) {
  if (const int injected = fault_inject("fchmod"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::fchmod(fd, mode);
}

int fs_fcntl(int fd, int command, int argument) {
  if (const int injected = fault_inject("fcntl"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::fcntl(fd, command, argument);
}

int fs_close(int fd) {
  if (const int injected = fault_inject("close"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::close(fd);
}

DIR* fs_fdopendir(int fd) {
  if (const int injected = fault_inject("fdopendir"); injected != 0) {
    errno = injected;
    return nullptr;
  }
  return ::fdopendir(fd);
}

struct dirent* fs_readdir(DIR* directory) {
  if (const int injected = fault_inject("readdir"); injected != 0) {
    errno = injected;
    return nullptr;
  }
  return ::readdir(directory);
}

int fs_closedir(DIR* directory) {
  if (const int injected = fault_inject("closedir"); injected != 0) {
    errno = injected;
    return -1;
  }
  return ::closedir(directory);
}

std::tm* fs_gmtime_r(const std::time_t* timep, std::tm* result) {
  if (const int injected = fault_inject("gmtime_r"); injected != 0) {
    errno = injected;
    return nullptr;
  }
  return ::gmtime_r(timep, result);
}

char* fs_crypt_r(const char* key, const char* salt, struct crypt_data* data) {
  if (const int injected = fault_inject("crypt_r"); injected != 0) {
    errno = injected;
    return nullptr;
  }
  return ::crypt_r(key, salt, data);
}

}  // namespace webdav