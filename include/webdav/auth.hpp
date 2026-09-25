#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <condition_variable>
#include <string>
#include <string_view>
#include <vector>

#include "webdav/config.hpp"

namespace webdav {

enum class AuthStatus { kOk, kUnauthorized };

struct AuthResult {
  AuthStatus status{AuthStatus::kUnauthorized};
  const User* user{nullptr};
};

// Injected so tests can drive bcrypt timing/cost without real hashing.
using VerifyFn = std::function<bool(const std::string& password, const std::string& hash)>;
using SleepFn = std::function<void(std::chrono::milliseconds)>;

// Defaults backed by libcrypt / the real clock.
VerifyFn default_verify();
SleepFn default_sleep();

// Base64 helpers (RFC 4648) used for HTTP Basic credentials.
std::string base64_encode(std::string_view input);
bool base64_decode(std::string_view input, std::string& output);

// Fixed-capacity counting semaphore used to bound concurrent bcrypt work.
class Semaphore {
 public:
  explicit Semaphore(int capacity);

  // Blocks until a slot is free.
  void acquire();
  void release();

  int capacity() const { return capacity_; }

 private:
  const int capacity_;
  int in_use_{0};
  std::mutex mutex_;
  std::condition_variable cv_;
};

// RaII guard for Semaphore.
class SemaphoreGuard {
 public:
  explicit SemaphoreGuard(Semaphore& sem) : sem_(&sem) { sem_->acquire(); }
  ~SemaphoreGuard() { sem_->release(); }
  SemaphoreGuard(const SemaphoreGuard&) = delete;
  SemaphoreGuard& operator=(const SemaphoreGuard&) = delete;

 private:
  Semaphore* sem_;
};

// Number of fixed slots in the per-client failure table.
inline constexpr std::size_t kAuthBackoffSlots = 1024;

class Authenticator {
 public:
  Authenticator(std::vector<User> users, int max_concurrent, int backoff_base_ms, int backoff_max_ms,
                VerifyFn verify, SleepFn sleep);

  Authenticator(const Authenticator&) = delete;
  Authenticator& operator=(const Authenticator&) = delete;

  // Parses a Basic `Authorization` header value and authenticates it for the
  // given client key (used only for backoff bookkeeping).
  AuthResult authenticate(std::string_view client_key, std::string_view authorization);

  // Number of slots currently used for concurrent verification (tests).
  int in_flight() const;

 private:
  struct Slot {
    std::uint64_t key_hash{0};
    bool used{false};
    std::uint32_t failures{0};
  };

  // Looks up or creates a slot for `key_hash`; never grows the table.
  std::size_t slot_index(std::uint64_t key_hash);

  std::chrono::milliseconds backoff_delay(std::uint32_t failures) const;
  AuthResult verify_password(std::string_view key, std::string_view user_name, std::string_view password);

  std::vector<User> users_;
  VerifyFn verify_;
  SleepFn sleep_;
  const int backoff_base_ms_;
  const int backoff_max_ms_;
  Semaphore semaphore_;

  mutable std::mutex in_flight_mutex_;
  int in_flight_{0};

  std::mutex table_mutex_;
  std::vector<Slot> table_;
};

}  // namespace webdav
