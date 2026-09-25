#include "webdav/auth.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <thread>
#include <utility>

#include "webdav/bcrypt.hpp"

namespace webdav {

namespace {

constexpr std::uint32_t kMaxFailures = 64;

// A syntactically valid bcrypt hash used to spend the same CPU on unknown
// users as on real ones. Cost 12 matches the documented example cost.
constexpr const char* kDummyHash =
    "$2b$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c";

std::uint64_t hash_key(std::string_view key) {
  std::uint64_t hash = 1469598103934665603ULL;  // FNV-1a
  for (const char c : key) {
    hash ^= static_cast<unsigned char>(c);
    hash *= 1099511628211ULL;
  }
  return hash;
}

// Compares two equal-length ASCII tokens. Callers only pass fixed-size scheme
// names, so no length check is needed and no unreachable branch is emitted.
bool iequals(std::string_view a, std::string_view b) {
  for (std::size_t i = 0; i < a.size(); ++i) {
    const auto ca = static_cast<unsigned char>(a[i]);
    const auto cb = static_cast<unsigned char>(b[i]);
    if (std::tolower(ca) != std::tolower(cb)) {
      return false;
    }
  }
  return true;
}

int base64_value(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '+') {
    return 62;
  }
  if (c == '/') {
    return 63;
  }
  return -1;
}

bool parse_basic(std::string_view header, std::string& user, std::string& password) {
  std::string_view value = header;
  while (!value.empty() && value.front() == ' ') {
    value.remove_prefix(1);
  }
  if (value.size() < 6 || !iequals(value.substr(0, 5), "basic") || value[5] != ' ') {
    return false;
  }
  std::string_view encoded = value.substr(6);
  while (!encoded.empty() && encoded.back() == ' ') {
    encoded.remove_suffix(1);
  }
  std::string decoded;
  if (!base64_decode(encoded, decoded)) {
    return false;
  }
  const std::size_t colon = decoded.find(':');
  if (colon == std::string::npos) {
    return false;
  }
  user = decoded.substr(0, colon);
  password = decoded.substr(colon + 1);
  return true;
}

}  // namespace

VerifyFn default_verify() {
  return [](const std::string& password, const std::string& hash) {
    return bcrypt_verify(password, hash);
  };
}

SleepFn default_sleep() {
  return [](std::chrono::milliseconds delay) { std::this_thread::sleep_for(delay); };
}

std::string base64_encode(std::string_view input) {
  static constexpr char kTable[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  output.reserve((input.size() + 2) / 3 * 4);
  std::size_t i = 0;
  while (i + 3 <= input.size()) {
    const auto n = (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16) |
                   (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8) |
                   static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 2]));
    output.push_back(kTable[(n >> 18) & 63]);
    output.push_back(kTable[(n >> 12) & 63]);
    output.push_back(kTable[(n >> 6) & 63]);
    output.push_back(kTable[n & 63]);
    i += 3;
  }
  const std::size_t remainder = input.size() - i;
  if (remainder == 1) {
    const auto n = static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16;
    output.push_back(kTable[(n >> 18) & 63]);
    output.push_back(kTable[(n >> 12) & 63]);
    output.push_back('=');
    output.push_back('=');
  } else if (remainder == 2) {
    const auto n = (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i])) << 16) |
                   (static_cast<std::uint32_t>(static_cast<unsigned char>(input[i + 1])) << 8);
    output.push_back(kTable[(n >> 18) & 63]);
    output.push_back(kTable[(n >> 12) & 63]);
    output.push_back(kTable[(n >> 6) & 63]);
    output.push_back('=');
  }
  return output;
}  // LCOV_EXCL_LINE

bool base64_decode(std::string_view input, std::string& output) {
  output.clear();
  if (input.size() % 4 != 0) {
    return false;
  }
  if (input.empty()) {
    return true;
  }
  std::size_t padding = 0;
  if (input[input.size() - 1] == '=') {
    ++padding;
  }
  if (input.size() >= 2 && input[input.size() - 2] == '=') {
    ++padding;
  }
  const std::size_t payload = input.size() - padding;
  for (std::size_t i = 0; i < payload; ++i) {
    if (base64_value(input[i]) < 0) {
      return false;
    }
  }
  std::uint32_t accumulator = 0;
  int bits = 0;
  for (std::size_t i = 0; i < payload; ++i) {
    accumulator = (accumulator << 6) | static_cast<std::uint32_t>(base64_value(input[i]));
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push_back(static_cast<char>((accumulator >> bits) & 0xFF));
    }
  }
  return true;
}

Semaphore::Semaphore(int capacity) : capacity_(capacity < 1 ? 1 : capacity) {}

void Semaphore::acquire() {
  std::unique_lock<std::mutex> lock(mutex_);
  cv_.wait(lock, [this] { return in_use_ < capacity_; });
  ++in_use_;
}

void Semaphore::release() {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    --in_use_;
  }
  cv_.notify_one();
}

Authenticator::Authenticator(std::vector<User> users, int max_concurrent, int backoff_base_ms,
                             int backoff_max_ms, VerifyFn verify, SleepFn sleep)
    : users_(std::move(users)),
      verify_(std::move(verify)),
      sleep_(std::move(sleep)),
      backoff_base_ms_(backoff_base_ms),
      backoff_max_ms_(backoff_max_ms),
      semaphore_(max_concurrent),
      table_(kAuthBackoffSlots) {}

std::size_t Authenticator::slot_index(std::uint64_t key_hash) {
  const std::size_t size = table_.size();
  const std::size_t start = static_cast<std::size_t>(key_hash % size);
  for (std::size_t step = 0; step < size; ++step) {
    const std::size_t index = (start + step) % size;
    Slot& slot = table_[index];
    if (slot.used && slot.key_hash == key_hash) {
      return index;
    }
    if (!slot.used) {
      slot.used = true;
      slot.key_hash = key_hash;
      slot.failures = 0;
      return index;
    }
  }
  // Table saturated: reuse the first probe slot. Memory stays fixed.
  Slot& slot = table_[start];
  slot = Slot{};
  slot.used = true;
  slot.key_hash = key_hash;
  return start;
}

std::chrono::milliseconds Authenticator::backoff_delay(std::uint32_t failures) const {
  long long delay_ms = backoff_base_ms_;
  for (std::uint32_t i = 1; i < failures && delay_ms < backoff_max_ms_; ++i) {
    delay_ms *= 2;
  }
  if (delay_ms > backoff_max_ms_) {
    delay_ms = backoff_max_ms_;
  }
  return std::chrono::milliseconds(delay_ms);
}

AuthResult Authenticator::verify_password(std::string_view key, std::string_view user_name,
                                          std::string_view password) {
  const std::uint64_t key_hash = hash_key(key);

  std::chrono::milliseconds delay{0};
  {
    std::lock_guard<std::mutex> lock(table_mutex_);
    const std::size_t index = slot_index(key_hash);
    if (table_[index].failures > 0) {
      delay = backoff_delay(table_[index].failures);
    }
  }
  if (delay.count() > 0) {
    sleep_(delay);
  }

  const User* matched = nullptr;
  for (const User& candidate : users_) {
    if (candidate.name == user_name) {
      matched = &candidate;
      break;
    }
  }
  const std::string hash = matched != nullptr ? matched->password_bcrypt : std::string(kDummyHash);
  const std::string password_copy(password);

  bool ok = false;
  {
    SemaphoreGuard guard(semaphore_);
    {
      std::lock_guard<std::mutex> lock(in_flight_mutex_);
      ++in_flight_;
    }
    ok = verify_(password_copy, hash);
    {
      std::lock_guard<std::mutex> lock(in_flight_mutex_);
      --in_flight_;
    }
  }

  {
    std::lock_guard<std::mutex> lock(table_mutex_);
    const std::size_t index = slot_index(key_hash);
    if (ok) {
      table_[index].failures = 0;
    } else if (table_[index].failures < kMaxFailures) {
      ++table_[index].failures;
    }
  }

  if (ok && matched != nullptr) {
    return AuthResult{AuthStatus::kOk, matched};
  }
  return AuthResult{AuthStatus::kUnauthorized, nullptr};
}

int Authenticator::in_flight() const {
  std::lock_guard<std::mutex> lock(in_flight_mutex_);
  return in_flight_;
}

AuthResult Authenticator::authenticate(std::string_view client_key, std::string_view authorization) {
  std::string user;
  std::string password;
  if (!parse_basic(authorization, user, password)) {
    return AuthResult{AuthStatus::kUnauthorized, nullptr};
  }
  return verify_password(client_key, user, password);
}

}  // namespace webdav
