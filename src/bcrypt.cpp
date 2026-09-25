#include "webdav/bcrypt.hpp"

#include <crypt.h>

#include <cstring>
#include <memory>
#include <string>

#include "webdav/fault.hpp"

namespace webdav {

namespace {

bool is_bcrypt_base64(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
         c == '/';
}

bool is_digit(char c) { return c >= '0' && c <= '9'; }

}  // namespace

bool is_valid_bcrypt_hash(std::string_view hash, int min_cost) {
  if (hash.size() != 60) {
    return false;
  }
  const bool prefix_ok = hash.compare(0, 4, "$2a$") == 0 || hash.compare(0, 4, "$2b$") == 0 ||
                         hash.compare(0, 4, "$2y$") == 0;
  if (!prefix_ok) {
    return false;
  }
  if (!is_digit(hash[4]) || !is_digit(hash[5])) {
    return false;
  }
  const int cost = (hash[4] - '0') * 10 + (hash[5] - '0');
  if (cost < min_cost || cost > 31) {
    return false;
  }
  if (hash[6] != '$') {
    return false;
  }
  for (std::size_t i = 7; i < 60; ++i) {
    if (!is_bcrypt_base64(hash[i])) {
      return false;
    }
  }
  return true;
}

bool ct_equal(const void* a, const void* b, std::size_t size) {
  const auto* pa = static_cast<const unsigned char*>(a);
  const auto* pb = static_cast<const unsigned char*>(b);
  unsigned char diff = 0;
  for (std::size_t i = 0; i < size; ++i) {
    diff = static_cast<unsigned char>(diff | (pa[i] ^ pb[i]));
  }
  return diff == 0;
}

bool bcrypt_verify(std::string_view password, std::string_view hash) {
  if (hash.size() != 60 || hash.find('\0') != std::string_view::npos) {
    return false;
  }
  const std::string password_copy(password);
  const std::string setting(hash);

  auto data = std::make_unique<crypt_data>();
  std::memset(data.get(), 0, sizeof(crypt_data));
  char* computed = fs_crypt_r(password_copy.c_str(), setting.c_str(), data.get());
  if (computed == nullptr) {
    return false;
  }
  const std::size_t length = std::strlen(computed);
  return length == hash.size() && ct_equal(computed, hash.data(), length);
}

}  // namespace webdav
