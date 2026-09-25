#include <gtest/gtest.h>

#include <crypt.h>

#include <cstring>
#include <string>

#include "webdav/bcrypt.hpp"
#include "webdav/fault.hpp"

namespace {

constexpr const char* kValidHash =
    "$2b$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c";

std::string hash_password(const std::string& password, const std::string& setting) {
  crypt_data data{};
  std::memset(&data, 0, sizeof(data));
  char* result = crypt_r(password.c_str(), setting.c_str(), &data);
  return result != nullptr ? std::string(result) : std::string();
}

}  // namespace

TEST(BcryptFormat, AcceptsWellFormedHashes) {
  EXPECT_TRUE(webdav::is_valid_bcrypt_hash(kValidHash, 10));
  EXPECT_TRUE(webdav::is_valid_bcrypt_hash(
      "$2a$10$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
  EXPECT_TRUE(webdav::is_valid_bcrypt_hash(
      "$2y$31$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
}

TEST(BcryptFormat, RejectsBadLength) {
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash("$2b$12$short", 10));
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(std::string(61, 'a'), 10));
}

TEST(BcryptFormat, RejectsBadPrefix) {
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2c$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$1a$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
}

TEST(BcryptFormat, RejectsBadCost) {
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2b$1x$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2b$09$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2b$32$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 4));
}

TEST(BcryptFormat, RejectsBadSeparatorAndAlphabet) {
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2b$12Xabcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2c", 10));
  EXPECT_FALSE(webdav::is_valid_bcrypt_hash(
      "$2b$12$abcdefghijklmnopqrstuu6rhbR2L7eR6YQOqvZ2jXKkLdJpZ6L2*", 10));
}

TEST(ConstantTimeEqual, ComparesEqualLengthBuffers) {
  const char a[] = "abcdef";
  const char b[] = "abcdef";
  const char c[] = "abcdeX";
  EXPECT_TRUE(webdav::ct_equal(a, b, 6));
  EXPECT_FALSE(webdav::ct_equal(a, c, 6));
  EXPECT_TRUE(webdav::ct_equal(a, c, 0));
}

TEST(BcryptVerify, MatchesCorrectPassword) {
  const std::string setting = "$2b$10$abcdefghijklmnopqrstuu";
  const std::string hash = hash_password("s3cret", setting);
  ASSERT_EQ(hash.size(), 60u);
  EXPECT_TRUE(webdav::bcrypt_verify("s3cret", hash));
  EXPECT_FALSE(webdav::bcrypt_verify("s3crey", hash));
  EXPECT_FALSE(webdav::bcrypt_verify("", hash));
}

TEST(BcryptVerify, RejectsMalformedInputs) {
  EXPECT_FALSE(webdav::bcrypt_verify("x", "too-short"));

  std::string with_nul(60, 'a');
  with_nul[10] = '\0';
  EXPECT_FALSE(webdav::bcrypt_verify("x", with_nul));

  // 60 characters with an unusable salt: crypt_r rejects the setting.
  const std::string bad_salt = "$2b$12$" + std::string(53, '*');
  ASSERT_EQ(bad_salt.size(), 60u);
  EXPECT_FALSE(webdav::bcrypt_verify("x", bad_salt));
}

TEST(BcryptVerify, ReportsCryptFailure) {
  webdav::set_fault_hook([](const char* operation) {
    return std::strcmp(operation, "crypt_r") == 0 ? EINVAL : 0;
  });
  EXPECT_FALSE(webdav::bcrypt_verify("x", kValidHash));
  webdav::set_fault_hook(nullptr);
}
