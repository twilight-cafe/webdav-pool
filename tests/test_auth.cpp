#include <gtest/gtest.h>

#include <crypt.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "webdav/auth.hpp"
#include "webdav/bcrypt.hpp"

namespace {

using namespace std::chrono_literals;

std::string bcrypt_hash(const std::string& password, const std::string& setting) {
  crypt_data data{};
  std::memset(&data, 0, sizeof(data));
  char* result = crypt_r(password.c_str(), setting.c_str(), &data);
  return result != nullptr ? std::string(result) : std::string();
}

std::string basic_header(const std::string& user, const std::string& password) {
  return "Basic " + webdav::base64_encode(user + ":" + password);
}

std::vector<webdav::User> make_users() {
  const std::string hash = bcrypt_hash("secret1", "$2b$10$abcdefghijklmnopqrstuu");
  return {webdav::User{"alice", hash, "/srv/alice"}, webdav::User{"bob", hash, "/srv/bob"}};
}

webdav::VerifyFn failing_verify() {
  return [](const std::string&, const std::string&) { return false; };
}

struct SleepRecorder {
  std::vector<std::chrono::milliseconds> sleeps;
  webdav::SleepFn fn() {
    return [this](std::chrono::milliseconds delay) { sleeps.push_back(delay); };
  }
};

}  // namespace

TEST(Base64, RoundTripsAllRemainders) {
  for (const std::string& input : {std::string(), std::string("a"), std::string("ab"),
                                   std::string("abc"), std::string("abcd"),
                                   std::string("hello:world")}) {
    std::string decoded;
    EXPECT_TRUE(webdav::base64_decode(webdav::base64_encode(input), decoded));
    EXPECT_EQ(decoded, input);
  }
  EXPECT_EQ(webdav::base64_encode("hello:world"), "aGVsbG86d29ybGQ=");
}

TEST(Base64, RejectsInvalidInput) {
  std::string out;
  EXPECT_FALSE(webdav::base64_decode("abc", out));       // not a multiple of 4
  EXPECT_FALSE(webdav::base64_decode("ab*d", out));      // illegal character
  EXPECT_FALSE(webdav::base64_decode("a=bc", out));      // padding in the middle
  EXPECT_TRUE(webdav::base64_decode("", out));           // empty is valid
  EXPECT_TRUE(out.empty());
}

TEST(SemaphoreTest, BoundsConcurrentAcquires) {
  webdav::Semaphore semaphore(1);
  semaphore.acquire();
  std::atomic<bool> entered{false};
  std::thread waiter([&] {
    semaphore.acquire();
    entered.store(true);
    semaphore.release();
  });
  std::this_thread::sleep_for(30ms);
  EXPECT_FALSE(entered.load());
  semaphore.release();
  waiter.join();
  EXPECT_TRUE(entered.load());
  EXPECT_EQ(semaphore.capacity(), 1);
}

TEST(AuthenticatorTest, AcceptsCorrectCredentials) {
  webdav::Authenticator auth(make_users(), 2, 250, 5000, webdav::default_verify(),
                             [](std::chrono::milliseconds) {});
  const webdav::AuthResult result = auth.authenticate("10.0.0.1", basic_header("alice", "secret1"));
  ASSERT_EQ(result.status, webdav::AuthStatus::kOk);
  ASSERT_NE(result.user, nullptr);
  EXPECT_EQ(result.user->name, "alice");
}

TEST(AuthenticatorTest, RejectsWrongPassword) {
  webdav::Authenticator auth(make_users(), 2, 250, 5000, webdav::default_verify(),
                             [](std::chrono::milliseconds) {});
  const webdav::AuthResult result =
      auth.authenticate("10.0.0.2", basic_header("alice", "wrong"));
  EXPECT_EQ(result.status, webdav::AuthStatus::kUnauthorized);
  EXPECT_EQ(result.user, nullptr);
}

TEST(AuthenticatorTest, UnknownUserStillRunsBcrypt) {
  std::string seen_hash;
  int calls = 0;
  webdav::VerifyFn verify = [&](const std::string&, const std::string& hash) {
    ++calls;
    seen_hash = hash;
    return false;
  };
  webdav::Authenticator auth(make_users(), 2, 250, 5000, verify,
                             [](std::chrono::milliseconds) {});
  const webdav::AuthResult result =
      auth.authenticate("10.0.0.3", basic_header("nobody", "whatever"));
  EXPECT_EQ(result.status, webdav::AuthStatus::kUnauthorized);
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(seen_hash.size(), 60u);
  EXPECT_TRUE(webdav::is_valid_bcrypt_hash(seen_hash, 10));
}

TEST(AuthenticatorTest, RejectsMalformedHeadersWithoutHashing) {
  int calls = 0;
  webdav::VerifyFn verify = [&](const std::string&, const std::string&) {
    ++calls;
    return true;
  };
  webdav::Authenticator auth(make_users(), 2, 250, 5000, verify, [](std::chrono::milliseconds) {});

  const std::string malformed[] = {
      "",          // missing header
      "Bearer abc",  // wrong scheme
      "Basic",     // scheme only
      "Basic ",    // empty token
      "Basic !!!!",  // illegal base64
      "Basic " + webdav::base64_encode("nocolon"),
  };
  for (const std::string& header : malformed) {
    const webdav::AuthResult result = auth.authenticate("10.0.0.4", header);
    EXPECT_EQ(result.status, webdav::AuthStatus::kUnauthorized) << "header=" << header;
  }
  EXPECT_EQ(calls, 0);

  // A lowercase scheme with surrounding spaces is still accepted and reaches
  // the verifier exactly once.
  const webdav::AuthResult result =
      auth.authenticate("10.0.0.4", "  basic " + webdav::base64_encode("alice:secret1"));
  EXPECT_EQ(result.status, webdav::AuthStatus::kOk);
  EXPECT_EQ(calls, 1);
}

TEST(AuthenticatorTest, AppliesEscalatingBackoffPerClient) {
  SleepRecorder recorder;
  webdav::Authenticator auth(make_users(), 2, 100, 400, failing_verify(), recorder.fn());

  for (int i = 0; i < 5; ++i) {
    (void)auth.authenticate("10.0.0.5", basic_header("alice", "wrong"));
  }
  ASSERT_EQ(recorder.sleeps.size(), 4u);
  EXPECT_EQ(recorder.sleeps[0], 100ms);
  EXPECT_EQ(recorder.sleeps[1], 200ms);
  EXPECT_EQ(recorder.sleeps[2], 400ms);
  EXPECT_EQ(recorder.sleeps[3], 400ms);  // clamped to the maximum
}

TEST(AuthenticatorTest, SuccessResetsBackoff) {
  SleepRecorder recorder;
  int attempt = 0;
  webdav::VerifyFn verify = [&](const std::string&, const std::string&) {
    ++attempt;
    return attempt >= 2;
  };
  webdav::Authenticator auth(make_users(), 2, 100, 4000, verify, recorder.fn());

  (void)auth.authenticate("10.0.0.6", basic_header("alice", "pw"));
  const webdav::AuthResult second = auth.authenticate("10.0.0.6", basic_header("alice", "pw"));
  EXPECT_EQ(second.status, webdav::AuthStatus::kOk);
  (void)auth.authenticate("10.0.0.6", basic_header("alice", "pw"));

  ASSERT_EQ(recorder.sleeps.size(), 1u);
  EXPECT_EQ(recorder.sleeps[0], 100ms);
}

TEST(AuthenticatorTest, KeepsConcurrencyWithinLimit) {
  constexpr int kLimit = 2;
  std::atomic<int> current{0};
  std::atomic<int> observed_max{0};
  webdav::VerifyFn verify = [&](const std::string&, const std::string&) {
    const int now = current.fetch_add(1) + 1;
    int previous = observed_max.load();
    while (now > previous && !observed_max.compare_exchange_weak(previous, now)) {
    }
    std::this_thread::sleep_for(20ms);
    current.fetch_sub(1);
    return false;
  };
  webdav::Authenticator auth(make_users(), kLimit, 1, 1, verify, [](std::chrono::milliseconds) {});

  std::vector<std::thread> threads;
  for (int i = 0; i < 8; ++i) {
    threads.emplace_back([&auth, i] {
      (void)auth.authenticate("client-" + std::to_string(i), basic_header("alice", "pw"));
    });
  }
  for (std::thread& thread : threads) {
    thread.join();
  }
  EXPECT_LE(observed_max.load(), kLimit);
  EXPECT_EQ(auth.in_flight(), 0);
}

TEST(Base64, HandlesPlusAndSlashAlphabet) {
  std::string input;
  input.push_back(static_cast<char>(0xfb));
  input.push_back(static_cast<char>(0xff));
  EXPECT_EQ(webdav::base64_encode(input), "+/8=");

  std::string decoded;
  EXPECT_TRUE(webdav::base64_decode("+/8=", decoded));
  EXPECT_EQ(decoded, input);
}

TEST(AuthenticatorTest, AcceptsTrailingSpacesAfterBasicToken) {
  webdav::Authenticator auth(make_users(), 2, 1, 1,
                             [](const std::string&, const std::string&) { return true; },
                             [](std::chrono::milliseconds) {});
  const std::string header = "Basic " + webdav::base64_encode("alice:secret1") + "   ";
  const webdav::AuthResult result = auth.authenticate("10.0.0.7", header);
  EXPECT_EQ(result.status, webdav::AuthStatus::kOk);
  ASSERT_NE(result.user, nullptr);
  EXPECT_EQ(result.user->name, "alice");
}

TEST(AuthenticatorTest, BackoffClampsMultiplicativeOvershoot) {
  SleepRecorder recorder;
  webdav::Authenticator auth(make_users(), 2, 100, 500, failing_verify(), recorder.fn());
  for (int i = 0; i < 5; ++i) {
    (void)auth.authenticate("10.0.0.8", basic_header("alice", "wrong"));
  }
  ASSERT_EQ(recorder.sleeps.size(), 4u);
  EXPECT_EQ(recorder.sleeps[0], 100ms);
  EXPECT_EQ(recorder.sleeps[1], 200ms);
  EXPECT_EQ(recorder.sleeps[2], 400ms);
  EXPECT_EQ(recorder.sleeps[3], 500ms);
}

TEST(AuthenticatorTest, SaturatesFixedSizeBackoffTable) {
  webdav::Authenticator auth(make_users(), 1, 1, 1, failing_verify(),
                             [](std::chrono::milliseconds) {});
  for (std::size_t i = 0; i < webdav::kAuthBackoffSlots + 1; ++i) {
    (void)auth.authenticate("client-" + std::to_string(i), basic_header("alice", "wrong"));
  }
  EXPECT_EQ(auth.in_flight(), 0);
}
