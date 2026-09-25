#pragma once

#include <cstddef>
#include <string_view>

namespace webdav {

// Validates the textual form "$2a$/$2b$/$2y$" + 2-digit cost + 53 payload
// characters. Cost must be in [min_cost, 31].
bool is_valid_bcrypt_hash(std::string_view hash, int min_cost);

// Length-independent constant-time equality for equal-length buffers.
bool ct_equal(const void* a, const void* b, std::size_t size);

// Verifies `password` against `hash`. Returns false on invalid input or any
// failure. Never throws.
bool bcrypt_verify(std::string_view password, std::string_view hash);

}  // namespace webdav
