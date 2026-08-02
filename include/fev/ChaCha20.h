#pragma once

#include <array>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace fev {

/// IETF ChaCha20 (RFC 8439) — used at rewrite time to produce ciphertext.
void chacha20Xor(std::uint8_t *Out, const std::uint8_t *In, std::size_t Len,
                 const std::uint8_t Key[32], const std::uint8_t Nonce[12],
                 std::uint32_t Counter = 1);

/// Derive a 32-byte key from an arbitrary seed string / integer.
std::array<std::uint8_t, 32> deriveChaChaKey(std::uint64_t Seed);

/// Per-literal 12-byte nonce from seed + literal index.
std::array<std::uint8_t, 12> deriveNonce(std::uint64_t Seed, unsigned Index);

/// Simple 32-bit FNV-1a over bytes (integrity tag for lazy decrypt).
std::uint32_t fnv1a32(const std::uint8_t *Data, std::size_t Len);

/// Format a byte array as a C compound literal: `{0x.., ...}`
std::string formatByteArray(const std::uint8_t *Data, std::size_t Len);

/// Shared ChaCha20 C runtime (include-guarded) for injected helpers.
std::string buildChaChaRuntimeC(const std::array<std::uint8_t, 32> &Key);

} // namespace fev
