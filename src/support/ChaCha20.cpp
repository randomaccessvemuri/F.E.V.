#include "fev/ChaCha20.h"

#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <cstring>

namespace fev {
namespace {

constexpr std::uint32_t rotl32(std::uint32_t V, int N) {
  return (V << N) | (V >> (32 - N));
}

void quarterRound(std::uint32_t &A, std::uint32_t &B, std::uint32_t &C,
                  std::uint32_t &D) {
  A += B;
  D ^= A;
  D = rotl32(D, 16);
  C += D;
  B ^= C;
  B = rotl32(B, 12);
  A += B;
  D ^= A;
  D = rotl32(D, 8);
  C += D;
  B ^= C;
  B = rotl32(B, 7);
}

std::uint32_t load32(const std::uint8_t *P) {
  return (std::uint32_t)P[0] | ((std::uint32_t)P[1] << 8) |
         ((std::uint32_t)P[2] << 16) | ((std::uint32_t)P[3] << 24);
}

void store32(std::uint8_t *P, std::uint32_t V) {
  P[0] = (std::uint8_t)(V);
  P[1] = (std::uint8_t)(V >> 8);
  P[2] = (std::uint8_t)(V >> 16);
  P[3] = (std::uint8_t)(V >> 24);
}

void chachaBlock(std::uint8_t Out[64], const std::uint8_t Key[32],
                 const std::uint8_t Nonce[12], std::uint32_t Counter) {
  std::uint32_t S[16];
  // "expand 32-byte k"
  S[0] = 0x61707865u;
  S[1] = 0x3320646eu;
  S[2] = 0x79622d32u;
  S[3] = 0x6b206574u;
  for (int I = 0; I < 8; ++I)
    S[4 + I] = load32(Key + 4 * I);
  S[12] = Counter;
  S[13] = load32(Nonce + 0);
  S[14] = load32(Nonce + 4);
  S[15] = load32(Nonce + 8);

  std::uint32_t W[16];
  std::memcpy(W, S, sizeof(W));
  for (int I = 0; I < 10; ++I) {
    quarterRound(W[0], W[4], W[8], W[12]);
    quarterRound(W[1], W[5], W[9], W[13]);
    quarterRound(W[2], W[6], W[10], W[14]);
    quarterRound(W[3], W[7], W[11], W[15]);
    quarterRound(W[0], W[5], W[10], W[15]);
    quarterRound(W[1], W[6], W[11], W[12]);
    quarterRound(W[2], W[7], W[8], W[13]);
    quarterRound(W[3], W[4], W[9], W[14]);
  }
  for (int I = 0; I < 16; ++I)
    store32(Out + 4 * I, W[I] + S[I]);
}

} // namespace

void chacha20Xor(std::uint8_t *Out, const std::uint8_t *In, std::size_t Len,
                 const std::uint8_t Key[32], const std::uint8_t Nonce[12],
                 std::uint32_t Counter) {
  std::size_t Off = 0;
  while (Off < Len) {
    std::uint8_t Block[64];
    chachaBlock(Block, Key, Nonce, Counter++);
    const std::size_t N = std::min<std::size_t>(64, Len - Off);
    for (std::size_t I = 0; I < N; ++I)
      Out[Off + I] = In[Off + I] ^ Block[I];
    Off += N;
  }
}

std::array<std::uint8_t, 32> deriveChaChaKey(std::uint64_t Seed) {
  std::array<std::uint8_t, 32> Key{};
  // Expand seed into 32 bytes with a cheap non-cryptographic mix; the stream
  // cipher provides the actual strength once keyed.
  std::uint64_t S = Seed ? Seed : 0xA5A5A5A5A5A5A5A5ULL;
  for (int I = 0; I < 4; ++I) {
    S ^= S >> 12;
    S ^= S << 25;
    S ^= S >> 27;
    S *= 0x2545F4914F6CDD1DULL;
    for (int B = 0; B < 8; ++B)
      Key[I * 8 + B] = (std::uint8_t)(S >> (8 * B));
  }
  return Key;
}

std::array<std::uint8_t, 12> deriveNonce(std::uint64_t Seed, unsigned Index) {
  std::array<std::uint8_t, 12> Nonce{};
  std::uint64_t A = Seed ^ (0x9E3779B97F4A7C15ULL * (Index + 1));
  std::uint32_t B = (std::uint32_t)(Index * 0x85EBCA77u) ^ (std::uint32_t)Seed;
  for (int I = 0; I < 8; ++I)
    Nonce[I] = (std::uint8_t)(A >> (8 * I));
  for (int I = 0; I < 4; ++I)
    Nonce[8 + I] = (std::uint8_t)(B >> (8 * I));
  return Nonce;
}

std::uint32_t fnv1a32(const std::uint8_t *Data, std::size_t Len) {
  std::uint32_t H = 2166136261u;
  for (std::size_t I = 0; I < Len; ++I) {
    H ^= Data[I];
    H *= 16777619u;
  }
  return H;
}

std::string formatByteArray(const std::uint8_t *Data, std::size_t Len) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  OS << "{";
  for (std::size_t I = 0; I < Len; ++I) {
    if (I)
      OS << ", ";
    OS << llvm::format("0x%02xu", (unsigned)Data[I]);
  }
  OS << "}";
  return OS.str();
}

std::string buildChaChaRuntimeC(const std::array<std::uint8_t, 32> &Key) {
  std::string Out;
  llvm::raw_string_ostream OS(Out);
  OS << R"(/* === fev ChaCha20 runtime (generated) === */
#ifndef FEV_CHACHA_RUNTIME_H
#define FEV_CHACHA_RUNTIME_H
#include <stdint.h>
#include <string.h>

static const uint8_t fev_chacha_key[32] = )"
     << formatByteArray(Key.data(), Key.size()) << R"(;

static uint32_t fev_rotl32(uint32_t v, int n) {
  return (v << n) | (v >> (32 - n));
}
static uint32_t fev_load32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static void fev_store32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void fev_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  *a += *b; *d ^= *a; *d = fev_rotl32(*d, 16);
  *c += *d; *b ^= *c; *b = fev_rotl32(*b, 12);
  *a += *b; *d ^= *a; *d = fev_rotl32(*d, 8);
  *c += *d; *b ^= *c; *b = fev_rotl32(*b, 7);
}
static void fev_chacha_block(uint8_t out[64], const uint8_t key[32],
                             const uint8_t nonce[12], uint32_t counter) {
  uint32_t s[16], w[16];
  int i;
  s[0]=0x61707865u; s[1]=0x3320646eu; s[2]=0x79622d32u; s[3]=0x6b206574u;
  for (i = 0; i < 8; ++i) s[4 + i] = fev_load32(key + 4 * i);
  s[12] = counter;
  s[13] = fev_load32(nonce + 0);
  s[14] = fev_load32(nonce + 4);
  s[15] = fev_load32(nonce + 8);
  for (i = 0; i < 16; ++i) w[i] = s[i];
  for (i = 0; i < 10; ++i) {
    fev_qr(&w[0],&w[4],&w[8],&w[12]); fev_qr(&w[1],&w[5],&w[9],&w[13]);
    fev_qr(&w[2],&w[6],&w[10],&w[14]); fev_qr(&w[3],&w[7],&w[11],&w[15]);
    fev_qr(&w[0],&w[5],&w[10],&w[15]); fev_qr(&w[1],&w[6],&w[11],&w[12]);
    fev_qr(&w[2],&w[7],&w[8],&w[13]); fev_qr(&w[3],&w[4],&w[9],&w[14]);
  }
  for (i = 0; i < 16; ++i) fev_store32(out + 4 * i, w[i] + s[i]);
}
static void fev_chacha20_xor(uint8_t *out, const uint8_t *in, unsigned n,
                             const uint8_t key[32], const uint8_t nonce[12]) {
  unsigned off = 0;
  uint32_t counter = 1;
  while (off < n) {
    uint8_t block[64];
    unsigned i, take;
    fev_chacha_block(block, key, nonce, counter++);
    take = n - off; if (take > 64) take = 64;
    for (i = 0; i < take; ++i) out[off + i] = in[off + i] ^ block[i];
    off += take;
  }
}
static uint32_t fev_fnv1a32(const uint8_t *data, unsigned n) {
  uint32_t h = 2166136261u;
  unsigned i;
  for (i = 0; i < n; ++i) { h ^= data[i]; h *= 16777619u; }
  return h;
}
static char *fev_lazy_str(char *buf, unsigned buf_n, const uint8_t *ct,
                          unsigned n, const uint8_t nonce[12], uint32_t tag,
                          int *ready) {
  if (!*ready) {
    if (n + 1 > buf_n) return buf;
    fev_chacha20_xor((uint8_t *)buf, ct, n, fev_chacha_key, nonce);
    buf[n] = '\0';
    if (fev_fnv1a32((const uint8_t *)buf, n) != tag)
      memset(buf, 0, buf_n);
    *ready = 1;
  }
  return buf;
}
#endif /* FEV_CHACHA_RUNTIME_H */
/* === end fev ChaCha20 runtime === */

)";
  return OS.str();
}

} // namespace fev
