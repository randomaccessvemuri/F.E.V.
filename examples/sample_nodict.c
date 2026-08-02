/* === fev ChaCha20 runtime (generated) === */
#ifndef FEV_CHACHA_RUNTIME_H
#define FEV_CHACHA_RUNTIME_H
#include <stdint.h>
#include <string.h>

static const uint8_t fev_chacha_key[32] = {0xc0u, 0x1eu, 0xdeu, 0x99u, 0xa7u, 0xceu, 0x00u, 0x90u, 0x4bu, 0x38u, 0x16u, 0xccu, 0x0au, 0x81u, 0xe1u, 0x0au, 0x75u, 0xecu, 0xcdu, 0x65u, 0xb8u, 0xd0u, 0xb7u, 0x99u, 0xfcu, 0x14u, 0x9eu, 0x4bu, 0x4eu, 0x74u, 0x45u, 0x10u};

static uint32_t fev_rotl32(uint32_t v, int n) {
  return (v << n) | (v >> (32 - n));
}
static uint32_t fev_load32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static void fev_store32(uint8_t *p, uint32_t v) {
  /* László-style CFF: XOR-encoded volatile dispatcher */
  volatile unsigned _fev_sw0 = 0xab1f643bu;
  volatile unsigned _fev_mod = 0u;
  goto _fev_L0;
_fev_L0:
  while (_fev_sw0 != 0xa600ac1cu) {
    switch (_fev_sw0 ^ 0xa5bf15a5u) {
    case 245395870u: {
      p[0] = (uint8_t)v;
      p[1] = (uint8_t)(v >> 8);
      p[2] = (uint8_t)(v >> 16);
      p[3] = (uint8_t)(v >> 24);
      _fev_sw0 = 0xa600ac1cu + _fev_mod;
      break;
    }
    default: {
      volatile unsigned _fev_trap = _fev_sw0; (void)_fev_trap;
      _fev_sw0 = 0xa600ac1cu;
      break;
    }
    }
  }
}

static void fev_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
  /* László-style CFF: XOR-encoded volatile dispatcher */
  volatile unsigned _fev_sw0 = 0xa1b8258eu;
  volatile unsigned _fev_mod = 0u;
  goto _fev_L0;
_fev_L0:
  while (_fev_sw0 != 0xa4af8c6cu) {
    switch (_fev_sw0 ^ 0xa5be15a5u) {
    case 67514411u: {
      *a += *b;
      *d ^= *a;
      *d = fev_rotl32(*d, 16);
      *c += *d;
      *b ^= *c;
      *b = fev_rotl32(*b, 12);
      *a += *b;
      *d ^= *a;
      *d = fev_rotl32(*d, 8);
      *c += *d;
      *b ^= *c;
      *b = fev_rotl32(*b, 7);
      _fev_sw0 = 0xa4af8c6cu + _fev_mod;
      break;
    }
    default: {
      volatile unsigned _fev_trap = _fev_sw0; (void)_fev_trap;
      _fev_sw0 = 0xa4af8c6cu;
      break;
    }
    }
  }
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
  uint32_t h;
  unsigned int i;
  /* László-style CFF: XOR-encoded volatile dispatcher */
  volatile unsigned _fev_sw0 = 0xafd7461du;
  volatile unsigned _fev_mod = 0u;
  goto _fev_L0;
_fev_L0:
  while (_fev_sw0 != 0xa08313d0u) {
    switch (_fev_sw0 ^ 0xa5bb15a1u) {
    case 174871484u: {
      h = 2166136261u;
      _fev_sw0 = 0xaddd5089u + _fev_mod;
      break;
    }
    case 140920104u: {
      i = 0;
      _fev_sw0 = 0xaf65d39du + _fev_mod;
      break;
    }
    case 199644439u: {
      h ^= data[i];
      h *= 16777619u;
      _fev_sw0 = 0xa4007ef7u + _fev_mod;
      break;
    }
    case 29059926u: {
      ++i;
      _fev_sw0 = 0xaf65d39du + _fev_mod;
      break;
    }
    case 182371900u: {
      if (i < n)
        _fev_sw0 = 0xae5d40b6u + _fev_mod;
      else
        _fev_sw0 = 0xa905ff98u + _fev_mod;
      break;
    }
    case 213838393u: {
      return h;
    }
    default: {
      volatile unsigned _fev_trap = _fev_sw0; (void)_fev_trap;
      _fev_sw0 = 0xa08313d0u;
      break;
    }
    }
  }
  __builtin_unreachable();
}

static char *fev_lazy_str(char *buf, unsigned buf_n, const uint8_t *ct,
                          unsigned n, const uint8_t nonce[12], uint32_t tag,
                          int *ready) {
  /* László-style CFF: XOR-encoded volatile dispatcher */
  volatile unsigned _fev_sw0 = 0xa3691a22u;
  volatile unsigned _fev_mod = 0u;
  goto _fev_L0;
_fev_L0:
  while (_fev_sw0 != 0xaaf6aed8u) {
    switch (_fev_sw0 ^ 0xa5ba15a1u) {
    case 93338718u: {
      memset(buf, 0, buf_n);
      _fev_sw0 = 0xaa824061u + _fev_mod;
      break;
    }
    case 201474039u: {
      return buf;
    }
    case 114495363u: {
      if (!*ready)
        _fev_sw0 = 0xa2bbe6afu + _fev_mod;
      else
        _fev_sw0 = 0xa36c3079u + _fev_mod;
      break;
    }
    case 17440087u: {
      if (fev_fnv1a32((const uint8_t *)buf, n) != tag)
        _fev_sw0 = 0xa02a29ffu + _fev_mod;
      else
        _fev_sw0 = 0xaa824061u + _fev_mod;
      break;
    }
    case 114697688u: {
      return buf;
    }
    case 242065134u: {
      fev_chacha20_xor((uint8_t *)buf, ct, n, fev_chacha_key, nonce);
      buf[n] = '\0';
      _fev_sw0 = 0xa4b008f6u + _fev_mod;
      break;
    }
    case 255350208u: {
      *ready = 1;
      _fev_sw0 = 0xa36c3079u + _fev_mod;
      break;
    }
    case 117568270u: {
      if (n + 1 > buf_n)
        _fev_sw0 = 0xa9b82a56u + _fev_mod;
      else
        _fev_sw0 = 0xabd78b4fu + _fev_mod;
      break;
    }
    default: {
      volatile unsigned _fev_trap = _fev_sw0; (void)_fev_trap;
      _fev_sw0 = 0xaaf6aed8u;
      break;
    }
    }
  }
  __builtin_unreachable();
}

#endif /* FEV_CHACHA_RUNTIME_H */
/* === end fev ChaCha20 runtime === */

static char *fev_str_0(void) {
  static char buf[24];
  static int ready;
  static const uint8_t ct[23] = {0xe7u, 0xf6u, 0xedu, 0x11u, 0x6fu, 0x11u, 0x57u, 0xa4u, 0x29u, 0xfeu, 0x24u, 0x25u, 0x66u, 0x8eu, 0xacu, 0x4au, 0x2au, 0x66u, 0x89u, 0x4au, 0x31u, 0x52u, 0xebu};
  static const uint8_t nonce[12] = {0x14u, 0xccu, 0x50u, 0x7fu, 0xb9u, 0x79u, 0x37u, 0x9eu, 0x01u, 0xb0u, 0x1au, 0x00u};
  return fev_lazy_str(buf, sizeof(buf), ct, 23u, nonce, 0xe4a66e39u, &ready);
}

#include <stdio.h>

static int _fev_impl_add(int a, int b) { return ((a) ^ (b)) + (2 * ((a) & (b))); }
static int add(int a, int b) {
  return _fev_impl_add(a, b);
}


int main(void) {
  int x;
  int y;
  int s;
  /* László-style CFF: XOR-encoded volatile dispatcher */
  volatile unsigned _fev_sw0 = 0xa7e3599bu;
  volatile unsigned _fev_mod = 0u;
  goto _fev_L0;
_fev_L0:
  while (_fev_sw0 != 0xa4901269u) {
    switch (((_fev_sw0) | (0xa5b815a3u)) - ((_fev_sw0) & (0xa5b815a3u))) {
    case 175505768u: {
      return 0;
    }
    case 39537720u: {
      x = 2;
      y = 3;
      s = ((x) ^ (y)) + (2 * ((x) & (y)));
      s = add(s, 0);
      printf(fev_str_0(), s);
      _fev_sw0 = ((0xafce14cbu) ^ (_fev_mod)) + (2 * ((0xafce14cbu) & (_fev_mod)));
      break;
    }
    default: {
      volatile unsigned _fev_trap = _fev_sw0; (void)_fev_trap;
      _fev_sw0 = 0xa4901269u;
      break;
    }
    }
  }
  __builtin_unreachable();
}

