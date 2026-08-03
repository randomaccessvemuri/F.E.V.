/*
 * Host buffer-integrity fixture for FEV interpass_validate.
 * Known payloads (≥8 bytes). After each pipeline step, FEV restores via
 * injected ensure/unscramble calls, then this main checks FNV tags.
 */
#include <stdint.h>
#include <stdio.h>

unsigned char buf_alpha[] = {
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x01, 0x23, 0x45,
    0x67, 0x89, 0xab, 0xcd, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
    0xba, 0xbe, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

unsigned char buf_beta[] = "FEV-buf-probe!";

static uint32_t _fev_probe_fnv(const uint8_t *p, unsigned n) {
  uint32_t h = 2166136261u;
  for (unsigned i = 0; i < n; ++i) {
    h ^= (uint32_t)p[i];
    h *= 16777619u;
  }
  return h;
}

int main(void) {
  /* FEV injects decrypt/unscramble ensures at the top of main. */
  uint32_t ha = _fev_probe_fnv(buf_alpha, (unsigned)sizeof(buf_alpha));
  uint32_t hb = _fev_probe_fnv(buf_beta, (unsigned)sizeof(buf_beta));
  if (ha != 0xb5376373u) {
    fprintf(stderr, "FAIL: buf_alpha fnv=%08x\n", ha);
    return 2;
  }
  if (hb != 0x02a29b14u) {
    fprintf(stderr, "FAIL: buf_beta fnv=%08x\n", hb);
    return 3;
  }
  if (buf_alpha[0] != 0x10u || buf_alpha[31] != 0x88u ||
      buf_beta[0] != (unsigned char)'F' ||
      buf_beta[sizeof(buf_beta) - 1] != 0) {
    fprintf(stderr, "FAIL: magic bytes\n");
    return 4;
  }
  printf("buffers ok alpha_fnv=%08x beta_fnv=%08x\n", ha, hb);
  return 0;
}
