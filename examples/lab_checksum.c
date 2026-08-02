/*
 * Benign lab sample for FEV + Dx_Trojan EDR / pipeline testing.
 *
 * FNV-1a over a fixed banner (char literals, no globals / stack arrays),
 * then a small integer mixer. Exit status = low 8 bits of the digest.
 *
 * No network, files, registry, injection, or WinAPI.
 *
 * Expected (no argv): exit 242
 */
#include <stdint.h>

static uint32_t step(uint32_t h, unsigned char c) {
  h ^= c;
  h *= 16777619u;
  return h;
}

static uint32_t mix(uint32_t x) {
  uint32_t a = x;
  for (int i = 0; i < 8; ++i) {
    if ((a & 1u) == 0)
      a = (a >> 1) ^ 0xA5A5A5A5u;
    else
      a = (a * 33u) + 7u;
  }
  return a;
}

/* Hash of "DxTrojan lab checksum - benign" (30 bytes). */
static uint32_t hash_banner(uint32_t h) {
  h = step(h, 'D');
  h = step(h, 'x');
  h = step(h, 'T');
  h = step(h, 'r');
  h = step(h, 'o');
  h = step(h, 'j');
  h = step(h, 'a');
  h = step(h, 'n');
  h = step(h, ' ');
  h = step(h, 'l');
  h = step(h, 'a');
  h = step(h, 'b');
  h = step(h, ' ');
  h = step(h, 'c');
  h = step(h, 'h');
  h = step(h, 'e');
  h = step(h, 'c');
  h = step(h, 'k');
  h = step(h, 's');
  h = step(h, 'u');
  h = step(h, 'm');
  h = step(h, ' ');
  h = step(h, '-');
  h = step(h, ' ');
  h = step(h, 'b');
  h = step(h, 'e');
  h = step(h, 'n');
  h = step(h, 'i');
  h = step(h, 'g');
  h = step(h, 'n');
  return h;
}

int main(void) {
  uint32_t h = 2166136261u;
  h = hash_banner(h);
  h = mix(h);
  return (int)(h & 0xffu);
}
