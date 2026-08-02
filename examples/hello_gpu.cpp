/*
 * Benign Dx_Trojan demo input.
 * Message is intentional plaintext here; FEV encrypt-strings (and friends)
 * should scrub it from the rewritten source / PE.
 *
 * Build note: Windows-oriented so mingw PE + later Dx_Trojan GPU path share one TU.
 */
#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

/* Loki/Dx_Trojan lifter entry — keep a small numeric kernel for VM path. */
extern "C" long target_function(unsigned long seed) {
  unsigned long x = seed ^ 0xA5A5A5A5ul;
  x = (x << 3) | (x >> 29);
  x ^= 0xC0FFEEul;
  x += seed;
  return (long)x;
}

int main(int argc, char **argv) {
  unsigned long seed = 42;
  if (argc > 1) {
    seed = 0;
    for (const char *p = argv[1]; *p; ++p)
      seed = seed * 131ul + (unsigned char)*p;
  }

  const long token = target_function(seed);
  (void)token;

  /* This literal is the FEV encrypt-strings target. */
  puts("Encrypted Hello from the GPU");
  return 0;
}
