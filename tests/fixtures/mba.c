#include <stdio.h>

/* Host MBA(+flatten) oracle: (7*9)+4 = 67, then /2+1 = 34. */
static int mix(int a, int b) {
  int t = a * b;
  t = t + 4;
  t = t / 2;
  t = t + 1;
  return t;
}

int main(void) {
  int x = 7;
  int y = 9;
  int z = mix(x, y);
  printf("mba demo: %d\n", z);
  return z == 34 ? 0 : 1;
}
