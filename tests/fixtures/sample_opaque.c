#include <stdio.h>

static int square(int x) { return x * x; }

int main(void) {
  int a = 3;
  int b = 4;
  int c = a + b;
  c = square(c);
  printf("opaque demo: %d\n", c);
  return 0;
}
