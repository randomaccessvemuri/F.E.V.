#include <stdio.h>

static int add(int a, int b) { return a + b; }

int main(void) {
  int x = 2;
  int y = 3;
  int s = x + y;
  s = add(s, 0);
  printf("hello from fev: sum=%d\n", s);
  return 0;
}
