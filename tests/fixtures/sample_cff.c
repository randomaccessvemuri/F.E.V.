#include <stdio.h>

int sum_to(int n) {
  int i = 1;
  int s = 0;
  while (i <= n) {
    if (i == 3) {
      i++;
      continue;
    }
    s += i;
    if (s > 100)
      break;
    i++;
  }
  return s;
}

int main(void) {
  int x = 0;
  for (int k = 0; k < 3; k++)
    x += k;
  switch (x) {
  case 0:
    x = 1;
    break;
  case 3:
    x = sum_to(5);
    break;
  default:
    x = -1;
    break;
  }
  printf("laszlo cff: x=%d\n", x);
  return x == 12 ? 0 : 1;
}
