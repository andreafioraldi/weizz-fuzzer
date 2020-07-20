#include <stdlib.h>

int main() {

  int a[2];
  read(0, a, sizeof(int)*2);
  
  if (a[0] == 0x1337) {
      if (a[1] == 0xdeadbeef) abort();
  }

}
