#include <unistd.h>
#include <cstdio>

namespace some_namespace {
  static __attribute__((noinline)) int some_function(int x, int y) {
	  volatile int z = x + y;
	  return z;
  }
}

int main() {
	printf