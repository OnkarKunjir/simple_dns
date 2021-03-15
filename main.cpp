#include <iostream>
#include <network.hpp>

int main() {
  Network network(8080);

  // initalize networking
  if (network.init("0.0.0.0") == -1) {
    return -1;
  }
  // network.serve();
  // network.test();

  network.test();
  return 0;
}
