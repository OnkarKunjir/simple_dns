#include <iostream>
#include <network.hpp>

int main() {
  Network network(8080);

  // initalize networking
  if (network.init("127.0.0.1") == -1) {
    return -1;
  }
  network.serve();

  return 0;
}
