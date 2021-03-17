#include <fstream>
#include <functional>
#include <iostream>
#include <network.hpp>
#include <string>
#include <unordered_map>

int load_blacklist(std::unordered_map<std::string, char> &domain,
                   const char *file_name) {
  std::ifstream domain_file(file_name);
  if (!domain_file.is_open())
    return -1;

  std::string line;
  while (std::getline(domain_file, line)) {
    domain[line] = 1;
  }
  domain_file.close();
  return 0;
}

int main() {
  std::unordered_map<std::string, char> domains;
  load_blacklist(domains, "blacklist.txt");

  auto filter = [&domains](const char *s) -> bool {
    return domains.count(s) > 0;
  };

  DNS dns(8080);
  dns.init("0.0.0.0");
  dns.serve(filter);

  // dns.test();
  return 0;
}
