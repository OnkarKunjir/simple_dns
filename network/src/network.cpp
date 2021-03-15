#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <network.hpp>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <vector>

#define LOG_DEBUG 0
#define LOG_ERROR 1

// utils function
void log(const char *msg, int log_level = 0) {
  switch (log_level) {
  case LOG_DEBUG:
    std::cout << "[DEBUG]\t";
    break;
  case LOG_ERROR:
    std::cout << "[ERROR]\n";
    break;
  }
  std::cout << msg << std::endl;
}

void print_sockaddr_in(const struct sockaddr_in *address) {
  // fucntion to print sockaddr_in
  std::cout << inet_ntoa(address->sin_addr) << ":" << ntohs(address->sin_port)
            << std::endl;
}

void print_dns_header(const struct dns_header *header) {
  printf("ID:\t%04x\n", ntohs(header->id));
  printf("Flags:\t%04x\n", ntohs(header->flags));
  std::cout << "qdcount:\t" << ntohs(header->qdcount) << std::endl;
  std::cout << "ancount:\t" << ntohs(header->ancount) << std::endl;
  std::cout << "nscount:\t" << ntohs(header->nscount) << std::endl;
  std::cout << "arcount:\t" << ntohs(header->arcount) << std::endl;
}

void print_dns_question(const struct dns_question *question) {
  std::cout << "Name:\t" << question->name << std::endl;
  printf("Type:\t%04x\n", question->type);
  printf("Class:\t%04x\n", question->cls);
}

dns_question get_dns_question(const unsigned char *packet) {
  // function extracts question form dns packet
  dns_question question;
  std::vector<unsigned char> labels;

  // extract all labels
  int offset = 0;
  unsigned char label_length = packet[offset++];

  while (label_length != 0) {
    for (int i = offset; i < offset + label_length; i++) {
      labels.push_back(packet[i]);
    }
    offset += label_length;
    label_length = packet[offset];
    offset++;
    if (label_length)
      labels.push_back('.');
  }

  question.name = std::string(labels.begin(), labels.end());

  question.type = packet[offset++];
  question.type = (question.type << 8) | packet[offset++];

  question.cls = packet[offset++];
  question.cls = (question.cls << 8) | packet[offset++];

  question.size = offset;
  return question;
}

// class functions
DNS::DNS(int port) : port(port) {}

DNS::~DNS() {
  // deallocate all the resources
  if (local_dns_sockfd > -1)
    close(local_dns_sockfd);
}

// Public functions

int DNS::init(const char *ip) {
  // function creates socket and binds to port
  // returns 0 upon successful creation of socket
  // else returns -1

  // initalize structure for this local dns
  local_dns_address.sin_port = htons(port);
  local_dns_address.sin_family = AF_INET;
  inet_aton(ip, &local_dns_address.sin_addr);

  if (create_socket(local_dns_sockfd, &local_dns_address) == -1) {
    return -1;
  }

  // initalize structure for public dns
  public_dns_address.sin_port = htons(53);
  public_dns_address.sin_family = AF_INET;
  inet_aton(DEFAULT_PUBLIC_DNS, &public_dns_address.sin_addr);

  return 0;
}

int DNS::serve() {
  // function starts serving dns queries.

  for (int i = 0; i < 1; i++) {
    std::basic_string<unsigned int> buffer(BUFFER_SIZE, 0);
    sockaddr_in client;

    int len = sizeof(client);
    int msg_len =
        recvfrom(local_dns_sockfd, (char *)buffer.c_str(), sizeof(buffer), 0,
                 (struct sockaddr *)&client, (socklen_t *)&len);

    if (msg_len == -1) {
      log("Failed to recive message", LOG_ERROR);
      return -1;
    }

    const dns_header *header = (const dns_header *)buffer.c_str();
    print_dns_header(header);

    dns_question question = get_dns_question(
        (const unsigned char *)buffer.c_str() + sizeof(dns_header));

    print_dns_question(&question);
  }
  return 0;
}

int DNS::test() {
  // unsigned char packet[] = {
  //     0x68, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  //     0x04, 0x70, 0x69, 0x6e, 0x67, 0x09, 0x61, 0x72, 0x63, 0x68, 0x6c, 0x69,
  //     0x6e, 0x75, 0x78, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1c, 0x00, 0x01,
  // };

  // struct dns_header *header = (struct dns_header *)packet;
  // print_dns_header(header);
  // dns_question question = get_dns_question(packet + sizeof(dns_header));
  // print_dns_question(&question);
  query(nullptr);
  return 0;
}

// private functions

int DNS::create_socket(int &sockfd, const struct sockaddr_in *address) {
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    log("Failed to create socket", LOG_ERROR);
    return -1;
  }
  int flag = 0;

  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &flag,
                 sizeof(flag)) == -1) {
    log("Faiiled to set socket options", LOG_ERROR);
    return -1;
  }

  if (bind(sockfd, (const struct sockaddr *)address, sizeof(sockaddr_in)) ==
      -1) {
    log("Failed to bind the socket", LOG_ERROR);
    return -1;
  }
  return 0;
}

std::basic_string<unsigned char> DNS::query(const char *packet) {
  std::basic_string<unsigned char> buffer = {
      0x68, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x70, 0x69, 0x6e, 0x67, 0x09, 0x61, 0x72, 0x63, 0x68, 0x6c, 0x69,
      0x6e, 0x75, 0x78, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1c, 0x00, 0x01,
  };
  int msg_len;
  sendto(local_dns_sockfd, buffer.c_str(), buffer.length(), 0,
         (const struct sockaddr *)&public_dns_address,
         sizeof(public_dns_address));

  struct sockaddr_in client;
  int len = sizeof(client);
  msg_len = recvfrom(local_dns_sockfd, (char *)buffer.c_str(), sizeof(buffer),
                     0, (struct sockaddr *)&client, (socklen_t *)&len);
  return buffer;
}
