#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <iostream>
#include <netinet/in.h>
#include <network.hpp>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <vector>

#define LOG_DEBUG 0
#define LOG_ERROR 1

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

Network::Network(int port) : port(port) {}

int Network::init(const char *ip) {
  // function creates socket and binds to port
  // returns 0 upon successful creation of socket
  // else returns -1
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    log("Failed to create socket", LOG_ERROR);
    return -1;
  }

  int flag = 0;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &flag,
                 sizeof(flag)) == -1) {
    log("Failed to set socket options", LOG_ERROR);
    return -1;
  }

  address.sin_port = htons(port);
  address.sin_family = AF_INET;
  inet_aton(ip, &address.sin_addr);

  if (bind(sockfd, (const struct sockaddr *)&address, sizeof(address)) == -1) {
    log("Failed to bind socket", LOG_ERROR);
    return -1;
  }
  return 0;
}

int Network::serve(unsigned int backlog) {
  std::string buffer(BUFFER_SIZE, 0);
  sockaddr_in client;
  int len = sizeof(client);
  recvfrom(sockfd, (char *)buffer.c_str(), sizeof(buffer), 0,
           (struct sockaddr *)&client, (socklen_t *)&len);

  return 0;
}

dns_question get_question(const unsigned char *packet) {
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
  return question;
}

int Network::test() {
  unsigned char packet[] = {
      0x68, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x70, 0x69, 0x6e, 0x67, 0x09, 0x61, 0x72, 0x63, 0x68, 0x6c, 0x69,
      0x6e, 0x75, 0x78, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1c, 0x00, 0x01,
  };

  struct dns_header *header = (struct dns_header *)packet;
  get_question(packet + sizeof(dns_header));
  return 0;
}

Network::~Network() {
  // deallocate all the resources
  if (sockfd > -1)
    close(sockfd);
}
