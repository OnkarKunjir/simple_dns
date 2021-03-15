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

  // socket for processing local queries
  local_dns_in_address.sin_family = AF_INET;
  local_dns_in_address.sin_port = htons(port);
  inet_aton(ip, &local_dns_in_address.sin_addr);

  if (create_socket(local_dns_sockfd, &local_dns_in_address) == -1) {
    log("Failed to create local dns socket", LOG_ERROR);
    return -1;
  }

  // socket for quering public dns
  local_dns_out_address.sin_family = AF_INET;
  local_dns_out_address.sin_port = htons(DEFAULT_PUBLIC_DNS_PORT);
  inet_aton(ip, &local_dns_out_address.sin_addr);
  if (create_socket(public_dns_sockfd, &local_dns_out_address) == -1) {
    log("Failed to create public dns socket", LOG_ERROR);
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

  while (true) {
    std::basic_string<unsigned char> buffer(BUFFER_SIZE, 0);
    sockaddr_in client;

    int len = sizeof(client);
    int msg_len =
        recvfrom(local_dns_sockfd, (char *)buffer.c_str(), BUFFER_SIZE, 0,
                 (struct sockaddr *)&client, (socklen_t *)&len);

    if (msg_len == -1) {
      log("Failed to recive message", LOG_ERROR);
      return -1;
    }

    std::basic_string<unsigned char> response =
        query((const char *)buffer.c_str(), msg_len);

    sendto(local_dns_sockfd, (const char *)response.c_str(), response.length(),
           0, (const struct sockaddr *)&client, sizeof(client));
  }
  return 0;
}

int DNS::test() {
  unsigned char packet[] = {
      0x68, 0xac, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x04, 0x70, 0x69, 0x6e, 0x67, 0x09, 0x61, 0x72, 0x63, 0x68, 0x6c, 0x69,
      0x6e, 0x75, 0x78, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1c, 0x00, 0x01,
  };

  // unsigned char packet[] = {
  //     0x2e, 0xbc, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  //     0x11, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74,
  //     0x79, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x07, 0x67, 0x73, 0x74, 0x61, 0x74,
  //     0x69, 0x63, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
  // };

  struct dns_header *header = (struct dns_header *)packet;
  print_dns_header(header);
  dns_question question = get_dns_question(packet + sizeof(dns_header));
  print_dns_question(&question);

  std::basic_string<unsigned char> response =
      query((const char *)packet, sizeof(packet));

  std::cout << "\nRESPONSE\n";
  header = (struct dns_header *)response.c_str();
  print_dns_header(header);
  question = get_dns_question(response.c_str() + sizeof(dns_header));
  print_dns_question(&question);

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

std::basic_string<unsigned char> DNS::query(const char *packet, int size) {
  // function queries to public dns server and returns response.

  // dns packet
  std::basic_string<unsigned char> buffer(BUFFER_SIZE, 0);
  int msg_len = 0;
  sendto(public_dns_sockfd, packet, size, 0,
         (const struct sockaddr *)&public_dns_address,
         sizeof(public_dns_address));

  int addr_size = sizeof(public_dns_address);

  msg_len =
      recvfrom(public_dns_sockfd, (char *)buffer.c_str(), BUFFER_SIZE, 0,
               (struct sockaddr *)&public_dns_address, (socklen_t *)&addr_size);

  return buffer;
}
