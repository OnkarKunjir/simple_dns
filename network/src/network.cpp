#include <arpa/inet.h>
#include <asm-generic/socket.h>
#include <functional>
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
    std::cout << "[ERROR]\t";
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

dns_answer generate_default_dns_answer(const struct dns_question *question) {
  dns_answer answer;
  answer.name = question->name;
  answer.type = question->type;
  answer.cls = question->cls;
  answer.ttl = 10;

  if (answer.type == 1) {
    // ipv4
    answer.rdlength = 4;
    answer.rdata = {0x00, 0x00, 0x00, 0x00};
  }
  return answer;
}

// www.google.com
// .www.google.com

// 0x04, 0x70, 0x69, 0x6e, 0x67, 0x09, 0x61, 0x72, 0x63, 0x68, 0x6c, 0x69, 0x6e,
// 0x75, 0x78, 0x03, 0x6f, 0x72, 0x67

void split_domain(const char *src, unsigned char *dst, int size) {
  int dst_index = 1, label_size = 0, label_index = 0;
  for (int i = 1; i < size + 1; i++) {
    if (src[i - 1] != '.') {
      dst[i] = src[i - 1];
      label_size++;
    } else {
      dst[label_index] = label_size;
      label_size = 0;
      label_index = i;
    }
  }
  dst[label_index] = label_size;
}

int get_dns_answer_packet(const struct dns_header *header,
                          const struct dns_question *question,
                          unsigned char *packet) {

  int size = sizeof(dns_header);

  const unsigned char *request_pkt = (const unsigned char *)header;
  // building header
  for (int i = 0; i < size; i++)
    packet[i] = request_pkt[i];
  packet[2] = 0x80;
  packet[3] = 0x03;
  packet[7] = 0x01; // sent number of answers to 1

  // build the question section
  split_domain(question->name.c_str(), packet + size, question->name.length());
  size += question->name.length() + 1;
  packet[size++] = 0;

  packet[size++] = (question->type >> 8);
  packet[size++] = (question->type);

  packet[size++] = (question->cls >> 8);
  packet[size++] = (question->cls);

  // building answer section.
  // pointer to domain name
  packet[size++] = 0xc0;
  packet[size++] = 0x0c;
  // type
  // packet[size++] = (question->type >> 8);
  // packet[size++] = (question->type);
  packet[size++] = 0x00;
  packet[size++] = 0x01;
  // class
  packet[size++] = (question->cls >> 8);
  packet[size++] = (question->cls);
  // ttl
  packet[size++] = 0x00;
  packet[size++] = 0x00;
  packet[size++] = 0x00;
  packet[size++] = 0xae;
  // rdlenght
  packet[size++] = 0x00;
  packet[size++] = 0x04;
  // ip address
  packet[size++] = 0x00;
  packet[size++] = 0x00;
  packet[size++] = 0x00;
  packet[size++] = 0x00;

  return size;
}

// class functions
DNS::DNS(int port) : port(port) { continue_serving = true; }

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

int DNS::serve(std::function<bool(const char *)> filter) {
  // function starts serving dns queries.
  while (true) {
    unsigned char buffer[BUFFER_SIZE], response[BUFFER_SIZE];
    sockaddr_in client;
    int len = sizeof(client), msg_len = 0;

    bool send_default = false; // send default response

    // recv packet
    msg_len = recvfrom(local_dns_sockfd, buffer, BUFFER_SIZE, 0,
                       (struct sockaddr *)&client, (socklen_t *)&len);
    // check packet for blocked ip addresses

    const struct dns_header *header = (const struct dns_header *)buffer;
    struct dns_question question;
    if (ntohs(header->qdcount) == 1) {
      // TODO: add support for packets with multiple questions.
      question = get_dns_question(buffer + sizeof(dns_header));
      if (filter(question.name.c_str())) {
        // found domain in blacklist
        send_default = true;
      }
    }

    // std::cout << question.name << std::endl;
    // send_default = true;
    // send response
    if (send_default) {
      // send default response

      msg_len = get_dns_answer_packet(header, &question, response);
      std::cout << "Blocking\t" << question.name << std::endl;

    } else {
      // query the public dns server.
      msg_len = query(buffer, msg_len, response);
    }

    if (msg_len > -1)
      sendto(local_dns_sockfd, response, msg_len, 0,
             (const struct sockaddr *)&client, sizeof(client));
  }

  return 0;
}

int DNS::test() {
  unsigned char packet[] = {
      0x63, 0xc4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x07, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65,
      0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
  };

  struct dns_header *header = (struct dns_header *)packet;
  // print_dns_header(header);
  dns_question question = get_dns_question(packet + sizeof(dns_header));
  // print_dns_question(&question);

  // struct dns_answer answer = generate_default_dns_answer(&question);

  unsigned char answer[BUFFER_SIZE];
  // for (int i = 0; i < BUFFER_SIZE; i++)
  //   answer[i] = 0;

  int len = get_dns_answer_packet(header, &question, answer);
  query(answer, len, answer);

  // std::basic_string<unsigned char> response =
  //     query((const char *)packet, sizeof(packet));

  // std::cout << "\nRESPONSE\n";
  // header = (struct dns_header *)response.c_str();
  // print_dns_header(header);
  // question = get_dns_question(response.c_str() + sizeof(dns_header));
  // print_dns_question(&question);

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

int DNS::query(const unsigned char *send_buffer, int size,
               char unsigned *recv_buffer) {
  // function queries to public dns server and returns response.

  // dns packet
  int msg_len = 0;
  sendto(public_dns_sockfd, send_buffer, size, 0,
         (const struct sockaddr *)&public_dns_address,
         sizeof(public_dns_address));

  int addr_size = sizeof(public_dns_address);

  msg_len =
      recvfrom(public_dns_sockfd, recv_buffer, BUFFER_SIZE, 0,
               (struct sockaddr *)&public_dns_address, (socklen_t *)&addr_size);

  return msg_len;
}
