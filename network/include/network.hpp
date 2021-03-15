#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

#define DEFAULT_BACKLOG 5
#define BUFFER_SIZE 1024             // buffer size in bytes.
#define DEFAULT_PUBLIC_DNS "8.8.8.8" // dns to fetch actual results from.
#define DEFAULT_PUBLIC_DNS_PORT 8081 // port number for public dns

struct dns_header {
  unsigned short int id;      // Identification number
  unsigned short int flags;   // flags for dns packet
  unsigned short int qdcount; // number of questions
  unsigned short int ancount; // number of answers
  unsigned short int nscount; // number of name server resource records
  unsigned short int
      arcount; // number of additional name server resourece records.
};

struct dns_question {
  std::string name;        // domain name of the to be quried
  unsigned short int type; // type
  unsigned short int cls;  // class
  unsigned int size;       // size in bytes of question inside packet
};

class Network {
public:
  unsigned int port;
  Network(int port);
  int init(const char *ip);
  int serve(unsigned int backlog = DEFAULT_BACKLOG);

  int test();
  ~Network();

  // static functions

private:
  int sockfd;
  sockaddr_in address;
  sockaddr_in public_dns;

  std::basic_string<unsigned char>
  query(const char *packet); // function queryies dns request to DEFAULT_DNS
};
