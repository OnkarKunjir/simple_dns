#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

#define DEFAULT_PUBLIC_DNS "8.8.8.8" // dns to fetch actual results from.
#define DEFAULT_PUBLIC_DNS_PORT 8081 // port number for public dns
#define BUFFER_SIZE 1024             // buffer size in bytes.

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

class DNS {
public:
  unsigned int port;
  DNS(int port);
  int init(const char *ip);
  int serve();

  int test();
  ~DNS();

  // static functions

private:
  int local_dns_sockfd, public_dns_sockfd;
  sockaddr_in local_dns_address;
  sockaddr_in public_dns_address;

  int create_socket(int &sockfd, const struct sockaddr_in *address);
  std::basic_string<unsigned char>
  query(const char *packet); // function queryies dns request to DEFAULT_DNS
};
