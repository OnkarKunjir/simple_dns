#pragma once

#include <arpa/inet.h>
#include <functional>
#include <netinet/in.h>
#include <string>

#define DEFAULT_PUBLIC_DNS "8.8.8.8" // dns to fetch actual results from.
#define DEFAULT_PUBLIC_DNS_PORT 5353 // port number for public dns
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

struct dns_answer {
  std::string name;                       // domain name of the to be quried
  unsigned short int type;                // type
  unsigned short int cls;                 // class
  unsigned short int ttl;                 // time to live
  unsigned short int rdlength;            // length of rdata
  std::basic_string<unsigned char> rdata; // record data
  unsigned int size; // size in bytes of question inside packet
};

class DNS {
public:
  unsigned int port;
  DNS(int port);
  int init(const char *ip);
  int serve(std::function<bool(const char *)> filter);

  int test();
  ~DNS();

  // static functions

private:
  int local_dns_sockfd, public_dns_sockfd;
  sockaddr_in local_dns_in_address;  // address to serve
  sockaddr_in local_dns_out_address; // address to query to public dns
  sockaddr_in public_dns_address;    // address of public dns

  int create_socket(int &sockfd, const struct sockaddr_in *address);
  int query(const unsigned char *send_buffer, int size,
            char unsigned *recv_buffer);
};
