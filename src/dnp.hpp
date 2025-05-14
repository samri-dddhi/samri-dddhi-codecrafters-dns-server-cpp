// src/dns.hpp
#ifndef DNS_HPP
#define DNS_HPP

#include <cstdint>
#include <string>
#include <vector>

// Example DNS message structure
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
};

struct DNSQuestion {
    std::string qName;
    uint16_t qType;
    uint16_t qClass;
};

struct DNSAnswer {
    std::string name;
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    std::vector<uint8_t> rdata;
};

struct DNS_message {
    DNSHeader header;
    DNSQuestion question;
    DNSAnswer answer;
};

#endif // DNS_HPP
