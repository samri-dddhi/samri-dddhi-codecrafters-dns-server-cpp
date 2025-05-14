#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
using namespace std;
struct DNS_header
{
    uint16_t ID;
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};
struct DNS_question
{
    string QNAME;
    uint16_t QTYPE;
    uint16_t QCLASS;
};
struct DNS_answer
{
    string NAME;
    uint16_t TYPE;
    uint16_t CLASS;
    uint32_t TTL;
    uint16_t RDLENGTH;
    uint32_t RDATA;
};
struct DNS_message
{
    DNS_header header;
    DNS_question question;
    DNS_answer answers;
};
DNS_message make_message()
{
    DNS_message message;
    message.header.ID = htons(1234);
    message.header.flags = htons(1 << 15);
    message.header.QDCOUNT = htons(1);
    message.header.ANCOUNT = htons(1);
    message.header.NSCOUNT = htons(0);
    message.header.ARCOUNT = htons(0);
    string s = "codecrafters";
    message.question.QNAME += char(s.size());
    message.question.QNAME += s;
    s = "io";
    message.question.QNAME += char(s.size());
    message.question.QNAME += s;
    message.question.QTYPE = htons(1);
    message.question.QCLASS = htons(1);
    message.answers.NAME = message.question.QNAME;
    message.answers.TYPE = htons(1);
    message.answers.CLASS = htons(1);
    message.answers.TTL = htonl(60);
    message.answers.RDLENGTH = htons(4);
    message.answers.RDATA = htons(0x08080808);
    return message;
}
int main()
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    // Disable output buffering
    setbuf(stdout, NULL);
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;
    // Uncomment this block to pass the first stage
    int udpSocket;
    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }
    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }
    sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(2053),
        .sin_addr = {htonl(INADDR_ANY)},
    };
    if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }
    int bytesRead;
    char buffer[1024];
    struct sockaddr_in clientAddress;
    socklen_t clientAddrLen = sizeof(clientAddress);
    while (true)
    {
        // Receive data
        bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), &clientAddrLen);
        if (bytesRead == -1)
        {
            perror("Error receiving data");
            break;
        }
        buffer[bytesRead] = '\0';
        std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;
        // Create an empty response
        DNS_message response = make_message();
        const uint16_t total_buffer_size = sizeof(response.header) + response.question.QNAME.size() + 5 + response.answers.NAME.size() + 10 + 5;
        unsigned char *response_bytes = new unsigned char[total_buffer_size + 1];
        memset(response_bytes, 0, total_buffer_size + 1);
        memcpy(response_bytes, (void *)&response.header, 12);
        auto ht = sizeof(response.header);
        response.question.QNAME.copy((char *)(response_bytes + ht), response.question.QNAME.size());
        memcpy(response_bytes + ht + response.question.QNAME.size() + 1, (void *)&response.question.QTYPE, 2);
        memcpy(response_bytes + ht + response.question.QNAME.size() + 3, (void *)&response.question.QCLASS, 2);
        ht = ht + response.question.QNAME.size() + 5;
        response.answers.NAME.copy((char *)(response_bytes + ht), response.answers.NAME.size());
        ht = ht + response.answers.NAME.size();
        memcpy(response_bytes + ht + 1, (void *)&response.answers.TYPE, 2);
        memcpy(response_bytes + ht + 3, (void *)&response.answers.CLASS, 2);
        memcpy(response_bytes + ht + 5, (void *)&response.answers.TTL, 4);
        memcpy(response_bytes + ht + 9, (void *)&response.answers.RDLENGTH, 2);
        memcpy(response_bytes + ht + 11, (void *)&response.answers.RDATA, 4);
        // Send response
        if (sendto(udpSocket, response_bytes, total_buffer_size, 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1)
        {
            perror("Failed to send response");
        }
    }
    close(udpSocket);
    return 0;
}