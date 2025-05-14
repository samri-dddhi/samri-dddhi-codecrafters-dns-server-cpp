#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
struct Header{
    uint16_t id, flags, qdcount, ancount, nscount, arcount;
    void to_big_endian(){
        id = htons(id);
        flags = htons(flags);
        qdcount = htons(qdcount);
        ancount = htons(ancount);
        nscount = htons(nscount);
        arcount = htons(arcount);
    }
};
std::string encode_domain_name(const std::string &domain){
    std::string temp, res;
        for (char c : domain){
            if (c == '.'){
                res.push_back(temp.size());
                res += temp;
                temp = "";
            }else{
                temp.push_back(c);
            }
        }
        res.push_back(temp.size());
        res += temp;
        res.push_back(0);
        return res;
}
struct Question{
    std::string name;
    uint16_t t, c;
    Question(std::string &domain, uint16_t type, uint16_t cl){
        name = encode_domain_name(domain);
        t = type;
        c = cl;
    }
    void to_big_endian(){
        t = htons(t);
        c = htons(c);
    }
};
struct Answer{
    std::string name;
    uint16_t t, c;
    uint32_t ttl;
    uint16_t rdlength;
    std::string rdata;
    void to_big_endian(){
        t = htons(t);
        c = htons(c);
        ttl = htons(ttl);
        rdlength = htons(rdlength);
    }
};
uint64_t serialize(char *dest, Header header, Question question, Answer answer){
    // Header
    memcpy(dest, &header, sizeof(Header));
    uint64_t offset = sizeof(Header);
    // Question
    memcpy(dest+offset,question.name.data(),question.name.size());
    offset += question.name.size();
    memcpy(dest+offset,&question.t,sizeof(question.t));
    offset += sizeof(question.t);
    memcpy(dest+offset,&question.c,sizeof(question.c));
    offset += sizeof(question.c);
    // Answer
    memcpy(dest+offset,answer.name.data(),answer.name.size());
    offset += answer.name.size();
    memcpy(dest+offset,&answer.t,sizeof(answer.t));
    offset += sizeof(answer.t);
    memcpy(dest+offset,&answer.c,sizeof(answer.c));
    offset += sizeof(answer.c);
    memcpy(dest+offset,&answer.ttl,sizeof(answer.ttl));
    offset += sizeof(answer.ttl);
    memcpy(dest+offset,&answer.rdlength,sizeof(answer.rdlength));
    offset += sizeof(answer.rdlength);
    memcpy(dest+offset,&answer.rdata,answer.rdata.size());
    offset += answer.rdata.size();
    return offset;
}
void unserialize(char *buf, Header &header){
    uint64_t offset = 0;
    memcpy(&header,buf,sizeof(header));
    offset += 12;
}
int main() {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    // Disable output buffering
    setbuf(stdout, NULL);
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    std::cout << "Logs from your program will appear here!" << std::endl;
   int udpSocket;
   struct sockaddr_in clientAddress;
   udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
   if (udpSocket == -1) {
       std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
       return 1;
   }
   // Since the tester restarts your program quite often, setting REUSE_PORT
   // ensures that we don't run into 'Address already in use' errors
   int reuse = 1;
   if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
       std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
       return 1;
   }
   sockaddr_in serv_addr = { .sin_family = AF_INET,
                             .sin_port = htons(2053),
                             .sin_addr = { htonl(INADDR_ANY) },
                           };
   if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
       std::cerr << "Bind failed: " << strerror(errno) << std::endl;
       return 1;
   }
   int bytesRead;
   char buffer[512];
   socklen_t clientAddrLen = sizeof(clientAddress);
   while (true) {
       // Receive data
       bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
       if (bytesRead == -1) {
           perror("Error receiving data");
           break;
       }
       buffer[bytesRead] = '\0';
       std::cout << "Received " << bytesRead << " bytes: " << buffer << std::endl;
       // Parse request
       Header request_header;
       unserialize(buffer, request_header);
       request_header.to_big_endian();
       // Create an empty response
        uint8_t opcode = request_header.flags >> 11 & 0b1111, rd = request_header.flags >> 8 & 1, rcode = opcode == 0 ? 0 : 4;
        Header header = {request_header.id, 1<<15 | opcode << 11 | rd << 8 | rcode, 1, 1, 0, 0};
        header.to_big_endian();
        std::string domain_name = "codecrafters.io";
        Question question = Question(domain_name, 1, 1);
        question.to_big_endian();
        Answer answer = {encode_domain_name(domain_name), 1, 1, 60, 4, ""};
        answer.to_big_endian();
        for (int i = 0; i < 4; i++) answer.rdata.push_back(8);
        char response[512];
        uint64_t size = serialize(response, header, question, answer);
        
        // Send header
        if (sendto(udpSocket, &response, size, 0, reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
           perror("Failed to send response");
        }
    }
    close(udpSocket);
    return 0;
}