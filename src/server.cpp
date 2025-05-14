#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <arpa/inet.h>
#include <algorithm>
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
struct Question{
    std::string name;
    uint16_t t, c;
    Question(){
        name = "";
        t = 0;
        c = 0;
    }
    Question(std::string domain, uint16_t type, uint16_t cl){
        name = domain;
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
uint64_t serialize_question(char *dest, Question question, uint64_t offset){
    memcpy(dest+offset,question.name.data(),question.name.size());
    offset += question.name.size();
    memcpy(dest+offset,&question.t,sizeof(question.t));
    offset += sizeof(question.t);
    memcpy(dest+offset,&question.c,sizeof(question.c));
    offset += sizeof(question.c);
    return offset;
}
uint64_t serialize_answer(char *dest, Answer answer, uint64_t offset){
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
    memcpy(dest+offset,answer.rdata.data(),answer.rdata.size());
    offset += answer.rdata.size();
    return offset;
}
uint64_t serialize(char *dest, Header header, std::vector<Question> &questions, std::vector<Answer> answers){
    // Header
    memcpy(dest, &header, sizeof(Header));
    uint64_t offset = sizeof(Header);
    // Question
    for (int i = 0; i < questions.size(); i++) offset = serialize_question(dest, questions[i], offset);
    // Answer
    for (int i = 0; i < answers.size(); i++) offset = serialize_answer(dest, answers[i], offset);
    return offset;
}
void unserialize(char *buf, Header &header, std::vector<Question> &questions, std::vector<Answer> &answers){
    // Header
    uint64_t offset = 0;
    memcpy(&header,buf,sizeof(header));
    offset += 12;
    // Question
    for (int i = 0; i < htons(header.qdcount); i++){
        Question question;
        bool compressed = false;
        uint64_t label_offset = offset;
        while(buf[label_offset] != 0){
            if ((uint8_t)buf[label_offset] >= 0b11000000){
                if (!compressed) offset = label_offset + 2;
                label_offset = ((unsigned int)(uint8_t)buf[label_offset] - 0xC0) << 8 | (uint8_t)buf[label_offset+1];
                compressed = true;
            }
            question.name.push_back(buf[label_offset++]);
        }
        question.name.push_back(buf[label_offset++]);
        if (!compressed) offset = label_offset;
        // if compressed then we already set offset properly in the loop
        memcpy(&question.t, buf+offset, sizeof(question.t));
        offset += sizeof(question.t);
        memcpy(&question.c, buf+offset, sizeof(question.c));
        offset += sizeof(question.c);
        questions.push_back(question);
    }
    for (int i = 0; i < htons(header.ancount); i++){
        Answer answer;
        while (buf[offset] != 0){
            answer.name.push_back(buf[offset++]);
        }
        answer.name.push_back(buf[offset++]);
        memcpy(&answer.t, buf+offset, sizeof(answer.t));
        offset += sizeof(answer.t);
        memcpy(&answer.c, buf+offset, sizeof(answer.c));
        offset += sizeof(answer.c);
        memcpy(&answer.ttl, buf+offset, sizeof(answer.ttl));
        offset += sizeof(answer.ttl);
        memcpy(&answer.rdlength, buf+offset, sizeof(answer.rdlength));
        offset += sizeof(answer.rdlength);
        for (int j = 0; j < htons(answer.rdlength); j++) answer.rdata.push_back(buf[offset++]);
        answers.push_back(answer);
    }
}
int main(int argc, char** argv) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    std::string dns_server_ip;
    int dns_server_port = -1;
    for (int i = 1; i < argc; i++){
        std::string arg = argv[i];
        if (arg == "--resolver"){
            arg = argv[i+1];
            int idx = arg.find(":");
            dns_server_ip = arg.substr(0,idx);
            dns_server_port = std::stoi(arg.substr(idx+1));
            break;
        }
    }
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
    int dnsSocket;
    struct sockaddr_in dnsAddress = { .sin_family = AF_INET,
                                .sin_port = htons(dns_server_port),
                                };
    dnsSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (dnsSocket == -1) {
        std::cerr << "DNS socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }
    if (inet_pton(AF_INET, dns_server_ip.c_str(), &dnsAddress.sin_addr) <= 0)
    {
        std::cerr << "Invalid resolver IP address: " << dns_server_ip << std::endl;
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
        std::vector<Question> request_questions;
        std::vector<Answer> placeholder_answers;
        unserialize(buffer, request_header, request_questions, placeholder_answers);
        request_header.to_big_endian();
        // Create an empty response
        uint8_t opcode = request_header.flags >> 11 & 0b1111, rd = request_header.flags >> 8 & 1, rcode = opcode == 0 ? 0 : 4;
        Header header = {request_header.id, 1<<15 | opcode << 11 | rd << 8 | rcode, request_questions.size(), request_questions.size(), 0, 0};
        header.to_big_endian();
        request_header.to_big_endian(); // switch back to big endian so we can forward it to dns server
        request_header.qdcount = htons((uint8_t)1);
        // Reuse request questions
        std::vector<Question> response_questions;
        std::vector<Answer> answers; // construct answers
        for (int i = 0; i < request_questions.size() && rcode == 0; i++){
            // forward request
            char toResolver[512];
            std::vector<Question> one_question = {request_questions[i]};
            int len = serialize(toResolver,request_header,one_question, placeholder_answers);
            if (sendto(dnsSocket, toResolver, len, 0, reinterpret_cast<struct sockaddr *>(&dnsAddress), sizeof(dnsAddress)) == -1){
                perror("Failed to send query to resolver");
                continue;
            }
            char dnsResponse[512];
            socklen_t dnsAddresslen = sizeof(clientAddress);
            len = recvfrom(dnsSocket, dnsResponse, sizeof(dnsResponse), 0, reinterpret_cast<struct sockaddr*>(&dnsAddress), &dnsAddresslen);
            if (len < 0){
                perror("Error recieving response from resolver");
                continue;
            }
            Header placeholder_header;
            std::vector<Question> placeholder_questions;
            std::vector<Answer> resolver_answers;
            unserialize(dnsResponse, placeholder_header, placeholder_questions, resolver_answers);
            response_questions.push_back(request_questions[i]);
            response_questions[i].t = 1;
            response_questions[i].c = 1;
            response_questions[i].to_big_endian();
            answers.push_back(resolver_answers[0]); // since there is only one answer from resolver
        }
        char response[512];
        uint64_t size = serialize(response, header, response_questions, answers);
        
        // Send header
        if (sendto(udpSocket, &response, size, 0, reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
            perror("Failed to send response");
        }
    }
    close(udpSocket);
    return 0;
}