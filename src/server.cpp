#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include "dns.hpp"
#if _WIN32
    typedef SOCKET Socket;
    typedef int socklen_t;
#else
    typedef int Socket;
#endif // _WIN32
int main()
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;
    // Disable output buffering
    setbuf(stdout, NULL);
#if _WIN32
    WSADATA wsaData;
    int iResult;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        std::cerr << "WSA initialization failed: " << iResult << std::endl;
        return 1;
    }
#endif
    // Uncomment this block to pass the first stage
    Socket udpSocket;
    struct sockaddr_in clientAddress;
#if _WIN32
    int protocol = IPPROTO_UDP;
#else
    int protocol = 0;
#endif
    udpSocket = socket(AF_INET, SOCK_DGRAM, protocol);
    if (udpSocket == -1)
    {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }
#if !_WIN32
    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }
#endif // !_WIN32
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(2053);
#if _WIN32
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
#else
    serv_addr.sin_addr = {htonl(INADDR_ANY)};
#endif // _WIN32
    if (bind(udpSocket, reinterpret_cast<struct sockaddr *>(&serv_addr), sizeof(serv_addr)) != 0)
    {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }
    int bytesRead;
    char buffer[512];
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
        std::cout << "Received " << bytesRead << " bytes" << std::endl;
        dns_packet_t request;
        request.deserialize((u8*)buffer, bytesRead);
        header_t request_header = request.get_header();
        // Prepare response
        dns_packet_t response;
        header_t header;
        header.id = request_header.id;
        header.opcode = request_header.opcode;
        header.rd = request_header.rd;
        header.rcode = (request_header.opcode == 0 ? 0 : 4);
        response.add_header(header);
        auto label = request.get_labels();
        response.add_question(label);
        u32 ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
        response.add_answer(request.get_labels(), ip);
        // Print info about packet to be sent
        if (false)
        {
            header_t response_header = response.get_header();
            std::cout << "Sending id " << response_header.id
                << " qdcount " << response_header.qdcount
                << " qr " << (int)response_header.qr
                << " labels " << response.get_labels()
                << std::endl;
        }
        response.serialize();
        // Send response
        std::cout << "Sending response..." << std::endl;
        if (sendto(udpSocket, (char*)response.data(), response.size(), 0, reinterpret_cast<struct sockaddr *>(&clientAddress), sizeof(clientAddress)) == -1)
        {
            perror("Failed to send response");
        }
    }
#if _WIN32
    closesocket(udpSocket);
    WSACleanup();
#else
    close(udpSocket);
#endif // _WIN32
    return 0;
}