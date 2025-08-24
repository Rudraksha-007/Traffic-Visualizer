#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

#define DNS_PORT 53
#define BUF_SIZE 512  // DNS packet max over UDP

struct DNSHeader {
    uint16_t id;       // Transaction ID
    uint16_t flags;    //additional flags(we dont use)
    uint16_t qdcount;  //n(questions)
    uint16_t ancount;  //number of ans(expected zero for a request)
    uint16_t nscount;  
    uint16_t arcount;  
};

struct DNSAnswer {
    uint16_t type;     // Type of record (A, CNAME, etc.)
    uint16_t class_;   // Class of record (IN for Internet)
    uint32_t ttl;      // Time to live
    uint16_t rdlength; // Length of RDATA
    unsigned char* rdata; // Resource data (IP address, etc.)
};

struct DNSRecord {
    std::string domain;
    struct in_addr ip;
};

bool ipStringToBytes(const char* ipStr, unsigned char out[4]) {
    unsigned int b1, b2, b3, b4;
    if (sscanf(ipStr, "%u.%u.%u.%u", &b1, &b2, &b3, &b4) != 4)
        return false;
    if (b1 > 255 || b2 > 255 || b3 > 255 || b4 > 255)
        return false;
    out[0] = (unsigned char)b1;
    out[1] = (unsigned char)b2;
    out[2] = (unsigned char)b3;
    out[3] = (unsigned char)b4;
    return true;
}

int main() {
    std::vector<DNSRecord> records = {
        {"example.com", {}},
        {"test.com", {}}
    };

    unsigned char ipBytes[4];
    ipStringToBytes("93.184.216.34", ipBytes);
    records[0].ip.s_addr = *(uint32_t*)ipBytes; // Convert to network byte order
    
    WSADATA wsaData;
    SOCKET sock;
    sockaddr_in serverAddr, clientAddr;

    char buffer[BUF_SIZE];

    // 1. Init Winsock library for the DNS server
    if (WSAStartup(MAKEWORD(2,2),&wsaData) != 0) {
        // version 2.2 
        std::cerr << "WSAStartup failed\n";
        return 1;
    }


    // 2. Create socket
    // AF_INET is for making sure IPv4 is used
    // SOCK_DGRAM is for socket type= UDP
    // IPPROTO_UDP specifies the UDP protocol
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed\n";
        WSACleanup();
        return 1;
    }

    // 3. Bind the socket to port 53 setup:

    // tells the OS that this socket will use IPv4 internet addresses 
    // address family field of the sockaddr_in struct 
    // set it to AF_INET ie address family : internet (IPv4)
    serverAddr.sin_family = AF_INET;

    // sin_port is the port number we want to listen on 
    // htons converts the port number from host byte order to network byte order
    // its called Host to Network Short
    //I want to store the port number my socket will bind to in a struct (sockaddr_in).
    // Network protocols require multi-byte numbers like ports to be in big-endian (network byte order).
    // My CPU might store numbers differently, so I call htons() to convert my port from my CPU’s format to less-endian(wtv the CPU supports) before taking it from windows.
    // This way, it works on any CPU

    serverAddr.sin_port = htons(DNS_PORT);

    // tells the API to setup the socket to listen on all available IP addresses:
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed. Try running as Admin.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Authoritative DNS Server running on port 53...\n";

    // 4. Main loop
    while (true) {
        int clientAddrLen = sizeof(clientAddr);
        int bytesReceived = recvfrom(sock, buffer, BUF_SIZE, 0,(sockaddr*)&clientAddr, &clientAddrLen);

        if (bytesReceived == SOCKET_ERROR) {
            std::cerr << "recvfrom() failed\n";
            continue;
        }
        
        std::cout << "Got DNS query of size " << bytesReceived << " bytes\n";
        // TODO: Parse domain from buffer here (RFC1035)
        
        DNSHeader dns;
        memcpy(&dns, buffer, sizeof(DNSHeader));

        uint16_t id = ntohs(dns.id); 
        uint16_t flags = ntohs(dns.flags); 
        uint16_t qdcount = ntohs(dns.qdcount); 
        
        // check if the query is authoritative or recursive
        // if((flags & 0x0100) != 0){
        //     std::cout << "Recursion desired for query ID: " << id << "\n";
        //     continue;
        // }
        // else{
        //     std::cout << "Recursion not desired for query ID: " << id << "\n";
        //     std::cout<<"Proceeding with auth. query processing\n";
        // }

        // this ptr is pointing inside the buffer itself exactly after the DNSHeader(skipping initial 12bytes)
        unsigned char* ptr = (unsigned char*)(buffer + sizeof(DNSHeader));
        std::string domain;

        while (*ptr != 0) {
            int label_len = *ptr;
            ptr++;
            for (int i = 0; i < label_len; i++) {
                domain.push_back(*ptr);
                ptr++;
            }
            domain.push_back('.'); // separate labels with dot
        }
        if (!domain.empty() && domain.back() == '.') {
            domain.pop_back();
        }
        ptr++; // skip the null byte

        // Extract QTYPE and QCLASS
        // std::cout<<(uint16_t)*ptr<<std::endl;
        // note : the ptr is pointing to the byte after the domain name
        // QTYPE and QCLASS are 2 bytes each the ptr points to each char which is 1byte 
        // we declare a uint16_t variable to hold the QTYPE and QCLASS values
        // and use memcpy to copy the 2 bytes from the ptr to the variable
        // the pointer itself points to a location in the buffer that is 1 byte long 
        // but memcpy takes the size of qtype which is 2 bytes
        // so it copies the next 2 bytes from the ptr to the qtype variable

        uint16_t qtype;
        memcpy(&qtype, ptr, sizeof qtype);   // copies 2 bytes
        qtype = ntohs(qtype);
        ptr += 2;

        uint16_t qclass;
        memcpy(&qclass, ptr, sizeof qclass);
        qclass = ntohs(qclass);
        ptr += 2;

        std::cout << "Domain: " << domain << "\n";
        std::cout << "QTYPE: " << qtype << " QCLASS: " << qclass << "\n";
        
        // TODO: Build response packet and send back
        char response[BUF_SIZE];
        int response_len = 0;

        // building the DNS response header:
        DNSHeader* response_header = (DNSHeader*)response;
        response_header->id = dns.id; // ID is already in network byte order from request
        response_header->flags = htons(0x8180); // Standard response flags
        response_header->qdcount = dns.qdcount; // Question count is same as request
        response_header->ancount = htons(0); // We'll add answers later
        response_header->nscount = htons(0);
        response_header->arcount = htons(0);
        response_len += sizeof(DNSHeader);
        
        // The question section from the query is copied directly to the response.
        // It starts right after the header and ends where your 'ptr' is.
        char* question_start_in_query = buffer + sizeof(DNSHeader);
        int question_len = (char*)ptr - question_start_in_query;

        memcpy(response + response_len, question_start_in_query, question_len);
        response_len += question_len;
        
        // TODO: Build the answer section here
        bool found=false;
        char *answer_ptr=response+response_len;
        // The answer section starts after the question section
        
        for(auto record:records){
            if(domain==record.domain){
                // 1. NAME: Add the 2-byte pointer (0xc00c)
                *(uint16_t*)answer_ptr = htons(0xc00c);
                answer_ptr += 2;

                // 2. TYPE: A Record (1)
                *(uint16_t*)answer_ptr = htons(1);
                answer_ptr += 2;

                // 3. CLASS: IN (1)
                *(uint16_t*)answer_ptr = htons(1);
                answer_ptr += 2;

                // 4. TTL: 3600 seconds
                *(uint32_t*)answer_ptr = htonl(3600);
                answer_ptr += 4;

                // 5. RDLENGTH: 4 bytes for an IPv4 address
                *(uint16_t*)answer_ptr = htons(4);
                answer_ptr += 2;

                // 6. RDATA: The IP address
                // record.ip.s_addr is already in network byte order
                *(uint32_t*)answer_ptr = record.ip.s_addr;
                answer_ptr += 4;

                // Update total response length
                response_len = answer_ptr - response;

                // Update the answer count in the header
                response_header->ancount = htons(ntohs(response_header->ancount) + 1);
                
                found = true;
                break; // Found our record, stop searching
            }
        }

        // For now, just send back the header and question section
        sendto(sock, response, response_len, 0,
               (sockaddr*)&clientAddr, clientAddrLen);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}