#pragma once

#include <pcap.h>
#include <netinet/in.h>
#include <iostream>
#include <vector>
#include <mutex>
#include <fstream>
#include <queue>
#include <condition_variable>
#include <thread>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h> 
#include <ctime>
#include <chrono>

namespace sniffer 
{
using byte = uint8_t;

class ProcessingUnit;

struct Packet 
{
    const pcap_pkthdr *header;
    std::vector<byte> data;
};

class Sniffer 
{
    public:
        explicit Sniffer(const std::string &m_interface, ProcessingUnit &m_processor);
        ~Sniffer() = default;
        void startSniffing();
        void endSniffing();
        void writePacketToFile(const Packet &packet, const std::string &path);

    private:
        static void packetHandler(u_char *userData, const pcap_pkthdr *pkthdr, const u_char *packet);
        std::vector<Packet> m_d;
        std::string m_interface;
        std::mutex m_mtx;
        bool m_isRunning = false;
        pcap_t *m_handle = nullptr;
        char m_errbuf[PCAP_BUF_SIZE];
        ProcessingUnit &m_processor;
};

} //namespace sniffer