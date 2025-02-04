#include "sniffer.h"
namespace sniffer
{

// Sniffer::Sniffer(const std::string &interface, const ProcessingUnit &processor) : m_interface (interface), m_processor (processor) {}

Sniffer::Sniffer(const std::string &interface) : m_interface (interface) {}

void Sniffer::startSniffing()
{
    m_handle = pcap_open_live(m_interface.c_str(), BUFSIZ, 1, 1000, m_errbuf);

    if (!m_handle) {
        std::cerr << "unable to open device\n" << m_errbuf;
        return;
    }
    std::cout << "Started sniffing on interface: " << m_interface << "\n";

    m_isRunning = true;
    pcap_loop(m_handle, 0, packetHandler, reinterpret_cast<u_char*>(this));
}

void Sniffer::endSniffing()
{
    if (m_isRunning) {
        pcap_breakloop(m_handle);
        m_isRunning = false;
    }
}

void Sniffer::writePacketToFile(const Packet &packet,const std::string &filename)
{
    std::ofstream file(filename, std::ios::binary | std::ios::app);
    
    if(!file) {
        std::cerr << "Unable to open file for writing packet data\n" << filename;
        return;
    }

    file.write(reinterpret_cast<const char*>(&packet.header), sizeof(packet.header));
    file.write(reinterpret_cast<const char*>(&packet.data), sizeof(packet.data));
    file.close();
}

void Sniffer::packetHandler(u_char *packetData, const pcap_pkthdr *header, const u_char *packet)
{
    auto sniffer = reinterpret_cast<Sniffer*>(packetData);

    Packet pkt;
    pkt.header = header;
    pkt.data.assign(packet, packet + header->len);

    {
        std::lock_guard<std::mutex> lock(sniffer->m_mtx);
        sniffer->m_d.push_back(pkt);
    }

    std::cout << "Sniffed packet with len (bytes): " << header->len << std::endl;

    struct ether_header *ethernetHeader = (struct ether_header *)pkt.data.data();
    
    if (ntohs(ethernetHeader->ether_type) != ETHERTYPE_IP) {
        return;
    }
    
    struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) 
              << " -> Destination IP: " << inet_ntoa(ipHeader->ip_dst) << "\n";

    if (ipHeader->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
        std::cout << "Protocol: TCP | Source Port: " << ntohs(tcpHeader->th_sport)
                  << " -> Destination Port: " << ntohs(tcpHeader->th_dport) << "\n";
    }  else if (ipHeader->ip_p == IPPROTO_UDP) {
        struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
        std::cout << "Protocol: UDP | Source Port: " << ntohs(udpHeader->uh_sport)
                  << " -> Destination Port: " << ntohs(udpHeader->uh_dport) << "\n";
    }  else {
        std::cout << "Protocol: " << (int)ipHeader->ip_p << " (не TCP и не UDP)\n";
    }

    
}
} //namespace sniffer