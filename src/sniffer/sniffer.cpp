#include "sniffer.h"
namespace sniffer
{

Sniffer::Sniffer(const std::string &interface) : m_interface (interface) {}


void Sniffer::startSniffing()
{
    m_handle = pcap_open_live(m_interface.c_str(), BUFSIZ, 1, 1000, m_errbuf);

    if (!m_handle) {
        std::cerr << "unable to open device\n" << m_errbuf;
        return;
    }
    std::cout << "Started sniffing on interface: " << m_interface;

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
}
} //namespace sniffer