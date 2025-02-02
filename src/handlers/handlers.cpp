#include "handlers.h"

namespace sniffer
{

void ProcessingUnit::startProcessing()
{
    isRunning = true;
    thread1 = std::thread(&ProcessingUnit::handler1, this);
    thread2 = std::thread(&ProcessingUnit::handler2, this);
    thread3 = std::thread(&ProcessingUnit::handler3, this);
}

void ProcessingUnit::stopProcessing()
{
    isRunning = false;
    cv1.notify_all();
    cv2.notify_all();
    cv3.notify_all();
    if (thread1.joinable()) thread1.join();
    if (thread2.joinable()) thread3.join();
    if (thread3.joinable()) thread3.join();
}

void ProcessingUnit::processPacket(const Packet &packet)
{
    struct ether_header *ethernetHeader = (struct ether_header *) packet.data.data();
    struct ip *ipHeader = (struct ip *)(packet.data.data() + sizeof(ethernetHeader));

    if (ipHeader->ip_p == IPPROTO_TCP) {
        struct tcphdr * tcpHeader = (struct tcphdr*)(packet.data.data() + sizeof(ethernetHeader) + (ipHeader->ip_hl * 4));

        uint16_t srcPort = ntohs(tcpHeader->th_sport);
        uint16_t dstPort = ntohs(tcpHeader->th_dport);

        if (srcPort == 21 || dstPort == 21) {
            m1.lock();
            q1.push(packet);
            cv1.notify_one();
        } else if (srcPort == 20 || dstPort == 20 || srcPort > 1023 || dstPort > 1023) {
            m2.lock();
            q2.push(packet);
            cv2.notify_one();
        } else {
            m3.lock();
            q3.push(packet);
            cv3.notify_one();
        }
    }
}

void ProcessingUnit::handler1()
{
    static const std::string filename = "ftp.pcap";
    std::ofstream out(filename, std::ios::binary | std::ios::app);

    if (!out) {
        std::cerr << "Unable to open file for writing packet data\n";
        return;
    }

    while (isRunning) {
        std::unique_lock<std::mutex> lock(m1);
        cv1.wait(lock, [this] {
            return !q1.empty() || isRunning;
        });
        while (!q1.empty()) {
            Packet pkt = q1.front();
            q1.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), sizeof(pkt.data.size()));
            out.close();

            std::cout << "FTP command handled\n";
            lock.lock();
        }
    }
}

void ProcessingUnit::handler2()
{
    static const std::string filename = "ftp_data.pcap";
    std::ofstream out(filename, std::ios::binary | std::ios::app);

    if (!out) {
        std::cerr << "Unable to open file for writing packet data\n";
        return;
    }

    while (isRunning) {
        std::unique_lock<std::mutex> lock(m2);
        cv2.wait(lock, [this] {
            return !q2.empty() || isRunning;
        });
        while (!q2.empty()) {
            Packet pkt = q2.front();
            q2.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), sizeof(pkt.data.size()));
            out.close();
            
            std::cout << "FTP command handled\n";
            lock.lock();
        }
    }
}

void ProcessingUnit::handler3()
{
    static const std::string filename = "other.pcap";
    std::ofstream out(filename, std::ios::binary | std::ios::app);

    if (!out) {
        std::cerr << "Unable to open file for writing packet data\n";
        return;
    }

    while (isRunning) {
        std::unique_lock<std::mutex> lock(m3);
        cv3.wait(lock, [this] {
            return !q3.empty() || isRunning;
        });
        while (!q3.empty()) {
            Packet pkt = q3.front();
            q3.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), sizeof(pkt.data.size()));
            out.close();
            
            std::cout << "FTP command handled\n";
            lock.lock();
        }
    }
}

} //namespace sniffer