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
    if (thread1.joinable()) 
        thread1.join();
    if (thread2.joinable()) 
        thread2.join();
    if (thread3.joinable()) 
        thread3.join();
}

void ProcessingUnit::processPacket(const Packet &packet)
{
    struct ether_header *ethernetHeader = (struct ether_header *) packet.data.data();
    struct ip *ipHeader = (struct ip *)(packet.data.data() + sizeof(struct ether_header));
    if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
        struct tcphdr * tcpHeader = (struct tcphdr*)(packet.data.data() + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));

        uint16_t srcPort = ntohs(tcpHeader->th_sport);
        uint16_t dstPort = ntohs(tcpHeader->th_dport);
        if (srcPort == 21 || dstPort == 21) {
            {
                std::lock_guard<std::mutex> lock(m1);
                q1.push(packet);
            }
            cv1.notify_one();
        // todo: handle active and passive FTP mode
        } else if (srcPort == 20 || dstPort == 20 /*|| srcPort > 1023 || dstPort > 1023*/) {
            {
                std::lock_guard<std::mutex> lock(m2);
                q2.push(packet);
            }
            cv2.notify_one();
        } else {
            if (ipHeader->ip_p == IPPROTO_UDP && (srcPort > 20000 && srcPort < 25000)) {
                auto stamp = std::chrono::system_clock::now();
                std::time_t timeAtTheMoment = std::chrono::system_clock::to_time_t(stamp);
                std::cout << "Обработчик 3: {" << std::ctime(&timeAtTheMoment) << "} пакет {" << IPPROTO_UDP << srcPort << "->" << dstPort << "} игнорируется\n";
                return;
            } else if (tcpHeader->syn == 1) {
                auto stamp = std::chrono::system_clock::now();
                std::time_t timeAtTheMoment = std::chrono::system_clock::to_time_t(stamp);
                std::cout << "Обработчик 3: {" << std::ctime(&timeAtTheMoment) << "} пакет {" << IPPROTO_UDP << srcPort << "->" << dstPort << "} инициирует соединение\n";
                return;
            } else { 
                {
                    std::lock_guard<std::mutex> lock(m3);
                    q3.push(packet);
                }
                cv3.notify_one();
            }
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
            return !q1.empty() || !isRunning;
        });
        while (!q1.empty()) {
            Packet pkt = q1.front();
            q1.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), pkt.data.size());

            std::cout << "FTP command handled\n";
            lock.lock();
        }
    }
    out.close();
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
            return !q2.empty() || !isRunning;
        });
        while (!q2.empty()) {
            Packet pkt = q2.front();
            q2.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), pkt.data.size());
            
            std::cout << "FTP data handled\n";
            lock.lock();
        }
    }
    out.close();
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
            return !q3.empty() || !isRunning;
        });
        while (!q3.empty()) {
            Packet pkt = q3.front();
            q3.pop();
            lock.unlock();
            out.write(reinterpret_cast<const char *>(&pkt.header), sizeof(pkt.header));
            out.write(reinterpret_cast<const char *>(pkt.data.data()), pkt.data.size());
            
            std::cout <<"Something other handled\n";
            lock.lock();
        }
    }
    out.close();
}

} //namespace sniffer