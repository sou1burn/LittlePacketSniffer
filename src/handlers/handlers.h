#pragma once
#include "sniffer.h"
#include <queue>
#include <condition_variable>
#include <thread>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

namespace sniffer
{
class ProcessingUnit
{
public:
    explicit ProcessingUnit() = default;
    ~ProcessingUnit() = default;

    void startProcessing();
    void stopProcessing();
    void processPacket(const Packet &packet);
private:
    void handler1();
    void handler2();
    void handler3();

    std::thread thread1, thread2, thread3;
    std::queue<Packet> q1, q2, q3;    
    std::condition_variable cv1, cv2, cv3;
    std::mutex m1, m2, m3;

    bool isRunning = false;
};

} //namespace sniffer