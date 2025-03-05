#include "handlers.h"

int main(int argc, char** argv) {

    sniffer::ProcessingUnit processor;
    sniffer::Sniffer sniffer(argv[1], processor);
    processor.startProcessing();
    std::thread sniffingThread([&sniffer/*, &processor*/]() {
        sniffer.startSniffing();
    });
    
    std::cout << "Press Enter to stop\n";
    std::cin.get();

    sniffer.endSniffing();
    processor.stopProcessing();
    sniffingThread.join();

    return 0;
}