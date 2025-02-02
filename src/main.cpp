#include "handlers.h"

namespace sniffer
{

} // namespace sniffer

int main(int argc, char** argv) {
    char errbuf[PCAP_BUF_SIZE];

    pcap_if_t *devs;

    if (pcap_findalldevs(&devs, errbuf) == -1) {
        std::cerr << "Try another time\n" << errbuf;
    }
    for (auto d = devs; d != nullptr; d = d->next) {
        std::cout << d->name << " ";
        if (d->description) 
            std::cout << d->description << "\n";
    }

    if (devs == NULL) 
    {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    return 0;
}