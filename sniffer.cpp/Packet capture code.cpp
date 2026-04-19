#include <pcap.h>
#include <iostream>

using namespace std;


void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << "Packet captured!" << endl;
    cout << "Packet length: " << header->len << endl;
    cout << "-----------------------------" << endl;
}

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    pcap_if_t *device = alldevs;
    cout << "Using device: " << device->name << endl;

 
    pcap_t *handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == NULL)
    {
        cerr << "Couldn't open device: " << errbuf << endl;
        return 1;
    }

   
    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}