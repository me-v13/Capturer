#include <pcap/pcap.h>
#include <iostream>

using namespace std;

// Packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    cout << "Packet captured!" << endl;
    cout << "Packet length: " << header->len << endl;
    cout << "-----------------------------" << endl;
}

int main()
{
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        cerr << "Error finding devices: " << errbuf << endl;
        return 1;
    }

    int i = 0;
    for (device = alldevs; device != NULL; device = device->next)
    {
        cout << ++i << ". " << device->name;
        if (device->description)
            cout << " (" << device->description << ")";
        cout << endl;
    }

    if (i == 0)
    {
        cout << "No devices found!" << endl;
        return 1;
    }

    int choice;
    cout << "\nEnter device number: ";
    cin >> choice;

    device = alldevs;
    
    for (int j = 1; j < choice; j++)
    {
        device = device->next;
    }

    cout << "\nUsing device: " << device->name << endl;

    pcap_t *handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (handle == NULL)
    {
        cerr << "Couldn't open device: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    cout << "Starting packet capture...\n" << endl;

    pcap_loop(handle, 10, packet_handler, NULL);

    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
