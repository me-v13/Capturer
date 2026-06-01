#include <pcap/pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
using namespace std;

int packetCount = 0;
struct IPHeader
{
    unsigned char ip_hl:4;
    unsigned char ip_v:4;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_off;
    unsigned char ip_ttl;
    unsigned char ip_p;
    unsigned short ip_sum;
    unsigned int ip_src;
    unsigned int ip_dst;
};
void setColor(int color)
{
    SetConsoleTextAttribute(
        GetStdHandle(STD_OUTPUT_HANDLE),
        color
    );
}
void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    packetCount++;

    time_t rawtime = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);

    setColor(10);

    cout << "\n=====================================\n";
    cout << "         PACKET CAPTURED\n";
    cout << "=====================================\n";

    setColor(7);

    cout << "Packet Number : "
         << packetCount << endl;

    cout << "Timestamp     : "
         << setfill('0')
         << setw(2) << timeinfo->tm_hour << ":"
         << setw(2) << timeinfo->tm_min << ":"
         << setw(2) << timeinfo->tm_sec
         << "." << header->ts.tv_usec
         << endl;

    cout << "Packet Length : "
         << header->len
         << " bytes" << endl;

    const int ethernetHeaderLength = 14;

    if (header->len > ethernetHeaderLength)
    {
        IPHeader* ipHeader =
    (IPHeader*)(packet + ethernetHeaderLength);

    cout << "IP Version    : "
     << (int)ipHeader->ip_v
     << endl;

in_addr src, dst;

src.S_un.S_addr = ipHeader->ip_src;
dst.S_un.S_addr = ipHeader->ip_dst;

cout << "Source IP     : "
     << inet_ntoa(src)
     << endl;

cout << "Destination IP: "
     << inet_ntoa(dst)
     << endl;

     

cout << "Protocol      : ";

switch(ipHeader->ip_p)
{
    case 6:
        setColor(11);
        cout << "TCP";
        break;

    case 17:
        setColor(14);
        cout << "UDP";
        break;

    case 1:
        setColor(13);
        cout << "ICMP";
        break;

    default:
        setColor(12);
        cout << "OTHER";
}

        setColor(7);

        cout << endl;
    }

    cout << "-------------------------------------\n";
}
void showMenu()
{
    setColor(11);

    cout << "\n=====================================\n";
    cout << "      NETWORK PACKET SNIFFER\n";
    cout << "=====================================\n";

    setColor(7);

    cout << "1. Show Devices\n";
    cout << "2. Start Packet Capture\n";
    cout << "3. Exit\n";

    cout << "=====================================\n";
    cout << "Enter choice: ";
}

int main()
{
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    int choice;

    do
    {
        showMenu();
        cin >> choice;

        switch(choice)
        {
            case 1:
            {
                if (pcap_findalldevs(&alldevs, errbuf) == -1)
                {
                    setColor(12);

                    cerr << "Error finding devices: "
                         << errbuf << endl;

                    setColor(7);

                    return 1;
                }

                setColor(14);

                cout << "\nAvailable Devices:\n";
                cout << "-------------------------------------\n";

                setColor(7);

                int i = 0;

                for (device = alldevs; device != NULL; device = device->next)
                {

                    cout << ++i << ". "<< device->name;

                    if (device->description)
                        cout << " ("
                             << device->description
                             << ")";

                    cout << endl;
                }

                if (i == 0)
                {
                    setColor(12);

                    cout << "No devices found!\n";

                    setColor(7);

                    break;
                }

                pcap_freealldevs(alldevs);

                break;
            }

            case 2:
            {
                if (pcap_findalldevs(&alldevs, errbuf) == -1)
                {
                    setColor(12);

                    cerr << "Error finding devices: "
                         << errbuf << endl;

                    setColor(7);

                    return 1;
                }

                int i = 0;

                setColor(14);

                cout << "\nAvailable Devices:\n";

                setColor(7);

                for (device = alldevs;
                     device != NULL;
                     device = device->next)
                {
                    cout << ++i << ". "
                         << device->name;

                    if (device->description)
                        cout << " ("
                             << device->description
                             << ")";

                    cout << endl;
                }

                if (i == 0)
                {
                    setColor(12);

                    cout << "No devices found!\n";

                    setColor(7);

                    break;
                }

                int devChoice;

                cout << "\nSelect device number: ";
                cin >> devChoice;

                if (devChoice < 1 || devChoice > i)
                {
                    setColor(12);

                    cout << "Invalid device choice!\n";

                    setColor(7);

                    pcap_freealldevs(alldevs);
                    break;
                }

                device = alldevs;

                for (int j = 1; j < devChoice; j++)
                {
                    device = device->next;
                }

                setColor(11);

                cout << "\nUsing device: "
                     << device->name << endl;

                setColor(7);

                pcap_t *handle =
                    pcap_open_live(device->name,
                                   65536,
                                   1,
                                   1000,
                                   errbuf);

                if (handle == NULL)
                {
                    setColor(12);

                    cerr << "Couldn't open device: "
                         << errbuf << endl;

                    setColor(7);

                    pcap_freealldevs(alldevs);
                    return 1;
                }

                packetCount = 0;

                setColor(10);

                cout << "\nStarting packet capture...\n";
                cout << "Capturing 10 packets...\n";

                setColor(7);

                pcap_loop(handle,
                          10,
                          packet_handler,
                          NULL);

                setColor(14);

                cout << "\nTotal Packets Captured : "
                     << packetCount << endl;

                setColor(7);

                pcap_close(handle);
                pcap_freealldevs(alldevs);

                break;
            }

            case 3:
            {
                setColor(14);

                cout << "\nExiting program...\n";

                setColor(7);

                break;
            }

            default:
            {
                setColor(12);

                cout << "\nInvalid choice!\n";

                setColor(7);
            }
        }

    } while(choice != 3);

    return 0;
}
