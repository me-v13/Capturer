#include <pcap/pcap.h>
#include <iostream>
#include <iomanip>
#include <ctime>

using namespace std;

int packetCount = 0;


void packet_handler(u_char *args,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    packetCount++;

   
    time_t rawtime = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&rawtime);

    cout << "\n=====================================\n";
    cout << "         PACKET CAPTURED\n";
    cout << "=====================================\n";

    cout << "Packet Number : " << packetCount << endl;

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

    cout << "-------------------------------------\n";
}

void showMenu()
{
    cout << "\n=====================================\n";
    cout << "      NETWORK PACKET SNIFFER\n";
    cout << "=====================================\n";

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
                    cerr << "Error finding devices: "
                         << errbuf << endl;
                    return 1;
                }

                cout << "\nAvailable Devices:\n";
                cout << "-------------------------------------\n";

                int i = 0;

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
                    cout << "No devices found!\n";
                    break;
                }

                pcap_freealldevs(alldevs);

                break;
            }

            case 2:
            {
                if (pcap_findalldevs(&alldevs, errbuf) == -1)
                {
                    cerr << "Error finding devices: "
                         << errbuf << endl;
                    return 1;
                }

                int i = 0;

                cout << "\nAvailable Devices:\n";

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
                    cout << "No devices found!\n";
                    break;
                }

                int devChoice;

                cout << "\nSelect device number: ";
                cin >> devChoice;

                if (devChoice < 1 || devChoice > i)
                {
                    cout << "Invalid device choice!\n";
                    pcap_freealldevs(alldevs);
                    break;
                }

                device = alldevs;

                for (int j = 1; j < devChoice; j++)
                {
                    device = device->next;
                }

                cout << "\nUsing device: "
                     << device->name << endl;

               
                pcap_t *handle =
                    pcap_open_live(device->name,
                                   65536,
                                   1,
                                   1000,
                                   errbuf);

                if (handle == NULL)
                {
                    cerr << "Couldn't open device: "
                         << errbuf << endl;

                    pcap_freealldevs(alldevs);
                    return 1;
                }

                cout << "\nStarting packet capture...\n";
                cout << "Capturing 10 packets...\n";

                // it captures packet
                pcap_loop(handle,
                          10,
                          packet_handler,
                          NULL);

                pcap_close(handle);
                pcap_freealldevs(alldevs);

                break;
            }

            case 3:
            {
                cout << "\nExiting program...\n";
                break;
            }

            default:
            {
                cout << "\nInvalid choice!\n";
            }
        }

    } while(choice != 3);

    return 0;
}
