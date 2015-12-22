#include <iostream>
#include <iomanip>
#include <limits>
#include <signal.h>

#include "netgazer.h"

using namespace std;
using namespace netgazer;

void dealSigInt(int signal)
{
	NetworkService::dispose();
}

int main(int argc, char * const * argv)
{
	NetworkService * service = NULL;
	Adapter * adapter = NULL;
	int adapter_count = 0, index = -1;

	try {
		/* get network service */
		service = NetworkService::instance();

		/* iterate adapters */
		cout << "List of available adapters" << endl;
		while ((adapter = service->nextAdapter()) != NULL) {
			cout << setw(4) << right << adapter_count << ": ";
			cout << setw(20) << right << adapter->name() << ": ";
			cout << setw(50) << left
			     << (adapter->description() == NULL ? "none" :
				adapter->description())
			     << endl;
			++adapter_count;
		}
		cout << setw(0) << endl;

		/* get input number */
		if (adapter_count == 0) {
			cout << "No adapter available." << endl;
			NetworkService::dispose();
			return 0;
		} else if (adapter_count == 1) {
			adapter_count = 0;
		} else {
			cout << "Please input a number (0 - "
				<< adapter_count - 1 << "): ",
			cin >> index;
			while (cin.fail()) {
				cout << "Bad input, please input again: ";
				cin.clear();
				cin.ignore(numeric_limits<streamsize>::max(),
					'\n');
				cin >> index;
			}
		}

		/* catch SIGINT */
		signal(SIGINT, dealSigInt);

		/* get and open the specified adapter */
		adapter = service->adapterBy(index);
		adapter->open(true, 1000);

		/* start capturing packets */
		Packet * p = NULL;
		while ((p = adapter->nextPacket()) != NULL) {
			/* packet length */
			cout << setw(20) << setfill(' ') << left
			     << "length:" << p->length() << endl;
			/* Ethernet type */
			cout << setw(20) << setfill(' ') << left
			    << "Ethernet type:" << p->ethernetType() << endl;
			/* timestamp */
			cout << setw(20) << setfill(' ') << left
			     << "Timestamp:" << p->timestamp() << endl;
			/* source MAC address */
			cout << setw(20) << setfill(' ') << left
			     << "Source MAC:" << p->srcMacAddr() << endl;
			/* destination MAC address */
			cout << setw(20) << setfill(' ') << left
			     << "Destination MAC:" << p->destMacAddr() << endl;

			if (p->ethernetType() == Packet::IP) {
				IPv4Packet * ipp = dynamic_cast<IPv4Packet *>(p);
				/* IP header length */
				cout << setw(20) << setfill(' ') << left
				     << "IP header length:" << ipp->headerLength()
				     << endl;
				/* IP packet total length */
				cout << setw(20) << setfill(' ') << left
				     << "IP total length:" << ipp->totalLength()
				     << endl;
				/* IP protocol type */
				cout << setw(20) << setfill(' ') << left
				     << "IP protocol type:" << ipp->ipType()
				     << endl;
				/* IP packet checksum */
				cout << setw(20) << setfill(' ') << left
				     << "IP Packet checksum:" << ipp->checksum()
				     << endl;
				/* source IP address */
				cout << setw(20) << setfill(' ') << left
				     << "Source IP:" << ipp->srcIPv4Addr()
				     << endl;
				/* destination IP address */
				cout << setw(20) << setfill(' ') << left
				     << "Destination IP:" << ipp->destIPv4Addr()
				     << endl;
			}
			cout << setw(0) << endl;
		}
	} catch (Exception & e) {
		cerr << e.what() << endl;
	}

	NetworkService::dispose();
	return 0;
}
