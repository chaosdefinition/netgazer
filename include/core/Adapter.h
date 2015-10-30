/*
 * header file for class Adapter
 */

#pragma once

#ifndef NG_ADAPTER_H_
#define NG_ADAPTER_H_

#include <vector>
#include <pcap/pcap.h>

#include "Packet.h"

namespace netgazer {
	class Adapter {
	/* constructors and destructor */
	private:
		Adapter(pcap_if_t * pcap_adapter);
	public:
		~Adapter();

	/* public methods */
	public:
		int open(bool promisc, char * errbuf);
		void close();
		int nextPacket(Packet ** packet);

	/* fields */
	private:
		pcap_if_t * m_pcap_adapter;
		pcap_t * m_pcap_handle;
		bool m_promisc;
		std::vector<Packet *> m_packets;

	/* friend declarations */
	friend class NetworkService;
	};
}

#endif /* NG_ADAPTER_H_ */
