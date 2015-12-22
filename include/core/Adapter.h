/*
 * header file for class Adapter
 */

#pragma once

#ifndef NG_ADAPTER_H_
#define NG_ADAPTER_H_

#include <deque>	/* for std::deque */
#include <pcap/pcap.h>	/* for libpcap types */

#include "Exception.h"		/* for netgazer::Exception */
#include "Packet.h"		/* for netgazer::Packet */

namespace netgazer {
	class Adapter {
	/* constructors and destructor */
	private:
		Adapter(pcap_if_t * pcap_adapter) throw (Exception);
	public:
		~Adapter();

	/* public methods */
	public:
		void open(bool promisc, int timeout) throw (Exception);
		void close();
		Packet * nextPacket() throw (Exception);
		const char * name() const throw (Exception);
		const char * description() const throw (Exception);

	/* fields */
	private:
		pcap_if_t * m_pcap_adapter;
		pcap_t * m_pcap_handle;
		bool m_promisc;
		std::deque<Packet *> m_packets;

	/* friend declarations */
	friend class NetworkService;
	};
}

#endif /* NG_ADAPTER_H_ */
