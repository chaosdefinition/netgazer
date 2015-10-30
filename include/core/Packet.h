#pragma once

#ifndef NG_PACKET_H_
#define NG_PACKET_H_

#include <pcap/pcap.h>

namespace netgazer {
	class Packet {
	/* constructors and destructor */
	private:
		Packet(struct pcap_pkthdr * header, const u_char * data);
	public:
		~Packet();

	/* public methods */
	public:
		size_t length();
		const u_char * data();

	/* fields */
	private:
		struct pcap_pkthdr * m_header;
		const u_char * m_data;

	/* friend declarations */
	friend class Adapter;
	};
}

#endif /* NG_PACKET_H_ */
