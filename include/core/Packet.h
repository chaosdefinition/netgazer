/*
 * header file for class Packet
 */

#pragma once

#ifndef NG_PACKET_H_
#define NG_PACKET_H_

#include <iostream>	/* for std::ostream */
#include <pcap/pcap.h>	/* for libpcap types */

#include "Exception.h"	/* for netgazer::Exception */

namespace netgazer {
	class Packet {
	/* internal structures and enumerations */
	public:
		/* Ethernet packet types */
		enum EthernetType {
			IP = 1,
			ARP = 2,
			RARP = 3,
			OTHER = 0,
		};
		/* MAC address */
		struct MacAddr {
			u_char addr[6];
		};
		/* Ethernet packet header */
		struct PacketHeader {
			struct MacAddr dest;
			struct MacAddr src;
			u_short type;
		};

	/* constructors and destructor */
	protected:
		Packet(const struct pcap_pkthdr * header, const u_char * data)
			throw (Exception);
	public:
		virtual ~Packet();

	/* public methods */
	public:
		size_t length() const throw (Exception);
		const u_char * data() const throw (Exception);
		struct timeval timestamp() const throw (Exception);
		enum EthernetType ethernetType() const throw (Exception);
		struct MacAddr srcMacAddr() const throw (Exception);
		struct MacAddr destMacAddr() const throw (Exception);

	/* protected static methods */
	protected:
		static bool isIpv4Packet(const struct pcap_pkthdr * pcap_header,
			const u_char * data) throw (Exception);

	/* fields */
	protected:
		struct pcap_pkthdr * m_header;
		u_char * m_data;

	/* friend declarations */
	friend class Adapter;
	};

	/* overriden operators for std::ostream */
	std::ostream & operator<<(std::ostream & os,
		enum Packet::EthernetType type);
	std::ostream & operator<<(std::ostream & os, const struct timeval & ts);
	std::ostream & operator<<(std::ostream & os,
		const struct Packet::MacAddr & mac);
}

#endif /* NG_PACKET_H_ */
