/*
 * header file for class IPv4Packet
 */

#pragma once

#ifndef NG_IPV4_PACKET_H_
#define NG_IPV4_PACKET_H_

#include <iostream>	/* for std::ostream */
#include <pcap/pcap.h>	/* for libpcap types */

#include "Packet.h"	/* for netgazer::Packet */

namespace netgazer {
	class IPv4Packet : public Packet {
	/* internal structures and enumerations */
	public:
		/* IP packet types */
		enum IPType {
			TCP = 1,
			UDP = 2,
			ICMP = 3,
			IGMP = 4,
			OTHER = 0,
		};
		/* IPv4 address */
		struct IPv4Addr {
			u_char addr[4];
		};
		/* IPv4 packet header */
		struct IPv4Header {
			u_char ihl : 4, version : 4;
			u_char tos;
			u_short length;
			u_short id;
			u_short off;
			u_char ttl;
			u_char protocol;
			u_short checksum;
			struct IPv4Addr src;
			struct IPv4Addr dest;
		};

	/* constructors and destructor */
	private:
		IPv4Packet(const struct pcap_pkthdr * header, const u_char * data)
			throw (Exception);
	public:
		~IPv4Packet();

	/* public methods */
	public:
		int headerLength() const throw (Exception);
		int totalLength() const throw (Exception);
		enum IPType ipType() const throw (Exception);
		u_short checksum() const throw (Exception);
		struct IPv4Addr srcIPv4Addr() const throw (Exception);
		struct IPv4Addr destIPv4Addr() const throw (Exception);

	/* fields */
	private:
		struct IPv4Header * m_ip_header;

	/* friend declarations */
	friend class Adapter;
	};

	/* overriden operators for std::ostream */
	std::ostream & operator<<(std::ostream & os,
		enum IPv4Packet::IPType type);
	std::ostream & operator<<(std::ostream & os,
		const struct IPv4Packet::IPv4Addr & ip);
}

#endif /* NG_IPV4_PACKET_H_ */
