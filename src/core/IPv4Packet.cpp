/*
 * implementation of class IPv4Packet
 */

#include <iostream>	/* for std::ostream */
#include <pcap/pcap.h>	/* for libpcap types and functions */

#include "core/Exception.h"	/* for netgazer::Exception */
#include "core/Packet.h"	/* for netgazer::Packet */
#include "core/IPv4Packet.h"	/* for netgazer::IPv4Packet */

using std::ostream;

namespace netgazer {
	/*
	 * constructor of IPv4Packet
	 *
	 * @header: a pointer to the pcap packet header
	 * @data: packet data
	 */
	IPv4Packet::IPv4Packet(const struct pcap_pkthdr * header,
		const u_char * data) throw (Exception)
		: Packet(header, data)
	{
		this->m_ip_header = (struct IPv4Packet::IPv4Header *)(data +
			sizeof(struct Packet::PacketHeader));
	}

	/*
	 * destructor of IPv4Packet
	 */
	IPv4Packet::~IPv4Packet()
	{
	}

	/*
	 * get the IP packet header length
	 *
	 * return: header length of this IPv4Packet
	 */
	int IPv4Packet::headerLength() const throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_ip_header->ihl;
	}

	/*
	 * get the IP packet length
	 *
	 * return: total length of this IPv4Packet
	 */
	int IPv4Packet::totalLength() const throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_ip_header->length;
	}

	/*
	 * get the IP type
	 *
	 * return: IP type of this IPv4Packet
	 */
	enum IPv4Packet::IPType IPv4Packet::ipType() const throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}

		switch (this->m_ip_header->protocol) {
		/* Internet Control Message Protocol */
		case 1:
			return IPv4Packet::ICMP;

		/* The Internet Group Management Protocol */
		case 2:
			return IPv4Packet::IGMP;

		/* Transmission Control Protocol */
		case 6:
			return IPv4Packet::TCP;

		/* User Datagram Protocol */
		case 17:
			return IPv4Packet::UDP;

		/* other protocols */
		default:
			return IPv4Packet::OTHER;
		}
	}

	u_short IPv4Packet::checksum() const throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_ip_header->checksum;
	}

	/*
	 * get the packet source IPv4 address
	 *
	 * return: source IPv4 address of this Packet
	 */
	struct IPv4Packet::IPv4Addr IPv4Packet::srcIPv4Addr() const
		throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_ip_header->src;
	}

	/*
	 * get the packet destination IPv4 address
	 *
	 * return: destination IPv4 address of this Packet
	 */
	struct IPv4Packet::IPv4Addr IPv4Packet::destIPv4Addr() const
		throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_ip_header->dest;
	}

	/*
	 * operator << for ostream to output IPv4 type
	 *
	 * @os: reference of an ostream object
	 * @type: IPv4 type
	 *
	 * return: os
	 */
	ostream & operator<<(ostream & os, enum IPv4Packet::IPType type)
	{
		switch (type) {
		case IPv4Packet::TCP:
			os << "TCP";
			break;
		case IPv4Packet::UDP:
			os << "UDP";
			break;
		case IPv4Packet::ICMP:
			os << "ICMP";
			break;
		case IPv4Packet::IGMP:
			os << "IGMP";
			break;
		default:
			os << "Other";
			break;
		}

		return os;
	}

	/*
	 * operator << for ostream to output IPv4 address
	 *
	 * @os: reference of an ostream object
	 * @ip: IPv4 address
	 *
	 * return: os
	 */
	ostream & operator<<(ostream & os, const struct IPv4Packet::IPv4Addr & ip)
	{
		for (int i = 0; i < 3; ++i) {
			os << (int)ip.addr[i] << ".";
		}
		os << (int)ip.addr[3];

		return os;
	}
}
