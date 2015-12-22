/*
 * implementation of class Packet
 */

#include <cstring>	/* for std::memcpy */
#include <new>		/* for std::bad_alloc */
#include <iostream>	/* for std::ostream */
#include <iomanip>	/* for std::hex, std::setw and std::setfill */
#include <ctime>	/* for std::strftime and std::localtime */
#include <pcap/pcap.h>	/* for libpcap types and functions */

#include "core/Packet.h"	/* for netgazer::Packet */
#include "core/Exception.h"	/* for netgazer::Exception */

using std::memcpy;
using std::bad_alloc;
using std::ostream;
using std::hex;
using std::setw;
using std::setfill;
using std::localtime;
using std::strftime;

namespace netgazer {
	/*
	 * constructor of Packet
	 *
	 * @header: a pointer to the pcap packet header
	 * @data: packet data
	 */
	Packet::Packet(const struct pcap_pkthdr * header, const u_char * data)
		throw (Exception)
	{
		if (header == NULL) {
			throw Exception("header is NULL");
		} else if (header->len < sizeof(struct Packet::PacketHeader)) {
			throw Exception("data size too small");
		}
		if (data == NULL) {
			throw Exception("data is NULL");
		}

		try {
			/* memory allocation */
			this->m_header = new struct pcap_pkthdr;
			this->m_data = new u_char[header->len];
		} catch (bad_alloc & e) {
			throw Exception(e.what());
		}

		/* initialize */
		memcpy(this->m_header, header, sizeof(*header));
		memcpy(this->m_data, data, header->len * sizeof(u_char));
	}

	/*
	 * destructor of Packet
	 */
	Packet::~Packet()
	{
		delete this->m_header;
		delete[] this->m_data;
	}

	/*
	 * get the packet length
	 *
	 * return: length of this Packet
	 */
	size_t Packet::length() const throw (Exception)
	{
		if (this->m_header == NULL) {
			throw Exception("header is NULL");
		}
		return this->m_header->len;
	}

	/*
	 * get the packet data
	 *
	 * return: data of this Packet
	 */
	const u_char * Packet::data() const throw (Exception)
	{
		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}
		return this->m_data;
	}

	/*
	 * get the packet timestamp
	 *
	 * return: timestamp of this Packet
	 */
	struct timeval Packet::timestamp() const throw (Exception)
	{
		if (this->m_header == NULL) {
			throw Exception("header is NULL");
		}
		return this->m_header->ts;
	}

	/*
	 * get the Ethernet packet type
	 *
	 * return: Ethernet type of this Packet
	 */
	enum Packet::EthernetType Packet::ethernetType() const throw (Exception)
	{
		struct Packet::PacketHeader * p = (struct Packet::PacketHeader *)
			this->m_data;

		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}

		switch(p->type) {
		/* Internet Protocol */
		case 0x0800: case 0x0008:
			return Packet::IP;

		/* Address Resolution Protocol */
		case 0x0806: case 0x0608:
			return Packet::ARP;

		/* Reverse Address Resolution Protocol */
		case 0x8035: case 0x3508:
			return Packet::RARP;

		/* other protocols */
		default:
			return Packet::OTHER;
		}
	}

	/*
	 * get the packet source MAC address
	 *
	 * return: source MAC address of this Packet
	 */
	struct Packet::MacAddr Packet::srcMacAddr() const throw (Exception)
	{
		struct Packet::PacketHeader * p = (struct Packet::PacketHeader *)
			this->m_data;
		struct Packet::MacAddr mac;

		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}

		memcpy(&mac, &(p->src), sizeof(mac));
		return mac;
	}

	/*
	 * get the packet destination MAC address
	 *
	 * return: destination MAC address of this Packet
	 */
	struct Packet::MacAddr Packet::destMacAddr() const throw (Exception)
	{
		struct Packet::PacketHeader * p = (struct Packet::PacketHeader *)
			this->m_data;
		struct Packet::MacAddr mac;

		if (this->m_data == NULL) {
			throw Exception("data is NULL");
		}

		memcpy(&mac, &(p->dest), sizeof(mac));
		return mac;
	}

	bool Packet::isIpv4Packet(const struct pcap_pkthdr * header,
			const u_char * data) throw (Exception)
	{
		struct Packet::PacketHeader * p = (struct Packet::PacketHeader *)
			data;

		if (header == NULL) {
			throw Exception("header is NULL");
		} else if (header->len < sizeof(struct Packet::PacketHeader)) {
			throw Exception("data size too small");
		}
		if (data == NULL) {
			throw Exception("data is NULL");
		}

		return (p->type == 0x0800 || p->type == 0x0008);
	}

	/*
	 * operator << for ostream to output Ethernet type
	 *
	 * @os: reference of an ostream object
	 * @type: Ethernet type
	 *
	 * return: os
	 */
	ostream & operator<<(ostream & os, enum Packet::EthernetType type)
	{
		switch (type) {
		case Packet::IP:
			os << "IP";
			break;
		case Packet::ARP:
			os << "ARP";
			break;
		case Packet::RARP:
			os << "RARP";
			break;
		default:
			os << "Other";
			break;
		}

		return os;
	}

	/*
	 * operator << for ostream to output timestamp
	 *
	 * @os: reference of an ostream object
	 * @ts: timestamp representation
	 *
	 * return: os
	 */
	ostream & operator<<(ostream & os, const struct timeval & ts)
	{
		char buf[20];

		/* do format */
		strftime(buf, sizeof(buf), "%F %T", localtime(&ts.tv_sec));

		/* do output */
		std::ios::fmtflags f(os.flags());
		os << buf << "." << setw(6) << setfill('0') << ts.tv_usec;
		os.flags(f);

		return os;
	}

	/*
	 * operator << for ostream to output MAC address
	 *
	 * @os: reference of an ostream object
	 * @mac: MAC address
	 *
	 * return: os
	 */
	ostream & operator<<(ostream & os, const struct Packet::MacAddr & mac)
	{
		std::ios::fmtflags f(os.flags());

		os << hex << setfill('0');
		for (int i = 0; i < 5; ++i) {
			os << setw(2) << (int)mac.addr[i] << ":";
		}
		os << setfill('0') << (int)mac.addr[5];
		os.flags(f);

		return os;
	}
}
