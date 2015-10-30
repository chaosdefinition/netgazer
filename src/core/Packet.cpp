/*
 * implementation of class Packet
 */

#include <new>

#include "core/Packet.h"

namespace netgazer {
	Packet::Packet(struct pcap_pkthdr * header, const u_char * data)
	{

	}

	Packet::~Packet()
	{

	}

	size_t Packet::length()
	{
		return this->m_header->len;
	}

	const u_char * Packet::data()
	{
		return this->m_data;
	}
}
