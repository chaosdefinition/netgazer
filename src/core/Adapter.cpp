/*
 * implementation of class Adapter
 */

#include <deque>	/* for std::deque */
#include <new>		/* for std::bad_alloc */
#include <pcap/pcap.h>	/* for libpcap types and functions */

#include "core/Adapter.h"	/* for netgazer::Adapter */
#include "core/Exception.h"	/* for netgazer::Exception */
#include "core/Packet.h"	/* for netgazer::Packet */
#include "core/IPv4Packet.h"	/* for netgazer::IPv4Packet */

using std::deque;
using std::bad_alloc;

namespace netgazer {
	/*
	 * constructor of Adapter
	 *
	 * @pcap_adapter: a pointer to pcap interface
	 */
	Adapter::Adapter(pcap_if_t * pcap_adapter) throw (Exception)
	{
		if (pcap_adapter == NULL) {
			throw Exception("pcap_adapter is NULL");
		}

		this->m_pcap_adapter = pcap_adapter;
		this->m_pcap_handle = NULL;
		this->m_promisc = false;
	}

	/*
	 * destructor of Adapter
	 */
	Adapter::~Adapter()
	{
		this->close();
	}

	/*
	 * open an adapter
	 *
	 * @promisc: whether to be put into promiscuous mode
	 * @timeout: the read timeout in milliseconds
	 */
	void Adapter::open(bool promisc, int timeout) throw (Exception)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		/* close first to make sure resources are deallocated */
		this->close();

		/* do open */
		this->m_pcap_handle = pcap_open_live(
			this->m_pcap_adapter->name,	/* device name */
			65536,				/* snapshot length */
			promisc,			/* promiscuous mode */
			timeout,			/* timeout */
			errbuf);
		if (this->m_pcap_handle == NULL) {
			throw Exception(errbuf);
		}
		this->m_promisc = promisc;
	}

	/*
	 * close an adapter
	 */
	void Adapter::close()
	{
		/* free all captured packets */
		for (deque<Packet *>::iterator i = this->m_packets.begin();
			i != this->m_packets.end(); ++i) {
			delete *i;
		}
		this->m_packets.clear();

		/* close opened adapter */
		if (this->m_pcap_handle != NULL) {
			pcap_close(this->m_pcap_handle);
			this->m_pcap_handle = NULL;
		}

		this->m_promisc = false;
	}

	/*
	 * get the next packet, it needs not to be freed by the caller
	 *
	 * return: a pointer to the next packet on success, NULL otherwise
	 */
	Packet * Adapter::nextPacket() throw (Exception)
	{
		struct pcap_pkthdr * header = NULL;
		const u_char * data = NULL;
		Packet * p = NULL;
		int ret = -1;

		/* check first if the adapter is not opened */
		if (this->m_pcap_handle == NULL) {
			throw Exception("adapter is not opened");
		}

		/* do get the next packet */
		ret = pcap_next_ex(this->m_pcap_handle, &header, &data);
		switch (ret) {
		/* success */
		case 1:
			try {
				if (Packet::isIpv4Packet(header, data)) {
					p = new IPv4Packet(header, data);
				} else {
					p = new Packet(header, data);
				}
			} catch (bad_alloc & e) {
				throw Exception(e.what());
			}
			this->m_packets.push_back(p);
			/* keep a maximum size of 100 */
			if (this->m_packets.size() >= 100) {
				delete this->m_packets.front();
				this->m_packets.pop_front();
			}
			/* fall-through */

		/* timeout or EOF */
		case 0: case -2:
			return p;

		/* error */
		case -1:
			throw Exception(pcap_geterr(this->m_pcap_handle));

		default:
			throw Exception("pcap error");
		}
	}

	/*
	 * get the adapter name
	 *
	 * return: name of this Adapter
	 */
	const char * Adapter::name() const throw (Exception)
	{
		if (this->m_pcap_adapter != NULL) {
			return this->m_pcap_adapter->name;
		}
		throw Exception("pcap_adapter is NULL");
	}

	/*
	 * get the adapter description
	 *
	 * return: description of this Adapter
	 */
	const char * Adapter::description() const throw (Exception)
	{
		if (this->m_pcap_adapter != NULL) {
			return this->m_pcap_adapter->description;
		}
		throw Exception("pcap_adapter is NULL");
	}
}
