/*
 * implementation of class Adapter
 */

#include <new>

#include "core/Adapter.h"

using std::vector;

namespace netgazer {
	/*
	 * constructor of Adapter
	 *
	 * @pcap_adapter: a pointer to pcap interface
	 */
	Adapter::Adapter(pcap_if_t * pcap_adapter)
	{
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
	 * @errbuf: buffer to hold error message
	 *
	 * return: 0 on success, -1 otherwise
	 */
	int Adapter::open(bool promisc, char * errbuf)
	{
		/* close first to make sure resources are deallocated */
		this->close();

		/* do open */
		this->m_pcap_handle = pcap_open_live(
			this->m_pcap_adapter->name,	/* device name */
			65536,				/* snapshot length */
			promisc,			/* promiscuous mode */
			0,				/* timeout */
			errbuf);
		if (this->m_pcap_handle == NULL) {
			return -1;
		}
		this->m_promisc = promisc;
		return 0;
	}

	/*
	 * close an adapter
	 */
	void Adapter::close()
	{
		/* free all captured packets */
		for (vector<Packet *>::iterator i = this->m_packets.begin();
			i != this->m_packets.end(); ++i) {
			delete *i;
		}
		this->m_packets.clear();

		/* close opened adapter */
		if (this->m_pcap_handle != NULL) {
			pcap_close(this->m_pcap_handle);
			this->m_pcap_handle = NULL;
		}
	}

	/*
	 * get the next packet, it needs not to be freed by the caller
	 *
	 * @packet: a pointer to place to store the next packet
	 *
	 * return: 1 on success, 0 on timeout, -1 on error, -2 on EOF
	 */
	int Adapter::nextPacket(Packet ** packet)
	{
		struct pcap_pkthdr * header = NULL;
		const u_char * data = NULL;
		int ret = -1;

		/* check first if the adapter is not opened */
		if (this->m_pcap_handle == NULL) {
			goto error;
		}

		/* do get the next packet */
		ret = pcap_next_ex(this->m_pcap_handle, &header, &data);
		if (ret > 0) {
			try {
				*packet = new Packet(header, data);
			} catch (std::bad_alloc & e) {
				goto error;
			}

			this->m_packets.push_back(*packet);
			return ret;
		}

	error:
		*packet = NULL;
		return ret;
	}
}
