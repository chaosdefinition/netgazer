/*
 * implementation of class NetworkService
 */

#include <vector>	/* for std::vector */
#include <new>		/* for std::bad_alloc */
#include <cstring>	/* for std::strcmp */
#include <pcap/pcap.h>	/* for libpcap types and functions */

#include "core/NetworkService.h"	/* for netgazer::NetworkService */
#include "core/Exception.h"		/* for netgazer::Exception */
#include "core/Adapter.h"		/* for netgazer::Adapter */

using std::vector;
using std::bad_alloc;

namespace netgazer {
	/* initialize ref */
	NetworkService * netgazer::NetworkService::ref = NULL;

	/*
	 * constructor of NetworkService
	 */
	NetworkService::NetworkService() throw (Exception)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		/* clear previous instance */
		if (NetworkService::ref != NULL) {
			delete NetworkService::ref;
		}
		/* do find all adapters */
		if (pcap_findalldevs(&(this->m_pcap_all_adapters), errbuf) == -1) {
			throw Exception(errbuf);
		}
		NetworkService::ref = this;
		this->m_pcap_adapter = this->m_pcap_all_adapters;
	}

	/*
	 * destructor of NetworkService
	 */
	NetworkService::~NetworkService()
	{
		/* free all opened adapters */
		for (vector<Adapter *>::iterator i = this->m_adapters.begin();
			i != this->m_adapters.end(); ++i) {
			delete *i;
		}
		this->m_adapters.clear();

		/* free all adapters */
		if (this->m_pcap_all_adapters != NULL) {
			pcap_freealldevs(this->m_pcap_all_adapters);
		}

		/* clear instance reference */
		if (NetworkService::ref != NULL) {
			NetworkService::ref = NULL;
		}
	}

	/*
	 * get the next adapter, it needs not to be freed by the caller
	 *
	 * return: a pointer to the next adapter on success, NULL otherwise
	 */
	Adapter * NetworkService::nextAdapter() throw (Exception)
	{
		Adapter * adapter = NULL;

		/* no next adapter */
		if (this->m_pcap_adapter == NULL) {
			return NULL;
		}

		try {
			adapter = new Adapter(this->m_pcap_adapter);
		} catch (bad_alloc & e) {
			throw Exception(e.what());
		}

		/* move the current pcap pointer to the next */
		this->m_pcap_adapter = this->m_pcap_adapter->next;

		/* store the Adapter pointer */
		this->m_adapters.push_back(adapter);
		return adapter;
	}

	/*
	 * get adapter by name, it needs not to be freed by the caller
	 *
	 * @name: name of adapter
	 *
	 * return: a pointer to the specified adapter on success, NULL otherwise
	 */
	Adapter * NetworkService::adapterBy(const char * name) throw (Exception)
	{
		pcap_if_t * p = this->m_pcap_all_adapters;
		Adapter * adapter = NULL;

		/* do find by name */
		while (p != NULL) {
			if (p->name != NULL && strcmp(p->name, name) == 0) {
				try {
					adapter = new Adapter(p);
				} catch (bad_alloc & e) {
					throw Exception(e.what());
				}

				this->m_adapters.push_back(adapter);
				return adapter;
			}
			p = p->next;
		}

		/* not found */
		return NULL;
	}

	/*
	 * get adapter by index, it needs not to be freed by the caller
	 *
	 * @index: zero-based index
	 *
	 * return: a pointer to the specified adapter on success, NULL otherwise
	 */
	Adapter * NetworkService::adapterBy(int index) throw (Exception)
	{
		pcap_if_t * p = this->m_pcap_all_adapters;
		Adapter * adapter = NULL;

		/* no adapter avaliable */
		if (p == NULL) {
			throw Exception("adapter index out of range");
		}
		/* do iterate */
		else {
			for (; index > 0; --index) {
				if (p->next == NULL) {
					throw Exception("adapter index out of "
						"range");
				}
				p = p->next;
			}
		}

		try {
			adapter = new Adapter(p);
		} catch (bad_alloc & e) {
			throw Exception(e.what());
		}

		this->m_adapters.push_back(adapter);
		return adapter;
	}

	/*
	 * reset the NetworkService
	 */
	void NetworkService::reset() throw (Exception)
	{
		char errbuf[PCAP_ERRBUF_SIZE];

		/* free all opened adapters */
		for (vector<Adapter *>::iterator i = this->m_adapters.begin();
			i != this->m_adapters.end(); ++i) {
			delete *i;
		}
		this->m_adapters.clear();

		/* free all adapters */
		if (this->m_pcap_all_adapters != NULL) {
			pcap_freealldevs(this->m_pcap_all_adapters);
		}

		/* find all adapters */
		if (pcap_findalldevs(&(this->m_pcap_all_adapters), errbuf) == -1) {
			throw Exception(errbuf);
		}
		this->m_pcap_adapter = this->m_pcap_all_adapters;
	}

	/*
	 * get an instance of NetworkService
	 *
	 * return: a pointer to NetworkService on success, NULL otherwise
	 */
	NetworkService * NetworkService::instance() throw (Exception)
	{
		NetworkService * p = NULL;

		if (NetworkService::ref == NULL) {
			try {
				p = new NetworkService();
			} catch (std::bad_alloc & e) {
				throw Exception(e.what());
			} catch (Exception & e) {
				/* failed to get adapters */
				if (NetworkService::ref == NULL && p != NULL) {
					delete p;
				}
				throw e;
			}
		}
		return NetworkService::ref;
	}

	/*
	 * dispose the previously acquired instance of NetworkService
	 */
	void NetworkService::dispose()
	{
		if (NetworkService::ref != NULL) {
			delete NetworkService::ref;
		}
	}
}
