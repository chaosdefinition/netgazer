/*
 * implementation of class NetworkService
 */

#include <new>

#include "core/NetworkService.h"

using std::vector;

namespace netgazer {
	/*
	 * constructor of NetworkService
	 *
	 * @errbuf: buffer to hold error message
	 */
	NetworkService::NetworkService(char * errbuf)
	{
		/* clear previous instance */
		if (NetworkService::ref != NULL) {
			delete NetworkService::ref;
		}
		/* do find all adapters */
		if (pcap_findalldevs(&(this->m_pcap_allAdapters), errbuf) == -1) {
			return;
		}
		NetworkService::ref = this;
		this->m_pcap_adapter = this->m_pcap_allAdapters;
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
		if (this->m_pcap_allAdapters != NULL) {
			pcap_freealldevs(m_pcap_allAdapters);
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
	Adapter * NetworkService::nextAdapter()
	{
		Adapter * adapter = NULL;

		/* no next adapter */
		if (this->m_pcap_adapter == NULL) {
			return NULL;
		}

		try {
			adapter = new Adapter(this->m_pcap_adapter);
		} catch (std::bad_alloc & e) {
			adapter = NULL;
		}

		if (adapter != NULL) {
			this->m_pcap_adapter = this->m_pcap_adapter->next;
			this->m_adapters.push_back(adapter);
		}
		return adapter;
	}

	/*
	 * get an instance of NetworkService
	 *
	 * @errbuf: buffer to hold error message
	 *
	 * return: a pointer to NetworkService on success, NULL otherwise
	 */
	static NetworkService * NetworkService::instance(char * errbuf)
	{
		NetworkService * p = NULL;

		if (NetworkService::ref == NULL) {
			try {
				p = new NetworkService(errbuf);
			} catch (std::bad_alloc & e) {
				p = NULL;
			}

			/* failed to get adapters */
			if (NetworkService::ref == NULL) {
				if (p != NULL) {
					delete p;
				}
			}
		}
		return NetworkService::ref;
	}
}
