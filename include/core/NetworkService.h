/*
 * header file for class NetworkService
 */

#pragma once

#ifndef NG_NETWORK_SERVICE_H_
#define NG_NETWORK_SERVICE_H_

#include <vector>
#include <pcap/pcap.h>

#include "Adapter.h"

namespace netgazer {
	class NetworkService {
	/* constructors and destructor */
	private:
		NetworkService(char * errbuf);
	public:
		~NetworkService();

	/* public methods */
	public:
		Adapter * nextAdapter();

	/* public static methods */
	public:
		static NetworkService * instance(char * errbuf);

	/* fields */
	private:
		pcap_if_t * m_pcap_allAdapters;
		pcap_if_t * m_pcap_adapter;
		std::vector<Adapter *> m_adapters;

	/* static fields */
	private:
		static NetworkService * ref;
	};
}

static NetworkService * netgazer::NetworkService::ref = NULL;

#endif /* NG_NETWORK_SERVICE_H_ */
