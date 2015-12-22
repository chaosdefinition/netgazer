/*
 * header file for class NetworkService
 */

#pragma once

#ifndef NG_NETWORK_SERVICE_H_
#define NG_NETWORK_SERVICE_H_

#include <vector>	/* for std::vector */
#include <pcap/pcap.h>	/* for libpcap types */

#include "Exception.h"	/* for netgazer::Exception */
#include "Adapter.h"	/* for netgazer::Adapter */

namespace netgazer {
	class NetworkService {
	/* constructors and destructor */
	private:
		NetworkService() throw (Exception);
	public:
		~NetworkService();

	/* public methods */
	public:
		Adapter * nextAdapter() throw (Exception);
		Adapter * adapterBy(const char * name) throw (Exception);
		Adapter * adapterBy(int index) throw (Exception);
		void reset() throw (Exception);

	/* public static methods */
	public:
		static NetworkService * instance() throw (Exception);
		static void dispose();

	/* fields */
	private:
		pcap_if_t * m_pcap_all_adapters;
		pcap_if_t * m_pcap_adapter;
		std::vector<Adapter *> m_adapters;

	/* static fields */
	private:
		static NetworkService * ref;
	};
}

#endif /* NG_NETWORK_SERVICE_H_ */
