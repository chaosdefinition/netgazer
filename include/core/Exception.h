/*
 * header file for class DefaultException
 */

#pragma once

#ifndef NG_EXCEPTION_H_
#define NG_EXCEPTION_H_

#include <string>	/* for std::string */

namespace netgazer {
	class Exception {
	/* constructors and destructor */
	public:
		Exception(const char * const & msg = "")
			: m_msg(msg)
		{
		}

		~Exception()
		{
		}

	/* public methods */
	public:
		const char * what()
		{
			return this->m_msg.c_str();
		}

	/* fields */
	private:
		const std::string m_msg;
	};
}

#endif /* NG_EXCEPTION_H_ */
