#ifndef __DATETIME_HEADER__
#define __DATETIME_HEADER__

#include <string>

namespace clibs
{

class datime
{
public:
	static const std::string getLocalTimestampStr();
	static inline const unsigned long getLocalTimestamp();
}; /* class datime */

} /* namespace clibs */

#endif /* __DATETIME_HEADER__ */
