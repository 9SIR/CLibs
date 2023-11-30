#include <chrono>
#include <ctime>

#include "datetime.h"

namespace clibs
{

const std::string
datime::getLocalTimestampStr()
{
	auto currentTime = std::chrono::system_clock::now();
	auto transformed = currentTime.time_since_epoch().count() / 1000000;
	auto millis = transformed % 1000;

	std::time_t tt = std::chrono::system_clock::to_time_t(currentTime);
	auto timeinfo = localtime(&tt);
	char buffer[32] = {0};
	strftime(buffer, 32, "%F %H:%M:%S", timeinfo);
	char datetime[32] = {0};
	sprintf(datetime, "%s:%03d", buffer, (int)millis);
	return std::string(datetime);
}

const unsigned long
datime::getLocalTimestamp()
{
	auto currentTime = std::chrono::system_clock::now();
	auto transformed = currentTime.time_since_epoch().count() / 1000000;
	return (unsigned long)transformed;
}

} /* namespace clibs */
