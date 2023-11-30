#ifndef __SOCKET_HEADER__
#define __SOCKET_HEADER__

#include <string>

namespace clibs
{

class sock
{
private:
	unsigned short tcport;
	unsigned short udport;
	unsigned short udpMCPort;
	std::string udpMutiCastIP;
	unsigned epollMaxSize;
	unsigned epollMaxEvents;
	unsigned epollWaitimeout; /* epoll_wait函數的最後一個參數，等待epoll event的超時時間 */

public:
	/* 防止構造函數輸入不同類型參數的隱式轉換 */
	explicit sock(const unsigned short tcport,
		      const unsigned epollMaxSize,
		      const unsigned epollMaxEvents,
		      const unsigned epollWaitimeout);

	explicit sock(const unsigned short udport);

	explicit sock(const unsigned short udpMutiCastPort,
		      const std::string &udpMutiCastIP);

	~sock();

	/* 取消複製構造函數  */
	sock(const sock&) = delete;
	sock& operator = (const sock&) = delete;

	const unsigned createAndBind(
		const std::string &protocol, struct sockaddr_in saddr_in);

	const unsigned createAndBindUseAddrinfo(
		const std::string &listenPort, const std::string &protocol);

	const bool setSocketKeepalive(
			const unsigned socketFD, const int maxKeepClients);

	const bool setSocketBuff(const unsigned socketFD,
	      const unsigned sendBuffSize, const unsigned recvBuffSize);

	const bool setIfrTXQlen(const unsigned socketFD,
					const char *dev, const unsigned len);

	const bool setSocketNonBlock(const unsigned socketFD);

	const bool setUDPGroupSockopt(const unsigned socketFD,
			const int ttl, const int loop, struct ip_mreq mreq);

	const bool acceptConn(const unsigned socketFD,
			const unsigned epollFD, const int keepalive);

	const bool readFromSocket(const unsigned socketFD);

	const bool epollEventsLoop(const unsigned socketFD,
					   const unsigned epollFD);

	const bool addEpollEvent(const unsigned epollFD,
			const unsigned fd, const unsigned estate);
	const bool deleteEpollEvent(const unsigned epollFD,
					    const unsigned fd);
	const bool modifyEpollEvent(const unsigned epollFD,
			const unsigned fd, const unsigned estate);

	void createTCPServer();
	void createUDPServer();
	void createUDPMutiCastServer();

	inline const unsigned getEpollMaxSize();
	inline const unsigned getEpollMaxEvents();
	inline const unsigned getEpollWaitimeout();

	inline const unsigned short getTCPort();
	inline const unsigned short getUDPort();
	inline const unsigned short getUDPMutiCastPort();
	inline const std::string& getUDPMutiCastIP();
}; /* class sock */

} /* namespace clibs */

#endif /* __SOCKET_HEADER__ */
