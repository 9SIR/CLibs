#include <iostream>
#include <cstring> /* std::memset */

#include <fcntl.h> /* fcntl */
#include <netdb.h> /* addrinfo */
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "socket_utils.h"
#include "../utils/datetime/datetime.h"

namespace clibs
{

sock::sock(const unsigned short tcpPort,
	   const unsigned maxSize,
	   const unsigned maxEvents,
	   const unsigned epollTimeout)
{
	this->tcport = tcpPort;
	this->epollMaxSize = maxSize;
	this->epollMaxEvents = maxEvents;
	this->epollWaitimeout = epollTimeout;
}

sock::sock(const unsigned short udpPort)
{
	this->udport = udpPort;
}

sock::sock(const unsigned short udpMutiCastPort,
	   const std::string &udpMutiCastIP)
{
	this->udpMCPort = udpMutiCastPort;
	this->udpMutiCastIP = udpMutiCastIP;
}

sock::~sock() {}

const unsigned
sock::createAndBind(const std::string &protocol, struct sockaddr_in saddr_in)
{
	if (protocol.empty()) return 0;

	const std::string tcpStr = "TCP";
	const std::string udpStr = "UDP";

	if (protocol != tcpStr && protocol != udpStr) return 0;

	bool isTCP = protocol == tcpStr;
	bool isUDP = protocol == udpStr;

	int socketType;
	if (isTCP)
		socketType = SOCK_STREAM;
	if (isUDP)
		socketType = SOCK_DGRAM;

	int socketFD = socket(AF_INET, socketType, 0);
	if (socketFD <= 0) {
		std::cout << "create udp socket Failed!!!" << std::endl;
		return 0;
	}

	int ret = bind(socketFD, (struct sockaddr *)&saddr_in, sizeof(saddr_in));
	if (ret < 0) {
		std::cout << "bind socket Failed!!!" << std::endl;
		return 0;
	}
	int reuse = 1;
	if (setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		std::cout << "set reuseaddr socketopt Failed!!!" << std::endl;
		return 0;
	}
	return socketFD;
}

const unsigned
sock::createAndBindUseAddrinfo(const std::string &listenPort,
			       const std::string &protocol)
{
	if (listenPort.empty() || protocol.empty()) return 0;

	const std::string tcpStr = "TCP";
	const std::string udpStr = "UDP";
	if (protocol != tcpStr && protocol != udpStr) return 0;

	bool isTCP = protocol == tcpStr;
	bool isUDP = protocol == udpStr;

	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *rp;
	int socketFD;

	std::memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
	if (isTCP)
		hints.ai_socktype = SOCK_STREAM; /* create a TCP socket */
	if (isUDP)
		hints.ai_socktype = SOCK_DGRAM; /* create an UDP socket */

	hints.ai_flags = AI_PASSIVE; /* All interfaces */

	int retval = getaddrinfo(NULL, listenPort.c_str(), &hints, &result);
	if (retval != 0) {
		std::cout << "getaddrinfo: " << gai_strerror(retval) << " Failed!!!" << std::endl;
		return 0;
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		socketFD = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (socketFD == -1)
			continue;

		if (bind(socketFD, rp->ai_addr, rp->ai_addrlen) == 0)
			break; /* We managed to bind successfully! */

		close(socketFD);
	}
	if (rp == NULL) {
		std::cout << "bind socket Failed!!!" << std::endl;
		return 0;
	}
	freeaddrinfo(result);
	return socketFD;
}

const bool
sock::setSocketKeepalive(const unsigned socketFD, const int maxKeepClients)
{
	int yes = 1;
	if (setsockopt(socketFD, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int)) < 0)
		return false;

	int idle = 1;
	if (setsockopt(socketFD, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(int)) < 0)
		return false;

	int interval = 1;
	if (setsockopt(socketFD, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(int)) < 0)
		return false;

	if (maxKeepClients > 0 && setsockopt(socketFD, IPPROTO_TCP, TCP_KEEPCNT, &maxKeepClients, sizeof(int)) < 0)
		return false;

	return true;
}

const bool
sock::acceptConn(const unsigned socketFD,
		 const unsigned epollFD, const int keepalive)
{
	struct sockaddr clientAddr;
	socklen_t client_len;
	int conn_fd = accept(socketFD, &clientAddr, &client_len);
	if (conn_fd <= 0) {
		std::cout << "accept client connection Failed!!!" << std::endl;
		return false;
	}
	if (keepalive)
		sock::setSocketKeepalive(conn_fd, 0);

	if (!sock::addEpollEvent(epollFD, conn_fd, EPOLLIN | EPOLLET)) {
		std::cout << "epoll_ctl Failed!!!" << std::endl;
		return false;
	}
	std::cout << ">>>>> Accepted Client: " << conn_fd << std::endl;
	return true;
}

const unsigned
sock::getEpollMaxSize()
{
	return epollMaxSize;
}
const unsigned
sock::getEpollMaxEvents()
{
	return epollMaxEvents;
}

const unsigned
sock::getEpollWaitimeout()
{
	return epollWaitimeout;
}

const unsigned short
sock::getTCPort()
{
	return tcport;
}

const unsigned short
sock::getUDPort()
{
	return udport;
}

const unsigned short
sock::getUDPMutiCastPort()
{
	return udpMCPort;
}

const std::string&
sock::getUDPMutiCastIP()
{
	return udpMutiCastIP;
}

const bool
sock::setSocketBuff(const unsigned socketFD,
	      const unsigned sendBuffSize, const unsigned recvBuffSize)
{
	if (socketFD == 0) return false;

	if (sendBuffSize > 0 && setsockopt(socketFD, SOL_SOCKET, SO_SNDBUF,
					   (const char*)&sendBuffSize, sizeof(int)) < 0)
		return false;

	if (recvBuffSize > 0 && setsockopt(socketFD, SOL_SOCKET, SO_RCVBUF,
					   (const char*)&recvBuffSize, sizeof(recvBuffSize)) < 0)
		return false;

	return true;
}

const bool
sock::setSocketNonBlock(const unsigned socketFD)
{
	if (socketFD == 0) return false;

	int flags = fcntl(socketFD, F_GETFL, 0);
	if (flags == -1) {
		std::cout << "fcntl F_GETFL Failed!!!" << std::endl;
		return false;
	}

	flags |= O_NONBLOCK;
	if (fcntl(socketFD, F_SETFL, flags) == -1) {
		std::cout << "fcntl F_SETFL Failed!!!" << std::endl;
		return false;
	}

	return true;
}

const bool
sock::setIfrTXQlen(const unsigned socketFD, const char *dev, const unsigned len)
{
	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::memcpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	ifr.ifr_qlen = len;

	if (ioctl(socketFD, SIOCSIFTXQLEN, &ifr) < 0) {
		std::cout << "set dev tx queue length Failed!!!" << std::endl;
		return false;
	}
	if (ioctl(socketFD, SIOCGIFTXQLEN, &ifr) < 0) {
		std::cout << "get dev tx queue length Failed!!!" << std::endl;
		return false;
	}
	return true;
}

const bool
sock::setUDPGroupSockopt(const unsigned socketFD,
			 const int ttl, const int loop, struct ip_mreq mreq)
{
	if (socketFD <= 0 || ttl < 0 || (loop != 0 && loop != 1))
		return false;

	/* 设置多播的TTL值 */
	if (ttl > 0 && setsockopt(socketFD, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
		std::cout << "setsockopt udp multicast TTL Failed!!!" << std::endl;
		return false;
	}
	/* 取消 loopback，不接收自己发送的数据报文 */
	if (setsockopt(socketFD, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
		std::cout << "setsockopt udp multicast loop Failed!!!" << std::endl;
		return false;
	}
	/* 加入多播组 */
	if (setsockopt(socketFD, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
		std::cout << "setsockopt add to udp multicast membership Failed!!!" << std::endl;
		return false;
	}

	return true;
}

const bool
sock::readFromSocket(const unsigned socketFD)
{
	ssize_t recvLen;
	const unsigned buffSize = 8192;
	char recvBuff[buffSize];
	datime dt;

	while (1) {
		std::memset(&recvBuff, 0, sizeof(recvBuff));
		recvLen = recv(socketFD, recvBuff, buffSize, 0);
		if (recvLen == 0) return true;
		if (recvLen < 0 && !(errno == EAGAIN || errno == EWOULDBLOCK)) {
			std::cout << "sock::readFromSocket Error!!!" << std::endl;
			return false;
		}
		std::cout << ">>>>> " << dt.getLocalTimestampStr();
		std::cout << "  LEN: " << recvLen;
		std::cout << ", BUFFER: " << recvBuff;
	}
}

const bool
sock::addEpollEvent(const unsigned epollFD,
	      const unsigned fd, const unsigned estate)
{
	struct epoll_event ev;
	ev.events = estate;
	ev.data.fd = fd;
	if (epoll_ctl(epollFD, EPOLL_CTL_ADD, fd, &ev) == -1)
		return false;

	return true;
}

const bool
sock::deleteEpollEvent(const unsigned epollFD, const unsigned fd)
{
	struct epoll_event ev;
	ev.data.fd = fd;
	if (epoll_ctl(epollFD, EPOLL_CTL_DEL, fd, &ev) == -1)
		return false;

	return true;
}

const bool
sock::modifyEpollEvent(const unsigned epollFD,
		 const unsigned fd, const unsigned estate)
{
	struct epoll_event ev;
	ev.events = estate;
	ev.data.fd = fd;
	if (epoll_ctl(epollFD, EPOLL_CTL_MOD, fd, &ev) == -1)
		return false;

	return true;
}

const bool
sock::epollEventsLoop(const unsigned socketFD, const unsigned epollFD)
{
	uint32_t index;
	int eventNum;
	struct epoll_event event;
	struct epoll_event curEvent;
	struct epoll_event epollEventsAry[this->getEpollMaxEvents()];

	while (1) {
		eventNum = epoll_wait(epollFD, epollEventsAry,
			this->getEpollMaxEvents(), this->getEpollWaitimeout());

		if (eventNum < 0 && errno != EINTR) {
			return false;
		}
		for (index = 0; index < eventNum; ++index) {
			curEvent = epollEventsAry[index];
			// If a new SOCKET user is detected to be connected to a bound SOCKET port
			// establish a new connection
			if (curEvent.data.fd == socketFD) {
				if (!sock::acceptConn(socketFD, epollFD, 0)) {
					std::cout << "acceptConn Failed in epoll loop!!!" << std::endl;
					continue;
				}
			}
			// If the user is already connected and receives data, read in.
			else if (curEvent.events & EPOLLIN) {
				if (!sock::readFromSocket(curEvent.data.fd)) {
					std::cout << "readFromSocket Failed in epoll loop!!!" << std::endl;
					continue;
				}
			}
			// If there is data to send
			else if (curEvent.events & EPOLLOUT) {
				// write_to_sock();
			} else {
				if (curEvent.events & EPOLLERR)
					std::cout << "epoll event loop Failed on EPOLLERR!!!" << std::endl;
				else if (curEvent.events & EPOLLHUP)
					std::cout << "epoll event loop Failed on EPOLLHUP!!!" << std::endl;
				else if (curEvent.events & EPOLLRDHUP)
					std::cout << "epoll event loop Failed on EPOLLRDHUP!!!" << std::endl;

				sock::deleteEpollEvent(epollFD, curEvent.data.fd);
				close(curEvent.data.fd);
			}
		}
	}
}

void
sock::createTCPServer()
{
	int epollFD = 0;
	struct sockaddr_in localAddr;
	std::memset(&localAddr, 0, sizeof(localAddr));
	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(sock::getTCPort());
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	const unsigned listen_sock_fd = sock::createAndBind("TCP", localAddr);
	if (listen_sock_fd <= 0) {
		std::cout << "createAndBind Failed in createTCPServer!!!" << std::endl;
		return;
	}
	int reuse = 1;
	if (setsockopt(listen_sock_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
		std::cout << "set reuseaddr socketopt Failed in createTCPServer!!!" << std::endl;
		goto ClearUpTCPSocket;
	}

	if (!sock::setSocketNonBlock(listen_sock_fd))
		goto ClearUpTCPSocket;

	if (listen(listen_sock_fd, SOMAXCONN) == -1) {
		std::cout << "listen socket Failed in createTCPServer!!!" << std::endl;
		goto ClearUpTCPSocket;
	}

	epollFD = epoll_create(this->getEpollMaxSize());
	if (epollFD == -1) {
		std::cout << "epoll_create Failed in createTCPServer!!!" << std::endl;
		goto ClearUpTCPSocket;
	}

	{	// Register the listening socket for epoll events
		struct epoll_event event;
		event.data.fd = listen_sock_fd;
		event.events = EPOLLIN | EPOLLET;
		if (epoll_ctl(epollFD, EPOLL_CTL_ADD, listen_sock_fd, &event) == -1) {
			std::cout << "epoll_ctl Failed in createTCPServer!!!" << std::endl;
			goto ClearUpTCPSocket;
		}
	}

	if (sock::epollEventsLoop(listen_sock_fd, epollFD))
		goto ClearUpTCPSocket;

	close(listen_sock_fd);
	close(epollFD);
	return;

ClearUpTCPSocket:
	if (listen_sock_fd > 0) {
		shutdown(listen_sock_fd, SHUT_RDWR);
		close(listen_sock_fd);
	}
	if (epollFD > 0)
		close(epollFD);
}

void
sock::createUDPMutiCastServer()
{
	struct sockaddr_in local_addr;
	std::memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(sock::getUDPMutiCastPort());
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	// local_addr.sin_addr.s_addr = inet_addr("0.0.0.0");

	const unsigned sock_fd = sock::createAndBind("UDP", local_addr);
	if (sock_fd == 0) {
		std::cout << "createAndBind Failed for socket fd is 0" << std::endl;
		return;
	}

	struct ip_mreq mreq; /* 多播组结构体 */
	std::memset(&mreq, 0, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = inet_addr(sock::getUDPMutiCastIP().c_str()); /* 多播组IP */
        mreq.imr_interface.s_addr = inet_addr("192.168.20.1");

	char buffer[BUFSIZ];

	if (!sock::setUDPGroupSockopt(sock_fd, 0, 0, mreq)) {
		std::cout << "set udp group sockopt Failed!!!" << std::endl;
		goto clean_udpsock_up;
	}
	int retval;
	socklen_t addr_len;
	struct sockaddr_in clientAddr; /* 用于记录发送方的地址信息 */

	while (1) {
		std::memset(buffer, 0, sizeof(buffer));
		retval = recvfrom(sock_fd, buffer, BUFSIZ, 0,
				  (struct sockaddr*)&clientAddr, &addr_len);
		if (retval < 0) {
			/* 退出多播组 */
			if (setsockopt(sock_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
				std::cout << "setsockopt drop from udp multicast membership Failed!!!" << std::endl;

			std::cout << "redvfrom Failed!!!" << std::endl;
			goto clean_udpsock_up;
		}
		std::cout << "length: " << retval << ", ";
		std::cout << "buffer: " << buffer << std::endl;
	}

clean_udpsock_up:
	close(sock_fd);
}

void
sock::createUDPServer()
{
	struct sockaddr_in local_addr;
	std::memset(&local_addr, 0, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(sock::getUDPort());
	local_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	const uint32_t socketFD = sock::createAndBind("UDP", local_addr);
	if (socketFD == 0) {
		std::cout << "createAndBind Failed for socket fd is 0" << std::endl;
		return;
	}

	const unsigned sock_recv_buf = 1024 * 1024;
	if (!setSocketBuff(socketFD, 0, sock_recv_buf)) {
		std::cout << "setSocketBuff Failed!!!" << std::endl;
		return;
	}

	char buffer[BUFSIZ];
	size_t buff_size = sizeof(buffer);
	struct sockaddr_in clientAddr; /* 用于记录发送方的地址信息 */
	socklen_t addr_len;
	int recv_cnt;

	while (1) {
		std::memset(buffer, 0, buff_size);
		recv_cnt = recvfrom(socketFD, buffer, buff_size,
				    0, (struct sockaddr*)&clientAddr, &addr_len);
		if (recv_cnt < 0) {
			std::cout << "udp recvfrom Failed!!!" << std::endl;
			break;
		}
		std::cout << "length: " << recv_cnt << ", ";
		std::cout << "buffer: " << buffer << std::endl;

		// if (sendto(socketFD, buffer, BUFSIZ,
		// 	   0, (struct sockaddr*)&clientAddr, addr_len) < 0) {
		// 	LOG_ERROR("ss", __FILE__, __LINE__, "udp sendto Failed!!!");
		// 	break;
		// }
	}
	close(socketFD);
}

} /* namespace clibs */
