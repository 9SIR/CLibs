#include <thread>
#include "socket_utils.h"

int
main(int argc, char *argv[])
{
	const unsigned short udpListenPort = 60053;
	clibs::sock udpServer(udpListenPort);
	std::thread udpServerThd(&clibs::sock::createUDPServer, &udpServer);

	const unsigned epollMaxSize = 1024;
	const unsigned epollMaxEvents = epollMaxSize;
	const unsigned epollWait = 10;
	const unsigned short tpcListenPort = 60000;
	clibs::sock tcpSocket(
		tpcListenPort, epollMaxSize, epollMaxEvents, epollWait
	);
	std::thread tcpServerThd(&clibs::sock::createTCPServer, &tcpSocket);

	tcpServerThd.join();
	udpServerThd.join();

	return 0;
}