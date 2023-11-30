#!/bin/bash

targe='SocketServer'

[ $targe ] && rm -f $targe

g++ -std=c++20 -o $targe \
	sockets/socket_server.cc sockets/socket_utils.cc \
	utils/datetime/datetime.cc
