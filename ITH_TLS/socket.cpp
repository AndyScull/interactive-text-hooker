/*  Copyright (C) 2010-2012  kaosu (qiupf2000@gmail.com)
 *  This file is part of the Interactive Text Hooker.

 *  Interactive Text Hooker is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.

 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.

 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>
#include "socket.h"
#include <ITH\IHF_SYS.h>
static const char* googleITH = "interactive-text-hooker.googlecode.com";
//74.125.31.82
static const DWORD googleITH4 = 0x521f7d4a; //
//2404:6800:800b::64
static const unsigned char googleITH6[0x10] = {0x24,0x4,0x68,0x00,0x80,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x65};

TransportSocket::~TransportSocket()
{
	close();
}
int TransportSocket::socket()
{
	int s = _InterlockedExchange((long*)&sock,1);
	if (s == 0)
	{
		s = ::socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		if (s != INVALID_SOCKET) sock = s;
		return s;
	}
	else sock = 0;
	return -1;
}

int TransportSocket::connect( char* server, int port )
{
	if (port == 0) port = 80;
	if (_stricmp(server,googleITH) == 0)
	{
		sockaddr_in6 addr6 = {};
		addr6.sin6_family = AF_INET6;
		addr6.sin6_port = htons(port);
		memcpy(addr6.sin6_addr.s6_addr,googleITH6,0x10);
		sock6 = ::socket(AF_INET6,SOCK_STREAM,IPPROTO_TCP);
		error = ::connect(sock6,(sockaddr*)&addr6,sizeof(addr6));
		if (error != 0)
		{
			closesocket(sock6);
			sock6 = 0;
		}
		else return 0;
		sockaddr_in remote;
		remote.sin_family = AF_INET;
		remote.sin_addr.s_addr = googleITH4;
		remote.sin_port = htons(port);
		return ::connect(sock, (struct sockaddr *)&remote, sizeof(remote));
	}
	
	unsigned long addr = 0;
	unsigned long ip1,ip2,ip3,ip4;
	if (sscanf(server,"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4) == 4)
	{
		addr |= ip4;
		addr <<= 8;
		addr |= ip3;
		addr <<= 8;
		addr |= ip2;
		addr <<= 8;
		addr |= ip1;
	}
	else
	{
		hostent* host = gethostbyname(server);
		if (host == 0) return -1;
		addr = *(ULONG*)host->h_addr_list[0];

	}

	sockaddr_in remote;
	remote.sin_family = AF_INET;
	remote.sin_addr.s_addr = addr;
	remote.sin_port = htons(port);
	return ::connect(sock, (struct sockaddr *)&remote, sizeof(struct sockaddr));
}

int TransportSocket::close()
{
	int s = _InterlockedExchange((long*)&sock6,0);
	if (s == 0)
	{
		s = _InterlockedExchange((long*)&sock,0);
		if (s == 0) return 0;
	}
	else closesocket(sock);
	shutdown(s, SD_BOTH);
	//Wait for gracefully shutdown. In normal network condition TCP should shutdown in 1 sec.
	//As only (20(IP) + 20(TCP)) * 2(FIN&ACK, ACK) = 80 bytes needed to be transmitted.
	LARGE_INTEGER sleep_time = {-10000000, -1};
	NtDelayExecution(0,&sleep_time);
	return closesocket(s);
}

int TransportSocket::send( void* data, int len )
{
	int s = sock6 != 0 ? sock6 : sock;
	return ::send(s,(char*)data,len,0);
}

int TransportSocket::recv( void* data, int len )
{
	int s = sock6 != 0 ? sock6 : sock;
	return ::recv(s,(char*)data,len,0);
}

/*void DNSCache::SetAddress(char* server, unsigned long addr)
{
	Insert(server, addr);
}

unsigned long DNSCache::GetAddress(char* server)
{
	TreeNode<char*,unsigned long>* node;
	node = Search(server);
	if (node == 0) return 0;
	return node->data;
}*/