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

#pragma once
#include <ITH\Hash.h>
#ifdef ITH_TLS
#define ITH_TLS_SERVICE __declspec(dllexport)
#else
#define ITH_TLS_SERVICE __declspec(dllimport)
#endif
#define ITH_TLS_API __stdcall

#ifndef ITH_TLS_SOCKET
#define ITH_TLS_SOCKET
class TransportSocket
{
public:
	TransportSocket() : sock(0), type(0), error_code(0), status(0) {}
	virtual ~TransportSocket();
	virtual int socket();
	virtual int connect(char* server, int port = 0); //pass 0 to make use of default port number. 
	//This number is 80 for plain socket and 443 for secure socket.
	virtual int close();
	virtual int send(void* data, int len);
	virtual int recv(void* data, int len);
	inline int Type() {return type;}
protected:
	int sock, type, error_code, status;
};
#endif
extern "C" {
	ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_Init();
	ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_Cleanup();
	ITH_TLS_SERVICE HashCalculator* ITH_TLS_API ITH_TLS_NewHashCalculator(HashType type);
	ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_DestroyHashCalculator(HashCalculator* hash);
	ITH_TLS_SERVICE TransportSocket* ITH_TLS_API ITH_TLS_NewSocket(DWORD secure);
	ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_DestroySocket(TransportSocket* socket);
	ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_RSAEncrypt(void* key, void* data, void* out, DWORD len_in_bytes);
};
