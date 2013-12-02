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

#include <windows.h>
#define ITH_TLS
#include <ITH\ITH_TLS.h>
#include <ITH\ntdll.h>
//#include "sha.h"
#include "socket.h"
#include "arithmetic.h"
//#include "tls.h"
#include <ITH\mem.h>
HANDLE hHeap;
//DNSCache* dns;

BOOL WINAPI DllMain(HANDLE hModule, DWORD reason, LPVOID lpReserved)
{
	switch(reason)
	{
	case DLL_PROCESS_ATTACH:
		{
			LdrDisableThreadCalloutsForDll(hModule);
			hHeap = RtlCreateHeap(HEAP_GROWABLE,0,0,0,0,0);
		}
		break;
	case DLL_PROCESS_DETACH:	
		RtlDestroyHeap(hHeap);
		hHeap = 0;
		break;
	}
	return TRUE;
}
ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_Init()
{
	WSADATA wsa;
	WSAStartup(MAKEWORD(2,2),&wsa);
	//dns = new DNSCache;
	//dns->Insert(DNSInitTableName[0],DNSInitTableAddr[0]);
	return 0;
}
ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_Cleanup()
{
	//delete dns;
	//dns = 0;
	WSACleanup();
	return 0;
}
ITH_TLS_SERVICE HashCalculator* ITH_TLS_API ITH_TLS_NewHashCalculator(HashType type)
{
	switch (type)
	{
	case HashTypeMD5:
		return new MD5Calc;
		break;
	case HashTypeSHA1:
		return new SHA1Calc;
		break;
	case HashTypeSHA256:
		return new SHA256Calc;
		break;
	default:
		return 0;
	}
}
ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_DestroyHashCalculator(HashCalculator* hash)
{
	delete hash;
	return 0;
}
ITH_TLS_SERVICE TransportSocket* ITH_TLS_API ITH_TLS_NewSocket(DWORD secure)
{
	if (secure == 0) return new TransportSocket;
	else return new SecureSocket;
}
ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_DestroySocket(TransportSocket* socket)
{
	delete socket;
	return 0;
}
ITH_TLS_SERVICE DWORD ITH_TLS_API ITH_TLS_RSAEncrypt(void* key, void* data, void* out, DWORD len_in_bytes)
{
	if (len_in_bytes > 0x100) return -1;
	static BYTE commong_exp[4] = {1,0,1,0}; //0x10001
	BYTE *key_tmp, *data_tmp;
	DWORD tmp_len = 0x10;
	while (len_in_bytes > tmp_len) tmp_len <<= 1;
	key_tmp = new BYTE[tmp_len];
	data_tmp = new BYTE[tmp_len];
	memcpy(key_tmp, key, len_in_bytes);
	memset(key_tmp + len_in_bytes, 0, tmp_len - len_in_bytes);
	memcpy(data_tmp, data, len_in_bytes);
	memset(data_tmp + len_in_bytes, 0, tmp_len - len_in_bytes);
	exp_mod(data_tmp, commong_exp, key_tmp, data_tmp, len_in_bytes, 4, len_in_bytes);
	memcpy(out, data_tmp, len_in_bytes);
	delete key_tmp;
	delete data_tmp;
	return 0;
}