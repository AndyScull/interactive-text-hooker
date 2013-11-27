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

#ifndef ITH_TLS_HEADER
#define ITH_TLS_HEADER
#include "aes256.h"
#include "hmac.h"
#include "socket.h"
#include <ITH\Hash.h>
#include <ITH\mem.h>
class PHashGen
{
public:
	PHashGen(HashType HashType, void* secret, int len_secret, void* seed, int len_seed);
	~PHashGen();
	int NextHash(void*);
private:
	unsigned char* secret;
	unsigned char* seed;
	int len_secret,len_seed;
	HashCalculator* hash;
};
int PRF_TLSv1(void* secret, int len_secret, void* text, int len_text, void* out, int len_out);
int ComputeMasterSecret(void* pre_master, void* master, void* client_random, void* server_random);
int ComputeKeyBlock(void* master, void* out, void* client_random, void* server_random);
int ComputeClientWriteKey(void* client_write, int len, void* out, void* client_ramdom, void* server_random);
int ComputeServerWriteKey(void* server_write, int len, void* out, void* client_ramdom, void* server_random);
int ComputeClientIV(void* out, int len, void* client_ramdom, void* server_random);
int ComputeClientVerify(void* out, void* master, void* hash_md5, void* hash_sha1);
int ComputeClientMAC(void* out, void* key, int len_key, void * seq, void* msg, int msg_len);

#endif