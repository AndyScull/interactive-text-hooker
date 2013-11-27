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

#ifndef ITH_SOCKET
#define ITH_SOCKET
#include "aes256.h"
#include <ITH\Hash.h>
#include <ITH\AVL.h>
#ifndef ITH_TLS_SOCKET
#define ITH_TLS_SOCKET
class TransportSocket
{
public:
	TransportSocket() : sock(0), sock6(0), error(0), status(0) {}
	virtual ~TransportSocket();
	virtual int socket();
	virtual int connect(char* server, int port);
	virtual int close();
	virtual int send(void* data, int len);
	virtual int recv(void* data, int len);
	//inline int Type() {return type;}
protected:
	int sock, sock6, error, status;
};
#endif


#define AES256_KEY_SIZE 0x20
#define AES256_BLOCK_SIZE 0x10
#define KEY_BLOCK_SIZE ((HASH_SIZE_SHA1 + AES256_KEY_SIZE + AES256_BLOCK_SIZE) * 2)
struct MasterSecret
{
	unsigned char secret[0x30];
};
struct RecordControlBlock
{
	int expect_recv;
	int already_recv;
	unsigned long long send_seq;
	unsigned long long recv_seq;
};
struct KeyBlock
{
	unsigned char client_mac[HASH_SIZE_SHA1],server_mac[HASH_SIZE_SHA1];
	unsigned char client_write[AES256_KEY_SIZE], server_write[AES256_KEY_SIZE];
	unsigned char client_iv[AES256_BLOCK_SIZE],server_iv[AES256_BLOCK_SIZE];
};


class SecureSocket : public TransportSocket
{
public:
	SecureSocket();
	~SecureSocket();
	//virtual int socket();
	virtual int connect(char* server, int port);
	virtual int close();
	virtual int send(void* data, int len);
	virtual int recv(void* data, int len);
protected:
	int send_type(void* data, int len, unsigned char type);
	int get_record();
	int build_ssl_client_hello(char* hello, unsigned char* client_random);
	int recv_full(void* buff, int len);
	int handshake();
	AES_CBC_Cipher* get_encryptor();
	AES_CBC_Cipher* get_decryptor();
	KeyBlock* get_key_block();
	//static const int port = 443;
	unsigned int buffer_size;
	//int sock;
	//unsigned int status;
	RecordControlBlock rcb;
	void* transfer_buffer;
	void* param_buffer;
};

/*class DNSCache : public AVLTree<char,unsigned long,SCMP,SCPY,SLEN>
{
public:
	void SetAddress(char* server, unsigned long addr);
	unsigned long GetAddress(char* server);

};
class DNSCache6 : public AVLTree<char,char*,SCMP,SCPY,SLEN>
{
public:
	void SetAddress(char* server, char* addr);
	char* GetAddress(char* server);
};
extern DNSCache *dns;*/
#endif