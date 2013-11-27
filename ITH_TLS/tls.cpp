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
#include "tls.h"
#include "prng.h"
#include "x509.h"
#include "arithmetic.h"
#include <ITH\ntdll.h>
void* AllocateMemory(unsigned int size)
{
	LPVOID buffer = 0;
	DWORD s = size;
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &s, MEM_COMMIT, PAGE_READWRITE);
	return buffer;
	//return VirtualAlloc(0,size, MEM_COMMIT, PAGE_READWRITE);
}
void ReleaseMemory(void* memory)
{
	DWORD size = 0;
	NtFreeVirtualMemory(NtCurrentProcess(), &memory, &size, MEM_RELEASE);
	//VirtualFree(memory, 0, MEM_RELEASE);
}
unsigned long GetUnixTime(void *p)
{
	__asm
	{
		sub esp,8
		mov eax,esp
		push eax
		call dword ptr [NtQuerySystemTime]
		pop eax
		pop edx
		add eax, 0x2ac18000
		adc edx, 0xfe624e21
		mov ecx, 0x989680
		div ecx
		bswap eax
		mov ecx, p
		mov [ecx],eax
	}
}
#define MAX_HASH_SIZE 64
#define TLS_RSA_WITH_AES_256_CBC_SHA 0x35
#define SSL_PROTOCAL_ALERT 0x15
#define SSL_PROTOCAL_HANDSHAKE 0x16
#define SSL_PROTOCAL_APPLICATION 0x17
#define SSL_VERSION_MAJOR 3
#define SSL_VERSION_MINOR 1
#define SSL_HANDSHAKE_CLIENT_HELLO 1
#define SSL_HANDSHAKE_SERVER_HELLO 2
#define SSL_HANDSHAKE_SERVER_CERTIFICATE 0xB
#define SSL_HANDSHAKE_SERVER_DONE 0xE
#define SSL_HANDSHAKE_CLIENT_KEYEX 0x10
#define SSL_HANDSHAKE_CHANGE_CIPHER_SPEC 0x14
#define SSL_RECORD_HEADER_LENGTH 5

PHashGen::PHashGen(HashType type, void* _secret, int _len_secret, void* _seed, int _len_seed)
{
	switch (type)
	{
	case HashTypeMD5:
		hash = new MD5Calc;
		break;
	case HashTypeSHA1:
		hash = new SHA1Calc;
		break;
	case HashTypeSHA256:
		hash = new SHA256Calc;
		break;
	default: break;
	}
	int hash_size = hash->HashValueSize();
	len_secret = _len_secret;
	len_seed = _len_seed + hash_size;
	secret = new unsigned char[len_secret];
	memcpy(secret,_secret,len_secret);
	seed = new unsigned char[len_seed];
	HMAC(secret, len_secret, _seed, _len_seed, seed, hash);
	memcpy(seed + hash_size,_seed, _len_seed);	
	//HMAC(secret, len_secret, seed, hash_size, seed, hash);
}
PHashGen::~PHashGen()
{
	delete hash;
	delete seed;
	delete secret;
}
int PHashGen::NextHash(void* phash)
{
	HMAC(secret, len_secret, seed, len_seed, phash, hash); //P_hash(i) = HMAC_hash(secret, A(i+1) + seed)
	HMAC(secret, len_secret, seed, hash->HashValueSize(), seed, hash); //A(i) = HMAC_hash(secret, A(i-1))
	return 0;
}

int PRF_TLSv1(void* secret, int len_secret, void* text, int len_text, void* out, int len_out)
{
	int len, half_len,i;
	char *p, *half_first, *half_second;
	half_len = (len_secret + 1) >> 1;
	half_first = new char[half_len];
	half_second = new char[half_len];
	memcpy(half_first, secret, half_len);
	memcpy(half_second, (char*)secret + len_secret - half_len, half_len);
	char buffer[MAX_HASH_SIZE];
	len = len_out;
	p = (char*)out;
	PHashGen hash_gen1(HashTypeMD5,half_first,half_len,text,len_text);
	PHashGen hash_gen2(HashTypeSHA1,half_second,half_len,text,len_text);
	while (len >= HASH_SIZE_MD5)
	{
		hash_gen1.NextHash(p);
		p += HASH_SIZE_MD5;
		len -= HASH_SIZE_MD5;
	}
	if (len)
	{
		hash_gen1.NextHash(buffer);
		memcpy(p,buffer,len);
	}
	len = len_out;
	p = (char*)out;
	while (len >= HASH_SIZE_SHA1)
	{
		hash_gen2.NextHash(buffer);
		for (i = 0; i < HASH_SIZE_SHA1; i++)
			p[i] ^= buffer[i];
		p += HASH_SIZE_SHA1;
		len -= HASH_SIZE_SHA1;
	}
	if (len)
	{
		hash_gen2.NextHash(buffer);
		for (i = 0; i < len; i++)
			p[i] ^= buffer[i];
	}
	delete half_first;
	delete half_second;
	return 0;
}
int FuncX(void* secret, int len_secret, void* label, int len_label, 
	void* client_random, void* server_random, void* out, int len)
{
	char* text = new char[len_label + 0x40];
	memcpy(text, label, len_label);
	memcpy(text + len_label, client_random, 0x20);
	memcpy(text + len_label + 0x20, server_random, 0x20);
	int res = PRF_TLSv1(secret, len_secret, text, len_label + 0x40, out, len);
	memset(text, 0, len_label + 0x40);
	delete text;
	return res;
}
int ComputeMasterSecret(void* pre_master, void* master, void* client_random, void* server_random)
{
	static char master_str[] = "master secret";
	FuncX(pre_master, 0x30, master_str, sizeof(master_str)-1, client_random, server_random, master, 0x30);
	return 0;
}
int ComputeKeyBlock(void* master, void* out, void* client_random, void* server_random)
{
	static char key_block[] = "key expansion";
	FuncX(master, 0x30, key_block, sizeof(key_block)-1, server_random, client_random, out, KEY_BLOCK_SIZE);
	return 0;
}
int ComputeClientWriteKey(void* client_write, int len, void* out, void* client_ramdom, void* server_random)
{
	static char client_write_str[] = "client write key";
	FuncX(client_write,len, client_write_str, sizeof(client_write_str)-1, 
		client_ramdom, server_random, out, len);
	return 0;
}
int ComputeServerWriteKey(void* server_write, int len, void* out, void* client_ramdom, void* server_random)
{
	static char server_write_str[] = "server write key";
	FuncX(server_write,len, server_write_str, sizeof(server_write_str)-1, 
		client_ramdom, server_random, out, len);
	return 0;
}
int ComputeClientIV(void* out, int len, void* client_ramdom, void* server_random)
{
	static char IV_str[] = "IV block";
	unsigned char block[0x40];
	memset(block,0,0x40);
	FuncX(block,len, IV_str, sizeof(IV_str)-1, client_ramdom, server_random, out, len);
	return 0;
}
int ComputeClientVerify(void* out, void* master, void* hash_md5, void* hash_sha1)
{
	static char client_finish[] = "client finished";
	int len = sizeof(client_finish) - 1;
	char* buffer = new char[len + HASH_SIZE_MD5 + HASH_SIZE_SHA1];
	memcpy(buffer, client_finish, len);
	memcpy(buffer + len, hash_md5, HASH_SIZE_MD5);
	memcpy(buffer + len + HASH_SIZE_MD5, hash_sha1, HASH_SIZE_SHA1);
	PRF_TLSv1(master, 0x30, buffer, len + HASH_SIZE_MD5 + HASH_SIZE_SHA1, out, 0xC);
	memset(buffer, 0, len + HASH_SIZE_SHA1 + HASH_SIZE_MD5);
	delete buffer;
	return 0;
}
int ComputeClientMAC(void* out, void* key, int len_key, void * seq, void* msg, int msg_len)
{
	//static char client_finish[] = "client finished";
	unsigned char* buffer = new unsigned char[msg_len + 8];
	memcpy(buffer, seq, 8);
	memcpy(buffer + 8, msg, msg_len);
	//memcpy(buffer + msg_len + 8, client_finish, sizeof(client_finish) - 1);
	SHA1Calc *sha1 = new SHA1Calc;
	HMAC(key, len_key, buffer, msg_len + 8, out, sha1);
	delete buffer;
	delete sha1;
	return 0;
}

SecureSocket::SecureSocket()
{
	buffer_size = 0x1000;
	param_buffer = AllocateMemory(buffer_size);
	transfer_buffer = AllocateMemory(buffer_size);
	memset(&rcb,0,sizeof(rcb));
	//status = 0;
	//type = 1;
}
SecureSocket::~SecureSocket()
{
	close();
	ReleaseMemory(param_buffer);
	ReleaseMemory(transfer_buffer);
}
int SecureSocket::connect(char* server, int port)
{
	if (port == 0) port = 443;
	if (_InterlockedExchange((long*)&status,1) == 1) return -1;
	if (TransportSocket::connect(server,port) == 0)
		if (handshake() == 0)
			return 0;
	status = 0;
	return -1;
}
int SecureSocket::close()
{
	if (sock)
	{
		if (status)
		{
			char notify[2] = {1,0};
			send_type(notify,2,SSL_PROTOCAL_ALERT);
			status = 0;
		}
		TransportSocket::close();
	}
	return 0;
}
int SecureSocket::send(void* data, int len)
{
	return send_type(data,len,SSL_PROTOCAL_APPLICATION);
}
int SecureSocket::recv(void* data, int len)
{
	unsigned char* buffer = (unsigned char*)transfer_buffer;
	unsigned char* d = (unsigned char*)data;
	int remain = rcb.expect_recv - rcb.already_recv;
	if (remain > len)
	{
		memcpy(data, buffer + rcb.already_recv, len);
		rcb.already_recv += len;
		return len;
	}
	else
	{
		int sum = 0, ret = 0;
		if (remain > 0)
		{
			memcpy(d, buffer + rcb.already_recv, remain);
			d += remain;
			sum = remain;
			rcb.already_recv = 0;
			rcb.expect_recv = 0;
		}
		while (sum < len)
		{
			ret = get_record();
			if (ret < 0) return ret;
			if (ret == 0) return sum;
			if (sum + rcb.expect_recv >= len)
			{
				rcb.already_recv = len - sum;
				memcpy(d, buffer, rcb.already_recv);
				break;
			}
			else
			{
				memcpy(d, buffer, rcb.expect_recv);
				sum += rcb.expect_recv;
				d += rcb.expect_recv;
				rcb.expect_recv = 0;
			}
		}		
		return len;
	}
}
int SecureSocket::send_type( void* data, int len, unsigned char type )
{
	SHA1Calc sha1;
	int i,pad_len,pad, original_len;
	unsigned char tmp[0x8];
	char* d = (char*)data;
	char* buffer = (char*)param_buffer + 0xC00;
	unsigned char* sequence = (unsigned char*)&rcb.send_seq;
	AES_CBC_Cipher* cipher = get_encryptor();
	original_len = len;
	while (len > 0x3E0)
	{
		HMAC_Calc mac(get_key_block()->client_mac,HASH_SIZE_SHA1,&sha1);

		*(unsigned long*)tmp = _byteswap_ulong(sequence[1]);
		*(unsigned long*)(tmp + 4) = _byteswap_ulong(sequence[0]);

		mac.HMAC_Update(tmp,8);
		tmp[0] = type;
		tmp[1] = SSL_VERSION_MAJOR; 
		tmp[2] = SSL_VERSION_MINOR;
		tmp[3] = 0x3; 
		tmp[4] = 0xE0;
		mac.HMAC_Update(tmp, SSL_RECORD_HEADER_LENGTH);
		mac.HMAC_Update(d, 0x3E0);
		tmp[3] = 0x4; tmp[4] = 0;
		TransportSocket::send(tmp,SSL_RECORD_HEADER_LENGTH);

		for (i = 0; i < 0x3E0; i+= AES256_BLOCK_SIZE)
			cipher->Encrypt(d + i, buffer + i);		
		mac.HMAC_Final(buffer + 0x3E0);
		memset(buffer + 0x3F4, 0xB, 0xC); //400-3E0-14(SHA1) = 0xC padding bytes (0xB)
		TransportSocket::send(buffer, 0x400);

		rcb.send_seq++;
		d += 0x3E0;
		len -= 0x3E0;
	}
	HMAC_Calc mac(get_key_block()->client_mac,HASH_SIZE_SHA1,&sha1);

	*(unsigned long*)tmp = _byteswap_ulong(sequence[1]);
	*(unsigned long*)(tmp + 4) = _byteswap_ulong(sequence[0]);

	mac.HMAC_Update(tmp,8);
	tmp[0] = type;
	tmp[1] = 3; tmp[2] = 1;
	tmp[3] = (len >> 8) & 0xFF; tmp[4] = len & 0xFF;
	mac.HMAC_Update(tmp,5);
	mac.HMAC_Update(d, len);
	pad = len + HASH_SIZE_SHA1;
	pad_len = (pad | 0xF) + 1;
	pad = pad_len - pad;
	tmp[3] = (pad_len >> 8) & 0xFF;
	tmp[4] = pad_len & 0xFF;
	
	len -= AES256_BLOCK_SIZE;
	for (i = 0; i < len; i += AES256_BLOCK_SIZE)
		cipher->Encrypt(d + i, buffer + i);
	len += AES256_BLOCK_SIZE;
	memcpy(buffer + i, d + i, len - i);
	mac.HMAC_Final(buffer + len);
	memset(buffer + len + HASH_SIZE_SHA1, pad - 1, pad);
	for (; i < pad_len; i += AES256_BLOCK_SIZE)
		cipher->Encrypt(buffer + i, buffer + i);
	rcb.send_seq++;
	TransportSocket::send(tmp, SSL_RECORD_HEADER_LENGTH);
	if (TransportSocket::send(buffer, pad_len) == pad_len)
		return original_len;
	else return -1;
}
int SecureSocket::get_record()
{
	char tmp[0x20];

	SHA1Calc sha1;
	HMAC_Calc mac(get_key_block()->server_mac,HASH_SIZE_SHA1,&sha1);
	AES_CBC_Cipher* decryptor = get_decryptor();
	unsigned long* sequence = (unsigned long*)&rcb.recv_seq;
	*(unsigned long*)tmp = _byteswap_ulong(sequence[1]);
	*(unsigned long*)(tmp + 4) = _byteswap_ulong(sequence[0]);
	mac.HMAC_Update(tmp, 8);

	int ret = recv_full(tmp, 5);
	if (ret <= 0) return ret;
	if (tmp[0] == SSL_PROTOCAL_ALERT)
	{
		if (tmp[3] == 0 && tmp[4] == 0x20)
		{
			if (recv_full(tmp,0x20) < 0) return -1;
			decryptor->Decrypt(tmp,tmp);
			decryptor->Decrypt(tmp+0x10,tmp+0x10);
			if (tmp[0] == 1) return 0;
		}
	}
	if (tmp[1] != SSL_VERSION_MAJOR || tmp[2] != SSL_VERSION_MINOR) return -1;
	unsigned int len = _byteswap_ushort(*(unsigned short*)(tmp + 3));
	if (len & 0xF) return -1;

	rcb.expect_recv = len;
	if (len > buffer_size)
	{
		ReleaseMemory(transfer_buffer);
		while (len > buffer_size) buffer_size <<= 1;
		transfer_buffer = AllocateMemory(buffer_size);
	}
	char* buffer = (char*)transfer_buffer;
	ret = recv_full(buffer, len);
	if (ret <= 0) return ret;
	unsigned int i;
	for (i = 0; i < len; i+= AES256_BLOCK_SIZE)
		decryptor->Decrypt(buffer + i, buffer + i);

	char pad = buffer[len - 1];
	if (pad < 0 || pad > 0xF) return -1;
	//len = buffer[len - 1];
	for (i = pad + 1; i > 0; i--)
		if (buffer[rcb.expect_recv - i] != pad) return -1;

	rcb.expect_recv -= pad + HASH_SIZE_SHA1 + 1;

	tmp[3] = (rcb.expect_recv >> 8) & 0xFF;
	tmp[4] = rcb.expect_recv & 0xFF;
	mac.HMAC_Update(tmp, SSL_RECORD_HEADER_LENGTH);
	mac.HMAC_Update(buffer, rcb.expect_recv);
	mac.HMAC_Final(tmp);
	if (memcmp(tmp,buffer + rcb.expect_recv, HASH_SIZE_SHA1) == 0)
	{
		rcb.recv_seq++;
		return rcb.expect_recv;
	}
	else
	{
		close(); //MAC verification failed.
		return -1; //Caused by software bug or connection compromised.
	}
}
int SecureSocket::build_ssl_client_hello(char* hello, unsigned char* client_random)
{
	char* p = hello;
	p[0] = SSL_HANDSHAKE_CLIENT_HELLO;
	p[1] = 0;
	p[2] = 0;
	//p[3] = 0; total length = 0x2b, filled later
	p[4] = SSL_VERSION_MAJOR;
	p[5] = SSL_VERSION_MINOR;
	p+=6;
	unsigned long long t =__rdtsc();
	HashSHA256((u8*)&t,8,client_random);
	GetUnixTime(client_random);
	//*(unsigned long*)p = _byteswap_ulong(_time32(0));
	memcpy(p,client_random,0x20);
	p += 0x20;
	p[0] = 0;
	p[1] = 0;
	p[2] = 2; //Length of cipher suites, 2 each. I only implemented so the length is 2(one cipher suite).
	p[3] = 0;
	p[4] = TLS_RSA_WITH_AES_256_CBC_SHA;
	p[5] = 1; //No compression method.
	p[6] = 0;
	p[7] = 0;
	p[8] = 0;
	p[9] = 0;
	p += 9;
	unsigned char l = p - hello;
	hello[3] = l - 4; //should be 0x2B
	return l;
}
int SecureSocket::recv_full(void* buff, int len)
{
	int tmp_ret = 0, ret = 0;
	char* buffer = (char*)buff;
	while (tmp_ret < len)
	{
		ret = TransportSocket::recv(buffer + tmp_ret, len - tmp_ret);
		if (ret <= 0) return ret;
		tmp_ret += ret;
	}
	return tmp_ret;
}
int SecureSocket::handshake()
{
	MD5Calc md5;
	SHA1Calc sha1;
	int i, ret, len, major, minor, session_len, cipher_suite, len_mod;
	char* buffer = (char*)transfer_buffer;
	unsigned char* b = (unsigned char*)transfer_buffer;
	unsigned int l = 0;
	unsigned char *pre_master_pad, *pub_mod, *rsa_buffer;
	unsigned char *client_random, *server_random, *pre_master, *master;
	Certificate *cert = 0;

	pre_master_pad = (unsigned char *)param_buffer + 0x400;
	pub_mod = pre_master_pad + 0x100; //0x500
	rsa_buffer = pub_mod + 0x100; //0x600
	client_random = rsa_buffer + 0x100; //0x700
	server_random = client_random + 0x20; //0x720
	pre_master = server_random + 0x20; //0x740
	master = pre_master + 0x30; //0x770
	PRNGContext* ctx = (PRNGContext*)(client_random + 0x100); //require 16 byte alignment. 0x800

	//send client hello
	buffer[0] = SSL_PROTOCAL_HANDSHAKE;
	buffer[1] = SSL_VERSION_MAJOR;
	buffer[2] = SSL_VERSION_MINOR;
	buffer[3] = 0;
	len = build_ssl_client_hello(buffer + SSL_RECORD_HEADER_LENGTH, client_random);
	buffer[4] = len;
	ret = TransportSocket::send(buffer, SSL_RECORD_HEADER_LENGTH);
	ret = TransportSocket::send(buffer + SSL_RECORD_HEADER_LENGTH, len);
	if(ret <= 0) return -1;
	md5.HashUpdate(buffer + SSL_RECORD_HEADER_LENGTH, ret);
	sha1.HashUpdate(buffer + SSL_RECORD_HEADER_LENGTH, ret);

	//get server hello
	ret = recv_full(buffer, SSL_RECORD_HEADER_LENGTH);
	if (ret < SSL_RECORD_HEADER_LENGTH) return -1;
	len = b[3]; len <<= 8; len |= b[4];
	l = len;
	ret = recv_full(buffer, len);
	if (ret < len) return -1;
	if (buffer[0] != SSL_HANDSHAKE_SERVER_HELLO) return -1;

	len = (((b[1] << 8) | b[2]) << 8) | b[3];
	if (len <= 0x30) return -1;
	major = buffer[4]; minor = buffer[5];
	if (major != SSL_VERSION_MAJOR || minor != SSL_VERSION_MINOR) return -1;

	memcpy(server_random, buffer + 6, 0x20);
	session_len = buffer[0x26];
	//skip session
	cipher_suite = _byteswap_ushort(*(unsigned short*)(buffer + 0x27 + session_len));
	if (cipher_suite != TLS_RSA_WITH_AES_256_CBC_SHA) return -1;
	len += 4;
	md5.HashUpdate(buffer, len);
	sha1.HashUpdate(buffer, len);

	//get server certificate
	if (len == l)
	{
		ret = recv_full(buffer, SSL_RECORD_HEADER_LENGTH);
		if (ret < SSL_RECORD_HEADER_LENGTH) return -1;
		len = b[3]; len <<= 8;
		len |= b[4];
		ret = recv_full(buffer,len);
		if (ret < len) return -1;
	}
	else //Already received.
	{
		l -= len;
		memcpy(buffer,buffer + len,l);
		ret = l;
	}
	int len_all,len_tmp,len_sum;

	if (b[0] != SSL_HANDSHAKE_SERVER_CERTIFICATE) return -1; //Check handshake type
	len_tmp = (((b[1] << 8) | b[2]) << 8) | b[3];
	len_all = (((b[4] << 8) | b[5]) << 8) | b[6];
	if (len_tmp != len_all + 3) return -1;
	len_tmp = (((b[7] << 8) | b[8]) << 8) | b[9];

	md5.HashUpdate(buffer, 7);
	sha1.HashUpdate(buffer, 7);
	len_sum = 0;
	unsigned char* p1,*p2;
	p1 = b + 10;

	cert = new Certificate;
	p2 = cert->Parse(p1);
	len_mod = cert->PublicKey(rsa_buffer); 
	delete cert; cert = 0;

	//Reverse byte order to perform multi-precision calculation.
	unsigned char *rsa_buffer_end = (unsigned char*)(rsa_buffer + len_mod - 4);
	for (i = 0; i < len_mod; i += 4)
		*(unsigned long*)(pub_mod + i) = _byteswap_ulong(*(unsigned long*)(rsa_buffer_end - i));
	//for (i = 0; i < len_mod; i++)
	//	pub_mod[i] = rsa_buffer[len_mod - 1 - i];
	
	if (p2 == 0) return -1;
	if (len_tmp != p2 - p1) return -1;
	len_tmp += 3;
	len_sum += len_tmp;
	p1 -= 3;
	md5.HashUpdate(p1, len_tmp);
	sha1.HashUpdate(p1, len_tmp);
	while (len_sum < len_all)
	{
		p1 = p2;
		len_tmp = (((p1[0] << 8) | p1[1]) << 8) | p2[2];
		len_tmp += 3;

		cert = new Certificate;
		p2 = cert->Parse(p1 + 3);
		delete cert;
		//p2 = ParseX509(p1 + 3,0,0);
		if (p2 == 0) return -1;
		if (len_tmp != p2 - p1) return -1;
		len_sum += len_tmp;
		md5.HashUpdate(p1, len_tmp);
		sha1.HashUpdate(p1, len_tmp);
	}
	if (len_sum != len_all) return -1;
	len_all += 7;

	//get server done
	if (ret - len_all > 0)
	{
		ret = ret - len_all;
		memcpy(b,p2,ret);
	}
	else
	{
		ret = recv_full(buffer, SSL_RECORD_HEADER_LENGTH);
		if (ret < SSL_RECORD_HEADER_LENGTH) return -1;
		len = b[3]; len <<= 8;
		len |= b[4];
		ret = recv_full(buffer, len);
		if (ret < len) return -1;
	}
	md5.HashUpdate(buffer, ret);
	sha1.HashUpdate(buffer, ret);

	//send client key exchange
	//record layer header
	buffer[0] = SSL_PROTOCAL_HANDSHAKE; 
	buffer[1] = SSL_VERSION_MAJOR;
	buffer[2] = SSL_VERSION_MINOR;
	buffer[3] = len_mod >> 8; 
	buffer[4] = (len_mod & 0xFF) + 6;
	//client key exchange
	buffer[5] = SSL_HANDSHAKE_CLIENT_KEYEX; 
	buffer[6] = 0; 
	buffer[7] = len_mod >> 8; 
	buffer[8] = (len_mod & 0xFF) + 2;
	//client key length
	buffer[9] = len_mod >> 8; 
	buffer[10] = len_mod & 0xFF;

	md5.HashUpdate(buffer + SSL_RECORD_HEADER_LENGTH, 6);
	sha1.HashUpdate(buffer + SSL_RECORD_HEADER_LENGTH, 6);
	TransportSocket::send(buffer, 11);
	PRNGInit(ctx);
	PRNGGen(ctx, pre_master, 0x30);
	pre_master[0] = SSL_VERSION_MAJOR;
	pre_master[1] = SSL_VERSION_MINOR;
	for (i = 0; i < 0x30; i++)
		pre_master_pad[i] = pre_master[0x2F - i];
	PRNGGen(ctx, pre_master_pad + 0x30, len_mod - 0x30);
	for (i = 0x30; i < len_mod; i++)
		if (pre_master_pad[i] == 0) pre_master_pad[i] = 0xFF; //prevent 00 in padding
	pre_master_pad[0x30] = 0; //padding end
	pre_master_pad[len_mod - 1] = 0; //padding flag
	pre_master_pad[len_mod - 2] = 2; //random byte padding

	static unsigned char exp[4] = {1,0,1,0}; //hardcoded common exp
	exp_mod(pre_master_pad, exp, pub_mod, rsa_buffer, len_mod, 4, len_mod);
	for (i = 0; i < len_mod; i++) buffer[i] = rsa_buffer[len_mod - 1 - i];
	memset(rsa_buffer, 0, len_mod);
	TransportSocket::send(buffer, len_mod);
	md5.HashUpdate(buffer, len_mod);
	sha1.HashUpdate(buffer, len_mod);
	
	//send change cipher spec
	buffer[0] = SSL_HANDSHAKE_CHANGE_CIPHER_SPEC;
	buffer[1] = SSL_VERSION_MAJOR;
	buffer[2] = SSL_VERSION_MINOR;
	buffer[3] = 0; 
	buffer[4] = 1;
	buffer[5] = 1;
	TransportSocket::send(buffer, 6);

	//send client finished
	ComputeMasterSecret(pre_master, master, client_random, server_random);
	KeyBlock* key = get_key_block();
	ComputeKeyBlock(master, key, client_random,server_random);

	get_encryptor()->Init(key->client_write, key->client_iv);
	get_decryptor()->Init(key->server_write, key->server_iv);
	
	md5.HashFinal(buffer);
	sha1.HashFinal(buffer + HASH_SIZE_MD5);
		
	ComputeClientVerify(buffer + 4, master, buffer, buffer + HASH_SIZE_MD5);
	buffer[0] = SSL_HANDSHAKE_CHANGE_CIPHER_SPEC;
	buffer[1] = buffer[2] = 0;
	buffer[3] = 0xC;
	send_type(buffer, 0x10, 0x16);

	//server change cipher spec
	ret = recv_full(buffer,6);
	if (ret <= 0) return -1;
	ret = recv(buffer, 0x10);
	memset((unsigned char*)param_buffer + 0x300,0,0x600);
	if (ret <= 0) return -1;
	return 0;
}
AES_CBC_Cipher* SecureSocket::get_encryptor()
{
	return (AES_CBC_Cipher*)param_buffer; //param_buffer: 0 ~ 0x100
}
AES_CBC_Cipher* SecureSocket::get_decryptor()
{
	return (AES_CBC_Cipher*)((DWORD)param_buffer + 0x100); //param_buffer: 0x100 ~ 0x200
}
KeyBlock* SecureSocket::get_key_block()
{
	return (KeyBlock*)((DWORD)param_buffer + 0x200); //param_buffer: 0x200 ~ 0x230
}
