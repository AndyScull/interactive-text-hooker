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
#include <memory.h>
#include <intrin.h>

#define HASH_SIZE_MD5 0x10
#define HASH_BLOCK_MD5 0x40
struct MD5_Context
{
	union{
		unsigned __int64 len;
		struct {
			unsigned int len_low,len_high;
		};
	};
	unsigned int h0,h1,h2,h3;
	unsigned int remain_len;
	unsigned char remain[0x40];
}; //0x5C

void HashMD5Block(void* block, MD5_Context* ctx);
void HashMD5(void* msg, unsigned int len, void* hash);
void HashMD5Init(MD5_Context* ctx);
void HashMD5Update(MD5_Context* ctx, void* msg, int len);
void HashMD5Final(MD5_Context* ctx, void* hash);

#define HASH_SIZE_SHA1 0x14
#define HASH_BLOCK_SHA1 0x40
struct SHA1_Context
{
	union{
		unsigned __int64 len;
		struct {
			unsigned int len_low,len_high;
		};
	};
	unsigned int h0,h1,h2,h3,h4;
	unsigned int remain_len;
	unsigned char remain[0x40];
}; //0x60

void HashSHA1Block(void* block, SHA1_Context* ctx);
void HashSHA1(void* msg, unsigned int len, void* hash);
void HashSHA1Init(SHA1_Context* ctx);
void HashSHA1Update(SHA1_Context* ctx, void* msg, int len);
void HashSHA1Final(SHA1_Context* ctx, void* hash);

#define HASH_SIZE_SHA256 32
#define HASH_BLOCK_SHA256 0x40
struct SHA256_Context
{
	union{
		unsigned __int64 len;
		struct {
			unsigned int len_low,len_high;
		};
	};
	unsigned int h0,h1,h2,h3,h4,h5,h6,h7;
	unsigned int remain_len;
	unsigned char remain[0x40];
}; //0x6C

void HashSHA256Block(void* block, SHA256_Context* ctx);
void HashSHA256(void* msg, unsigned int len, void* hash);
void HashSHA256Init(SHA256_Context* ctx);
void HashSHA256Update(SHA256_Context* ctx, void* msg, int len);
void HashSHA256Final(SHA256_Context* ctx, void* hash);

#ifndef ITH_TLS_HASH_CALC
#define ITH_TLS_HASH_CALC
class HashCalculator
{
public:
	HashCalculator() {}
	virtual ~HashCalculator() {}
	virtual void HashInit() {}
	virtual void HashUpdate(void* msg, int len) {}
	virtual void HashFinal(void* hash) {}
	virtual int HashValueSize() const {return 0;}
	virtual int HashBlockSize() const {return 0;}
};

enum HashType
{
	HashTypeMD5 = 0,
	HashTypeSHA1,
	HashTypeSHA256
};
#endif

class MD5Calc : public HashCalculator
{
public:
	MD5Calc();
	virtual ~MD5Calc();
	virtual void HashInit();
	virtual void HashUpdate(void* msg, int len);
	virtual void HashFinal(void* hash);
	virtual int HashValueSize() const;
	virtual int HashBlockSize() const;
private:
	MD5_Context ctx;
};

class SHA1Calc : public HashCalculator
{
public:
	SHA1Calc();
	virtual ~SHA1Calc();
	virtual void HashInit();
	virtual void HashUpdate(void* msg, int len);
	virtual void HashFinal(void* hash);
	virtual int HashValueSize() const;
	virtual int HashBlockSize() const;
private:
	SHA1_Context ctx;
};

class SHA256Calc : public HashCalculator
{
public:
	SHA256Calc();
	virtual ~SHA256Calc();
	virtual void HashInit();
	virtual void HashUpdate(void* msg, int len);
	virtual void HashFinal(void* hash);
	virtual int HashValueSize() const;
	virtual int HashBlockSize() const;
private:
	SHA256_Context ctx;
};
