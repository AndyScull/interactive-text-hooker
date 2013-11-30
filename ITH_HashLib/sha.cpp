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


#include "ITH\Hash.h"

/* FIPS 180-2: Secure Hash Standard (SHS)
// http://csrc.nist.gov/publications/fips/fips180-2/fips180-2withchangenotice.pdf
*/
#define ROTR(x,y) (_rotr(x,y))
#define ROTL(x,y) (_rotl(x,y))
#define BSWAP(x) (_byteswap_ulong(x))
unsigned int md5_constant[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
unsigned int md5_initial[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
unsigned int md5_r[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};
#define MD5F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5I(x, y, z) ((y) ^ ((x) | (~z)))

void HashMD5Init(MD5_Context* ctx)
{
	memcpy(&ctx->h0, md5_initial, HASH_SIZE_MD5);
	ctx->len = 0;
	ctx->remain_len = 0;
}
void HashMD5Update(MD5_Context* ctx, void* msg, int len)
{
	unsigned char* message = (unsigned char*)msg;
	ctx->len += len;
	if (len + ctx->remain_len >= HASH_BLOCK_MD5)
	{
		int t = HASH_BLOCK_MD5 - ctx->remain_len;
		memcpy(ctx->remain + ctx->remain_len, message, t);
		message += t;
		len -= t;
		HashMD5Block(ctx->remain,ctx);
		while (len >= HASH_BLOCK_MD5)
		{
			HashMD5Block(message, ctx);
			len -= HASH_BLOCK_MD5;
			message += HASH_BLOCK_MD5;
		}
		ctx->remain_len = len;
		memcpy(ctx->remain,message,len);
	}
	else
	{
		memcpy(ctx->remain + ctx->remain_len, message, len);
		ctx->remain_len += len;
	}

}
void HashMD5Final(MD5_Context* ctx, void* hash)
{
	if (ctx->remain_len >= HASH_BLOCK_MD5 - 8)
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_MD5 - ctx->remain_len);
		HashMD5Block(ctx->remain,ctx);
		memset(ctx->remain, 0, HASH_BLOCK_MD5 - 8);
		ctx->len <<= 3;
		*(unsigned long long*)(ctx->remain + HASH_BLOCK_MD5 - 8) = ctx->len;
		HashMD5Block(ctx->remain,ctx);
	}
	else
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_MD5 - 8 - ctx->remain_len);
		ctx->len <<= 3;
		*(unsigned long long*)(ctx->remain + HASH_BLOCK_MD5 - 8) = ctx->len;
		HashMD5Block(ctx->remain,ctx);
	}
	memcpy(hash, &ctx->h0, HASH_SIZE_MD5);

}
void HashMD5Block(void* hash_block, MD5_Context* ctx)
{
	unsigned int* block = (unsigned int*)hash_block;
	int a,b,c,d,f,g,i,t;
	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	for (i = 0; i < 16; i++)
	{
		f = MD5F(b,c,d);
		t = d;
		d = c;
		c = b;
		b = b +	ROTL(a + f + md5_constant[i] + block[i], md5_r[i]);
		a = t;
	}
	for (; i < 32; i++)
	{
		f = MD5G(b,c,d);
		g = (5 * i + 1) & 0xF;
		t = d;
		d = c;
		c = b;
		b = b +	ROTL(a + f + md5_constant[i] + block[g], md5_r[i]);
		a = t;
	}
	for (; i < 48; i++)
	{
		f = MD5H(b,c,d);
		g = (3 * i + 5) & 0xF;
		t = d;
		d = c;
		c = b;
		b = b +	ROTL(a + f + md5_constant[i] + block[g], md5_r[i]);
		a = t;
	}
	for (; i < 64; i++)
	{
		f = MD5I(b,c,d);
		g = (7 * i) & 0xF;
		t = d;
		d = c;
		c = b;
		b = b +	ROTL(a + f + md5_constant[i] + block[g], md5_r[i]);
		a = t;
	}
	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	a = b = c = d = f = g = t = 0;
}
#define Ch(x,y,z) (((x) & (y)) ^ ((~x) & (z)))
#define Parity(x,y,z) ((x) ^ (y) ^ (z))
#define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

unsigned int sha1_constant[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};
unsigned int sha1_initial[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

void HashSHA1Init(SHA1_Context* ctx)
{
	memcpy(&ctx->h0, sha1_initial, HASH_SIZE_SHA1);
	ctx->len = 0;
	ctx->remain_len = 0;
}
void HashSHA1Update(SHA1_Context* ctx, void* msg, int len)
{
	unsigned char* message = (unsigned char*)msg;
	ctx->len += len;
	if (len + ctx->remain_len >= HASH_BLOCK_SHA1)
	{
		int t = HASH_BLOCK_SHA1 - ctx->remain_len;
		memcpy(ctx->remain + ctx->remain_len, message, t);
		message += t;
		len -= t;
		HashSHA1Block(ctx->remain,ctx);
		while (len >= HASH_BLOCK_SHA1)
		{
			HashSHA1Block(message, ctx);
			len -= HASH_BLOCK_SHA1;
			message += HASH_BLOCK_SHA1;
		}
		ctx->remain_len = len;
		memcpy(ctx->remain,message,len);
	}
	else
	{
		memcpy(ctx->remain + ctx->remain_len, msg, len);
		ctx->remain_len += len;
	}

}
void HashSHA1Final(SHA1_Context* ctx, void* hash)
{
	if (ctx->remain_len >= HASH_BLOCK_SHA1 - 8)
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_SHA1 - ctx->remain_len);
		HashSHA1Block(ctx->remain,ctx);
		memset(ctx->remain, 0, HASH_BLOCK_SHA1 - 8);
		ctx->len <<= 3;
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA1 - 8) = BSWAP(ctx->len_high);
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA1 - 4) = BSWAP(ctx->len_low);
		HashSHA1Block(ctx->remain,ctx);
	}
	else
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_SHA1 - 8 - ctx->remain_len);
		ctx->len <<= 3;
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA1 - 8) = BSWAP(ctx->len_high);
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA1 - 4) = BSWAP(ctx->len_low);
		HashSHA1Block(ctx->remain,ctx);
	}
	unsigned long* h = (unsigned long*)hash;
	h[0] = BSWAP(ctx->h0);
	h[1] = BSWAP(ctx->h1);
	h[2] = BSWAP(ctx->h2);
	h[3] = BSWAP(ctx->h3);
	h[4] = BSWAP(ctx->h4);
	unsigned char* hs = (unsigned char*)hash;

}
void HashSHA1Block(void* hash_block, SHA1_Context* ctx)
{
	unsigned int a,b,c,d,e,T,i;
	unsigned char* block = (unsigned char*)hash_block;
	unsigned int w[0x50];
	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;
	for (i = 0; i < 16; i++) w[i] = BSWAP(*(unsigned int*)(block + i * 4));
	for (i = 16; i < 80; i++) w[i] = ROTL( w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	
	for (i = 0; i < 20; i++)
	{
		T = ROTL(a,5) + Ch(b,c,d) + e + sha1_constant[0] + w[i];
		e = d;
		d = c;
		c = ROTL(b,30);
		b = a;
		a = T;

	}
	for (i=20;i<40;i++)
	{
		T = ROTL(a,5) + Parity(b,c,d) + e + sha1_constant[1] + w[i];
		e = d;
		d = c;
		c = ROTL(b,30);
		b = a;
		a = T;

	}
	for (i=40;i<60;i++)
	{
		T = ROTL(a,5) + Maj(b,c,d) + e + sha1_constant[2] + w[i];
		e = d;
		d = c;
		c = ROTL(b,30);
		b = a;
		a = T;

	}
	for (i=60;i<80;i++)
	{
		T = ROTL(a,5) + Parity(b,c,d) + e + sha1_constant[3] + w[i];
		e = d;
		d = c;
		c = ROTL(b,30);
		b = a;
		a = T;

	}

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	a = b = c = d = e = T = 0;
	memset(w, 0, 0x140);
}
void HashSHA1(void* msg, unsigned int len, void* hash)
{
	SHA1_Context ctx;
	HashSHA1Init(&ctx);
	HashSHA1Update(&ctx,msg,len);
	HashSHA1Final(&ctx,hash);
}

unsigned int sha256_constant[0x40] = 
{
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
unsigned int sha256_initial[8] = {
	0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
	0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
};

#define SigmaB0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define SigmaB1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SigmaS0(x) (ROTR(x,7)^ROTR(x,18)^(x>>3))
#define SigmaS1(x) (ROTR(x,17)^ROTR(x,19)^(x>>10))

void HashSHA256Init(SHA256_Context* ctx)
{
	memcpy(&ctx->h0, sha256_initial, HASH_SIZE_SHA256);
	ctx->len = 0;
	ctx->remain_len = 0;
}
void HashSHA256Update(SHA256_Context* ctx, void* msg, int len)
{
	unsigned char* message = (unsigned char*)msg;
	ctx->len += len;
	if (len + ctx->remain_len >= HASH_BLOCK_SHA256)
	{
		int t = HASH_BLOCK_SHA256 - ctx->remain_len;
		memcpy(ctx->remain + ctx->remain_len, message, t);
		message += t;
		len -= t;
		HashSHA256Block(ctx->remain,ctx);
		while (len >= HASH_BLOCK_SHA256)
		{
			HashSHA256Block(message, ctx);
			len -= HASH_BLOCK_SHA256;
			message += HASH_BLOCK_SHA256;
		}
		memcpy(ctx->remain,message,len);
		ctx->remain_len = len;
	}
	else
	{
		memcpy(ctx->remain + ctx->remain_len, msg, len);
		ctx->remain_len += len;
	}
	
	
}
void HashSHA256Final(SHA256_Context* ctx, void* hash)
{
	if (ctx->remain_len >= HASH_BLOCK_SHA256 - 8)
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_SHA256 - ctx->remain_len);
		HashSHA256Block(ctx->remain,ctx);
		memset(ctx->remain, 0, HASH_BLOCK_SHA256 - 8);
		ctx->len <<= 3;
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA256 - 8) = BSWAP(ctx->len_high);
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA256 - 4) = BSWAP(ctx->len_low);
		HashSHA256Block(ctx->remain,ctx);
	}
	else
	{
		ctx->remain[ctx->remain_len] = 0x80;
		ctx->remain_len++;
		memset(ctx->remain + ctx->remain_len, 0, HASH_BLOCK_SHA256 - 8 - ctx->remain_len);
		ctx->len <<= 3;
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA256 - 8) = BSWAP(ctx->len_high);
		*(unsigned int*)(ctx->remain + HASH_BLOCK_SHA256 - 4) = BSWAP(ctx->len_low);
		HashSHA256Block(ctx->remain,ctx);
	}
	unsigned long* h = (unsigned long*)hash;
	h[0] = BSWAP(ctx->h0);
	h[1] = BSWAP(ctx->h1);
	h[2] = BSWAP(ctx->h2);
	h[3] = BSWAP(ctx->h3);
	h[4] = BSWAP(ctx->h4);
	h[5] = BSWAP(ctx->h5);
	h[6] = BSWAP(ctx->h6);
	h[7] = BSWAP(ctx->h7);
}
void HashSHA256Block(void* hash_block, SHA256_Context* ctx)
{
	unsigned int a,b,c,d,e,f,g,h,T1,T2,i;
	unsigned int w[0x40];
	unsigned char* block = (unsigned char*)hash_block;
	a = ctx->h0; b = ctx->h1;
	c = ctx->h2; d = ctx->h3;
	e = ctx->h4; f = ctx->h5;
	g = ctx->h6; h = ctx->h7;
	for (i = 0; i < 16; i++) w[i] = BSWAP(*(unsigned int*)(block + i * 4));
	for (i = 16; i < 64; i++) w[i] = SigmaS1(w[i-2]) + w[i-7] + SigmaS0(w[i-15]) + w[i-16];
	for (i = 0; i < 64; i++)
	{
		T1 = h + SigmaB1(e) + Ch(e,f,g) + sha256_constant[i] + w[i];
		T2 = SigmaB0(a) + Maj(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
	ctx->h5 += f;
	ctx->h6 += g;
	ctx->h7 += h;
	a = b = c = d = e = f = g = h = T1 = T2 = 0;
	memset(w,0,0x100);
}
void HashSHA256(void* msg, unsigned int len, void* hash)
{
	SHA256_Context ctx;
	HashSHA256Init(&ctx);
	HashSHA256Update(&ctx,msg,len);
	HashSHA256Final(&ctx,hash);
}

MD5Calc::MD5Calc() {this->HashInit();}
MD5Calc::~MD5Calc() {memset(this,0,sizeof(MD5Calc));}
void MD5Calc::HashInit(){HashMD5Init(&ctx);}
void MD5Calc::HashUpdate(void* msg, int len){HashMD5Update(&ctx,msg,len);}
void MD5Calc::HashFinal(void* hash){HashMD5Final(&ctx,hash);}
int MD5Calc::HashValueSize() const{return HASH_SIZE_MD5;}
int MD5Calc::HashBlockSize() const{return HASH_BLOCK_MD5;}

SHA1Calc::SHA1Calc() {this->HashInit();}
SHA1Calc::~SHA1Calc() {memset(this,0,sizeof(SHA1Calc));}
void SHA1Calc::HashInit(){HashSHA1Init(&ctx);}
void SHA1Calc::HashUpdate(void* msg, int len){HashSHA1Update(&ctx,msg,len);}
void SHA1Calc::HashFinal(void* hash){HashSHA1Final(&ctx,hash);}
int SHA1Calc::HashValueSize() const{return HASH_SIZE_SHA1;}
int SHA1Calc::HashBlockSize() const{return HASH_BLOCK_SHA1;}

SHA256Calc::SHA256Calc() {this->HashInit();}
SHA256Calc::~SHA256Calc() {memset(this,0,sizeof(SHA256Calc));}
void SHA256Calc::HashInit(){HashSHA256Init(&ctx);}
void SHA256Calc::HashUpdate(void* msg, int len){HashSHA256Update(&ctx,msg,len);}
void SHA256Calc::HashFinal(void* hash){HashSHA256Final(&ctx,hash);}
int SHA256Calc::HashValueSize() const{return HASH_SIZE_SHA256;}
int SHA256Calc::HashBlockSize() const{return HASH_BLOCK_SHA256;}

