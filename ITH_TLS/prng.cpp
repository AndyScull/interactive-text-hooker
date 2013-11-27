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


#include "aes256.h"
#include "prng.h"
//#include "sha.h"
#include <ITH\Hash.h>
void PRNGInit(PRNGContext* ctx)
{
	unsigned int seed;
	__asm rdtsc
	__asm mov seed,eax
	HashSHA256((u8*)&seed, 4, ctx->prng_key);
	memset(ctx->prng_key + 32,0,224);
	KeyExpansion(ctx->prng_key);
}
void PRNGGen(PRNGContext* ctx, unsigned char *dest, unsigned int size)
{
	unsigned int i,remain;
	if (size<=0) return;
	memset(dest,0,size);
	remain=size&0xF;
	size &= ~0xF;
	for (i=0;i<size;i+=0x10)
	{
		AES256EncryptRound(ctx->seed,ctx->seed,ctx->prng_key,4);
		memcpy(dest+i,ctx->seed, 0x10);
		//memcpy(dest+(i<<4),ctx->seed,0x10);
	}
	if (remain)
	{
		AES256EncryptRound(ctx->seed,ctx->seed,ctx->prng_key,4);
		memcpy(dest+size,ctx->seed,remain);
	}
}