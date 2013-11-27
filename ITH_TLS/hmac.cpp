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

#include "hmac.h"
#include <intrin.h>
int HMAC(void* key, int len_key, void* msg, int len_msg, void* hmac, HashCalculator* hash)
{
	int i, hash_value_size;
	unsigned char ipad[HMAC_BLOCK_SIZE],opad[HMAC_BLOCK_SIZE];
	unsigned char buffer[HMAC_BLOCK_SIZE];
	hash_value_size = hash->HashValueSize();
	if (len_key > HMAC_BLOCK_SIZE)
	{
		hash->HashInit();
		hash->HashUpdate(key,len_key);
		hash->HashFinal(buffer);
		memset(buffer + hash_value_size, 0, HMAC_BLOCK_SIZE - hash_value_size);
	}
	else if (len_key < HMAC_BLOCK_SIZE)
	{
		memcpy(buffer, key, len_key);
		memset(buffer + len_key, 0, HMAC_BLOCK_SIZE - len_key);
	}
	else
		memcpy(buffer, key, len_key);
	memset(ipad, 0x36, HMAC_BLOCK_SIZE);
	memset(opad, 0x5C, HMAC_BLOCK_SIZE);
	for (i = 0; i < HMAC_BLOCK_SIZE; i++)
	{
		ipad[i] ^= buffer[i];
		opad[i] ^= buffer[i];
	}
	hash->HashInit();
	hash->HashUpdate(ipad,HMAC_BLOCK_SIZE);
	hash->HashUpdate(msg,len_msg);
	hash->HashFinal(buffer);

	hash->HashInit();
	hash->HashUpdate(opad,HMAC_BLOCK_SIZE);
	hash->HashUpdate(buffer,hash_value_size);
	hash->HashFinal(hmac);

	return 0;
}


HMAC_Calc::HMAC_Calc( void* key, int key_len, HashCalculator* hash)
{
	HMAC_Init(key,key_len,hash);
}

HMAC_Calc::~HMAC_Calc()
{
	memset(opad,0,HMAC_BLOCK_SIZE);
}

int HMAC_Calc::HMAC_Init( void* key, int len_key, HashCalculator* hash)
{
	char ipad[HMAC_BLOCK_SIZE];
	hash_calc = hash;
	hash_calc->HashInit();
	int i, size = hash_calc->HashValueSize();
	memset(ipad, 0x36, HMAC_BLOCK_SIZE);
	memset(opad, 0x5c, HMAC_BLOCK_SIZE);
	if (len_key > HMAC_BLOCK_SIZE)
	{
		char buffer[HMAC_BLOCK_SIZE];	
		hash_calc->HashUpdate(key,len_key);
		hash_calc->HashFinal(buffer);
		for (i = 0; i < size; i+=4)
		{
			unsigned int t = *(unsigned int*)(buffer + i);
			*(unsigned int*)(ipad + i) ^= t;
			*(unsigned int*)(opad + i) ^= t;
		}
	}
	else
	{
		char* p = (char*)key;
		for (i = 0; i < len_key; i += 4)
		{
			unsigned int t = *(unsigned int*)(p + i);
			*(unsigned int*)(ipad + i) ^= t;
			*(unsigned int*)(opad + i) ^= t;
		}		
	}
	hash_calc->HashUpdate(ipad,HMAC_BLOCK_SIZE);
	memset(ipad, 0, HMAC_BLOCK_SIZE);
	return 0;
}

int HMAC_Calc::HMAC_Update( void* msg, int len )
{
	hash_calc->HashUpdate(msg,len);
	return 0;
}

int HMAC_Calc::HMAC_Final( void* out )
{
	char buffer[HMAC_BLOCK_SIZE];
	hash_calc->HashFinal(buffer);
	hash_calc->HashInit();
	hash_calc->HashUpdate(opad,HMAC_BLOCK_SIZE);
	hash_calc->HashUpdate(buffer,hash_calc->HashValueSize());
	hash_calc->HashFinal(out);
	return 0;
}
