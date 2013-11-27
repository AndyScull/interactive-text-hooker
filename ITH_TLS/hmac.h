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

#ifndef ITH_HMAC
#define ITH_HMAC
#include <ITH\Hash.h>
#define HMAC_BLOCK_SIZE 64
class HMAC_Calc
{
public:
	HMAC_Calc(void* key, int key_len, HashCalculator* hash);
	~HMAC_Calc();
	int HMAC_Init(void* key, int key_len, HashCalculator* hash);
	int HMAC_Update(void* msg, int len);
	int HMAC_Final(void* out);
private:
	char opad[HMAC_BLOCK_SIZE];
	HashCalculator* hash_calc;
};
int HMAC(void* key, int len_key, void* msg, int len_msg, void* hmac, HashCalculator*);
#endif