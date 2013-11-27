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

#ifndef ITH_ARITHMETIC
#define ITH_ARITHMETIC
#include "sizedef.h"
//void mulmnu( short w[],  short u[],  short v[], int m, int n);
int mulmnu(u8 w[], u8 u[], u8 v[], int m, int n);
int divmnu( u8 q[],  u8 r[], const  u8 u[], const u8 v[], int m, int n);
int divmnu32(u32 q[], u32 r[], const u32 u[], const u32 v[], int m, int n);
int div_long(void* q, void* r, const void* u, const void* v, unsigned m, unsigned n);
void exp_mod(u8* base, u8* exp, u8* mod,u8* res, u32 base_size, u32 exp_size, u32 mod_size);
#endif