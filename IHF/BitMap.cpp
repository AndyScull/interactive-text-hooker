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

#include "ITH\BitMap.h"

#include <memory.h>
#include <intrin.h>

BitMap::BitMap(): size(0x20)
{
	//map=new BYTE[size];
}
BitMap::BitMap(unsigned long init_size): size(init_size>>3)
{
	map=new unsigned char[size];
}
BitMap::~BitMap()
{
	if (map) 
	{
		delete map;
		map=0;
	}
}
bool BitMap::Check(unsigned long number)
{	
	if ((number>>3)>=size) return false;
	return (map[number>>3]&(1<<(number&7)))!=0;
}
void BitMap::Set(unsigned long number)
{
	if (number>>16) return;
	unsigned long s=number>>3;
	unsigned long t=s>>2;
	if (s&3) t++; 
	s=t<<2;  //Align to 4 byte.
	if (s>=size)
	{
		t=size;
		while (s>=size) size<<=1;
		unsigned char* temp=new unsigned char[size];
		memcpy(temp,map,t);
		delete map;
		map=temp;
	}	
	map[number>>3]|=1<<(number&7);
}
void BitMap::Reset()
{
	memset(map,0,size);
}
void BitMap::Clear(unsigned long number)
{
	if ((number>>3)>=size) return;
	map[number>>3]&=~(1<<(number&7));
}
