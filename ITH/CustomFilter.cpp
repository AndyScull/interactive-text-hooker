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

#include <ITH\ntdll.h>
#include <ITH\IHF_SYS.h>
#include <intrin.h>
#include <ITH\CustomFilter.h>

static DWORD zeros[4]={0,0,0,0};

CustomFilterUnicode::CustomFilterUnicode()
{
	map=0;
	size=0x2000;
	NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&map,0,&size,MEM_COMMIT,PAGE_READWRITE);
}
CustomFilterUnicode::~CustomFilterUnicode()
{
	NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&map,&size,MEM_RELEASE);
	map=0;
}
void CustomFilterUnicode::Set(WORD number)
{
	map[number>>3]|=1<<(number&7);

}
void CustomFilterUnicode::Clear(WORD number)
{
	map[number>>3]&=~(1<<(number&7));

}
bool CustomFilterUnicode::Check(WORD number)
{
	return (map[number>>3]>>(number&7))&1;
}
void CustomFilterUnicode::Traverse(CustomFilterCallBack callback, PVOID param)
{
	union{ __m128d m0; __m128i i0;};
	union{ __m128d m1; __m128i i1;};
	DWORD mask,i,j,k,t,ch;
	m1=_mm_loadu_pd((const double*)zeros);
	BYTE* ptr=map;
	BYTE* end=map+size;
	while (ptr<end) //multi byte
	{
		m0=_mm_load_pd((const double*)ptr);
		i0=_mm_cmpeq_epi8(i0,i1); //SSE zero test, 16 bytes/loop, 256 bit/loop, overall 256 loop.
		mask=_mm_movemask_epi8(i0);
		if (mask!=0xFFFF)
		{
			for (i=0;i<0x10;i+=4)
			{
				if (*(DWORD*)(ptr+i)==0) continue; //dword compare, 4 bytes/loop
				for (j=0;j<4;j++)
				{
					if (ptr[i+j]) //byte compare, one byte/loop
					{
						t=1;
						for (k=0;k<8;k++)//test bit, one bit/loop
						{
							if (ptr[i+j]&t) 
							{
								ch=((ptr-map+i+j)<<3)+k;			
								callback(ch&0xFFFF, param);
							}
							t<<=1;
						}
					}
				}
			}
		}
		ptr+=0x10;
	}
}

CustomFilterMultiByte::CustomFilterMultiByte()
{
	map=0;
	size=0x1000;
	NtAllocateVirtualMemory(NtCurrentProcess(),(PVOID*)&map,0,&size,MEM_COMMIT,PAGE_READWRITE);

}
CustomFilterMultiByte::~CustomFilterMultiByte()
{
	NtFreeVirtualMemory(NtCurrentProcess(),(PVOID*)&map,&size,MEM_RELEASE);
	map=0;
}
void CustomFilterMultiByte::Set(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1) ascii_map[c>>3]|=1<<(c&7);
	else
	{
		number>>=8;
		number|=(c-0x80)<<8;
		map[number>>3]|=1<<(number&7);
	}

}
void CustomFilterMultiByte::Clear(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1) ascii_map[c>>3]&=~(1<<(c&7));
	else
	{
		number>>=8;
		number|=(c-0x80)<<8;
		map[number>>3]&=~(1<<(number&7));
	}
}
bool CustomFilterMultiByte::Check(WORD number)
{
	BYTE c=number&0xFF;
	if (LeadByteTable[c]==1)
		return (ascii_map[c>>3]>>(c&7))&1;
	else
	{
		number=(number>>8)+((c-0x80)<<8);
		return (map[number>>3]>>(number&7))&1;
	}
}
void CustomFilterMultiByte::Reset()
{
	BitMap::Reset();
	memset(ascii_map,0,0x20);
}
void CustomFilterMultiByte::Traverse(CustomFilterCallBack callback, PVOID param)
{
	union{ __m128d m0; __m128i i0;};
	union{ __m128d m1; __m128i i1;};
	DWORD mask,i,j,k,t,ch,cl;
	m1=_mm_loadu_pd((const double*)zeros);
	BYTE* ptr=map;
	BYTE* end=map+size;
	while (ptr<end) //multi byte
	{
		m0=_mm_load_pd((const double*)ptr);
		i0=_mm_cmpeq_epi8(i0,i1); //SSE zero test, 16 bytes/loop, 256 bit/loop, overall 256 loop.
		mask=_mm_movemask_epi8(i0);
		if (mask!=0xFFFF)
		{
			for (i=0;i<0x10;i+=4)
			{
				if (*(DWORD*)(ptr+i)==0) continue; //dword compare, 4 bytes/loop
				for (j=0;j<4;j++)
				{
					if (ptr[i+j]) //byte compare, one byte/loop
					{
						t=1;
						for (k=0;k<8;k++)//test bit, one bit/loop
						{
							if (ptr[i+j]&t) 
							{
								ch=((ptr-map+i+j)<<3)+k;			
								cl=(ch&0xFF)<<8;
								ch=(ch>>8)+0x80;
								ch|=cl;
								callback(ch&0xFFFF, param);
							}
							t<<=1;
						}
					}
				}
			}
		}
		ptr+=0x10;
	}

	for (i=0;i<0x20;i+=4) //single byte
	{
		if (*(DWORD*)(ascii_map+i))
		{
			for (j=0;j<4;j++)
			{
				if (ascii_map[i+j])
				{
					t=1;
					for (k=0;k<8;k++)
					{
						if (ascii_map[i+j]&t)
						{
							ch=((i+j)<<3)+k;
							callback(ch&0xFFFF, param);
						}
						t<<=1;
					}
				}
			}
		}
	}
}
