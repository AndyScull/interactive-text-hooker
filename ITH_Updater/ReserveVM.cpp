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

#include "ReserveVM.h"
#include <ITH\ntdll.h>
#define assert(x) {if (!(x)) __asm int 3}
IthReservedVirtualMemory::IthReservedVirtualMemory()
{
	mem = 0;
	commit_size = DEFAULT_COMMIT_SIZE;
	DWORD reserve_size = DEFAULT_RESERVE_SIZE;
	NtAllocateVirtualMemory(NtCurrentProcess(), &mem, 0, &reserve_size, MEM_RESERVE, PAGE_READWRITE);
	NtAllocateVirtualMemory(NtCurrentProcess(), &mem, 0, &commit_size, MEM_COMMIT, PAGE_READWRITE);
}
IthReservedVirtualMemory::~IthReservedVirtualMemory()
{
	DWORD size = 0;
	NtFreeVirtualMemory(NtCurrentProcess(), &mem, &size, MEM_RELEASE);

}

DWORD IthReservedVirtualMemory::WriteBytes(LPVOID p, DWORD len, DWORD position)
{
	while (position + len > commit_size)
	{
		if (commit_size == DEFAULT_RESERVE_SIZE)
		{
			return ~0;
		}
		else
		{
			LPVOID m = (char*)mem + commit_size;
			DWORD size = commit_size;
			NtAllocateVirtualMemory(NtCurrentProcess(), &m, 0, &size, MEM_COMMIT, PAGE_READWRITE);
			assert(size == commit_size);
			commit_size <<= 1;
		}
	}
	memcpy((LPVOID)((DWORD)mem + position), p, len);
	return 0;
}

DWORD IthReservedVirtualMemory::EraseBytes(DWORD position, DWORD len)
{
	if (position < commit_size)
	{
		DWORD l = commit_size - position;
		len = len < l ? len : l;
		memset((char*)mem+position,0,len);
	}
}

DWORD IthReservedVirtualMemory::Resize( DWORD size )
{
	if (size < DEFAULT_RESERVE_SIZE)
	{
		while (commit_size < size)
		{
			LPVOID m = (char*)mem + commit_size;
			DWORD alloc_size = commit_size;
			NtAllocateVirtualMemory(NtCurrentProcess(), &m, 0, &alloc_size, MEM_COMMIT, PAGE_READWRITE);
			assert(alloc_size == commit_size);
			commit_size <<= 1;
		}
		return 0;
	}
	else return -1;
}
