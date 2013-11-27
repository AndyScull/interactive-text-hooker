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
#ifndef DEFAULT_MM

extern "C" {
	__declspec(dllimport) void* __stdcall RtlAllocateHeap(void* hHeap, unsigned long flags, unsigned long size);
	__declspec(dllimport) int __stdcall RtlFreeHeap(void*,unsigned long,void*);
};

extern void* hHeap;

//HEAP_ZERO_MEMORY flag is critical. All new objects are assumed with zero initialized.
inline void * __cdecl operator new(size_t lSize)
{
	return RtlAllocateHeap(hHeap, 8, lSize);
}
inline void __cdecl operator delete(void *pBlock)
{
	RtlFreeHeap(hHeap, 0, pBlock);
}
inline void __cdecl operator delete[](void* pBlock)
{
	RtlFreeHeap(hHeap, 0, pBlock);
}
#endif