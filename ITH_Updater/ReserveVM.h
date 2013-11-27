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
#define DEFAULT_RESERVE_SIZE 0x400000 //1M
#define DEFAULT_COMMIT_SIZE 0x1000 //4K
class IthReservedVirtualMemory
{
public:
	IthReservedVirtualMemory();
	~IthReservedVirtualMemory();
	unsigned long WriteBytes(void* p, unsigned long len, unsigned long position);
	unsigned long EraseBytes(unsigned long position, unsigned long len);
	unsigned long Resize(unsigned long size);
	void* Memory() const {return mem;}
private:
	void* mem;
	unsigned long commit_size;
};