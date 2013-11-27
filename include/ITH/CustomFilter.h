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
#include <windows.h>
#include <ITH\BitMap.h>
typedef void (*CustomFilterCallBack) (WORD, PVOID);

class CustomFilterUnicode : public BitMap
{
public:
	CustomFilterUnicode();
	~CustomFilterUnicode();
	bool Check(WORD number);
	void Set(WORD number);
	void Clear(WORD number);
	void Traverse(CustomFilterCallBack callback, PVOID param);

};

class CustomFilterMultiByte : public BitMap
{
public:
	CustomFilterMultiByte();
	~CustomFilterMultiByte();
	bool Check(WORD number);
	void Set(WORD number);
	void Clear(WORD number);
	void Reset();
	void Traverse(CustomFilterCallBack callback, PVOID param);
private:
	BYTE ascii_map[0x20];
};