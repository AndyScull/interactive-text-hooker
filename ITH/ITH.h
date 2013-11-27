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
inline DWORD Hash(LPWSTR module, int length = -1)
{
	bool flag=(length==-1);
	DWORD hash=0;
	for (;*module&&(flag||length--);module++)
	{
		hash = _rotr(hash,7) + *module;
		//hash=((hash>>7)|(hash<<25))+(*module);
	}
	return hash;
}
DWORD ProcessCommand(LPWSTR cmd, DWORD pid);
DWORD GetProcessPath(HANDLE hProc, LPWSTR path);
DWORD GetProcessPath(DWORD pid, LPWSTR path);
DWORD GetProcessMemory(HANDLE hProc, DWORD& mem_size, DWORD& ws);
void ConsoleOutput(LPCWSTR);
int UTF8to16len(const char* mb);
int UTF8to16(const char* mb, wchar_t* wc);
int UTF16to8(const wchar_t* wc, char* mb);
wchar_t* AllocateUTF16AndConvertUTF8(const char* utf8);
bool CheckHashStr(BYTE* value, DWORD size_in_bytes, const char* str);
bool CompareHashStr(const char* s1, const char* s2);
void ByteToHexStr(char* hex_str, unsigned char b);
LPWSTR SaveProcessTitle(DWORD pid); //New allocated from heap.