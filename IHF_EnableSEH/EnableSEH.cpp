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

#include <windows.h>
#include <stdio.h>
static BYTE file[0x1000];
int main()
{
	HANDLE hFile=INVALID_HANDLE_VALUE;
	LPWSTR f=wcsrchr(GetCommandLine(),L' ');
	if (f==0) return 1;
	f++;

	hFile=CreateFile(f,GENERIC_WRITE|GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
	if (hFile == INVALID_HANDLE_VALUE) return 1;
	DWORD high;
	DWORD size=GetFileSize(hFile,&high);
	DWORD d;
	if (high == 0 && size < 0x1000000)
	{
		//char* file=(char*)HeapAlloc(GetProcessHeap(),0, size);
		ReadFile(hFile,file,0x1000,&d,0);
		IMAGE_DOS_HEADER *DosHdr=(IMAGE_DOS_HEADER*)file;
		IMAGE_NT_HEADERS *NtHdr=(IMAGE_NT_HEADERS*)((DWORD)DosHdr+DosHdr->e_lfanew);
		if ((BYTE*)&NtHdr->OptionalHeader.DllCharacteristics - file>= 0x1000)
		{
			MessageBox(0,L"Out",0,0);
		}
		else
		{
			NtHdr->OptionalHeader.DllCharacteristics&=0xFBFF;
			SetFilePointer(hFile,0,0,FILE_BEGIN);
			WriteFile(hFile,file,0x1000,&d,0);
		}
	}

	CloseHandle(hFile);
	ExitProcess(0);
}