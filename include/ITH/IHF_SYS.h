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
#include <ITH\ntdll.h>
extern "C" {
extern WORD* NlsAnsiCodePage;
int disasm(BYTE* opcode0);
int FillRange(LPWSTR name,DWORD* lower, DWORD* upper);
int MB_WC(char* mb, wchar_t* wc);
int MB_WC_count(char* mb, int mb_length);
int WC_MB(wchar_t *wc, char* mb);
DWORD SearchPattern(DWORD base, DWORD base_length, LPVOID search, DWORD search_length); //KMP
BOOL IthInitSystemService();
void IthCloseSystemService();
DWORD IthGetMemoryRange(LPVOID mem, DWORD* base, DWORD* size);
BOOL IthCheckFile(LPWSTR file);
BOOL IthFindFile(LPWSTR file);
BOOL IthGetFileInfo(LPWSTR file, LPVOID info, DWORD size = 0x1000);
BOOL IthCheckFileFullPath(LPWSTR file);
HANDLE IthCreateFile(LPWSTR name, DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateFileInDirectory(LPWSTR name, HANDLE dir, DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateDirectory(LPWSTR name);
HANDLE IthCreateFileFullPath(LPWSTR full_path, DWORD option, DWORD share, DWORD disposition);
HANDLE IthPromptCreateFile(DWORD option, DWORD share, DWORD disposition);
HANDLE IthCreateSection(LPWSTR name, DWORD size, DWORD right);
HANDLE IthCreateEvent(LPWSTR name, DWORD auto_reset=0, DWORD init_state=0);
HANDLE IthOpenEvent(LPWSTR name);
void IthSetEvent(HANDLE hEvent);
void IthResetEvent(HANDLE hEvent);
HANDLE IthCreateMutex(LPWSTR name, BOOL InitialOwner, DWORD* exist=0);
HANDLE IthOpenMutex(LPWSTR name);
BOOL IthReleaseMutex(HANDLE hMutex);
//DWORD IthWaitForSingleObject(HANDLE hObject, DWORD dwTime);
HANDLE IthCreateThread(LPVOID start_addr, DWORD param, HANDLE hProc=(HANDLE)-1);
DWORD GetExportAddress(DWORD hModule,DWORD hash);
void IthSleep(int time);
void IthSystemTimeToLocalTime(LARGE_INTEGER* ptime);
void FreeThreadStart(HANDLE hProc);
void CheckThreadStart();
}
extern HANDLE hHeap;
extern DWORD current_process_id,debug;
extern BYTE LeadByteTable[];
extern LPVOID page;
extern BYTE launch_time[];
inline DWORD GetHash(LPSTR str)
{
	DWORD hash=0;
	for (;*str;str++)
	{
		hash=((hash>>7)|(hash<<25))+(*str);
	}
	return hash;
}
inline DWORD GetHash(LPWSTR str)
{
	DWORD hash=0;
	for (;*str;str++)
	{
		hash=((hash>>7)|(hash<<25))+(*str);
	}
	return hash;
}
inline void IthBreak()
{
	if (debug) __debugbreak();
}
inline LPWSTR GetMainModulePath()
{
	__asm
	{
		mov eax, fs:[0x30]
		mov eax, [eax + 0xC]
		mov eax, [eax + 0xC]
		mov eax, [eax + 0x28]
	}
}