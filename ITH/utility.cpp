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

//#include <ITH\ntdll.h>
#include <ITH\common.h>
#include <ITH\HookManager.h>
#include <ITH\mem.h>
#include <ITH\IHF_SYS.h>
#include <ITH\ITH_TLS.h>
#include "ITH.h"
extern HookManager* man;
DWORD GetProcessPath(HANDLE hProc, LPWSTR path)
{
	PROCESS_BASIC_INFORMATION info;
	LDR_DATA_TABLE_ENTRY entry;
	PEB_LDR_DATA ldr;
	PEB peb; 
	if (NT_SUCCESS(NtQueryInformationProcess(hProc, ProcessBasicInformation, &info, sizeof(info), 0)))
		if (info.PebBaseAddress)
			if (NT_SUCCESS(NtReadVirtualMemory(hProc, info.PebBaseAddress, &peb,sizeof(peb), 0)))
				if (NT_SUCCESS(NtReadVirtualMemory(hProc, peb.Ldr, &ldr, sizeof(ldr), 0)))
					if (NT_SUCCESS(NtReadVirtualMemory(hProc, (LPVOID)ldr.InLoadOrderModuleList.Flink,
						&entry, sizeof(LDR_DATA_TABLE_ENTRY), 0)))
						if (NT_SUCCESS(NtReadVirtualMemory(hProc, entry.FullDllName.Buffer,
							path, MAX_PATH * 2, 0))) return 1;
	return 0;
}
DWORD GetProcessPath(DWORD pid, LPWSTR path)
{
	CLIENT_ID id;
	OBJECT_ATTRIBUTES oa = {};
	HANDLE hProc; 
	NTSTATUS status;
	id.UniqueProcess = pid;
	id.UniqueThread = 0;
	oa.uLength = sizeof(oa);
	status = NtOpenProcess(&hProc , PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &oa, &id);
	if (NT_SUCCESS(status))
	{
		DWORD flag = GetProcessPath(hProc, path);
		NtClose(hProc);
		return flag;
	}
	else return 0;
};
DWORD GetProcessMemory1(HANDLE hProc, DWORD& size, DWORD& ws)
{
	DWORD len = 0x10000, s = 0, retl = 0;
	DWORD *buffer = 0;
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	while (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete buffer;
		len <<= 1;
		buffer = new DWORD[len];
		status = NtQueryVirtualMemory(hProc, 0, MemoryWorkingSetList, buffer, len<<2, &retl);
	}
	if (!NT_SUCCESS(status)) 
	{
		delete buffer;
		return 0;
	}
	len = *(DWORD*)buffer;
	ws = len << 2;
	for (DWORD i = 1; i <= len; i++)
		s += (buffer[i] >> 8) & 1; //Hot spot.
	size = (len - s) << 2;
	delete buffer;
	return 1;
}
DWORD GetProcessMemory(HANDLE hProc, DWORD& mem_size, DWORD& ws)
{
	DWORD len,retl,s;
	LPVOID buffer = 0;
	NTSTATUS status;
	static const DWORD table[]={0x100,0x100,0x100,0x100};
	len = 0x4000;
	status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(status)) return 0;
	status = NtQueryVirtualMemory(hProc, 0, MemoryWorkingSetList, buffer, len, &retl);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		len = *(DWORD*)buffer;
		len = ((len << 2) & 0xFFFFF000) + 0x1000;
		s = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &s, MEM_RELEASE);
		buffer = 0;
		status = NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &len, MEM_COMMIT, PAGE_READWRITE);
		if (!NT_SUCCESS(status)) return 0;
		status = NtQueryVirtualMemory(hProc, 0, MemoryWorkingSetList, buffer, len, &retl);
		if (!NT_SUCCESS(status)) return 0;
	}
	else if (!NT_SUCCESS(status)) return 0;
	__asm
	{
		mov esi,buffer
		mov edi,[esi]
		mov eax,ws
		lea ebx,[edi*4]
		mov [eax],ebx
		mov ecx,edi

		xor edx,edx
		bt edi,8
		sbb edx,0
		shl edx,8
		lea edi,[esi+ebx+4]
		pxor xmm4,xmm4
		pxor xmm5,xmm5
		pxor xmm6,xmm6
		pxor xmm7,xmm7
		lea eax,[esp-0x20]
		and al,0xF0
		movdqu xmm0,table
		movdqa [eax],xmm0
		prefetcht0 [eax]
		mov ebx,0x40
		lea eax,[eax]
sse_calc:
		movdqa xmm0,[esi]
		movdqa xmm1,[esi+0x10]
		movdqa xmm2,[esi+0x20]
		movdqa xmm3,[esi+0x30]
		pand xmm0,[eax]
		pand xmm1,[eax]
		pand xmm2,[eax]
		pand xmm3,[eax]
		paddd xmm4,xmm0
		paddd xmm5,xmm1
		paddd xmm6,xmm2
		paddd xmm7,xmm3
		add esi,ebx
		cmp esi,edi
		jb sse_calc

		paddd xmm4,xmm5
		paddd xmm6,xmm7
		paddd xmm4,xmm6
		movaps [eax],xmm4
		add edx,[eax]
		add edx,[eax+0x4]
		add edx,[eax+0x8]
		add edx,[eax+0xC]
		shr edx,8
		sub edx,ecx
		neg edx
		add edx,edx
		mov ecx,mem_size
		add edx,edx
		mov [ecx],edx
	}
	s = 0;
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &s, MEM_RELEASE);
	return 1;
}
DWORD GetCode(const HookParam& hp, LPWSTR buffer, DWORD pid)
{
	WCHAR c;
	LPWSTR ptr=buffer;
	if (hp.type&PRINT_DWORD) c=L'H';
	else if (hp.type&USING_UNICODE)
	{
		if (hp.type&USING_STRING) c=L'Q';
		else if (hp.type&STRING_LAST_CHAR) c=L'L';
		else c=L'W';
	}
	else
	{
		if (hp.type&USING_STRING) c=L'S';
		else if (hp.type&BIG_ENDIAN) c=L'A';
		else if (hp.type&STRING_LAST_CHAR) c=L'E';
		else c=L'B';
	}
	ptr+=swprintf(ptr,L"/H%c",c);
	if(hp.type&NO_CONTEXT) *ptr++=L'N';
	if (hp.off>>31) ptr+=swprintf(ptr,L"-%X",-(hp.off+4));
	else ptr+=swprintf(ptr,L"%X",hp.off);
	if (hp.type&DATA_INDIRECT)
	{
		if (hp.ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.ind);
		else ptr+=swprintf(ptr,L"*%X",hp.ind);
	}
	if (hp.type&USING_SPLIT)
	{
		if (hp.split>>31) ptr+=swprintf(ptr,L":-%X",-(4+hp.split));
		else ptr+=swprintf(ptr,L":%X",hp.split);
	}
	if (hp.type&SPLIT_INDIRECT)
	{
		if (hp.split_ind>>31) ptr+=swprintf(ptr,L"*-%X",-hp.split_ind);
		else ptr+=swprintf(ptr,L"*%X",hp.split_ind);
	}
	if (pid)
	{		
		ProcessRecord *pr = man->GetProcessRecord(pid);
		if (pr)
		{
			MEMORY_BASIC_INFORMATION info;
			HANDLE hProc=pr->process_handle;
			if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,
				MemoryBasicInformation,&info,sizeof(info),0)))
			{
				if (info.Type & MEM_IMAGE)
				{
					
					WCHAR path[MAX_PATH];
					if (NT_SUCCESS(NtQueryVirtualMemory(hProc,(PVOID)hp.addr,
						MemorySectionName,path,MAX_PATH*2,0)))
					{
						ptr+=swprintf(ptr,L"@%X:%s",hp.addr-(DWORD)info.AllocationBase,wcsrchr(path,L'\\')+1);
						return ptr - buffer;
					}
				}
			}
		}
	}
	if (hp.module)
	{
		ptr+=swprintf(ptr,L"@%X!%X",hp.addr,hp.module);
		if (hp.function) ptr+=swprintf(ptr,L"!%X",hp.function);
	}
	else ptr+=swprintf(ptr,L"@%X",hp.addr);
	return ptr - buffer;
}
int UTF8to16len(const char* mb)
{
	int len = 0;
	char c;
	while((c = *mb) != 0)
	{
		if (c & 0x80)
		{
			while (c & 0x80)
			{
				mb++;
				c <<= 1;
			}
		}
		else
		{
			mb++;
		}
		len++;
	}
	return len;
}
int UTF8to16(const char* mb, wchar_t* wc)
{
	__asm
	{
		mov esi, mb
		mov edi, wc
		push edi
_next_char:
		movzx eax, byte ptr[esi]
		test al,al
		jz _finish
		test al,0x80
		jnz _non_ascii
		stosw
		inc esi
		jmp _next_char
_non_ascii:
		test al,0x40
		jz _finish
		test al,0x20
		jz _utf11bit
		and al,0xF
		mov cl,[esi + 1]
		and cl,0x3F
		mov dl,[esi + 2]
		and dl,0x3F
		shl eax,6
		or al,cl
		shl eax,6
		or al,dl
		stosw
		add esi,3
		jmp _next_char
_utf11bit:
		and al,0x1F
		shl eax,6
		movzx ecx,[esi+1]
		and cl,0x3F
		or eax,ecx
		stosw
		add esi,2
		jmp _next_char
_finish:
		pop eax
		sub edi,eax
		mov eax,edi
		shr eax,1
	}
}
int UTF8to16_c(const char* mb, wchar_t* wc)
{
	int len = 0;
	char c;
	wchar_t w;
	while ((c = *mb) != 0)
	{
		if (c & 0x80)
		{
			if (c & 40)
			{
				if (c & 0x20)
				{
					if (c & 0x10)
						return len;
					w = c & 0xF;
					w = (w << 6) | (mb[1] & 0x3F);
					w = (w << 6) | (mb[2] & 0x3F);
					*wc++ = w;
					mb += 3;
				}
				else
				{
					w = c & 0x1F;
					w = (w << 6) | (mb[1] & 0x3F);
					*wc++ = w;
					mb += 2;
				}
			}
			else return len;
		}
		else
		{
			*wc++ = c;
			mb++;
		}
		len++;
	}
	return len;
}
wchar_t* AllocateUTF16AndConvertUTF8(const char* utf8)
{
	int len = UTF8to16len(utf8);
	if (len == 0) return 0;
	wchar_t* str = new wchar_t[len + 1];
	UTF8to16(utf8, str);
	str[len] = 0;
	return str;
}
void ReleaseUTF16String(wchar_t* str)
{
	delete str;
}
int UTF16to8(const wchar_t* wc, char* mb)
{
	wchar_t c;
	char* start = mb;
	while (c = *wc++)
	{
		if (c >> 7)
		{
			if (c >> 11)
			{
				mb[2] = (c & 0x3F) | 0x80;
				c >>= 6;
				mb[1] = (c & 0x3F) | 0x80;
				c >>= 6;
				mb[0] = c | 0xE0;
				mb += 3;
			}
			else
			{
				mb[1] = (c & 0x3F) | 0x80;
				mb[0] = (c >> 6) | 0xC0;
				mb += 2;
			}
		}
		else
		{
			*mb++ = c & 0xFF;
		}
	}
	return mb - start;
}

#define MAX_HASH_SIZE 0x20
BYTE hex_table_inverse[0x80] = {
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
	-1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};
DWORD StrToHexByte(const char* str)
{
	BYTE c0 = str[1], c1 = str[0];
	if ((c0 | c1) & 0x80) return -1;
	c0 = hex_table_inverse[c0];
	c1 = hex_table_inverse[c1];
	return (c1 << 4) | c0;
}
void ByteToHexStr(char* hex_str, unsigned char b)
{
	static const char hex_table[] = "0123456789ABCDEF";
	hex_str[1] = hex_table[b & 0xF];
	hex_str[0] = hex_table[b >> 4];
}
bool CheckHashStr(BYTE* value, DWORD size_in_bytes, const char* str)
{
	DWORD i;
	for (i = 0; i < size_in_bytes; i++)
	{
		DWORD t = StrToHexByte(str);
		if (t == -1) return false;
		if (value[i] != (t & 0xFF)) return false;
		str += 2;
	}
	if (*str) return false;
	return true;

}
bool CompareHashStr(const char* s1, const char* s2)
{
	DWORD c1, c2;
	while (*s1)
	{
		c1 = StrToHexByte(s1);
		c2 = StrToHexByte(s2);
		if ((c1 | c2) == -1) return false; //Either s1 or s2 contains odd chars or invalid chars.
		if (c1 != c2) return false;
		s1 += 2;
		s2 += 2;
	}
	return true;
}
static char HTTP_OK[] = "HTTP/1.1 200 OK\r\n";
static char HTTP_END[] = "\r\n\r\n";
struct TitleParam
{
	DWORD pid,buffer_len,retn_len;
	LPWSTR buffer;
};
BOOL CALLBACK EnumProc(HWND hwnd,LPARAM lParam)
{
	TitleParam* p = (TitleParam*)lParam;
	CLIENT_ID id;
	id.UniqueThread = GetWindowThreadProcessId(hwnd,&id.UniqueProcess);
	if (id.UniqueProcess == p->pid)
	{
		if (GetWindowLong(hwnd,GWL_STYLE) & WS_VISIBLE)
		{
			p->retn_len = GetWindowTextLength(hwnd);
			if (p->retn_len)
			{
				p->buffer = new WCHAR[p->retn_len + 1];
				GetWindowText(hwnd,p->buffer,p->retn_len + 1);
				p->buffer[p->retn_len] = 0;
				return FALSE;
			}
		}
	}
	return TRUE;
}
LPWSTR SaveProcessTitle(DWORD pid)
{
	TitleParam p;
	p.buffer = 0;
	p.pid = pid;
	p.buffer_len = 0;
	p.retn_len = 0;
	EnumWindows(EnumProc, (LPARAM)&p);
	return p.buffer;
}
