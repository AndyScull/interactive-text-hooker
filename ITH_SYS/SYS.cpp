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

// disable C++ exceptions in STL
#define _HAS_EXCEPTIONS 0
#define _STATIC_CPPLIB
#define _DISABLE_DEPRECATE_STATIC_CPPLIB

#include <string>

#include <windows.h>

#include <ITH\ntdll.h>
#include <ITH\IHF_SYS.h>

#define SEC_BASED 0x200000
LPVOID page;
UINT page_locale;
DWORD current_process_id,debug;
HANDLE hHeap, root_obj, dir_obj, codepage_section, thread_man_section;
BYTE LeadByteTable[0x100]={
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
	2,2,2,2,2,2,2,2,2,2,2,2,2,1,1,1
};
BYTE launch_time[0x10];
static BYTE file_info[0x1000];

std::wstring SYS_get_base_named_objects_path()
{
	std::wstring base_name_objects_path;

	// get our terminal services session id
	DWORD session_id;
	ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
	// create a path to the kernel BaseNamedObjects
	if( session_id == 0 ) {
		// there is no 0 session, this just means an OS without terminal services
		base_name_objects_path = L"\\BaseNamedObjects";
	}
	else {
		wchar_t path_buffer[MAX_PATH];
		wsprintf(path_buffer, L"\\Sessions\\%d\\BaseNamedObjects", session_id);
		base_name_objects_path = path_buffer;
	}

	return base_name_objects_path;
}

std::wstring SYS_get_executable_path()
{
	// get the full path of the executable
	wchar_t module_filepath[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), module_filepath, MAX_PATH);
	// strip the filename and trailing slash
	std::wstring executable_path = module_filepath;
	size_t slash_pos = executable_path.rfind(L'\\');
	if( slash_pos != std::string::npos ) {
		executable_path.erase(slash_pos);
	}
	
	return executable_path;
}

DWORD GetShareMemory()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x4C]
	}
}
LARGE_INTEGER* GetTimeBias()
{
	__asm mov eax,0x7ffe0020
}
/*__declspec(naked) void normal_asm()
{
	__asm
	{
		push ecx
		push edx
		mov fs:[0],esp
		push ebp
		call eax
_terminate:
		push eax
		push -2
		call dword ptr [NtTerminateThread]
	}
}*/

/*
__declspec(naked) void RegToStrAsm()
{
	__asm
	{
		mov edx, 8
_cvt_loop:
		mov eax, ecx
		and eax, 0xF
		cmp eax, 0xA
		jb _below_ten
		add al,7
_below_ten:
		add al,0x30
		stosw
		ror ecx,4
		dec edx
		jne _cvt_loop
		retn
	}
}
__declspec(naked) void except_asm()
{
	__asm
	{
		mov eax,[esp + 4]
		xor esi,esi
		mov ebp,[eax]
		mov ecx,[esp + 0xC]
		mov ebx,[ecx + 0xB8]
		sub esp,0x240
		lea edi,[esp + 0x40]
		mov eax,esp
		push esi
		push 0x1C
		push eax
		push esi
		push ebx
		push -1
		call dword ptr [NtQueryVirtualMemory]
		test eax,eax
		jne _terminate
		mov eax,esp
		push eax
		push 0x200
		push edi
		push 2
		push ebx
		push -1
		call dword ptr [NtQueryVirtualMemory]
		test eax,eax
		jne _terminate
		pop esi
		xadd edi,esi
		std
		mov al,0x5C
		repen scasw
		mov word ptr [edi + 2], 0x3A
		mov ecx,ebx
		sub ecx,[esp]
		call RegToStrAsm
		inc edi
		inc edi
		xchg esi,edi
		mov ecx,ebp
		call RegToStrAsm
		inc edi
		inc edi
		xor eax,eax
		mov [edi + 0x10], eax
		push 0
		push edi
		push esi
		push 0
		call dword ptr [MessageBoxW]
		or eax, -1
		jmp _terminate
	}
}
*/

BYTE normal_routine[0x14] = {
	0x51,0x52,0x64,0x89,0x23,0x55,0xFF,0xD0,0x50,0x6A,0xFE,0xFF,0x15,0x14,0x00,0x00,0x00
};

BYTE except_routine[0xe0] = {
	0xBA,0x08,0x00,0x00,0x00,0x8B,0xC1,0x83,0xE0,0x0F,0x83,0xF8,0x0A,0x72,0x02,0x04,
	0x07,0x04,0x30,0x66,0xAB,0xC1,0xC9,0x04,0x4A,0x75,0xEA,0xC3,0x00,0x00,0x00,0x00,
	0x8B,0x44,0xE4,0x04,0x31,0xF6,0x8B,0x28,0x8B,0x4C,0xE4,0x0C,0x8B,0x99,0xB8,0x00,
	0x00,0x00,0x81,0xEC,0x40,0x02,0x00,0x00,0x8D,0x7C,0xE4,0x40,0x89,0xE0,0x56,0x6A,
	0x1C,0x50,0x56,0x53,0x6A,0xFF,0xFF,0x15,0x18,0x00,0x00,0x00,0x85,0xC0,0x75,0x98,
	0x89,0xE0,0x50,0x68,0x00,0x02,0x00,0x00,0x57,0x6A,0x02,0x53,0x6A,0xFF,0xFF,0x15,
	0x18,0x00,0x00,0x00,0x85,0xC0,0x75,0xe6,0x5E,0x0F,0xC1,0xF7,0xFD,0xB0,0x5C,0x66,
	0xF2,0xAF,0x66,0xC7,0x47,0x02,0x3A,0x00,0x89,0xD9,0x2B,0x0C,0xE4,0xE8,0x7E,0xFF,
	0xFF,0xFF,0x47,0x47,0x87,0xFE,0x89,0xE9,0xE8,0x73,0xFF,0xFF,0xFF,0x47,0x47,0x31,
	0xC0,0x89,0x47,0x10,0x6A,0x00,0x57,0x56,0x6A,0x00,0xFC,0xFF,0x15,0x1C,0x00,0x00,
	0x00,0x83,0xC8,0xFF,0xEB,0xBE
};
#define ADDR0 0xD
#define	ADDR1 0x48
#define ADDR2 0x60
#define ADDR3 0x9D
class ThreadStartManager
{
public:
	LPVOID GetProcAddr(HANDLE hProc)
	{
		AcquireLock();
		DWORD pid,addr,len;
		if (hProc==NtCurrentProcess()) pid=current_process_id;
		else
		{
			PROCESS_BASIC_INFORMATION info;
			NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),&len);
			pid=info.uUniqueProcessId;
		}
		pid>>=2;
		for (UINT_PTR i=0;i<count;i++)
		{
			if ((proc_record[i]&0xFFF)==pid)
			{
				addr=proc_record[i]&~0xFFF;
				ReleaseLock();
				return (LPVOID)addr;
			}
		}
		len=0x1000;
		NtAllocateVirtualMemory(hProc,(PVOID*)(proc_record+count),0,&len,
			MEM_COMMIT,PAGE_EXECUTE_READWRITE);
		DWORD base = proc_record[count];
		proc_record[count] |= pid;
		union
		{
			LPVOID buffer;
			DWORD b;
		};
		b = base;
		LPVOID fun_table[3];
		*(DWORD*)(normal_routine + ADDR0) += base;
		NtWriteVirtualMemory(hProc, buffer, normal_routine, 0x14, 0);
		*(DWORD*)(normal_routine + ADDR0) -= base;
		b += 0x14;
		fun_table[0] = NtTerminateThread;
		fun_table[1] = NtQueryVirtualMemory;
		fun_table[2] = MessageBoxW;
		NtWriteVirtualMemory(hProc, buffer, fun_table, 0xC, 0);
		b += 0xC;
		*(DWORD*)(except_routine + ADDR1) += base;
		*(DWORD*)(except_routine + ADDR2) += base;
		*(DWORD*)(except_routine + ADDR3) += base;
		NtWriteVirtualMemory(hProc, buffer, except_routine, 0xE0, 0);
		*(DWORD*)(except_routine + ADDR1) -= base;
		*(DWORD*)(except_routine + ADDR2) -= base;
		*(DWORD*)(except_routine + ADDR3) -= base;
		count++;
		ReleaseLock();
		return (LPVOID)base;
	}
	void ReleaseProcessMemory(HANDLE hProc)
	{
		DWORD pid,addr,len;
		AcquireLock();
		if (hProc==NtCurrentProcess()) pid=current_process_id;
		else
		{
			PROCESS_BASIC_INFORMATION info;
			NtQueryInformationProcess(hProc,ProcessBasicInformation,&info,sizeof(info),&len);
			pid=info.uUniqueProcessId;
		}
		pid>>=2;
		//NtWaitForSingleObject(thread_man_mutex,0,0);
		for (UINT_PTR i=0;i<count;i++)
		{
			if ((proc_record[i]&0xFFF)==pid)
			{
				addr=proc_record[i]&~0xFFF;
				DWORD size=0x1000;
				NtFreeVirtualMemory(hProc,(PVOID*)&addr,&size,MEM_RELEASE);
				count--;
				for (UINT_PTR j=i;j<count;j++)
				{
					proc_record[j]=proc_record[j+1];
				}
				proc_record[count]=0;
				ReleaseLock();
				//NtReleaseMutant(thread_man_mutex,0);
				return;
			}
		}
		ReleaseLock();
		//NtReleaseMutant(thread_man_mutex,0);
	}
	void CheckProcessMemory()
	{
		UINT_PTR i,j,flag,addr;
		DWORD len;
		CLIENT_ID id;
		OBJECT_ATTRIBUTES oa={0};
		HANDLE hProc;
		BYTE buffer[8];
		AcquireLock();
		id.UniqueThread=0;
		oa.uLength=sizeof(oa);
		for (i=0;i<count;i++)
		{
			id.UniqueProcess=(proc_record[i]&0xFFF)<<2;
			addr=proc_record[i]&~0xFFF;
			flag=0;
			if (NT_SUCCESS(NtOpenProcess(&hProc,PROCESS_VM_OPERATION|PROCESS_VM_READ,&oa,&id)))	
			{
				if (NT_SUCCESS(NtReadVirtualMemory(hProc,(PVOID)addr,buffer,8,&len)))
					if (memcmp(buffer,normal_routine,4)==0) flag=1;
				NtClose(hProc);
			}
			if (flag==0)
			{
				for (j=i;j<count;j++) proc_record[j]=proc_record[j+1];
				count--; i--;
			}
		}
		ReleaseLock();
	}
	void AcquireLock()
	{
		LONG *p = (LONG*)&mutex;
		while (_interlockedbittestandset(p,0)) YieldProcessor();
	}
	void ReleaseLock()
	{
		LONG *p = (LONG*)&mutex;
		_interlockedbittestandreset(p,0);
	}
private:
	UINT_PTR mutex,count;
	DWORD proc_record[1];
};
ThreadStartManager* thread_man;
extern "C" {
int FillRange(LPWSTR name,DWORD* lower, DWORD* upper)
{
	PLDR_DATA_TABLE_ENTRY it;
	LIST_ENTRY *begin;
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov it,eax
		mov begin,eax
	}
	while (it->SizeOfImage)
	{
		if (_wcsicmp(it->BaseDllName.Buffer,name)==0)
		{
			*lower=(DWORD)it->DllBase;
			*upper=*lower;
			MEMORY_BASIC_INFORMATION info={0};
			DWORD l,size; 
			size=0;
			do
			{
				NtQueryVirtualMemory(NtCurrentProcess(),(LPVOID)(*upper),MemoryBasicInformation,&info,sizeof(info),&l);
				if (info.Protect&PAGE_NOACCESS) 
				{
					it->SizeOfImage=size;
					break;
				}
				size+=info.RegionSize;
				*upper+=info.RegionSize;
			}while (size<it->SizeOfImage);
			return 1;
		}
		it=(PLDR_DATA_TABLE_ENTRY)it->InLoadOrderModuleList.Flink;
		if (it->InLoadOrderModuleList.Flink==begin) break;
	}
	return 0;
}
DWORD SearchPattern(DWORD base, DWORD base_length, LPVOID search, DWORD search_length) //KMP
{
	__asm
	{
		mov eax,search_length
alloc:
		push 0
		sub eax,1
		jnz alloc

		mov edi,search
		mov edx,search_length 
		mov ecx,1
		xor esi,esi
build_table:
		mov al,byte ptr [edi+esi]
		cmp al,byte ptr [edi+ecx]
		sete al
		test esi,esi
		jz pre
		test al,al
		jnz pre
		mov esi,[esp+esi*4-4]
		jmp build_table
pre:
		test al,al
		jz write_table
		inc esi
write_table:
		mov [esp+ecx*4],esi

		inc ecx
		cmp ecx,edx
		jb build_table

		mov esi,base
		xor edx,edx
		mov ecx,edx
matcher:
		mov al,byte ptr [edi+ecx]
		cmp al,byte ptr [esi+edx]
		sete al
		test ecx,ecx
		jz match
		test al,al
		jnz match
		mov ecx, [esp+ecx*4-4]
		jmp matcher
match:
		test al,al
		jz pre2
		inc ecx
		cmp ecx,search_length
		je finish
pre2:
		inc edx
		cmp edx,base_length //search_length
		jb matcher
		mov edx,search_length
		dec edx
finish:
		mov ecx,search_length
		sub edx,ecx
		lea eax,[edx+1]
		lea ecx,[ecx*4]
		add esp,ecx
	}
}
DWORD IthGetMemoryRange(LPVOID mem, DWORD* base, DWORD* size)
{
	DWORD r;
	MEMORY_BASIC_INFORMATION info;
	NtQueryVirtualMemory(NtCurrentProcess(),mem,MemoryBasicInformation,&info,sizeof(info),&r);
	if (base) *base=(DWORD)info.BaseAddress;
	if (size) *size=info.RegionSize;
	return (info.Type&PAGE_NOACCESS)==0;
}
//Get full path of current process.
LPWSTR GetModulePath()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov eax,[eax+0xC]
		mov eax,[eax+0x28]
	}
}
//SJIS->Unicode. 'mb' must be null-terminated. 'wc' should have enough space ( 2*strlen(mb) is safe).
int MB_WC(char* mb, wchar_t* wc)
{
	__asm
	{
		mov esi,mb
		mov edi,wc
		mov edx,page
		lea ebx,LeadByteTable
		add edx,0x220
		push 0
_mb_translate:
		movzx eax,word ptr [esi]
		test al,al
		jz _mb_fin
		movzx ecx,al
		xlat
		test al,1
		cmovnz cx, word ptr [ecx*2+edx-0x204]
		jnz _mb_next
		mov cx,word ptr [ecx*2+edx]
		mov cl,ah
		mov cx, word ptr [ecx*2+edx]
_mb_next:
		mov [edi],cx
		add edi,2
		movzx eax,al
		add esi,eax
		inc dword ptr [esp]
		jmp _mb_translate
_mb_fin:
		pop eax
	}
}

//Count characters of 'mb' string. 'mb_length' is max length.
int MB_WC_count(char* mb, int mb_length)
{
	__asm
	{
		xor eax,eax
		xor edx,edx
		mov esi,mb
		mov edi,mb_length
		lea ebx,LeadByteTable
_mbc_count:
		mov dl,byte ptr [esi]
		test dl,dl
		jz _mbc_finish
		movzx ecx, byte ptr [ebx+edx]
		add esi,ecx
		inc eax
		sub edi,ecx
		ja _mbc_count
_mbc_finish:
	}
}

//Unicode->SJIS. Analogous to MB_WC.
int WC_MB(wchar_t *wc, char* mb)
{
	__asm
	{
		mov esi,wc
		mov edi,mb
		mov edx,page
		add edx,0x7C22
		xor ebx,ebx
_wc_translate:
		movzx eax,word ptr [esi]
		test eax,eax
		jz _wc_fin
		mov cx,word ptr [eax*2+edx]
		test ch,ch
		jz _wc_single
		mov [edi+ebx],ch
		inc ebx
_wc_single:
		mov [edi+ebx],cl
		inc ebx
		add esi,2
		jmp _wc_translate
_wc_fin:
		mov eax,ebx
	}
}
void FreeThreadStart(HANDLE hProc)
{
	thread_man->ReleaseProcessMemory(hProc);
}
void CheckThreadStart()
{
	thread_man->CheckProcessMemory();
}

//Initialize environment for NT native calls. Not thread safe so only call it once in one module.
//1. Create new heap. Future memory requests are handled by this heap.
//Destroying this heap will completely release all dynamically allocated memory, thus prevent memory leaks on unload.
//2. Create handle to root directory of process objects (section/event/mutex/semaphore).
//NtCreate* calls will use this handle as base directory.
//3. Load SJIS code page. First check for Japanese locale. If not then load from 'C_932.nls' in system folder.
//MB_WC & WC_MB use this code page for translation.
//4. Locate current NT path (start with \??\).
//NtCreateFile requires full path or a root handle. But this handle is different from object.
//5. Map shared memory for ThreadStartManager into virtual address space.
//This will allow IthCreateThread function properly.
BOOL IthInitSystemService()
{
	PPEB peb;
	NTSTATUS status;
	DWORD size;
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	IO_STATUS_BLOCK ios;
	HANDLE codepage_file;
	LARGE_INTEGER sec_size={0x1000,0};

	__asm
	{
		mov eax,fs:[0x18]
		mov ecx,[eax+0x20]
		mov eax,[eax+0x30]
		mov peb,eax
			mov current_process_id,ecx
	}
	// FIXME: this is now the last usage of peb
	debug = peb->BeingDebugged;

	// FIXME: we should be able to use the default heap setup by Windows
	hHeap = RtlCreateHeap(HEAP_GROWABLE,0,0,0,0,0);

	// initialize the name based objects, before this is done mutexes and
	// critical sections do not work, thus neither does STL
	std::wstring base_named_objects_path = SYS_get_base_named_objects_path();
	RtlInitUnicodeString(&us, base_named_objects_path.c_str());
	status = NtOpenDirectoryObject(&root_obj,READ_CONTROL|0xF,&oa);
	if (!NT_SUCCESS(status)) return FALSE;

	// get the directory we are install to
	std::wstring executable_path = L"\\??\\" + SYS_get_executable_path();
	RtlInitUnicodeString(&us, executable_path.c_str());
	status = NtOpenFile(&dir_obj,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,
		&oa,&ios,FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT);
	if (!NT_SUCCESS(status)) return FALSE;
	
	// check for Japanese codepage
	page_locale = GetACP();
	if( page_locale == 932 )
	{
		oa.hRootDirectory = root_obj;
		oa.uAttributes |= OBJ_OPENIF;
	}
	else
	{
		OutputDebugString(L"3.2");
		// get the path to C:\Windows\System32
		wchar_t windows_system_path[MAX_PATH];
		GetSystemDirectory(windows_system_path, MAX_PATH);
		// create the japanese codepage filepath
		std::wstring jp_codepage_filepath = L"\\??\\";
		jp_codepage_filepath += windows_system_path;
		jp_codepage_filepath += L"\\C_932.nls";

		RtlInitUnicodeString(&us, jp_codepage_filepath.c_str());
		status = NtOpenFile(&codepage_file,FILE_READ_DATA,&oa,&ios,FILE_SHARE_READ,0);
		if (!NT_SUCCESS(status)) return FALSE;
		oa.hRootDirectory=root_obj;
		oa.uAttributes|=OBJ_OPENIF;
		RtlInitUnicodeString(&us,L"JPN_CodePage");	
		status = NtCreateSection(&codepage_section,SECTION_MAP_READ,
			&oa,0,PAGE_READONLY,SEC_COMMIT,codepage_file);
		if (!NT_SUCCESS(status)) return FALSE;
		NtClose(codepage_file); 
		size=0; page=0;
		status = NtMapViewOfSection(codepage_section,NtCurrentProcess(),
			&page,0,0,0,&size,ViewUnmap,0,PAGE_READONLY);		
		if (!NT_SUCCESS(status)) return FALSE;
	}

	RtlInitUnicodeString(&us,L"ITH_SysSection");
	status = NtCreateSection(&thread_man_section,SECTION_ALL_ACCESS,&oa,&sec_size,
		PAGE_EXECUTE_READWRITE,SEC_COMMIT,0); 
	if (!NT_SUCCESS(status)) return FALSE;
	size=0;
	status = NtMapViewOfSection(thread_man_section,NtCurrentProcess(),
		(PVOID*)&thread_man,0,0,0,&size,ViewUnmap,0,PAGE_EXECUTE_READWRITE);
	return NT_SUCCESS(status);
}

//Release resources allocated by IthInitSystemService.
//After destroying the heap, all memory allocated by ITH module is returned to system.
void IthCloseSystemService()
{
	if( page_locale != 932 )
	{
		NtUnmapViewOfSection(NtCurrentProcess(),page);
		NtClose(codepage_section);
	}
	NtUnmapViewOfSection(NtCurrentProcess(),thread_man);
	RtlDestroyHeap(hHeap);
	NtClose(root_obj);
	NtClose(thread_man_section);

}
//Check for existence of a file in current folder. Thread safe after init.
//For ITH main module, it's ITH folder. For target process it's the target process's current folder.
BOOL IthCheckFile(LPWSTR file)
{
	//return IthGetFileInfo(file,file_info);
	HANDLE hFile;
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file);
	OBJECT_ATTRIBUTES oa = {sizeof(oa),dir_obj,&us,0,0,0};
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,FILE_READ_DATA,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0)))
	{
		NtClose(hFile);
		return TRUE;
	}
	else return FALSE;
}
//Check for existence of files in current folder.
//Unlike IthCheckFile, this function allows wildcard character.
BOOL IthFindFile(LPWSTR file)
{
	NTSTATUS status;
	HANDLE h;
	UNICODE_STRING us;
	OBJECT_ATTRIBUTES oa={sizeof(oa),dir_obj,&us,OBJ_CASE_INSENSITIVE,0,0};
	us.Buffer = file;
	LPWSTR path = wcsrchr(file, L'\\');
	if (path)
	{
		us.Length = (path - file) << 1;
		us.MaximumLength = us.Length;
	}
	else
	{
		us.Length = 0;
		us.MaximumLength = 0;
	}
	IO_STATUS_BLOCK ios;
	if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
		&oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		BYTE info[0x400];
		if (path) RtlInitUnicodeString(&us,path+1);
		else RtlInitUnicodeString(&us,file);
		status=NtQueryDirectoryFile(h,0,0,0,&ios,info,0x400,FileBothDirectoryInformation,TRUE,&us,TRUE);
		NtClose(h);
		return NT_SUCCESS(status);
	}
	return FALSE;
}
//Analogous to IthFindFile, but return detail information in 'info'.
BOOL IthGetFileInfo(LPWSTR file, LPVOID info, DWORD size)
{
	NTSTATUS status;
	HANDLE h;
	UNICODE_STRING us;
	LPWSTR path = wcsrchr(file, L'\\');
	us.Buffer = file;
	if (path)
	{
		us.Length = (path - file) << 1;
		us.MaximumLength = us.Length;
	}
	else
	{
		us.Length = 0;
		us.MaximumLength = 0;
	}
	//RtlInitUnicodeString(&us,file);
	OBJECT_ATTRIBUTES oa={sizeof(oa),dir_obj,&us,OBJ_CASE_INSENSITIVE,0,0};
	IO_STATUS_BLOCK ios;
	if (NT_SUCCESS(NtOpenFile(&h,FILE_LIST_DIRECTORY|SYNCHRONIZE,
		&oa,&ios,FILE_SHARE_READ,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT)))
	{
		RtlInitUnicodeString(&us,file);
		status=NtQueryDirectoryFile(h,0,0,0,&ios,info,size,FileBothDirectoryInformation,0,&us,0);
		status=NT_SUCCESS(status);
		NtClose(h);
	}
	else status=FALSE;
	
	return status;
}
//Check for existence of a file with full NT path(start with \??\).
BOOL IthCheckFileFullPath(LPWSTR file)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,file);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,FILE_READ_DATA,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0)))
	{
		NtClose(hFile);
		return TRUE;
	}
	else return FALSE;
}
//Create or open file in current folder. Analogous to Win32 CreateFile.
//option: GENERIC_READ / GENERIC_WRITE.
//share: FILE_SHARE_READ / FILE_SHARE_WRITE / FILE_SHARE_DELETE. 0 for exclusive access.
//disposition: FILE_OPEN / FILE_OPEN_IF. 
//Use FILE_OPEN instead of OPEN_EXISTING and FILE_OPEN_IF for CREATE_ALWAYS. 
HANDLE IthCreateFile(LPWSTR name, DWORD option, DWORD share, DWORD disposition)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),dir_obj,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,
		option|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,share,disposition,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
//Create a directory file in current folder.
HANDLE IthCreateDirectory(LPWSTR name)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),dir_obj,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,FILE_LIST_DIRECTORY|FILE_TRAVERSE|SYNCHRONIZE,&oa,&isb,0,0,
		FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_OPEN_IF,FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthCreateFileInDirectory(LPWSTR name, HANDLE dir, DWORD option, DWORD share, DWORD disposition)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	if (dir == 0) dir = dir_obj;
	OBJECT_ATTRIBUTES oa={sizeof(oa),dir,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,
		option|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,share,disposition,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
//Analogous to IthCreateFile, but with full NT path. 
HANDLE IthCreateFileFullPath(LPWSTR path, DWORD option, DWORD share, DWORD disposition)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,path);
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,0,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,
		option|FILE_READ_ATTRIBUTES|SYNCHRONIZE
		,&oa,&isb,0,0,share,disposition,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
/*
//Prompt for file name.
HANDLE IthPromptCreateFile(DWORD option, DWORD share, DWORD disposition)
{
	OPENFILENAME ofn={sizeof(ofn)};       // common dialog box structure
	WCHAR szFile[MAX_PATH];       // buffer for file name
	wcscpy(current_dir,L"ITH_export.txt");
	wcscpy(szFile,file_path);

	//szFile[0]=0;
	ofn.lpstrFile = szFile + 4;
	ofn.nMaxFile = MAX_PATH;
	ofn.lpstrFilter = L"Text\0*.txt";
	BOOL result;
	if (disposition==FILE_OPEN)
		result=GetOpenFileName(&ofn);
	else
		result=GetSaveFileName(&ofn);
	if (result)
	{
		LPWSTR s=szFile+wcslen(szFile) - 4;
		if (_wcsicmp(s,L".txt")!=0) wcscpy(s + 4,L".txt");
		return IthCreateFileFullPath(szFile,option,share,disposition);
	}
	else return INVALID_HANDLE_VALUE;
}
*/
//Create section object for sharing memory between processes.
//Similar to CreateFileMapping.
HANDLE IthCreateSection(LPWSTR name, DWORD size, DWORD right)
{
	HANDLE hSection;
	LARGE_INTEGER s={size,0};
	OBJECT_ATTRIBUTES* poa = 0;
	if (name)
	{
		
		UNICODE_STRING us;
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		poa = &oa;
	}
	if (NT_SUCCESS(NtCreateSection(&hSection,GENERIC_ALL,poa,&s,
		right,SEC_COMMIT,0)))
		return hSection;
	else return INVALID_HANDLE_VALUE;
}
//Create event object. Similar to CreateEvent.
HANDLE IthCreateEvent(LPWSTR name, DWORD auto_reset, DWORD init_state)
{
	HANDLE hEvent;
	OBJECT_ATTRIBUTES* poa = 0;
	if (name)
	{
		UNICODE_STRING us;
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		poa = &oa;
	}
	if (NT_SUCCESS(NtCreateEvent(&hEvent,EVENT_ALL_ACCESS,poa,auto_reset,init_state)))
		return hEvent;
	else return INVALID_HANDLE_VALUE;
}
HANDLE IthOpenEvent(LPWSTR name)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,0,0,0};
	HANDLE hEvent;
	if (NT_SUCCESS(NtOpenEvent(&hEvent,EVENT_ALL_ACCESS,&oa)))
		return hEvent;
	else return INVALID_HANDLE_VALUE;
}
void IthSetEvent(HANDLE hEvent)
{
	NtSetEvent(hEvent,0);
}
void IthResetEvent(HANDLE hEvent)
{
	NtClearEvent(hEvent);
}
//Create mutex object. Similar to CreateMutex.
//If 'exist' is not null, it will be written 1 if mutex exist.
HANDLE IthCreateMutex(LPWSTR name, BOOL InitialOwner, DWORD* exist)
{
	UNICODE_STRING us;
	HANDLE hMutex; NTSTATUS status;
	OBJECT_ATTRIBUTES* poa = 0;
	if (name)
	{
		RtlInitUnicodeString(&us,name);
		OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,OBJ_OPENIF,0,0};
		poa = &oa;
	}
	status=NtCreateMutant(&hMutex,MUTEX_ALL_ACCESS,poa,InitialOwner);
	if (NT_SUCCESS(status))
	{
		if (exist) *exist=(STATUS_OBJECT_NAME_EXISTS==status);
		return hMutex;
	}
	else 
		return INVALID_HANDLE_VALUE;
}
HANDLE IthOpenMutex(LPWSTR name)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	OBJECT_ATTRIBUTES oa={sizeof(oa),root_obj,&us,0,0,0};
	HANDLE hMutex;
	if (NT_SUCCESS(NtOpenMutant(&hMutex,MUTEX_ALL_ACCESS,&oa)))
		return hMutex;
	else return INVALID_HANDLE_VALUE;
}
BOOL IthReleaseMutex(HANDLE hMutex)
{
	return NT_SUCCESS(NtReleaseMutant(hMutex,0));
}

#define DEFAULT_STACK_LIMIT 0x400000
#define DEFAULT_STACK_COMMIT 0x10000
#define PAGE_SIZE 0x1000
//Create new thread. 'hProc' must have following right. 
//PROCESS_CREATE_THREAD, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE.
HANDLE IthCreateThread(LPVOID start_addr, DWORD param, HANDLE hProc)
{
	HANDLE hThread;
	CLIENT_ID id;
	LPVOID protect;
	USER_STACK stack={};
	CONTEXT ctx={CONTEXT_FULL};
	DWORD size=DEFAULT_STACK_LIMIT,commit=DEFAULT_STACK_COMMIT,x;
	if (!NT_SUCCESS(NtAllocateVirtualMemory(hProc,&stack.ExpandableStackBottom,
		0,&size,MEM_RESERVE,PAGE_READWRITE))) return INVALID_HANDLE_VALUE;

	stack.ExpandableStackBase=(char*)stack.ExpandableStackBottom+size;
	stack.ExpandableStackLimit=(char*)stack.ExpandableStackBase-commit;
	size=PAGE_SIZE;
	commit+=size;
	protect=(char*)stack.ExpandableStackBase-commit;
	NtAllocateVirtualMemory(hProc,&protect,0,&commit,MEM_COMMIT,PAGE_READWRITE);
	NtProtectVirtualMemory(hProc,&protect,&size,PAGE_READWRITE|PAGE_GUARD,&x);
	ctx.SegGs=0;
	ctx.SegFs=0x38;
	ctx.SegEs=0x20;
	ctx.SegDs=0x20;
	ctx.SegSs=0x20;
	ctx.SegCs=0x18;
	ctx.EFlags=0x3000;
	ctx.Eip=(DWORD)thread_man->GetProcAddr(hProc);
	ctx.Eax=(DWORD)start_addr;
	ctx.Ecx=ctx.Eip + 0x40;
	ctx.Edx=0xFFFFFFFF;
	ctx.Esp=(DWORD)stack.ExpandableStackBase-0x10;
	ctx.Ebp=param;

	if (NT_SUCCESS(NtCreateThread(&hThread,THREAD_ALL_ACCESS,0,hProc,&id,&ctx,&stack,TRUE)))
	{
		//On x64 Windows, NtCreateThread in ntdll calls NtCreateThread in ntoskrnl via WOW64,
		//which maps 32-bit system call to the correspond 64-bit version.
		//This layer doesn't correctly copy whole CONTEXT structure, so we must set it manually
		//after the thread is created.
		//On x86 Windows, this step is not necessary.
		NtSetContextThread(hThread,&ctx);
		NtResumeThread(hThread,0);
		return hThread;
	}
	return INVALID_HANDLE_VALUE;
}
//Query module export table. Return function address if found.
//Similar to GetProcAddress
DWORD GetExportAddress(DWORD hModule,DWORD hash)
{
	IMAGE_DOS_HEADER *DosHdr;
	IMAGE_NT_HEADERS *NtHdr;
	IMAGE_EXPORT_DIRECTORY *ExtDir;
	UINT uj;
	char* pcExportAddr,*pcFuncPtr,*pcBuffer;
	DWORD dwReadAddr,dwFuncAddr,dwFuncName;
	WORD wOrd;
	DosHdr=(IMAGE_DOS_HEADER*)hModule;
	if (IMAGE_DOS_SIGNATURE==DosHdr->e_magic)
	{
		dwReadAddr=hModule+DosHdr->e_lfanew;
		NtHdr=(IMAGE_NT_HEADERS*)dwReadAddr;
		if (IMAGE_NT_SIGNATURE==NtHdr->Signature)
		{
			pcExportAddr=(char*)((DWORD)hModule+
				(DWORD)NtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			if (pcExportAddr==0) return 0;
			ExtDir=(IMAGE_EXPORT_DIRECTORY*)pcExportAddr;
			pcExportAddr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNames);

			for (uj=0;uj<ExtDir->NumberOfNames;uj++)
			{
				dwFuncName=*(DWORD*)pcExportAddr;
				pcBuffer=(char*)((DWORD)hModule+dwFuncName);
				if (GetHash(pcBuffer)==hash)
				{
					pcFuncPtr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfNameOrdinals+(uj*sizeof(WORD)));
					wOrd=*(WORD*)pcFuncPtr;
					pcFuncPtr=(char*)((DWORD)hModule+(DWORD)ExtDir->AddressOfFunctions+(wOrd*sizeof(DWORD)));
					dwFuncAddr=*(DWORD*)pcFuncPtr;
					return hModule+dwFuncAddr;
				}
				pcExportAddr+=sizeof(DWORD);
			}
		}
	}
	return 0;
}

void IthSleep(int time)
{
	__asm
	{
		mov eax,0x2710
		mov ecx,time
		mul ecx
		neg eax
		adc edx,0
		neg edx
		push edx
		push eax
		push esp
		push 0
		call dword ptr [NtDelayExecution]
		add esp,8
	}
}
void IthSystemTimeToLocalTime(LARGE_INTEGER* time)
{
	time->QuadPart-=GetTimeBias()->QuadPart;
}
}
