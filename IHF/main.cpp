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
#include <intrin.h>
#include <ITH\ntdll.h>
#include <ITH\IHF_SYS.h>
#include <ITH\CustomFilter.h>
#include <CommCtrl.h>

#define IHF
#include <ITH\IHF.h>
#include "language.h"
#include "main.h"
//#include "CommandQueue.h"
static CRITICAL_SECTION cs;
static WCHAR exist[]=L"ITH_PIPE_EXIST";
static WCHAR mutex[]=L"ITH_RUNNING";
static WCHAR EngineName[]=L"ITH_engine.dll";
static WCHAR DllName[]=L"IHF_DLL.dll";
static HANDLE hMutex;
static DWORD admin;
//extern LPWSTR current_dir;
extern CRITICAL_SECTION detach_cs;

SettingManager* setman;
HWND hMainWnd;
HANDLE hPipeExist;
BOOL running;
void CreateNewPipe();
void GetDebugPriv(void)
{
	HANDLE	hToken;
	DWORD	dwRet;
	NTSTATUS status;

	TOKEN_PRIVILEGES Privileges = {1,{0x14,0,SE_PRIVILEGE_ENABLED}};

	NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);	

	status = NtAdjustPrivilegesToken(hToken, 0, &Privileges, sizeof(Privileges), 0, &dwRet);

	if (STATUS_SUCCESS == status)
	{
		admin = 1;
	}
	else 
	{
		WCHAR buffer[0x10];
		swprintf(buffer, L"%.8X",status);
		MessageBox(0, NotAdmin, buffer, 0);
	}

	NtClose(hToken);
}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason) 
	{ 
	case DLL_PROCESS_ATTACH:
		LdrDisableThreadCalloutsForDll(hinstDLL);
		InitializeCriticalSection(&cs);
		IthInitSystemService();
		GetDebugPriv();
		//Used by timers.
		InitCommonControls();
		hMainWnd = CreateWindow(L"Button", L"InternalWindow", 0, 0, 0, 0, 0, 0, 0, hinstDLL, 0);
		break;
	case DLL_PROCESS_DETACH:
		if (running) IHF_Cleanup();
		DeleteCriticalSection(&cs);
		IthCloseSystemService();
		DestroyWindow(hMainWnd);
		break;
	default:
		break;
	}
	return true;
}
HANDLE IthOpenPipe(LPWSTR name, ACCESS_MASK direction)
{
	UNICODE_STRING us;
	RtlInitUnicodeString(&us,name);
	SECURITY_DESCRIPTOR sd={1};
	OBJECT_ATTRIBUTES oa={sizeof(oa),0,&us,OBJ_CASE_INSENSITIVE,&sd,0};
	HANDLE hFile;
	IO_STATUS_BLOCK isb;
	if (NT_SUCCESS(NtCreateFile(&hFile,direction,&oa,&isb,0,0,FILE_SHARE_READ,FILE_OPEN,0,0,0)))
		return hFile;
	else return INVALID_HANDLE_VALUE;
}
DWORD Inject(HANDLE hProc, LPWSTR engine)
{
	LPVOID lpvAllocAddr = 0;
	DWORD dwWrite = 0x1000, len = 0;
	HANDLE hTH;
	WCHAR path[MAX_PATH];
	LPWSTR p;
	if (!IthCheckFile(DllName)) return -1;
	p = GetMainModulePath();
	len = wcslen(p);
	memcpy(path, p, len << 1);
	memset(path + len, 0, (MAX_PATH - len) << 1);
	for (p = path + len; *p != L'\\'; p--); //Always a \ after drive letter.
	p++;
	wcscpy(p, DllName);

	NtAllocateVirtualMemory(hProc, &lpvAllocAddr, 0, &dwWrite, MEM_COMMIT, PAGE_READWRITE);
	if (lpvAllocAddr == 0) return -1;

	CheckThreadStart();

	//Copy module path into address space of target process.
	NtWriteVirtualMemory(hProc, lpvAllocAddr, path, MAX_PATH << 1, &dwWrite);

	hTH = IthCreateThread(LoadLibrary, (DWORD)lpvAllocAddr, hProc);
	if (hTH == 0 || hTH == INVALID_HANDLE_VALUE)
	{
		ConsoleOutput(ErrorRemoteThread);
		return -1;
	}
	NtWaitForSingleObject(hTH, 0, 0);

	THREAD_BASIC_INFORMATION info;
	NtQueryInformationThread(hTH, ThreadBasicInformation, &info, sizeof(info), &dwWrite);
	NtClose(hTH);
	if (info.ExitStatus != 0)
	{
		wcscpy(p, engine);
		NtWriteVirtualMemory(hProc, lpvAllocAddr, path, MAX_PATH << 1, &dwWrite);
		hTH = IthCreateThread(LoadLibrary, (DWORD)lpvAllocAddr, hProc);
		if (hTH == 0 || hTH == INVALID_HANDLE_VALUE)
		{
			ConsoleOutput(ErrorRemoteThread);
			return -1;
		}
		NtWaitForSingleObject(hTH, 0, 0);
		NtClose(hTH);
	}

	dwWrite = 0;
	NtFreeVirtualMemory(hProc, &lpvAllocAddr, &dwWrite, MEM_RELEASE);
	return info.ExitStatus;
}
void ConsoleOutput(LPCWSTR text)
{
	man->AddConsoleOutput(text);
}
#define IHS_SIZE 0x80
#define IHS_BUFF_SIZE (IHS_SIZE - sizeof(HookParam))
struct InsertHookStruct
{
	SendParam sp;
	BYTE name_buffer[IHS_SIZE];
};
IHFSERVICE DWORD IHFAPI IHF_Init()
{
	BOOL result = false;
	DWORD present;
	EnterCriticalSection(&cs);
	hMutex = IthCreateMutex(mutex,1,&present);
	if (present)
	{
		MessageBox(0,L"Already running.",0,0);
	}
	else if (!running)
	{
		running = true;
		setman = new SettingManager;

		setman->SetValue(SETTING_SPLIT_TIME, 200);
		man = new HookManager;
		//cmdq = new CommandQueue;
		InitializeCriticalSection(&detach_cs);
	
		result = true;

	}
	LeaveCriticalSection(&cs);
	return result;
}
IHFSERVICE DWORD IHFAPI IHF_Start()
{
	//IthBreak();
	CreateNewPipe();
	hPipeExist = IthCreateEvent(exist);
	NtSetEvent(hPipeExist,0);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_Cleanup()
{
	BOOL result = false;
	EnterCriticalSection(&cs);
	if (running)
	{
		running = false;
		HANDLE hRecvPipe = IthOpenPipe(recv_pipe,GENERIC_WRITE);
		NtClose(hRecvPipe);
		NtClearEvent(hPipeExist);
		//delete cmdq;
		delete man;
		NtClose(hMutex);		
		NtClose(hPipeExist);
		DeleteCriticalSection(&detach_cs);
		result = true;
	}
	LeaveCriticalSection(&cs);
	return result;
}
IHFSERVICE DWORD IHFAPI IHF_GetPIDByName(LPWSTR pwcTarget)
{
	DWORD dwSize = 0x20000, dwExpectSize = 0;
	LPVOID pBuffer = 0;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
	DWORD dwPid = 0;
	DWORD dwStatus;

	NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &dwSize, MEM_COMMIT, PAGE_READWRITE);
	dwStatus = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &dwExpectSize);
	if (!NT_SUCCESS(dwStatus))
	{
		NtFreeVirtualMemory(NtCurrentProcess(),&pBuffer,&dwSize,MEM_RELEASE);
		if (dwStatus != STATUS_INFO_LENGTH_MISMATCH || dwExpectSize < dwSize) return 0;
		dwSize = (dwExpectSize | 0xFFF) + 0x4001; //
		pBuffer = 0;
		NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &dwSize, MEM_COMMIT, PAGE_READWRITE);
		dwStatus = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &dwExpectSize);
		if (!NT_SUCCESS(dwStatus)) goto _end;
	}

	for (spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)pBuffer; spiProcessInfo->dNext;)
	{
		spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)
			((DWORD)spiProcessInfo + spiProcessInfo -> dNext);
		if (_wcsicmp(pwcTarget, spiProcessInfo -> usName.Buffer) == 0) 
		{
			dwPid = spiProcessInfo->dUniqueProcessId;
			break;
		}
	}
	if (dwPid == 0) ConsoleOutput(ErrorNoProcess);
_end:
	NtFreeVirtualMemory(NtCurrentProcess(),&pBuffer,&dwSize,MEM_RELEASE);
	return dwPid;
}
IHFSERVICE DWORD IHFAPI IHF_InjectByPID(DWORD pid, LPWSTR engine)
{
	WCHAR str[0x80];
	DWORD s;
	if (!running) return 0;
	if (pid == current_process_id) 
	{
		ConsoleOutput(SelfAttach);
		return -1;
	}
	if (man->GetProcessRecord(pid))
	{
		ConsoleOutput(AlreadyAttach);
		return -1;
	}
	swprintf(str, L"ITH_HOOKMAN_%d", pid);
	NtClose(IthCreateMutex(str, 0, &s));
	if (s) return -1;
	CLIENT_ID id;
	OBJECT_ATTRIBUTES oa = {};
	HANDLE hProc;
	id.UniqueProcess = pid;
	id.UniqueThread = 0;
	oa.uLength=sizeof(oa);
	if (!NT_SUCCESS(NtOpenProcess(&hProc,
		PROCESS_QUERY_INFORMATION|
		PROCESS_CREATE_THREAD|
		PROCESS_VM_OPERATION|
		PROCESS_VM_READ|
		PROCESS_VM_WRITE,
		&oa, &id)))
	{
		ConsoleOutput(ErrorOpenProcess);
		return -1;
	}
	
	if (engine == 0) engine = EngineName;
	DWORD module = Inject(hProc,engine);
	NtClose(hProc);
	if (module == -1) return -1;
	swprintf(str, FormatInject, pid, module);
	ConsoleOutput(str);
	return module;
}
IHFSERVICE DWORD IHFAPI IHF_ActiveDetachProcess(DWORD pid)
{
	DWORD module, engine, dwWrite;
	HANDLE hProc, hThread, hCmd;	
	IO_STATUS_BLOCK ios;
	//man->LockHookman();
	ProcessRecord* pr = man->GetProcessRecord(pid);
	hCmd = man->GetCmdHandleByPID(pid);
	if (pr == 0 || hCmd == 0) return FALSE;
	//hProc = pr->process_handle; //This handle may be closed(thus invalid) during the detach process.
	NtDuplicateObject(NtCurrentProcess(), pr->process_handle, 
		NtCurrentProcess(), &hProc, 0, 0, DUPLICATE_SAME_ACCESS); //Make a copy of the process handle.
	module = pr->module_register;
	if (module == 0) return FALSE;
	engine = pr->engine_register;
	engine &= ~0xFF;
	SendParam sp = {};
	sp.type = 4;
	NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam),0,0);
	//cmdq->AddRequest(sp, pid);
	dwWrite = 0x1000;
	hThread = IthCreateThread(LdrUnloadDll, engine, hProc);
	if (hThread == 0 || 
		hThread == INVALID_HANDLE_VALUE) return FALSE;
	NtWaitForSingleObject(hThread, 0, 0);
	NtClose(hThread);
	hThread = IthCreateThread(LdrUnloadDll, module, hProc);
	if (hThread == 0 ||
		hThread == INVALID_HANDLE_VALUE) return FALSE;
	NtWaitForSingleObject(hThread, 0, 0);
	//man->UnlockHookman();
	THREAD_BASIC_INFORMATION info;
	NtQueryInformationThread(hThread, ThreadBasicInformation, &info, sizeof(info), 0);					
	NtClose(hThread);
	NtSetEvent(hPipeExist, 0);
	FreeThreadStart(hProc);
	NtClose(hProc);
	dwWrite = 0x1000;
	return info.ExitStatus;
}
IHFSERVICE DWORD IHFAPI IHF_GetHookManager(HookManager** hookman)
{
	if (running)
	{
		*hookman = man;
		return 0;
	}
	else return 1;
}
IHFSERVICE DWORD IHFAPI IHF_GetSettingManager(SettingManager** set_man)
{
	if (running)
	{
		*set_man = setman;
		return 0;
	}
	else return 1;
}
IHFSERVICE DWORD IHFAPI IHF_InsertHook(DWORD pid, HookParam* hp, LPWSTR name)
{
	InsertHookStruct s;
	HANDLE hCmd = man->GetCmdHandleByPID(pid);
	if (hCmd == 0) return -1;
	{
		s.sp.type = IHF_COMMAND_NEW_HOOK;
		s.sp.hp = *hp;
		DWORD len;
		if (name) len = wcslen(name) << 1;
		else len = 0;
		if (len >= IHS_BUFF_SIZE - 2) len = IHS_BUFF_SIZE - 2;
		memcpy(s.name_buffer, name, len);
		s.name_buffer[len] = 0;
		s.name_buffer[len + 1] = 0;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hCmd, 0,0,0, &ios, &s, IHS_SIZE, 0, 0);
	}

	//memcpy(&sp.hp,hp,sizeof(HookParam));
	//cmdq->AddRequest(sp, pid);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_ModifyHook(DWORD pid, HookParam* hp)
{
	SendParam sp;
	HANDLE hModify,hCmd;
	hCmd = GetCmdHandleByPID(pid);
	if (hCmd == 0) return -1;
	hModify = IthCreateEvent(L"ITH_MODIFY_HOOK");
	sp.type = IHF_COMMAND_MODIFY_HOOK;
	sp.hp = *hp;
	IO_STATUS_BLOCK ios;
	if (NT_SUCCESS(NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam), 0, 0)))
		NtWaitForSingleObject(hModify, 0, 0);
	NtClose(hModify);
	man -> RemoveSingleHook(pid, sp.hp.addr);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_RemoveHook(DWORD pid, DWORD addr)
{

	HANDLE hRemoved,hCmd;
	hCmd = GetCmdHandleByPID(pid);
	if (hCmd == 0) return -1;
	hRemoved = IthCreateEvent(L"ITH_REMOVE_HOOK");
	SendParam sp = {};
	IO_STATUS_BLOCK ios;
	sp.type = IHF_COMMAND_REMOVE_HOOK;
	sp.hp.addr = addr;
	//cmdq -> AddRequest(sp, pid);
	NtWriteFile(hCmd, 0,0,0, &ios, &sp, sizeof(SendParam),0,0);
	NtWaitForSingleObject(hRemoved, 0, 0);
	NtClose(hRemoved);
	man -> RemoveSingleHook(pid, sp.hp.addr);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_IsAdmin()
{
	return admin;
}
IHFSERVICE DWORD IHFAPI IHF_AddLink(DWORD from, DWORD to)
{
	man->AddLink(from & 0xFFFF, to & 0xFFFF);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_UnLink(DWORD from)
{
	man->UnLink(from & 0xFFFF);
	return 0;
}
IHFSERVICE DWORD IHFAPI IHF_UnLinkAll(DWORD from)
{
	man->UnLinkAll(from & 0xFFFF);
	return 0;
}
