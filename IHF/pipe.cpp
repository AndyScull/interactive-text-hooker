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

#include "main.h"
#include <ITH\HookManager.h>
//#include "CommandQueue.h"

#define NAMED_PIPE_DISCONNECT 1
#define NAMED_PIPE_CONNECT 2

WCHAR recv_pipe[]=L"\\??\\pipe\\ITH_PIPE";
WCHAR command_pipe[]=L"\\??\\pipe\\ITH_COMMAND";

static bool newline=false;
static bool detach=false;

CRITICAL_SECTION detach_cs;
//HANDLE hDetachEvent;
extern HANDLE hPipeExist;

//DWORD WINAPI UpdateWindows(LPVOID lpThreadParameter);
BYTE* Filter(BYTE *str, int len)
{
	WORD s;
	while (1)
	{
		s = *(WORD*)str;
		if (len >= 2)
		{
			if (s <= 0x20) {str += 2; len -= 2;}
			else break;
		}
		else if (str[0] <= 0x20) 
		{
			str++;
			len--;
		}
		else break;
	}
	return str;
}
void CreateNewPipe()
{
	static DWORD acl[7]={0x1C0002,
		1,
		0x140000,
		GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
		0x101,
		0x1000000,
		0};
	static SECURITY_DESCRIPTOR sd = {1,0,4,0,0,0,(PACL)acl};

	HANDLE hTextPipe, hCmdPipe, hThread;
	IO_STATUS_BLOCK ios;
	UNICODE_STRING us;

	OBJECT_ATTRIBUTES oa = {sizeof(oa), 0, &us, OBJ_CASE_INSENSITIVE, &sd, 0};
	LARGE_INTEGER time = {-500000, -1};

	RtlInitUnicodeString(&us,recv_pipe);
	if (!NT_SUCCESS(NtCreateNamedPipeFile(
		&hTextPipe,
		GENERIC_READ | SYNCHRONIZE, 
		&oa, 
		&ios,
		FILE_SHARE_WRITE,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		1, 1, 0, -1,
		0x1000,
		0x1000,
		&time)))
	{
		ConsoleOutput(ErrorCreatePipe);
		return;
	}

	RtlInitUnicodeString(&us, command_pipe);
	if (!NT_SUCCESS(NtCreateNamedPipeFile(
		&hCmdPipe,
		GENERIC_WRITE | SYNCHRONIZE,
		&oa,
		&ios,
		FILE_SHARE_READ,
		FILE_OPEN_IF,
		FILE_SYNCHRONOUS_IO_NONALERT,
		1, 1, 0, -1,
		0x1000,
		0x1000,
		&time)))
	{
		ConsoleOutput(ErrorCreatePipe);
		return;
	}
	hThread = IthCreateThread(RecvThread, (DWORD)hTextPipe);
	man -> RegisterPipe(hTextPipe, hCmdPipe, hThread);
}
void DetachFromProcess(DWORD pid)
{
	HANDLE hMutex, hEvent;		
	IO_STATUS_BLOCK ios;
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == 0) return;
	//IthBreak();
	hEvent = IthCreateEvent(0);	
	if (STATUS_PENDING == NtFsControlFile(
		man -> GetCmdHandleByPID(pid),
		hEvent,
		0,0,
		&ios,
		CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_DISCONNECT, 0, 0),
		0,0,0,0))
	{
		NtWaitForSingleObject(hEvent, 0, 0);
	}
	NtClose(hEvent);

	WCHAR mutex[0x20];
	swprintf(mutex,L"ITH_DETACH_%d",pid);	

	hMutex = IthOpenMutex(mutex);
	if (hMutex != INVALID_HANDLE_VALUE)
	{
		NtWaitForSingleObject(hMutex, 0, 0);
		NtReleaseMutant(hMutex, 0);
		NtClose(hMutex);
	}

	//NtSetEvent(hDetachEvent, 0);	
	if (running) NtSetEvent(hPipeExist, 0);
}
void OutputDWORD(DWORD d)
{
	WCHAR str[0x20];
	swprintf(str, L"%.8X", d);
	ConsoleOutput(str);
}

bool GetProcessPath(DWORD pid, LPWSTR path);

DWORD WINAPI RecvThread(LPVOID lpThreadParameter)
{
	HANDLE hTextPipe, hDisconnect;
	IO_STATUS_BLOCK ios; 
	NTSTATUS status;

	hTextPipe = (HANDLE)lpThreadParameter;
	NtFsControlFile(hTextPipe,
		0,0,0,
		&ios,
		CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_CONNECT, 0, 0),
		0,0,0,0);
	if (!running)
	{
		NtClose(hTextPipe);
		return 0;
	}

	DWORD pid, hookman, module, engine, RecvLen;

	BYTE *buff, *it;

	buff = new BYTE[0x1000];
	NtReadFile(hTextPipe, 0, 0, 0, &ios, buff, 16, 0, 0);

	pid = *(DWORD*)buff;
	hookman = *(DWORD*)(buff + 0x4);
	module = *(DWORD*)(buff + 0x8);
	engine = *(DWORD*)(buff + 0xC);
	man -> RegisterProcess(pid, hookman, module, engine);

	CreateNewPipe();

	//NtClose(IthCreateThread(UpdateWindows,0));

	while (running)
	{
		status = NtReadFile(hTextPipe,
			0,0,0,
			&ios,
			buff,
			0xF80,
			0,0);
		if (!NT_SUCCESS(status)) break;

		RecvLen = ios.uInformation;
		if (RecvLen < 0xC) break;
		DWORD hook = *(DWORD*)buff;

		union {DWORD retn; DWORD cmd_type;};
		union {DWORD split; DWORD new_engine_type;};

		retn = *(DWORD*)(buff + 4);
		split = *(DWORD*)(buff + 8);

		
		buff[RecvLen] = 0;
		buff[RecvLen+1] = 0;


		if (hook == IHF_NOTIFICATION) 
		{
			switch (cmd_type)
			{
			case IHF_NOTIFICATION_NEWHOOK:
				{
					static long lock;
					while (_InterlockedExchange(&lock,1) == 1);
					ProcessEventCallback new_hook = man->ProcessNewHook();					
					if (new_hook) new_hook(pid);
					lock = 0;
				}
				break;
			case IHF_NOTIFICATION_TEXT:
				{
					ConsoleOutput((LPWSTR)(buff+8));
				}
				

				break;
			}
		}
		else
		{
			it = Filter(buff + 0xC, RecvLen - 0xC);
			RecvLen = RecvLen - (it - buff);
			if (RecvLen >> 31) RecvLen = 0; 
			man -> DispatchText(pid, it, hook, retn, split, RecvLen);
		}
	}

	EnterCriticalSection(&detach_cs);

	hDisconnect = IthCreateEvent(0);

	if (STATUS_PENDING == NtFsControlFile(
		hTextPipe,
		hDisconnect,
		0, 0,
		&ios,
		CTL_CODE(FILE_DEVICE_NAMED_PIPE, NAMED_PIPE_DISCONNECT, 0, 0),
		0, 0, 0, 0))
	{
		NtWaitForSingleObject(hDisconnect, 0, 0);
	}
	NtClose(hDisconnect);
	DetachFromProcess(pid);
	man -> UnRegisterProcess(pid);

	//NtClearEvent(hDetachEvent);

	LeaveCriticalSection(&detach_cs);	

	if (running)
	{
		swprintf((LPWSTR)buff, FormatDetach, pid);
		ConsoleOutput((LPWSTR)buff);
		//NtClose(IthCreateThread(UpdateWindows, 0));
	}
	delete buff;
	return 0;
}

