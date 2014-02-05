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

#include "IHF_CLIENT.h"
#include <ITH\AVL.h>
#include <ITH\ntdll.h>
WCHAR mutex[]=L"ITH_GRANT_PIPE";
WCHAR exist[]=L"ITH_PIPE_EXIST";
WCHAR detach_mutex[0x20];
WCHAR write_event[0x20];
WCHAR engine_event[0x20];
WCHAR recv_pipe[]=L"\\??\\pipe\\ITH_PIPE";
WCHAR command[]=L"\\??\\pipe\\ITH_COMMAND";

LARGE_INTEGER wait_time={-100*10000,-1};
LARGE_INTEGER sleep_time={-20*10000,-1};

DWORD engine_type;
DWORD engine_base;
DWORD module_base;

HANDLE hPipe,hCommand,hDetach;//,hLose;
IdentifyEngineFun IdentifyEngine; 
InsertHookFun InsertHook;
InsertDynamicHookFun InsertDynamicHook;

bool hook_inserted=0;

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
DWORD WINAPI WaitForPipe(LPVOID lpThreadParameter) //Dynamic detect ITH main module status. 
{
	int i;
	TextHook *man;
	struct
	{
		DWORD pid;
		TextHook *man;
		DWORD module;
		DWORD engine;
	} u;
	HANDLE hMutex,hPipeExist;
	//swprintf(engine_event,L"ITH_ENGINE_%d",current_process_id);
	swprintf(detach_mutex,L"ITH_DETACH_%d",current_process_id);
	//swprintf(lose_event,L"ITH_LOSEPIPE_%d",current_process_id);
	//hEngine=IthCreateEvent(engine_event);
	//NtWaitForSingleObject(hEngine,0,0);
	//NtClose(hEngine);
	while (engine_base == 0) NtDelayExecution(0, &wait_time);
	//LoadEngine(L"ITH_Engine.dll");
	u.module=module_base;
	u.pid=current_process_id;
	u.man=hookman;
	u.engine=engine_base;
	hPipeExist=IthOpenEvent(exist);
	IO_STATUS_BLOCK ios;
	//hLose=IthCreateEvent(lose_event,0,0);
	if (hPipeExist!=INVALID_HANDLE_VALUE)
	while (running)
	{
		hPipe=INVALID_HANDLE_VALUE;
		hCommand=INVALID_HANDLE_VALUE;
		while (NtWaitForSingleObject(hPipeExist,0,&wait_time)==WAIT_TIMEOUT)
			if (!running) goto _release;
		hMutex=IthCreateMutex(mutex,0);
		NtWaitForSingleObject(hMutex,0,0);
		while (hPipe==INVALID_HANDLE_VALUE||
			hCommand==INVALID_HANDLE_VALUE) {
			NtDelayExecution(0,&sleep_time);
			if (hPipe==INVALID_HANDLE_VALUE)
				hPipe=IthOpenPipe(recv_pipe,GENERIC_WRITE);
			if (hCommand==INVALID_HANDLE_VALUE)
				hCommand=IthOpenPipe(command,GENERIC_READ);
		}
		//NtClearEvent(hLose);
		NtWriteFile(hPipe,0,0,0,&ios,&u,16,0,0);
		live=true;
		for (man=hookman,i=0;i<current_hook;man++)
			if (man->RecoverHook()) i++;
		OutputConsole(dll_name);
		OutputConsole(L"Pipe connected.");
		//OutputDWORD(tree->Count());
		NtReleaseMutant(hMutex,0);
		NtClose(hMutex);
		if (!hook_inserted && engine_base) 
		{
			hook_inserted=true;
			IdentifyEngine();
		}
		hDetach=IthCreateMutex(detach_mutex,1);
		while (running&&NtWaitForSingleObject(hPipeExist,0,&sleep_time)==WAIT_OBJECT_0) 
			NtDelayExecution(0,&sleep_time);
		live=false;
		for (man=hookman,i=0;i<current_hook;man++)
			if (man->RemoveHook()) i++;
		if (!running)
		{
			NtWriteFile(hPipe,0,0,0,&ios,man,4,0,0);
			IthReleaseMutex(hDetach);					
		}
		NtClose(hDetach);
		NtClose(hPipe);
	}
_release:
	//NtClose(hLose);
	NtClose(hPipeExist);
	return 0;
}
DWORD WINAPI CommandPipe(LPVOID lpThreadParameter)
{
	DWORD command;
	BYTE buff[0x400]={};
	HANDLE hPipeExist;
	hPipeExist=IthOpenEvent(exist);
	IO_STATUS_BLOCK ios={0};
	NTSTATUS status;
	if (hPipeExist!=INVALID_HANDLE_VALUE)
	while (running)
	{
		while (!live) 
		{
			if (!running) goto _detach;
			NtDelayExecution(0,&sleep_time);
		}
		status=NtReadFile(hCommand,0,0,0,&ios,buff,0x200,0,0);
		if (status==STATUS_PIPE_BROKEN||
			status==STATUS_PIPE_DISCONNECTED)
		{
			NtClearEvent(hPipeExist);
			continue;
		}
		if (status==STATUS_PENDING)
		{
			NtWaitForSingleObject(hCommand,0,0);
			switch (ios.Status)
			{
			case 0:
				break;
			case STATUS_PIPE_BROKEN:
			case STATUS_PIPE_DISCONNECTED:
				NtClearEvent(hPipeExist);
				continue;
				break;
			default:
				if (NtWaitForSingleObject(hDetach,0,&wait_time)==WAIT_OBJECT_0)
				goto _detach;
			}			
		}
		if (ios.uInformation)
		if (live)
		{
			command=*(DWORD*)buff;
			switch(command)
			{
			case IHF_COMMAND_NEW_HOOK:
				//IthBreak();
				buff[ios.uInformation] = 0;
				buff[ios.uInformation + 1] = 0;
				NewHook(*(HookParam*)(buff+4),(LPWSTR)(buff + 4 + sizeof(HookParam)),0);
				break;
			case IHF_COMMAND_REMOVE_HOOK:
				{
					DWORD rm_addr=*(DWORD*)(buff+4);
					HANDLE hRemoved=IthOpenEvent(L"ITH_REMOVE_HOOK");

					TextHook* in=hookman;
					int i;
					for (i=0;i<current_hook;in++)
					{
						if (in->Address()) i++;
						if (in->Address()==rm_addr) break;
					}
					if (in->Address()) 
						in->ClearHook();
					IthSetEvent(hRemoved);
					NtClose(hRemoved);
					break;
				}
			case IHF_COMMAND_MODIFY_HOOK:
				{
					DWORD rm_addr=*(DWORD*)(buff+4);
					HANDLE hModify=IthOpenEvent(L"ITH_MODIFY_HOOK");
					TextHook* in=hookman;
					int i;
					for (i=0;i<current_hook;in++)
					{
						if (in->Address()) i++;
						if (in->Address()==rm_addr) break;
					}
					if (in->Address()) 
						in->ModifyHook(*(HookParam*)(buff+4));
					IthSetEvent(hModify);
					NtClose(hModify);
					break;

				}
				break;
			case IHF_COMMAND_DETACH:
				running=false;
				live=false;
				goto _detach;
			default:
				break;
			}
		}
	}
_detach:
	NtClose(hPipeExist);
	NtClose(hCommand);
	return 0;
}
extern "C" {
DWORD IHFAPI OutputConsole(LPWSTR str)
{
	if (live)
	if (str)
	{
		int t, len, sum;
		BYTE buffer[0x80];
		BYTE *buff;
		len = wcslen(str) << 1;
		t = swprintf((LPWSTR)(buffer + 8),L"%d: ",current_process_id) << 1;
		sum = len + t + 8;
		if (sum > 0x80) 
		{
			buff = new BYTE[sum];
			memcpy(buff + 8, buffer + 8, t);			
		}
		else buff = buffer;
		*(DWORD*)buff = IHF_NOTIFICATION; //cmd
		*(DWORD*)(buff + 4) = IHF_NOTIFICATION_TEXT; //console
		memcpy(buff + t + 8, str, len);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buff,sum,0,0);
		if (buff!=buffer) delete buff;
		return len;
	}
	return 0;
}

// AndyScull - for compatibility with VNR code
DWORD IHFAPI ConsoleOutput(LPSTR str)
{
	
	if (live)
	if (str)
	{
		int t, len, sum, slen;
		slen = strlen(str) + 1;
		len = MultiByteToWideChar(CP_ACP, 0, str, slen, 0, 0);
		wchar_t* wstr = new wchar_t[len];
		MultiByteToWideChar(CP_ACP, 0, str, slen, wstr, len);

		BYTE buffer[0x80];
		BYTE *buff;
		len = wcslen(wstr) << 1;
		t = swprintf((LPWSTR)(buffer + 8),L"%d: ",current_process_id) << 1;
		sum = len + t + 8;
		if (sum > 0x80) 
		{
			buff = new BYTE[sum];
			memcpy(buff + 8, buffer + 8, t);			
		}
		else buff = buffer;
		*(DWORD*)buff = IHF_NOTIFICATION; //cmd
		*(DWORD*)(buff + 4) = IHF_NOTIFICATION_TEXT; //console
		memcpy(buff + t + 8, wstr, len);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buff,sum,0,0);
		if (buff!=buffer) delete buff;
		delete wstr;
		return len;
	}
	return 0;
}



DWORD IHFAPI OutputDWORD(DWORD d)
{
	WCHAR str[0x10];
	swprintf(str,L"%.8X",d);
	OutputConsole(str);
	return 0;
}
DWORD IHFAPI OutputRegister(DWORD *base)
{
	WCHAR str[0x40];
	swprintf(str,L"EAX:%.8X",base[0]);
	OutputConsole(str);
	swprintf(str,L"ECX:%.8X",base[-1]);
	OutputConsole(str);
	swprintf(str,L"EDX:%.8X",base[-2]);
	OutputConsole(str);
	swprintf(str,L"EBX:%.8X",base[-3]);
	OutputConsole(str);
	swprintf(str,L"ESP:%.8X",base[-4]);
	OutputConsole(str);
	swprintf(str,L"EBP:%.8X",base[-5]);
	OutputConsole(str);
	swprintf(str,L"ESI:%.8X",base[-6]);
	OutputConsole(str);
	swprintf(str,L"EDI:%.8X",base[-7]);
	OutputConsole(str);
	return 0;
}
DWORD IHFAPI RegisterEngineModule(DWORD base, DWORD idEngine, DWORD dnHook)
{
	IdentifyEngine = (IdentifyEngineFun)idEngine;
	InsertDynamicHook = (InsertDynamicHookFun)dnHook;
	engine_base = base;
	return 0;
}
DWORD IHFAPI NotifyHookInsert(DWORD addr)
{
	if (live)
	{
		BYTE buffer[0x10];
		*(DWORD*)buffer=IHF_NOTIFICATION;
		*(DWORD*)(buffer+4)=IHF_NOTIFICATION_NEWHOOK;
		*(DWORD*)(buffer+8)=addr;
		*(DWORD*)(buffer+0xc)=0;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,0x10,0,0);
	}
	return 0;
}
}
