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

#include <ITH\IHF.h>
#include <ITH\ntdll.h>
#include <ITH\IHF_SYS.h>
#include <ITH\CustomFilter.h>
#include <windows.h>
#include "profile.h"
HookManager* man;
HINSTANCE hIns;
ATOM MyRegisterClass(HINSTANCE hInstance);
BOOL InitInstance(HINSTANCE hInstance, DWORD nCmdShow, RECT *rc);
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
RECT window;
extern HWND hMainWnd;

CustomFilterUnicode* uni_filter;
CustomFilterMultiByte* mb_filter;
SettingManager* setman;
DWORD split_time,cyclic_remove,global_filter;
DWORD process_time,inject_delay,insert_delay,
	auto_inject,auto_insert,clipboard_flag,
	window_left,window_right,window_top,window_bottom;
char* setting_string[] = {
	"split_time",
	"process_time",
	"inject_delay",
	"insert_delay",
	"auto_inject",
	"auto_insert",
	"auto_copy",
	"auto_suppress",
	"global_filter",
	"window_left",
	"window_right",
	"window_top",
	"window_bottom"
};

DWORD* setting_variable[] = {
	&split_time,
	&process_time,
	&inject_delay,
	&insert_delay,
	&auto_inject,
	&auto_insert,
	&clipboard_flag,
	&cyclic_remove,
	&global_filter,
	&window_left,
	&window_right,
	&window_top,
	&window_bottom
};

DWORD default_setting[]={
	200,	//split_time
	50,		//process_time
	3000,	//inject_delay
	500,	//insert_delay
	1,		//auto_inject
	1,		//auto_insert
	0,		//clipboard_flag
	0,		//cyclic_remove
	0,		//global_filter
	100,	//window_left
	800,	//window_right
	100,	//window_top
	600		//window_bottom
};

static const int setting_count = sizeof(setting_string) / sizeof(char*);
void RecordMBChar(WORD mb, PVOID f)
{
	TiXmlElement* filter = (TiXmlElement*)f;
	DWORD m = mb;
	char buffer[0x10];
	buffer[0] = 'm';
	sprintf(buffer + 1,"%.4X",m);
	filter->SetAttribute(buffer, "0");

}
void RecordUniChar(WORD uni, PVOID f)
{
	TiXmlElement* filter = (TiXmlElement*)f;
	DWORD m = uni;
	char buffer[0x10];
	buffer[0] = 'u';
	sprintf(buffer + 1,"%.4X",m);
	filter->SetAttribute(buffer, "0");
}
void SaveSettings()
{
	GetWindowRect(hMainWnd, &window);
	window_left = window.left;
	window_right = window.right;
	window_top = window.top;
	window_bottom = window.bottom;

	HANDLE hFile = IthCreateFile(L"ITH.xml",
		FILE_WRITE_DATA,
		FILE_SHARE_READ,
		FILE_OVERWRITE_IF);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		TiXmlDocument doc;
		TiXmlDeclaration decl("1.0","utf-8","");
		doc.InsertEndChild(decl);

		TiXmlElement* root = NewElement("ITH_Setting");
		doc.LinkEndChild(root);


		for (int i = 0; i < setting_count; i++)			
			root->SetAttribute(setting_string[i],*setting_variable[i]);
		
		TiXmlElement* filter = NewElement("SingleCharFilter");
		root->LinkEndChild(filter);

		mb_filter->Traverse(RecordMBChar, filter);
		uni_filter->Traverse(RecordUniChar, filter);

		TiXmlString str;
		doc.Print(str);
		IO_STATUS_BLOCK ios;

		NtWriteFile(hFile,
			0,0,0,
			&ios,
			(PVOID)str.c_str(),
			str.length(),
			0,0);
		NtClose(hFile);
	}
}
void DefaultSetting()
{
	for (int i=0; i < sizeof(setting_variable) / sizeof(LPVOID); i++)
	{
		*setting_variable[i] = default_setting[i];
	}
	window.left = window_left;
	window.right = window_right;
	window.top = window_top;
	window.bottom = window_bottom;
}
void LoadSettings()
{
	HANDLE hFile = IthCreateFile(L"ITH.xml",
		FILE_READ_DATA,
		FILE_SHARE_READ,
		FILE_OPEN);

	if (hFile!=INVALID_HANDLE_VALUE)
	{
		IO_STATUS_BLOCK ios;
		FILE_STANDARD_INFORMATION info;
		LPVOID buffer;

		NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);

		buffer = 0;
		NtAllocateVirtualMemory(NtCurrentProcess(), 
			&buffer, 0, 
			&info.AllocationSize.LowPart, 
			MEM_COMMIT, 
			PAGE_READWRITE);

		NtReadFile(hFile,
			0,0,0,
			&ios,
			buffer,
			info.AllocationSize.LowPart,
			0,0);

		NtClose(hFile);

		TiXmlDocument doc;
		doc.Parse((char*)buffer);

		NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);

		if (doc.Error())
		{
			DefaultSetting();
			return;
		}

		TiXmlElement* root = doc.RootElement();
		if (root == 0)
		{
			DefaultSetting();
			return;
		}

		TiXmlAttribute* attr;
		int i;
		for (i = 0, attr = root->FirstAttribute(); attr; attr = attr->Next(), i++)
		{
			if (i >= setting_count) break;
			if (strcmp(attr->Name(),setting_string[i]) == 0)
			{
				if (1 != sscanf(attr->Value(), "%d", setting_variable[i]))
					*setting_variable[i] = default_setting[i];
			}
			else *setting_variable[i] = default_setting[i];
		}

		TiXmlElement* filter = root->FirstChildElement("SingleCharFilter");
		if (filter)
		{
			for (attr = filter->FirstAttribute(); attr; attr = attr->Next())
			{
				const char* str = attr->Name();
				DWORD c;
				if (str[0] == 'm')
				{
					if (1 == sscanf(str + 1, "%x", &c))
						mb_filter->Set(c & 0xFFFF);
				}
				else if (str[0] == 'u')
				{
					if (1 == sscanf(str + 1, "%x", &c))
						uni_filter->Set(c & 0xFFFF);
				}
			}
		}
		if (auto_inject > 1) auto_inject = 1;
		if (auto_insert > 1) auto_insert = 1;
		if (clipboard_flag > 1) clipboard_flag = 1;
		if (cyclic_remove > 1) cyclic_remove = 1;

		if ((window_left | window_right | window_top | window_bottom)>>31) //Either is negative
		{
			window_left = 100;
			window_top = 100;
			window_right = 800;
			window_bottom = 600;
		}
		else
		{
			if (window_right < window_left || window_right-window_left < 600) window_right = window_left + 600;
			if (window_bottom < window_top || window_bottom-window_top < 200) window_bottom = window_top + 200;
		}

		window.left = window_left;
		window.right = window_right;
		window.top = window_top;
		window.bottom = window_bottom;

	}
	else
	{
		DefaultSetting();

	}
}

extern LPCWSTR ClassName,ClassNameAdmin;
static WCHAR mutex[]=L"ITH_RUNNING";
DWORD FindITH()
{
	HWND hwnd=FindWindow(ClassName, ClassName);
	
	if (hwnd == 0) hwnd=FindWindow(ClassName, ClassNameAdmin);
	if (hwnd)
	{
		ShowWindow(hwnd,SW_SHOWNORMAL);
		SetForegroundWindow(hwnd);
		return 0;
	}
	return 1;
}
HINSTANCE GetModuleBase()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x8]
	}
}
LONG WINAPI UnhandledExcept(_EXCEPTION_POINTERS *ExceptionInfo)
{
	WCHAR code[0x10],name[0x200];
	EXCEPTION_RECORD* rec = ExceptionInfo->ExceptionRecord;
	swprintf(code, L"%.8X",rec->ExceptionCode);
	MEMORY_BASIC_INFORMATION info;
	DWORD retn, addr;
	if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), rec->ExceptionAddress,
		MemoryBasicInformation,&info, sizeof(info), &retn)))
	{
		if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(), rec->ExceptionAddress, 
			MemorySectionName, name, 0x400, &retn)))
		{
			LPWSTR ptr = wcsrchr(name, L'\\');
			if (ptr)
			{
				addr = (DWORD)rec->ExceptionAddress;
				swprintf(ptr - 8, L"%.8X", addr - (DWORD)info.AllocationBase);
				*ptr = L':';
				MessageBox(0, ptr - 8, code, 0);
				NtTerminateProcess(NtCurrentProcess(), 0);
			}
		}
	}
	swprintf(name, L"%.8X",ExceptionInfo->ExceptionRecord->ExceptionAddress);
	MessageBox(0,name,code,0);
	NtTerminateProcess(NtCurrentProcess(), 0);
	return 0;
}
int main()
{
	if (!IthInitSystemService()) 
	{
		NtTerminateProcess(NtCurrentProcess(), 0);
	}
	IthCreateMutex(L"ITH_MAIN_RUNNING",TRUE);
	if (IHF_Init())
	{
		SetUnhandledExceptionFilter(UnhandledExcept);
		IHF_GetHookManager(&man);
		IHF_GetSettingManager(&setman);
		pfman = new ProfileManager;
		mb_filter = new CustomFilterMultiByte;
		uni_filter = new CustomFilterUnicode;

		LoadSettings();
		setman->SetValue(SETTING_SPLIT_TIME,split_time);

		setman->SetValue(SETTING_CLIPFLAG,clipboard_flag);
		hIns = GetModuleBase();
		MyRegisterClass(hIns);
		
		InitInstance(hIns,IHF_IsAdmin(),&window);
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		delete mb_filter;
		delete uni_filter;
		delete pfman;
		man = 0;

	}
	else
	{
		FindITH();
	}
	IHF_Cleanup();
	IthCloseSystemService();
	NtTerminateProcess(NtCurrentProcess(),0);
}
