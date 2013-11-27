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
//#include <windows.h>
#define IHF
#include <ITH\IHF_DLL.h>
#include <ITH\IHF_SYS.h>

#define HEADER_SIZE 0xC
extern int current_hook;
extern WCHAR dll_mutex[];
extern WCHAR dll_name[];
extern DWORD trigger;
//extern DWORD current_process_id;
template <class T,class D, class fComp, class fCopy, class fLength> class AVLTree;
struct FunctionInfo
{
	DWORD addr;
	DWORD module;
	DWORD size;
	LPWSTR name;
};
class SCMP;
class SCPY;
class SLEN;
extern AVLTree<char, FunctionInfo, SCMP, SCPY, SLEN> *tree;
void InitFilterTable();

int disasm(BYTE* opcode0);
class TextHook : public Hook
{
public:
	int InsertHook();
	int InsertHookCode();
	int InitHook(const HookParam&, LPWSTR name=0, WORD set_flag=0);
	int InitHook(LPVOID addr, DWORD data, DWORD data_ind, 
		DWORD split_off, DWORD split_ind, WORD type, DWORD len_off=0);
	DWORD Send(DWORD dwDataBase, DWORD dwRetn);
	int RecoverHook();
	int RemoveHook();
	int ClearHook();
	int ModifyHook(const HookParam&);
	int SetHookName(LPWSTR name);
	int GetLength(DWORD base, DWORD in);
};

extern TextHook *hookman,*current_available;
void InitDefaultHook();
struct FilterRange
{
	DWORD lower,upper;
};
extern FilterRange filter[8];
int FillRange(LPWSTR name,DWORD* lower, DWORD* upper);
extern bool running,live;
extern HANDLE hPipe,hmMutex;
DWORD WINAPI WaitForPipe(LPVOID lpThreadParameter);
DWORD WINAPI CommandPipe(LPVOID lpThreadParameter);
void RequestRefreshProfile();
typedef DWORD (*IdentifyEngineFun)();
typedef DWORD (*InsertHookFun)(DWORD);
typedef DWORD (*InsertDynamicHookFun)(LPVOID addr, DWORD frame, DWORD stack);
extern IdentifyEngineFun IdentifyEngine; 
extern InsertDynamicHookFun InsertDynamicHook;