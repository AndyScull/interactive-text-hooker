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
#include <ITH\common.h>
#include <ITH\ntdll.h>
#include <ITH\IHF_SYS.h>
#include "language.h"

#define GLOBAL extern
#define SHIFT_JIS 0x3A4
class HookManager;
//class CommandQueue;
class SettingManager;
class TextHook;
class BitMap;
class CustomFilterMultiByte;
class CustomFilterUnicode;
#define TextHook Hook
GLOBAL BOOL running;
//GLOBAL BitMap *pid_map;
GLOBAL CustomFilterMultiByte *mb_filter;
GLOBAL CustomFilterUnicode *uni_filter;
GLOBAL HookManager *man;
//GLOBAL CommandQueue *cmdq;
GLOBAL SettingManager* setman;
GLOBAL WCHAR recv_pipe[];
GLOBAL WCHAR command[];
GLOBAL HANDLE hPipeExist;
GLOBAL DWORD split_time,cyclic_remove,clipboard_flag,global_filter;
GLOBAL CRITICAL_SECTION detach_cs;

DWORD WINAPI RecvThread(LPVOID lpThreadParameter);
DWORD WINAPI CmdThread(LPVOID lpThreadParameter);

void ConsoleOutput(LPCWSTR text);
DWORD	GetCurrentPID();
DWORD	GetProcessIDByPath(LPWSTR str);
HANDLE	GetCmdHandleByPID(DWORD pid);
DWORD	Inject(HANDLE hProc);
DWORD	InjectByPID(DWORD pid);
DWORD	PIDByName(LPWSTR target);
DWORD	Hash(LPWSTR module, int length=-1);
