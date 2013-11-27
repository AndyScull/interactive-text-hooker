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
#include <ITH\HookManager.h>
#define IHFAPI __stdcall
#ifdef IHF
	#define IHFSERVICE __declspec(dllexport)
#else
	#define IHFSERVICE __declspec(dllimport)
#endif
#define ITH_DEFAULT_ENGINE 0

extern "C" {
	IHFSERVICE DWORD IHFAPI IHF_Init();
	IHFSERVICE DWORD IHFAPI IHF_Start();
	IHFSERVICE DWORD IHFAPI IHF_Cleanup();
	IHFSERVICE DWORD IHFAPI IHF_GetPIDByName(LPWSTR pwcTarget);
	IHFSERVICE DWORD IHFAPI IHF_InjectByPID(DWORD pid, LPWSTR engine);
	IHFSERVICE DWORD IHFAPI IHF_ActiveDetachProcess(DWORD pid);
	IHFSERVICE DWORD IHFAPI IHF_GetHookManager(HookManager** hookman);
	IHFSERVICE DWORD IHFAPI IHF_GetSettingManager(SettingManager** set_man);
	IHFSERVICE DWORD IHFAPI IHF_InsertHook(DWORD pid, HookParam* hp, LPWSTR name = 0);
	IHFSERVICE DWORD IHFAPI IHF_ModifyHook(DWORD pid, HookParam* hp);
	IHFSERVICE DWORD IHFAPI IHF_RemoveHook(DWORD pid, DWORD addr);
	IHFSERVICE DWORD IHFAPI IHF_IsAdmin();
	//IHFSERVICE DWORD IHFAPI IHF_GetFilters(PVOID* mb_filter, PVOID* uni_filter);
	IHFSERVICE DWORD IHFAPI IHF_AddLink(DWORD from, DWORD to);
	IHFSERVICE DWORD IHFAPI IHF_UnLink(DWORD from);
	IHFSERVICE DWORD IHFAPI IHF_UnLinkAll(DWORD from);
}