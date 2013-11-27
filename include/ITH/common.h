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
#include <windows.h>
#include <ITH\string.h>
#include <ITH\mem.h>

#define IHF_COMMAND -1
#define IHF_COMMAND_NEW_HOOK 0
#define IHF_COMMAND_REMOVE_HOOK 1
#define IHF_COMMAND_MODIFY_HOOK 2
#define IHF_COMMAND_DETACH 3
#define IHF_NOTIFICATION -1
#define IHF_NOTIFICATION_TEXT 0
#define IHF_NOTIFICATION_NEWHOOK 1

#define USING_STRING			0x1
#define USING_UNICODE		0x2
#define BIG_ENDIAN			0x4
#define DATA_INDIRECT		0x8
#define USING_SPLIT			0x10
#define SPLIT_INDIRECT		0x20
#define MODULE_OFFSET		0x40
#define FUNCTION_OFFSET	0x80
#define PRINT_DWORD		0x100
#define STRING_LAST_CHAR 0x200
#define NO_CONTEXT			0x400
#define EXTERN_HOOK		0x800
#define HOOK_AUXILIARY 0x2000
#define HOOK_ENGINE 0x4000
#define HOOK_ADDITIONAL 0x8000

#define MAX_HOOK 32



struct HookParam //0x24
{
	typedef void (*DataFun)(DWORD, HookParam*, DWORD*, DWORD*, DWORD*);

	DWORD addr;
	DWORD off,ind,split,split_ind;
	DWORD module,function;
	DataFun extern_fun;
	DWORD type;
	WORD length_offset;
	BYTE hook_len,recover_len;
};
struct SendParam
{
	DWORD type;
	HookParam hp;
};
class Hook //0x80
{
public:
	inline DWORD Address() const {return hp.addr;}
	inline DWORD Type() const {return hp.type;}
	inline WORD Length() const {return hp.hook_len;}
	inline LPWSTR Name() const {return hook_name;}
	inline int NameLength() const {return name_length;}
//protected:
	HookParam hp;
	LPWSTR hook_name;
	int name_length;
	BYTE recover[0x68-sizeof(HookParam)];
	BYTE original[0x10];
};
