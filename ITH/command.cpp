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
#include "ITH.h"
#include "language.h"
#include <windows.h>
void ConsoleOutput(LPCWSTR text)
{

}
int Convert(LPWSTR str, DWORD *num, LPWSTR delim)
{
	if (num == 0) return -1;
	WCHAR t = *str,tc = *(str+0xF);
	WCHAR temp[0x10]={};
	LPWSTR it = temp,istr = str,id = temp;
	if (delim) 
	{
		id=wcschr(delim, t);
		str[0xF] = delim[0];
	}
	else str[0xF] = 0;
	while (id == 0 && t)
	{
		*it = t;
		it++; istr++;
		t = *istr;
		if (delim) id = wcschr(delim, t);
	}
	swscanf(temp, L"%x", num);
	str[0xF] = tc;
	if (id == 0 || istr - str == 0xF) return -1;
	if (t == 0) return istr - str;
	else return id - delim;
}
bool Parse(LPWSTR cmd, HookParam& hp)
{
	int t;
	bool accept = false;
	memset(&hp, 0, sizeof(hp));
	DWORD *data = &hp.off;
	LPWSTR offset = cmd + 1;
	LPWSTR delim_str = L":*@!";
	LPWSTR delim = delim_str;
	if (*offset == L'n' || *offset == 'N') 
	{
		offset++;
		hp.type |= NO_CONTEXT;
	}
	while (!accept)
	{
		t = Convert(offset, data, delim);
		if (t < 0) 
		{
_error:
			//ConsoleOutput(L"Syntax error.");
			return false;
		}
		offset = wcschr(offset , delim[t]);
		if (offset) offset++;
		else goto _error;
		switch (delim[t])
		{
		case L':':
			data = &hp.split;
			delim = delim_str+1;
			hp.type |= USING_SPLIT;
			break;
		case L'*':
			if (hp.split) 
			{
				data = &hp.split_ind;
				delim = delim_str+2;
				hp.type |= SPLIT_INDIRECT;
			}
			else 
			{
				hp.type |= DATA_INDIRECT;
				data = &hp.ind;
			}
			break;
		case L'@':
			accept = true;
			break;
		}
	}
	t = Convert(offset, &hp.addr, delim_str);
	if (t < 0) return false;
	if (hp.off & 0x80000000) hp.off -= 4;
	if (hp.split & 0x80000000) hp.split -= 4;
	LPWSTR temp = offset;
	offset = wcschr(offset, L':');
	if (offset)
	{
		hp.type |= MODULE_OFFSET;
		offset++;
		delim = wcschr(offset, L':');
		
		if (delim)
		{
			*delim = 0;
			delim++;
			_wcslwr(offset);
			hp.function = Hash(delim);
			hp.module = Hash(offset, delim - offset - 1);
			hp.type |= FUNCTION_OFFSET;
		}			
		else
		{		
			hp.module = Hash(_wcslwr(offset));
		}
	}
	else
	{
		offset = wcschr(temp, L'!');
		if (offset)
		{
			hp.type |= MODULE_OFFSET;
			swscanf(offset + 1, L"%x", &hp.module);
			offset = wcschr(offset + 1, L'!');
			if (offset)
			{
				hp.type |= FUNCTION_OFFSET;
				swscanf(offset + 1, L"%x", &hp.function);
			}
		}
	}
	switch (*cmd)
	{
	case L's':
	case L'S':
		hp.type |= USING_STRING;
		break;
	case L'e':
	case L'E':
		hp.type |= STRING_LAST_CHAR;
	case L'a':
	case L'A':
		hp.type |= BIG_ENDIAN;
		hp.length_offset = 1;
		break;
	case L'b':
	case L'B':
		hp.length_offset = 1;
		break;
	case L'h':
	case L'H':
		hp.type |= PRINT_DWORD;
	case L'q':
	case L'Q':
		hp.type |= USING_STRING | USING_UNICODE;
		break;
	case L'l':
	case L'L':
		hp.type |= STRING_LAST_CHAR;
	case L'w':
	case L'W':
		hp.type |= USING_UNICODE;
		hp.length_offset = 1;
		break;
	default:
		break;
	}
	//ConsoleOutput(L"Try to insert additional hook.");
	return true;
}
//void AddLink(WORD from, WORD to);

DWORD ProcessCommand(LPWSTR cmd, DWORD pid)
{
	int t;
	LPWSTR ts = wcsrchr(cmd, L':');
	if (ts) *ts = 0;
	_wcslwr(cmd);
	if (ts) *ts = L':'; //Prevent modification to function names, as they are case sensitive.

	switch (cmd[0])
	{
	case L'/':
		switch (cmd[1])
		{

		case L'p':
			{			
				if (cmd[2] == L'n') 
				{
					pid = IHF_GetPIDByName(cmd + 3);
					if (pid == 0) break;
				}
				else
					swscanf(cmd + 2, L"%d", &pid);
				t = IHF_InjectByPID(pid, ITH_DEFAULT_ENGINE);
			}
			break;
		case L'h':
			{
				HookParam hp;
				if (Parse(cmd + 2, hp)) IHF_InsertHook(pid ,&hp);
			}
			break;
		default:
			break;
			//ConsoleOutput(ErrorSyntax);
		}
		break;
	case L'l':
		{
			DWORD from, to;
			swscanf(cmd+1, L"%x-%x", &from, &to);
			IHF_AddLink(from, to);
		}
		break;
	case L'u':
		{
			DWORD from;
			if (cmd[1] == L'a')
			{
				if (swscanf(cmd + 2, L"%x",&from) == 1)
					IHF_UnLinkAll(from);
			}
			else
			{
				if (swscanf(cmd + 1, L"%x",&from) == 1)
					IHF_UnLink(from);
			}
		}

		break;
	default:
		break;
	}
	return 0;
}
