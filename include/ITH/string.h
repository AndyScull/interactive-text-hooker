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
#define _INC_SWPRINTF_INL_
#define CRT_IMPORT __declspec(dllimport)
extern "C" {
CRT_IMPORT int swprintf(wchar_t * _String, const wchar_t * _Format, ...);
CRT_IMPORT int sprintf(char * _String, const char * _Format, ...);
CRT_IMPORT int swscanf(const wchar_t * _Src,  const wchar_t * _Format, ...);
CRT_IMPORT int sscanf(const char * _String, const char * _Format, ...);
CRT_IMPORT int wprintf(const wchar_t* _Format, ...);
CRT_IMPORT int printf(const char* _Format, ...);
CRT_IMPORT int _wputs(const wchar_t* _String);
CRT_IMPORT int puts(const char* _String);
CRT_IMPORT int _stricmp(const char * _Str1, const char * _Str2);
CRT_IMPORT int _wcsicmp(const wchar_t * _Str1, const wchar_t * _Str2);
//CRT_IMPORT size_t strlen(const char *);
//CRT_IMPORT size_t wcslen(const wchar_t *);
//CRT_IMPORT char *strcpy(char *,const char *);
//CRT_IMPORT wchar_t *wcscpy(wchar_t *,const wchar_t *);
CRT_IMPORT void * memmove(void * _Dst, const void * _Src, size_t _Size);
CRT_IMPORT const char * strchr(const char * _Str, int _Val);
CRT_IMPORT int strncmp(const char * _Str1, const char * _Str2, size_t _MaxCount);
}
