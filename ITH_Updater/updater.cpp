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

#include <ITH\IHF_SYS.h>
#include <ITH\ITH_TLS.h>
#include <ITH\string.h>
#include <ITH\mem.h>
#include <ITH\tinyxml.h>
#include <windows.h>
#include "resource.h"
#include "ReserveVM.h"
#define MAX_HASH_SIZE 0x20
BYTE hex_table_inverse[0x80] = {
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	0, 1, 2, 3,  4, 5, 6, 7,  8, 9,-1,-1, -1,-1,-1,-1,
	-1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,10,11,12, 13,14,15,-1, -1,-1,-1,-1, -1,-1,-1,-1,
	-1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
};
DWORD StrToHexByte(const char* str)
{
	BYTE c0 = str[1], c1 = str[0];
	if ((c0 | c1) & 0x80) return -1;
	c0 = hex_table_inverse[c0];
	c1 = hex_table_inverse[c1];
	return (c1 << 4) | c0;
}
void ByteToHexStr(char* hex_str, unsigned char b)
{
	static const char hex_table[] = "0123456789ABCDEF";
	hex_str[1] = hex_table[b & 0xF];
	hex_str[0] = hex_table[b >> 4];
}
bool CheckHashStr(BYTE* value, DWORD size_in_bytes, const char* str)
{
	DWORD i;
	for (i = 0; i < size_in_bytes; i++)
	{
		DWORD t = StrToHexByte(str);
		if (t == -1) return false;
		if (value[i] != (t & 0xFF)) return false;
		str += 2;
	}
	if (*str) return false;
	return true;

}
bool CompareHashStr(const char* s1, const char* s2)
{
	DWORD c1, c2;
	while (*s1)
	{
		c1 = StrToHexByte(s1);
		c2 = StrToHexByte(s2);
		if ((c1 | c2) == -1) return false; //Either s1 or s2 contains odd chars or invalid chars.
		if (c1 != c2) return false;
		s1 += 2;
		s2 += 2;
	}
	return true;
}
int UTF16to8Len(const wchar_t* wc)
{
	wchar_t c;
	int len = 0;
	while (c = *wc++)
	{
		len++;
		if (c >> 7)
		{
			len++;
			if (c >> 11) len ++;
		}
	}
	return len;
}
int UTF16to8(const wchar_t* wc, char* mb)
{
	wchar_t c;
	char* start = mb;
	while (c = *wc++)
	{
		if (c >> 7)
		{
			if (c >> 11)
			{
				mb[2] = (c & 0x3F) | 0x80;
				c >>= 6;
				mb[1] = (c & 0x3F) | 0x80;
				c >>= 6;
				mb[0] = c | 0xE0;
				mb += 3;
			}
			else
			{
				mb[1] = (c & 0x3F) | 0x80;
				mb[0] = (c >> 6) | 0xC0;
				mb += 2;
			}
		}
		else
		{
			*mb++ = c & 0xFF;
		}
	}
	return mb - start;
}
int UTF8to16len(const char* mb)
{
	int len = 0;
	char c;
	while((c = *mb) != 0)
	{
		if (c & 0x80)
		{
			while (c & 0x80)
			{
				mb++;
				c <<= 1;
			}
		}
		else
		{
			mb++;
		}
		len++;
	}
	return len;
}
int UTF8to16(const char* mb, wchar_t* wc)
{
	__asm
	{
		mov esi, mb
		mov edi, wc
		push edi
_next_char:
		movzx eax, byte ptr[esi]
		test al,al
		jz _finish
		test al,0x80
		jnz _non_ascii
		stosw
		inc esi
		jmp _next_char
_non_ascii:
		test al,0x40
		jz _finish
		test al,0x20
		jz _utf11bit
		and al,0xF
		mov cl,[esi + 1]
		and cl,0x3F
		mov dl,[esi + 2]
		and dl,0x3F
		shl eax,6
		or al,cl
		shl eax,6
		or al,dl
		stosw
		add esi,3
		jmp _next_char
_utf11bit:
		and al,0x1F
		shl eax,6
		movzx ecx,[esi+1]
		and cl,0x3F
		or eax,ecx
		stosw
		add esi,2
		jmp _next_char
_finish:
		pop eax
		sub edi,eax
		mov eax,edi
		shr eax,1
	}
}
HINSTANCE GetModuleBase()
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0x8]
	}
}
DLGPROC proc;
HWND hConsole, hCmd;
CRITICAL_SECTION console_cs;
bool secure_sock, connected, verbose;
TransportSocket* sock;

void PrintConsole(LPWSTR str)
{
	EnterCriticalSection(&console_cs);
	DWORD t;
	t=SendMessage(hConsole,WM_GETTEXTLENGTH,0,0);
	SendMessage(hConsole,EM_SETSEL,t,-1);
	SendMessage(hConsole,EM_REPLACESEL,FALSE,(LPARAM)str);
	LeaveCriticalSection(&console_cs);
}
void PrintConsole(char* str)
{
	EnterCriticalSection(&console_cs);
	DWORD t;
	t=SendMessage(hConsole,WM_GETTEXTLENGTH,0,0);
	SendMessage(hConsole,EM_SETSEL,t,-1);
	SendMessageA(hConsole,EM_REPLACESEL,FALSE,(LPARAM)str);
	LeaveCriticalSection(&console_cs);
}
void PrintConsoleNewLine()
{
	EnterCriticalSection(&console_cs);
	DWORD t;
	t=SendMessage(hConsole,WM_GETTEXTLENGTH,0,0);
	SendMessage(hConsole,EM_SETSEL,t,-1);
	SendMessage(hConsole,EM_REPLACESEL,FALSE,(LPARAM)L"\r\n");
	LeaveCriticalSection(&console_cs);
}
void PrintConsoleSucceeded()
{
	PrintConsole("Succeeded.\r\n");
}
void PrintConsoleFailed()
{
	PrintConsole("Failed.\r\n");
}
DWORD EncodePercentLen(char* toEncode)
{
	int len = strlen(toEncode);
	int i, sum;
	for (i = 0, sum = 0; i < len; i++)
	{
		sum++;
		if (toEncode[i] & 0x80) sum += 2;
	}
	return sum;
}
DWORD EncodePercent(const char* toEncode, int len, char* out)
{
	char* start = out;
	int i;
	static const char hex_str_table[] = "0123456789ABCDEF";
	for (i = 0; i < len; i++)
	{
		unsigned char c = toEncode[i]; //c must be unsigned, otherwise >> will be translated into SAR
		if (c & 0x80)
		{
			*out++ = '%';
			*out++ = hex_str_table[c >> 4];
			*out++ = hex_str_table[c & 0xF];
		}
		else *out++ = c;
	}
	return out - start;
}
DWORD SyncFile(HANDLE hFile, char* link)
{
	int len = strlen(link), i, j, k;
	if (len > 0x380) return -1;
	link[len] = '/';
	char *ptr, *end;
	char buffer[0x400];
	for (ptr = link; *ptr != '/'; ptr++);
	link[len] = 0;
	if (ptr - link != len) *ptr++ = 0;
	static const char format[] = 
		"GET /%s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: keep-alive\r\n"
		"User-Agent: ITH 3.0\r\n"
		"\r\n";
	len = sprintf(buffer, format, ptr, link);

	if (!connected)
	{
		PrintConsole("Connecting to ");
		PrintConsole(link);
		PrintConsole("...\r\n");
		int port = 0;
		char c = link[0], *p;
		link[0] = ':';
		for (p = ptr; *p != ':'; p--);
		link[0] = c;
		if (p != link) sscanf(p + 1, "%d", &port);
		if (sock->connect(link, port) < 0)
		{
			PrintConsole("Failed to connect.\r\n");
			return -1;
		}
		connected = 1;
	}
	ptr--;
	if (*ptr == 0) *ptr = '/';
	if (verbose) PrintConsole(buffer);
	if (len != sock->send(buffer, len))
	{
		PrintConsole("Failed to send.\r\n");
		return -1;
	}
	for (i = 0, j = 0; j < 4; i++)
	{
		if (i >= 0x400) return -1;
		if (1 != sock->recv(buffer + i, 1))
		{
			PrintConsole("Failed to recv.\r\n");
			return -1;
		}
		switch (j)
		{
		case 0:
			if (buffer[i] == '\r') j++;
			break;
		case 1:
			if (buffer[i] == '\n') j++;
			else j = 0;
			break;
		case 2:
			if (buffer[i] == '\r') j++;
			else j = 0;
			break;
		case 3:
			if (buffer[i] == '\n') j++;
			else j = 0;
			break;
		default:break;
		}
	}
	buffer[i] = 0;
	if (verbose) PrintConsole(buffer);
	static const char HTTP_1_1[] = "HTTP/1.1";
	if (memcmp(buffer, HTTP_1_1, 8) != 0) return -1;
	int code;
	if (1 != sscanf(buffer + 9, "%d", &code)) return -1;
	if (code == 304) return 0;
	if (code != 200) return -1;
	static const char HTTP_CONTENT_LENGTH[] = "Content-Length: ";
	ptr = strstr(buffer, HTTP_CONTENT_LENGTH);
	if (ptr == 0) return -1;
	ptr += sizeof(HTTP_CONTENT_LENGTH) - 1;
	for (end = ptr; *end != '\r'; end++);
	*end = 0;
	if (end - ptr > 8) return -1;
	if (1 != sscanf(ptr, "%d", &len)) return -1;
	IthReservedVirtualMemory mem;
	j = 0;
	k = len;
	IO_STATUS_BLOCK ios;
	while (len > 0)
	{
		i = len < 0x400 ? len : 0x400;
		i = sock->recv(buffer, i);
		if (i <= 0) return -1;
		if (mem.WriteBytes(buffer, i, j) == -1)
		{
			NtWriteFile(hFile, 0,0,0, &ios, mem.Memory(), j, 0, 0);
			j = 0;
			if (mem.WriteBytes(buffer, i, j) < 0) return -1;
		}
		len -= i;
		j += i;
	}
	
	LARGE_INTEGER file_end;
	file_end.HighPart = 0;
	file_end.LowPart = k;
	NtWriteFile(hFile, 0,0,0, &ios, mem.Memory(), j, 0, 0);
	NtSetInformationFile(hFile, &ios, &file_end, sizeof(file_end), FileEndOfFileInformation);
	return j;
}
DWORD SyncFile(LPWSTR file, HANDLE hDir, char* base_link, bool forceUpdate)
{
	HANDLE hFile = IthCreateFileInDirectory(file, hDir, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, FILE_OPEN_IF);	
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBox(0,L"Failed to create file.",file,0);
		return -1;
	}
	char *url, *ptr, *file_utf8;
	int base_len, file_len;
	base_len = strlen(base_link);
	file_len = UTF16to8Len(file);
	url = new char[base_len + file_len * 3 + 2];
	file_utf8 = new char[file_len];
	UTF16to8(file, file_utf8); //No \0 marker.
	memcpy(url, base_link, base_len);
	if (url[base_len - 1] != '/') url[base_len++] = '/';
	ptr = url + base_len;
	ptr[EncodePercent(file_utf8, file_len, ptr)] = 0;
	DWORD result = SyncFile(hFile, url);
	if (result == -1)
	if (secure_sock)
	{
		if (IDYES == MessageBox(0,L"Try plain http instead?",L"SSL connection failed",MB_YESNO))
		{
			connected = false;
			ITH_TLS_DestroySocket(sock);
			sock = ITH_TLS_NewSocket(false);
			sock->socket();
			result = SyncFile(hFile, url);
		}
	}
	NtClose(hFile);
	delete url;
	delete file_utf8;
	return result;
}
DWORD CheckBigFileHashValue(HANDLE hFile, const char* hash, DWORD size) //smaller than 4G = 2^32
{
	LPVOID buffer = 0;
	DWORD allocate_size = DEFAULT_RESERVE_SIZE;
	HashCalculator* sha256 = ITH_TLS_NewHashCalculator(HashTypeSHA256);
	IO_STATUS_BLOCK ios;
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &allocate_size, MEM_COMMIT, PAGE_READWRITE);
	while (size > DEFAULT_RESERVE_SIZE)
	{
		NtReadFile(hFile, 0,0,0, &ios, buffer, DEFAULT_RESERVE_SIZE, 0,0);
		sha256->HashUpdate(buffer, DEFAULT_RESERVE_SIZE);
		size -= DEFAULT_RESERVE_SIZE;
	}
	if (size)
	{
		NtReadFile(hFile, 0,0,0, &ios, buffer, size, 0,0);
		sha256->HashUpdate(buffer, size);
	}
	BYTE value[0x20];
	sha256->HashFinal(value);
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &allocate_size, MEM_RELEASE);
	ITH_TLS_DestroyHashCalculator(sha256);
	return CheckHashStr(value, 0x20, hash);;
}
DWORD CheckFileHashValue(HANDLE hFile, const char* hash)
{
	FILE_STANDARD_INFORMATION info;
	IO_STATUS_BLOCK ios;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	if (info.AllocationSize.LowPart > DEFAULT_RESERVE_SIZE)
	{
		return CheckBigFileHashValue(hFile, hash, info.EndOfFile.LowPart);
	}
	LPVOID buffer = 0;
	HashCalculator* sha256 = ITH_TLS_NewHashCalculator(HashTypeSHA256);
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, 
		&info.AllocationSize.LowPart, MEM_COMMIT, PAGE_READWRITE);
	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0,0);
	sha256->HashUpdate(buffer, info.EndOfFile.LowPart);
	BYTE value[0x20];
	sha256->HashFinal(value);
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
	ITH_TLS_DestroyHashCalculator(sha256);
	return CheckHashStr(value, 0x20, hash);
}
DWORD SyncFolderFiles(TiXmlElement* files, HANDLE hDir, char* base_link)
{
	TiXmlElement* file;
	
	for (file = files->FirstChildElement(); file; file = file->NextSiblingElement())
	{
		if (strcmp(file->Value(),"File") != 0) continue;
		const char* name = file->Attribute("Name");
		const char* hash = file->Attribute("SHA256");
		if (name == 0 || hash == 0) continue;
		int len = UTF8to16len(name);
		LPWSTR str = new WCHAR[len + 1];
		UTF8to16(name, str);
		str[len] = 0;
		
		HANDLE hFile = IthCreateFileInDirectory(str, hDir, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			PrintConsole("Getting file ");
			PrintConsole(str);
			PrintConsoleNewLine();
			if (-1 != SyncFile(str, hDir, base_link, false))
			{
				PrintConsoleSucceeded();
				hFile = IthCreateFileInDirectory(str, hDir, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
				if (CheckFileHashValue(hFile, hash))
					PrintConsole(L"Hash check passed.\r\n");
				NtClose(hFile);
			}
			else PrintConsoleFailed();
		}
		else
		{
			PrintConsole(str);
			PrintConsole(" found.\r\n");
			DWORD result = CheckFileHashValue(hFile, hash);
			NtClose(hFile);
			if (result)
				PrintConsole(L"Hash check passed.\r\n");
			else 
			{
				PrintConsole(L"Hash check failed. Updating...\r\n");
				if (-1 != SyncFile(str, hDir, base_link, true))
				{
					PrintConsoleSucceeded();
					hFile = IthCreateFileInDirectory(str, hDir, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
					if (CheckFileHashValue(hFile, hash))
						PrintConsole(L"Hash check passed.\r\n");
					NtClose(hFile);
				}
				else PrintConsoleFailed();
			}
		}
		delete str;
	}
	
	return 0;
}
DWORD SyncFolder(LPWSTR path, char* base_link)
{
	DWORD result = -1;
	HANDLE hDir = IthCreateDirectory(path);
	if (hDir == INVALID_HANDLE_VALUE) return -1;
	SyncFile(L"index.xml", hDir, base_link, true);
	HANDLE hFile = IthCreateFileInDirectory(L"index.xml", hDir, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		NtClose(hDir);
		return -1;
	}
	FILE_STANDARD_INFORMATION info;
	IO_STATUS_BLOCK ios;
	LPVOID buffer = 0;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, 
		&info.AllocationSize.LowPart, MEM_COMMIT, PAGE_READWRITE);
	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
	NtClose(hFile);
	TiXmlDocument doc;
	doc.Parse((char*)buffer);
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
	if (!doc.Error())
	{
		TiXmlElement* root = doc.RootElement(), *node;
		if (root && strcmp(root->Value(),"ITH_Manifest") == 0)
		{

			node = root->FirstChildElement("Files");
			if (node) result = SyncFolderFiles(node, hDir, base_link);
			node = root->FirstChildElement("Folders");
			if (node)
			{
				for (node = node->FirstChildElement(); node; node = node->NextSiblingElement())
				{
					if (strcmp(node->Value(),"Folder") != 0) continue;
					const char* sub_path = node->Attribute("Name");
					if (sub_path == 0) continue;
					int path_len = wcslen(path);
					int sub_len = UTF8to16len(sub_path); 
					LPWSTR new_path = new WCHAR[path_len + sub_len + 2]; //One for '\', one for '\0'
					memcpy(new_path, path, path_len << 1);
					if (path_len && new_path[path_len - 1] != '\\')
						new_path[path_len++] = '\\';
					UTF8to16(sub_path, new_path + path_len);
					new_path[path_len + sub_len] = 0;

					path_len = strlen(base_link);
					sub_len = strlen(sub_path);
					char* new_base_link = new char[path_len + sub_len * 3 + 2];
					char* ptr;
					memcpy(new_base_link, base_link, path_len);
					if (new_base_link[path_len - 1] != '/')
						new_base_link[path_len++] = '/';
					ptr = new_base_link + path_len;
					ptr[EncodePercent(sub_path, sub_len, ptr)] = 0;

					SyncFolder(new_path, new_base_link);

					delete new_path;
					delete new_base_link;
				}
			}
		}
	}
	NtClose(hDir);
	return result;
}
HANDLE hSyncThread;
volatile long syncFlag;
static const DWORD HTTP_STR = 0x70747468;
DWORD SyncProfileThread()
{
	verbose = true;
	char* base_link, *ptr;
	HANDLE hDir = IthCreateDirectory(L"Profile");
	if (hDir == INVALID_HANDLE_VALUE) return -1;
	int len = GetWindowTextLengthA(hCmd);
	if (len <= 0) return -1;
	base_link = new char[len + 10];
	GetWindowTextA(hCmd, base_link, len + 1);
	if (base_link[len - 1] != '/') base_link[len++] = '/';
	memcpy(base_link + len, "Profile", 8);
	base_link[len + 9] = 0;
	if (memcmp(base_link, &HTTP_STR, 4) == 0)
	{
		secure_sock = false;
		ptr = base_link + 4;
		if (*ptr == 's')
		{
			secure_sock = true;
			ptr++;
		}
		if (ptr[0] == ':' &&
			ptr[1] == '/' &&
			ptr[2] == '/')
		{
			ptr += 3;
			connected = false;
			sock = ITH_TLS_NewSocket(secure_sock);
			if (sock->socket() >= 0)
			{
				SyncFolder(L"Profile",ptr);
			}
			ITH_TLS_DestroySocket(sock);
			sock = 0;
		}
		
	}
	NtClose(hDir);
	delete base_link;
	syncFlag = 0;
	return 0;
}
DWORD SyncProfile()
{
	long flag = _InterlockedExchange(&syncFlag,1);
	if (flag) return 0;
	HANDLE h = IthCreateThread(SyncProfileThread,0);
	if (h != INVALID_HANDLE_VALUE) NtClose(h);
	return 0;
}
DWORD SyncAllThread()
{
	verbose = true;
	char* base_link, *ptr;
	int len = GetWindowTextLengthA(hCmd);
	if (len <= 0) return -1;
	base_link = new char[len + 1];
	GetWindowTextA(hCmd, base_link, len + 1);
	base_link[len] = 0;

	if (memcmp(base_link, &HTTP_STR, 4) == 0)
	{
		secure_sock = false;
		ptr = base_link + 4;
		if (*ptr == 's')
		{
			secure_sock = true;
			ptr++;
		}
		if (ptr[0] == ':' &&
			ptr[1] == '/' &&
			ptr[2] == '/')
		{
			ptr += 3;
			connected = false;
			sock = ITH_TLS_NewSocket(secure_sock);
			if (sock->socket() >= 0)
			{
				SyncFolder(L"",ptr);
			}
			ITH_TLS_DestroySocket(sock);
			sock = 0;
		}

	}
	delete base_link;
	syncFlag = 0;
	return 0;
}
DWORD SyncAll()
{
	long flag = _InterlockedExchange(&syncFlag,1);
	if (flag) return 0;
	HANDLE h = IthCreateThread(SyncAllThread,0);
	if (h != INVALID_HANDLE_VALUE) NtClose(h);
	return 0;
}
LRESULT CALLBACK EditProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CHAR:  //Filter user input.
		return 0;
	default:
		{
			return proc(hWnd, message, wParam, lParam);	
		}

	}

}
static const WCHAR init_msg[] = L"Interactive Text Hooker Updater\r\n";
static const WCHAR default_link[] = L"https://interactive-text-hooker.googlecode.com/svn/project/ITH3/Release/";
//static const WCHAR default_link[] = L"https://127.0.0.1/Release/";
BOOL CALLBACK UpdateDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			SetWindowPos(hDlg, HWND_TOP, 200,200,0,0,SWP_NOSIZE);
			InitializeCriticalSection(&console_cs);

			hConsole = GetDlgItem(hDlg, IDC_EDIT1);
			hCmd = GetDlgItem(hDlg, IDC_EDIT2);
			proc = (DLGPROC)SetWindowLongPtr(hConsole,GWLP_WNDPROC, (LONG)EditProc);
			SendMessage(hConsole, WM_SETTEXT, 0, (LPARAM)init_msg);
			SendMessage(hCmd, WM_SETTEXT, 0, (LPARAM)default_link);
			return TRUE;
		}
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case WM_DESTROY:
			case IDOK:
				EndDialog(hDlg, 0);
				DeleteCriticalSection(&console_cs);
				break;
			case IDC_BUTTON1:
				SendMessage(hConsole, WM_SETTEXT, 0, (LPARAM)L"");
				break;
			case IDC_BUTTON2:
				SyncProfile();
				break;
			case IDC_BUTTON3:
				SyncAll();
				break;
			}
		}
		return TRUE;
	default:
		return FALSE;
	}
}
static WCHAR mutex[]=L"ITH_RUNNING";
int main()
{
	IthInitSystemService();
	DWORD exist;
	IthCreateMutex(mutex, 0, &exist);
	if (exist == 0)
	{
		ITH_TLS_Init();
		DialogBoxParam(GetModuleBase(), (LPWSTR)IDD_DIALOG1, 0, UpdateDlgProc, 0);
		ITH_TLS_Cleanup();
	}
	else MessageBox(0, L"Please close ITH and all attached games first.", L"ITH is running", MB_OK);
	IthCloseSystemService();
	NtTerminateProcess(NtCurrentProcess(), 0);
	return 0;
}
