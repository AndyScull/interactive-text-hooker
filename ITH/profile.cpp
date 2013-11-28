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


#include "ITH.h"
#include <ITH\IHF.h>
#include <ITH\IHF_SYS.h>
#include <ITH\Hash.h>
#include <ITH\ntdll.h>
#include "profile.h"
extern bool Parse(LPWSTR cmd, HookParam& hp);

bool MonitorFlag;

ProfileManager* pfman;
HookNameManager* hnman;
extern HookManager* man;
extern HWND hMainWnd;
extern DWORD auto_inject, auto_insert,inject_delay;
static WCHAR process_path[MAX_PATH];

LPWSTR EngineHookName[]=
{
	L"Unknown",  //0
	L"KiriKiri1",  //1
	L"BGI",  //2
	L"Reallive",  //3
	L"MAJIRO",  //4
	L"CMVS",  //5
	L"rUGP",  //6
	L"Lucifen",  //7
	L"System40",  //8
	L"AtelierKaguya",  //9
	L"CIRCUS",  //10
	L"ShinaRio",  //11
	L"MBL",  //12
	L"TinkerBell",  //13
	L"YU-RIS",  //14
	L"Cotopha",  //15
	L"Malie",  //16
	L"SofthouseChara",  //17
	L"CatSystem2",  //18
	L"IronGameSystem",  //19
	L"Waffle",  //20
	L"NitroPlus",  //21
	L"DotNet1",  //22
	L"RetouchSystem",  //23
	L"SiglusEngine",  //24
	L"AbelSoftware",  //25
	L"Live",  //26
	L"QLIE",  //27
	L"Bruns",  //28
	L"SystemC",  //29
	L"ApRicot",  //30
	L"CaramelBox"  //31
};
LPWSTR HookNameInitTable[]={
	L"ConsoleOutput",
	L"GetTextExtentPoint32A",
	L"GetGlyphOutlineA",
	L"ExtTextOutA",
	L"TextOutA",
	L"GetCharABCWidthsA",
	L"DrawTextA",
	L"DrawTextExA",
	L"GetTextExtentPoint32W",
	L"GetGlyphOutlineW",
	L"ExtTextOutW",
	L"TextOutW",
	L"GetCharABCWidthsW",
	L"DrawTextW",
	L"DrawTextExW"
};
extern const DWORD EngineHookNameSize = sizeof(EngineHookName) / sizeof (LPWSTR);



bool CheckFileHash(TiXmlElement* hash, LPWSTR path)
{
	MD5Calc *md5 = 0;
	SHA1Calc *sha1 = 0;
	SHA256Calc *sha256 = 0;
	WCHAR nt_path[MAX_PATH];
	DWORD len = wcslen(path);
	if (len >= MAX_PATH - 4) return false;
	nt_path[0] = nt_path[3] = L'\\';
	nt_path[1] = nt_path[2] = L'?';
	wcscpy(nt_path + 4, path);
	HANDLE hFile = IthCreateFileFullPath(nt_path, FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE) return true;

	bool flag = true;

	if (hash->Attribute("MD5")) md5 = new MD5Calc;
	if (hash->Attribute("SHA1")) sha1 = new SHA1Calc;
	if (hash->Attribute("SHA256")) sha256 = new SHA256Calc;

	if (md5 || sha1 || sha256)
	{
		FILE_STANDARD_INFORMATION info;
		IO_STATUS_BLOCK ios;
		NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
		PVOID buffer = 0;
		DWORD size = 0x100000;
		NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &size, MEM_COMMIT, PAGE_READWRITE);
		while (info.EndOfFile.QuadPart > size)
		{
			NtReadFile(hFile, 0,0,0, &ios, buffer, size, 0, 0);
			info.EndOfFile.QuadPart -= size;
			if (md5) md5->HashUpdate(buffer, size);
			if (sha1) sha1->HashUpdate(buffer, size);
			if (sha256) sha256->HashUpdate(buffer, size);
		}
		NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
		if (md5) md5->HashUpdate(buffer, info.EndOfFile.LowPart);
		if (sha1) sha1->HashUpdate(buffer, info.EndOfFile.LowPart);
		if (sha256) sha256->HashUpdate(buffer, info.EndOfFile.LowPart);
		NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &size, MEM_RELEASE);

		BYTE hash_value[0x20];
		if (flag && md5)
		{
			md5->HashFinal(hash_value);
			flag = CheckHashStr(hash_value, md5->HashValueSize(), hash->Attribute("MD5"));
		}
		if (flag && sha1)
		{
			sha1->HashFinal(hash_value);
			flag = CheckHashStr(hash_value, sha1->HashValueSize(), hash->Attribute("SHA1"));
		}
		if (flag && sha256)
		{
			sha256->HashFinal(hash_value);
			flag = CheckHashStr(hash_value, sha256->HashValueSize(), hash->Attribute("SHA256"));
		}
	}

	if (md5) delete md5;
	if (sha1) delete sha1;
	if (sha256) delete sha256;
	NtClose(hFile);
	return flag;
}

void InsertHashNode(LPWSTR path, TiXmlElement* file)
{
	WCHAR nt_path[MAX_PATH];
	DWORD len = wcslen(path);
	if (len >= MAX_PATH - 4) return;
	nt_path[0] = nt_path[3] = L'\\';
	nt_path[1] = nt_path[2] = L'?';
	wcscpy(nt_path + 4, path);
	HANDLE hFile = IthCreateFileFullPath(nt_path,FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE) return;

	TiXmlElement* hash = file->FirstChildElement("Hash");
	if (hash == 0)
	{
		hash = NewElement("Hash");
		file->LinkEndChild(hash);
	}
	else
	{
		hash->Clear();
	}

	SHA256Calc sha256;;

	FILE_STANDARD_INFORMATION info;
	IO_STATUS_BLOCK ios;
	LPVOID buffer;
	DWORD size = 0x100000, hash_size, i;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	buffer = 0;
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	while (info.EndOfFile.QuadPart > size)
	{
		NtReadFile(hFile, 0,0,0, &ios, buffer, size, 0,0);
		//md5->HashUpdate(buffer, size);
		//sha1->HashUpdate(buffer, size);
		sha256.HashUpdate(buffer, size);
		info.EndOfFile.QuadPart -= size;
	}
	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0,0);
	//md5->HashUpdate(buffer, info.EndOfFile.LowPart);
	//sha1->HashUpdate(buffer, info.EndOfFile.LowPart);
	sha256.HashUpdate(buffer, info.EndOfFile.LowPart);
	char hash_str[0x80],hash_value[0x20];

	/*hash_size = md5->HashValueSize();
	md5->HashFinal(hash_value);
	for (i = 0; i < hash_size; i++)
		ByteToHexStr(hash_str + (i << 1), hash_value[i]);
	hash_str[hash_size << 1] = 0;
	hash->SetAttribute("MD5",hash_str);

	hash_size = sha1->HashValueSize();
	sha1->HashFinal(hash_value);
	for (i = 0; i < hash_size; i++)
		ByteToHexStr(hash_str + (i << 1), hash_value[i]);
	hash_str[hash_size << 1] = 0;
	hash->SetAttribute("SHA1",hash_str);*/	

	hash_size = sha256.HashValueSize();
	sha256.HashFinal(hash_value);
	for (i = 0; i < hash_size; i++)
		ByteToHexStr(hash_str + (i << 1), hash_value[i]);
	hash_str[hash_size << 1] = 0;
	hash->SetAttribute("SHA256",hash_str);


	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &size, MEM_RELEASE);
	NtClose(hFile);
}

Profile::Profile()
{
	memset(this, 0, sizeof(Profile));
	select_index = -1;
}
Profile::Profile(const Profile& pf) 
{
	//Soft copy, intended for initializing use.
	//Avoid multiple memory allocations and releases for same object.
	if(&pf != this)
	{
		memcpy(this, &pf, sizeof(Profile));
	}
}
Profile::~Profile() 
{
	Release();
}

bool Profile::XmlReadProfile(TiXmlElement* profile)
{

	TiXmlElement* hooks_node = profile->FirstChildElement("Hooks");
	TiXmlElement* threads_node = profile->FirstChildElement("Threads");
	TiXmlElement* links_node = profile->FirstChildElement("Links");

	if (hooks_node && !XmlReadProfileHook(hooks_node)) return false;
	if (threads_node && !XmlReadProfileThread(threads_node)) return false;
	if (links_node && !XmlReadProfileLink(links_node)) return false;

	TiXmlElement* select_node = profile->FirstChildElement("Select");
	if (select_node)
	{
		DWORD tmp_select;
		const char* select_str = select_node->Attribute("ThreadIndex");
		if (select_str == 0) return false;
		if (1 != sscanf(select_str, "%x", &tmp_select)) return false;
		select_index = tmp_select & 0xFFFF;
	}

	return true;
}
bool Profile::XmlReadProfileHook(TiXmlElement* hooks_node)
{
	TiXmlElement* hook;
	for (hook = hooks_node->FirstChildElement(); hook; hook = hook->NextSiblingElement())
	{
		const char* name_str = hook->Value();
		if (name_str == 0 || strcmp(name_str, "Hook") != 0) return false;
		const char* str = hook->Attribute("Type");
		LPWSTR code;
		if (str == 0) return false;
		if (str[1] != 0) return false;
		switch (str[0])
		{
		case 'H':
			str = hook->Attribute("Code");
			if (str == 0) return false;
			if (str[0] != '/') return false;
			if (str[1] != 'H' && str[1] != 'h') return false;
			code = AllocateUTF16AndConvertUTF8(str + 2);
			if (code == 0) return false;
			HookParam hp;
			if (Parse(code, hp))
			{
				str = hook->Attribute("Name");
				if (str == 0 || *str == 0) AddHook(hp, 0);
				else
				{
					WCHAR small_str[0x40],*ptr;
					DWORD len = UTF8to16len(str);
					if (len < 0x40) ptr = small_str;
					else ptr = new WCHAR[len + 1];
					ptr[UTF8to16(str,ptr)] = 0;
					AddHook(hp, ptr);
					if (ptr != small_str) delete ptr;
				}
			}
			delete code;

			break;
		default:
			return false;
		}
	}
	return true;
}
bool Profile::XmlReadProfileThread(TiXmlElement* threads_node)
{
	TiXmlElement *thread;
	WCHAR hook_name_buffer[0x100];
	for (thread = threads_node->FirstChildElement(); thread; thread = thread -> NextSiblingElement())
	{
		const char* name_str = thread->Value();
		if (name_str == 0 || strcmp(name_str, "Thread") != 0) return false;
		ThreadProfile tp;
		tp.hm_index = 0;
		tp.hook_addr = 0;
		const char* hook_name = thread->Attribute("HookName");
		if (hook_name == 0) return false;
		const char* context = thread->Attribute("Context");
		if (context == 0) return false;
		const char* sub_context = thread->Attribute("SubContext");
		if (sub_context == 0) return false;
		const char* mask = thread->Attribute("Mask");
		if (mask == 0) return false;

		if (1 != sscanf(context, "%x", &tp.retn)) return false;
		if (1 != sscanf(sub_context, "%x", &tp.split)) return false;
		DWORD mask_tmp;
		if (1 != sscanf(mask, "%x", &mask_tmp)) return false;
		tp.flags = mask_tmp & 0xFFFF;
		if (UTF8to16len(hook_name) >= 0x100) return false;
		hook_name_buffer[UTF8to16(hook_name,hook_name_buffer)] = 0;
		tp.hook_name_index = hnman->InsertName(hook_name_buffer);
		DWORD i,j,len;
		const char* comment = thread->Attribute("Comment");
		len = 0;
		if (comment)
		{
			len = UTF8to16len(comment);
			if (len)
			{
				tp.comment = new WCHAR[len+1];
				UTF8to16(comment,tp.comment);
				tp.comment[len] = 0;
			}
			else tp.comment = 0;
			
		}
		else tp.comment = 0;
		j = thread_count;
		i = AddThread(&tp);
		if (i < j && len) delete tp.comment;
	}
	return true;
}
bool Profile::XmlReadProfileLink(TiXmlElement* links_node)
{
	TiXmlElement* link;
	for (link = links_node->FirstChildElement(); link; link = link->NextSiblingElement())
	{
		const char* name_str = link->Value();
		if (name_str == 0 || strcmp(name_str, "Link") != 0) return false;
		DWORD link_from,link_to;
		name_str = link->Attribute("From");
		if (name_str == 0) return false;
		if (1 != sscanf(name_str, "%x", &link_from)) return false;
		name_str = link->Attribute("To");
		if (name_str == 0) return false;
		if (1 != sscanf(name_str, "%x", &link_to)) return false;
		LinkProfile lp;
		lp.from_index = link_from & 0xFFFF;
		lp.to_index = link_to & 0xFFFF;
		AddLink(&lp);
	}
	return true;
}
bool Profile::XmlWriteProfile(TiXmlElement* profile_node)
{
	TiXmlElement* node;
	if (hook_count)
	{
		node = NewElement("Hooks");
		XmlWriteProfileHook(node);
		profile_node->LinkEndChild(node);
	}
	if (thread_count)
	{
		node = NewElement("Threads");
		XmlWriteProfileThread(node);
		profile_node->LinkEndChild(node);
	}
	if (link_count)
	{
		node = NewElement("Links");
		XmlWriteProfileLink(node);
		profile_node->LinkEndChild(node);
	}
	if (select_index != 0xFFFF)
	{
		node = NewElement("Select");
		node->SetAttribute("ThreadIndex",select_index);
		profile_node->LinkEndChild(node);
	}

	return true;
}
bool Profile::XmlWriteProfileHook(TiXmlElement* hooks_node)
{
	DWORD i,count,len;
	count = hook_count;
	WCHAR code[MAX_PATH];
	for (i = 0; i < count; i++)
	{
		TiXmlElement* hook = NewElement("Hook");
		len = GetCode(hooks[i].hp, code);
		hook->SetAttribute("Type","H");
		hook->SetAttributeWithUTF16("Code",code);
		if (hooks[i].name) hook->SetAttributeWithUTF16("Name",hooks[i].name);
		hooks_node->LinkEndChild(hook);
	}
	return true;
}
bool Profile::XmlWriteProfileThread(TiXmlElement* threads_node)
{
	DWORD i,count;
	LPWSTR name;
	char str[0x100],*ptr;
	ptr = str;
	count = thread_count;
	for (i = 0; i < count; i++)
	{
		name = hnman->GetName(threads[i].hook_name_index);
		if (name == 0) return false;	
		TiXmlElement* node = NewElement("Thread");
		node->SetAttributeWithUTF16("HookName",name);
		sprintf(str,"%x",threads[i].flags & 3);
		node->SetAttribute("Mask",str);
		sprintf(str,"%x",threads[i].split);
		node->SetAttribute("SubContext",str);
		sprintf(str,"%x",threads[i].retn);
		node->SetAttribute("Context",str);
		if (threads[i].comment)
		{
			node->SetAttributeWithUTF16("Comment",threads[i].comment);
		}
		threads_node->LinkEndChild(node);
	}
	return true;
}
bool Profile::XmlWriteProfileLink(TiXmlElement* links_node)
{
	DWORD i,count;
	char str[0x100];
	count = link_count;
	for (i = 0; i < count; i++)
	{
		TiXmlElement* node = NewElement("Link");
		sprintf(str,"%x",links[i].from_index);
		node->SetAttribute("From",str);
		sprintf(str,"%x",links[i].to_index);
		node->SetAttribute("To",str);
		links_node->LinkEndChild(node);
	}
	return true;
}
void Profile::ClearHooks()
{
	hook_count = 0;
}
void Profile::Release()
{
	if (title)
	{
		delete title;
		title = 0;
	}
	ReleaseData();
}
void Profile::ReleaseData()
{
	if (hook_allocate)
	{
		for (WORD i = 0; i < hook_count; i++)
		{
			if (hooks[i].name) delete hooks[i].name;
		}
		delete hooks;
	}

	if (thread_allocate) 
	{
		DWORD count = thread_count,i;
		for (i = 0; i < thread_count; i++)
			if (threads[i].comment) delete threads[i].comment;
		delete threads;
	}

	if (link_allocate) 
	{
		delete links;
	}

	memset(this, 0, sizeof(Profile) - sizeof(LPWSTR));
	select_index = -1;
}
int Profile::AddHook(const HookParam& hp, LPWSTR name)
{
	//if (hook_count == 4) return;
	DWORD i,count;
	count = hook_count;
	for (i = 0; i < count; i++)
	{
		HookParam* h = &hooks[i].hp;
		if (h->addr == hp.addr &&
			h->module == hp.module &&
			h->function == hp.function)
			return i;
	}
	if (hook_count >= hook_allocate)
	{
		hook_allocate += 4;
		HookProfile* temp = new HookProfile[hook_allocate];
		if (hooks)
		{
			memcpy(temp, hooks, hook_count * sizeof(HookProfile));
			delete hooks;
		}
		hooks = temp;
	}
	hooks[hook_count].hp = hp;
	if (name)
	{
		DWORD len = wcslen(name);
		hooks[hook_count].name = new WCHAR[len+1];
		memcpy(hooks[hook_count].name, name, len << 1);
		hooks[hook_count].name[len] = 0;
	}
	return hook_count++;
}

int Profile::AddThread(ThreadProfile *tp)
{
	//tp -> hook_addr = 0;
	tp -> hm_index = 0;
	for (int i = 0; i < thread_count; i++) 
	{
		if (memcmp(tp, threads + i, sizeof(DWORD)*3) == 0) //Only compare name, context, subcontext.
		{
			return i;
		}
	}
	if (thread_count >= thread_allocate)
	{
		thread_allocate += 4;
		ThreadProfile* temp = new ThreadProfile[thread_allocate];
		if (threads)
		{
			memcpy(temp, threads, thread_count * sizeof(ThreadProfile));
			delete threads;
		}
		threads = temp;
	}

	memcpy(threads + thread_count, tp, sizeof(ThreadProfile)); //Comment is not allocated.

	return thread_count++;
}
int Profile::AddLink(LinkProfile* lp)
{
	for (int i = 0; i < link_count; i++)
	{
		if (memcmp(lp, links + i, sizeof(LinkProfile)) == 0) 
		{
			return i;
		}
	}

	if (link_count >=link_allocate)
	{
		link_allocate = link_count + 4;
		LinkProfile* temp = new LinkProfile[link_allocate];
		if (links)
		{
			memcpy(temp, links, link_count * sizeof(LinkProfile));
			delete links;
		}
		links = temp;
	}

	memcpy(links + link_count, lp, sizeof(LinkProfile));

	return link_count++;
}
void Profile::RemoveHook(int index)
{
	if (index >= 0 && index < hook_count)
	{
		if (hooks[index].name) delete hooks[index].name;
		hook_count--;
		int i;
		for (i = index; i < hook_count; i++)
		{
			hooks[i] = hooks[i + 1];
		}
		memset(hooks + i, 0, sizeof(HookProfile));
	}
}
void Profile::RemoveThread(int index)
{
	if (index >= 0 && index < thread_count)
	{
		int i;
		for (i = link_count - 1; i >= 0; i--)
		{
			if (links[i].from_index == index + 1 ||
				links[i].to_index == index + 1)
			{
				RemoveLink(i);
			}
		}

		if (select_index == index) select_index = -1;

		if (threads[i].comment) delete threads[i].comment;

		thread_count--;
		for (i = index; i < thread_count; i++)
		{
			threads[i] = threads[i+1];
		}
		
		memset(threads + thread_count, 0, sizeof(ThreadProfile));		
		
		if (index < select_index) select_index--;
	}
}
void Profile::RemoveLink(int index)
{
	if (index >= 0 && index < link_count)
	{
		link_count--;
		for (int i = index; i < link_count; i++)
		{
			links[i] = links[i + 1];
		}		
		memset(links + link_count, 0, sizeof(LinkProfile));
	}
}
Profile& Profile::operator = (Profile& pf)
{
	if(&pf != this)
	{
		Release();
		memcpy(this, &pf, sizeof(Profile));
	}
	return *this;
}

DWORD WINAPI MonitorThread(LPVOID lpThreadParameter);

ProfileManager::ProfileManager()
{
	InitializeCriticalSection(&pfcs);
	hnman = new HookNameManager;
	LoadProfile();
	MonitorFlag = true;
	profile_changed = 0;
	current_select_pid = 0;
	current_select_profile = 0;
	hMonitorThread = IthCreateThread(MonitorThread, 0);
}
ProfileManager::~ProfileManager()
{
	MonitorFlag = false;
	if (profile_changed) SaveProfile();
	ClearProfile();
	NtWaitForSingleObject(hMonitorThread, 0, 0);
	NtClose(hMonitorThread);
	delete hnman;
	hnman = 0;
	DeleteCriticalSection(&pfcs);
	profile_table.DeleteAll();
}
Profile* ProfileManager::GetProfile(LPWSTR path)
{
	ProfileNode* pfn = profile_tree.Search(path);
	if (pfn == 0) return 0;
	return profile_table.Get(pfn->data);
}
Profile* ProfileManager::GetProfile(DWORD pid)
{
	if (pid == current_select_pid)
		return profile_table[current_select_profile];
	WCHAR path[MAX_PATH];
	if (GetProcessPath(pid, path))
	{
		TreeNode<LPWSTR,DWORD>* node = profile_tree.Search(path);
		if (node) return profile_table[node->data];
	}
	return 0;
}
Profile* ProfileManager::GetProfileByIndex(DWORD index)
{
	TreeNode<LPWSTR,DWORD>* node = profile_tree.SearchIndex(index);
	if (node) return profile_table[node->data];
	else return 0;
}
TiXmlElement* ProfileManager::GetProfileXmlByIndex(DWORD index)
{
	TreeNode<LPWSTR,DWORD>* node = profile_tree.SearchIndex(index);
	if (node) return xml_table[node->data];
	else return 0;
}
bool ProfileManager::AddProfile(TiXmlElement* game)
{
	TiXmlElement *file, *profile, *hash;
	//if (strcmp(game->Value(),"Game") != 0) return false;

	file = game->FirstChildElement("File");
	profile = game->FirstChildElement("Profile");
	if (file == 0 || profile == 0) return false;

	const char* path = file->Attribute("Path");
	if (path == 0) return false;

	hash = file->FirstChildElement("Hash");

	WCHAR nt_path[MAX_PATH];
	DWORD len;
	len = UTF8to16len(path);
	if (len >= MAX_PATH) return false;
	UTF8to16(path, nt_path);
	nt_path[len] = 0;
	if (hash && !CheckFileHash(hash, nt_path)) return false;

	Profile *pf = new Profile;
	if (!pf->XmlReadProfile(profile))
	{
		delete pf;
		return false;
	}

	const char* profile_title = game->Attribute("Title");
	if (profile_title == 0 || *profile_title == 0) pf->title = 0;
	else pf->title = AllocateUTF16AndConvertUTF8(profile_title);
	LockProfileManager();
	xml_table.Set(AddProfile(nt_path, pf),game);
	UnlockProfileManager();
	return true;
}
DWORD ProfileManager::AddProfile(LPWSTR path, Profile* p)
{
	DWORD result = -1;
	LockProfileManager();
	TreeNode<LPWSTR,DWORD>* node = profile_tree.Insert(path, profile_table.next);
	if (node->data == profile_table.next)
	{
		profile_table.Append(p);
		result = node->data;
	}
	UnlockProfileManager();
	return result;
}
void ProfileManager::RefreshProfileXml(LPWSTR path)
{	
	LockProfileManager();
	TreeNode<LPWSTR,DWORD> *node = profile_tree.Search(path);
	if (node) RefreshProfileXml(node);
	UnlockProfileManager();
}
void ProfileManager::RefreshProfileXml(DWORD index)
{
	LockProfileManager();
	TreeNode<LPWSTR,DWORD>* node = profile_tree.SearchIndex(index);
	if (node) RefreshProfileXml(node);
	UnlockProfileManager();
}
void ProfileManager::RefreshProfileXml(TreeNode<LPWSTR,DWORD>* node)
{
	TiXmlElement *root = doc.RootElement();
	TiXmlElement *game,*profile_node,*file_node;// = xml_table[node->data];
	Profile* pf = profile_table[node->data];
	if (pf == 0 || root == 0) return;
	LPWSTR path = node->key;
	profile_changed = 1;
	game = xml_table[node->data];
	if (game == 0)
	{
		game = NewElement("Game");
		file_node = NewElement("File");
		file_node->SetAttributeWithUTF16("Path",path);
		InsertHashNode(path,file_node);
		game->LinkEndChild(file_node);
		profile_node = NewElement("Profile");
		game->LinkEndChild(profile_node);
		pf->XmlWriteProfile(profile_node);
		root->LinkEndChild(game);
		xml_table.Set(node->data, game);
	}
	else
	{
		profile_node = game->FirstChildElement("Profile");
		if (profile_node) profile_node->Clear();
		else 
		{
			profile_node = NewElement("Profile");
			game->LinkEndChild(profile_node);
		}
		pf->XmlWriteProfile(profile_node);
	}
	if (pf->title)
	{
		game->SetAttributeWithUTF16("Title",pf->title);
	}
}
void ProfileManager::ClearProfile()
{
	LockProfileManager();
	profile_tree.DeleteAll();
	Profile* pf;
	while (profile_table.used)
	{
		pf = profile_table[profile_table.used - 1];
		delete pf;
		profile_table.Set(profile_table.used - 1,0);
	}
	UnlockProfileManager();
}
void ProfileManager::LoadProfile()
{

	HANDLE hFile = IthCreateFile(L"ITH_Profile.xml", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		TiXmlDeclaration decl("1.0","utf-8","");
		doc.InsertEndChild(decl);
		TiXmlElement* root = NewElement("ITH_Profile");
		doc.LinkEndChild(root);
		return;
	}
	FILE_STANDARD_INFORMATION info;
	IO_STATUS_BLOCK ios;
	LPVOID buffer;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	buffer = 0;
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &info.AllocationSize.LowPart, MEM_COMMIT, PAGE_READWRITE);
	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
	doc.Parse((const char*)buffer);
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
	NtClose(hFile);
	//doc.LoadFile("ITH_Profile.xml");
	if (doc.Error()) return;
	TiXmlElement* root = doc.RootElement();
	if (strcmp(root->Value(),"ITH_Profile") != 0) return;
	TiXmlElement* game;
	for (game = root->FirstChildElement(); game; game = game->NextSiblingElement())
	{
		AddProfile(game);
	}

}
void ProfileManager::SaveProfile()
{
	HANDLE hFile = IthCreateFile(L"ITH_Profile.xml", FILE_WRITE_DATA, 0, FILE_OPEN_IF);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		TiXmlString str;
		LockProfileManager();
		doc.Print(str,0);
		UnlockProfileManager();
		IO_STATUS_BLOCK ios;
		NtWriteFile(hFile, 0,0,0, &ios, (PVOID)str.c_str(), str.length(), 0,0);
		LARGE_INTEGER end;
		end.LowPart = str.length();
		end.HighPart = 0;
		NtSetInformationFile(hFile, &ios, &end, sizeof(end), FileEndOfFileInformation);
		NtClose(hFile);
	}
}
void ProfileManager::ExportProfile(LPWSTR file, DWORD index)
{
	ExportProfile(file, profile_tree.SearchIndex(index));
}
void ProfileManager::ExportProfile(LPWSTR file, LPWSTR path)
{
	ExportProfile(file, profile_tree.Search(path));
}
void ProfileManager::ExportProfile(LPWSTR file, TreeNode<LPWSTR,DWORD>* node)
{	
	if (node == 0) return;
	TiXmlElement* game = xml_table[node->data];
	if (game == 0) return;
	if (game->FirstChildElement("File") == 0) return;
	LPWSTR exe = wcsrchr(node->key, L'\\');
	if (exe == 0) return;
	exe++;

	TiXmlDocument doc_export;
	TiXmlDeclaration decl("1.0","utf-8","");
	doc_export.InsertEndChild(decl);
	TiXmlElement* root_profile = NewElement("ITH_Profile");
	doc_export.LinkEndChild(root_profile);
	TiXmlElement* game_copy = (TiXmlElement*)game->Clone();
	TiXmlElement* file_copy = game_copy->FirstChildElement("File");
	file_copy->RemoveAttribute("Path");
	file_copy->SetAttributeWithUTF16("Name",exe);
	root_profile->LinkEndChild(game_copy);
	
	HANDLE hFile = IthCreateFile(file, GENERIC_WRITE, FILE_SHARE_READ, FILE_OPEN_IF);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		TiXmlString str;
		doc_export.Print(str);
		IO_STATUS_BLOCK ios;
		NtWriteFile(hFile, 0,0,0, &ios, (PVOID)str.c_str(), str.length(), 0,0);
		LARGE_INTEGER end = {str.length(),0};
		NtSetInformationFile(hFile, &ios, &end, 8, FileEndOfFileInformation);
		NtClose(hFile);
	}
}
void ProfileManager::ExportAllProfile(LPWSTR file)
{
	TiXmlDocument doc_export(doc);
	TiXmlElement* root = doc_export.RootElement();
	if (root)
	{
		TiXmlElement* game;
		for (game = root->FirstChildElement(); game; game = game->NextSiblingElement())
		{
			if (strcmp(game->Value(),"Game") != 0) continue;
			TiXmlElement* file_node = game->FirstChildElement("File");
			if (file_node == 0) continue;
			const char* path = file_node->Attribute("Path");
			if (path == 0) continue;
			path = strrchr(path,'\\');
			if (path == 0) continue;
			file_node->SetAttribute("Name", path + 1);
			file_node->RemoveAttribute("Path");
		}
		TiXmlString str;
		doc_export.Print(str);
		HANDLE hFile = IthCreateFile(file, GENERIC_WRITE, FILE_SHARE_READ, FILE_OPEN_IF);
		if (hFile != INVALID_HANDLE_VALUE)
		{
			IO_STATUS_BLOCK ios;
			NtWriteFile(hFile, 0,0,0,&ios,(PVOID)str.c_str(),str.length(),0,0);
			LARGE_INTEGER end = {str.length(),0};
			NtSetInformationFile(hFile, &ios, &end, 8, FileEndOfFileInformation);
			NtClose(hFile);
		}
	}
}
void ProfileManager::DeleteProfile(int index)
{
	TreeNode<LPWSTR, DWORD>* node = profile_tree.SearchIndex(index);
	if (node)
	{
		DWORD data = node->data;
		profile_tree.Delete(node->key);
		delete profile_table.Get(data);
		profile_table.Set(data,0);
		TiXmlElement *root = doc.RootElement();
		if (root)
		{
			TiXmlElement *game;
			game = xml_table[data];
			if (game)
			{
				xml_table.Set(data,0);
				root->RemoveChild(game);
				SaveProfile();
			}
		}
	}
	/*ProfileNode* pf = GetProfile(index);
	if (pf == 0) return;
	profile_tree.Delete(pf -> key);*/
}
void ProfileManager::DeleteProfile(LPWSTR path)
{
	profile_tree.Delete(path);
}
void ProfileManager::RefreshProfileAddr(DWORD pid, LPWSTR path)
{
	//EnterCriticalSection(&pfcs);
	DWORD i, j;
	if (path == 0)
	{
		if (pid == current_select_pid)
		{
			Profile* pf = profile_table[current_select_profile];
			if (pf)
			{
				for (i = 0; i < pf->thread_count; i++)
					pf->threads[i].hook_addr = 0;
			}
		}
		return;
	}
	TreeNode<LPWSTR,DWORD>* pfn = profile_tree.Search(path);
	if (pfn == 0) return;
		
	Profile* pf = profile_table.Get(pfn->data);
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pf == 0 || pr == 0) return;

	current_select_profile = pfn->data;
	current_select_pid = pid;
	AVLTree<WCHAR, DWORD, WCMP, WCPY, WLEN> remote_names;
	WCHAR name[MAX_PATH];
	DWORD retn;
	Hook* hks, *hke;
	hks = (Hook*)pr->hookman_map;
	hke = hks + MAX_HOOK;
	for (; hks != hke; hks++)
	{
		if (hks->Address() == 0) continue;
		if (hks->NameLength() >= MAX_PATH) break;
		NtReadVirtualMemory(pr->process_handle, hks->Name(), name, hks->NameLength() << 1, &retn);
		name[hks->NameLength()] = 0;
		remote_names.Insert(name, hks->Address());
	}
		
	LPWSTR thread_name;
	for (i = 0; i < pf -> thread_count; i++)
	{
		j = pf -> threads[i].hook_name_index;
		thread_name = hnman->GetName(j);
		TreeNode<LPWSTR,DWORD>* node = remote_names.Search(thread_name);
		if (node) pf -> threads[i].hook_addr = node->data;
	}	
}
bool ProfileManager::IsPathProfile(LPWSTR path)
{
	return (profile_tree.Search(path) != 0);
}
bool ProfileManager::IsProfileCurrent(Profile* pf)
{
	Profile* profile = profile_table[current_select_profile];
	if (profile == 0) return false;
	return profile == pf;
}
DWORD ProfileManager::ProfileCount()
{
	return profile_tree.Count();
}
DWORD ProfileManager::GetCurrentPID()
{
	return current_select_pid;
}
void ProfileManager::LockProfileManager()
{
	EnterCriticalSection(&pfcs);
}
void ProfileManager::UnlockProfileManager()
{
	LeaveCriticalSection(&pfcs);
}

void GetThreadString(ThreadProfile* tp, LPWSTR str)
{
	str += swprintf(str, L"%.4X:", tp -> hook_name_index);
	if (tp -> flags & THREAD_MASK_RETN)
	{
		tp -> retn &= 0xFFFF;
		str += swprintf(str, L"XXXX%.4X:", tp -> retn);
	}
	else
	{
		str += swprintf(str, L"%.8X:", tp -> retn);
	}

	if (tp -> flags & THREAD_MASK_SPLIT)
	{
		tp -> split &= 0xFFFF;
		str += swprintf(str, L"XXXX%.4X", tp -> split);
	}
	else
	{
		str += swprintf(str, L"%.8X",tp -> split);
	}
}

extern DWORD inject_delay, insert_delay, process_time;
DWORD WINAPI InjectThread(LPVOID lpThreadParameter)
{
	WCHAR path[MAX_PATH];
	DWORD pid = (DWORD)lpThreadParameter;

	//static DWORD inject_delay = 3000;
	IthSleep(inject_delay);

	if (!man) return 0;
	DWORD status = IHF_InjectByPID(pid, ITH_DEFAULT_ENGINE);
	if (!auto_insert) return status;
	if (status == -1) return status;

	IthSleep(insert_delay);

	if (GetProcessPath(pid, path))
	{
		SendParam sp;
		sp.type = 0;
		Profile* pf = pfman->GetProfile(path);
		for (int i = 0; i < pf -> hook_count; i++)
		{
			IHF_InsertHook(pid, &pf->hooks[i].hp, pf->hooks[i].name);
		}
	}
	return status;
}
DWORD WINAPI MonitorThread(LPVOID lpThreadParameter)
{
	//SetEnvironmentVariable(L"__COMPAT_LAYER", L"#ApplicationLocale");
	//SetEnvironmentVariable(L"AppLocaleID", L"0411");

	DWORD size, rs;
	LPVOID addr; 
	NTSTATUS status;
	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;

	size = 0x20000; addr = 0;
	NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
	while (MonitorFlag)
	{
		status = NtQuerySystemInformation(SystemProcessInformation, addr, size, &rs);
		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
			addr = 0;
			size = (rs & 0xFFFFF000) + 0x4000;
			NtAllocateVirtualMemory(NtCurrentProcess(), &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
			status = NtQuerySystemInformation(SystemProcessInformation, addr, size, &rs);
		}
		if (!NT_SUCCESS(status)) 
		{
			//man -> AddConsoleOutput(ErrorMonitor);
			break;
		}
		for (spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)addr; MonitorFlag && spiProcessInfo -> dNext;)
		{
			IthSleep(process_time);

			spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)	
				((DWORD)spiProcessInfo + spiProcessInfo -> dNext);

			if (!auto_inject || man->GetProcessRecord(spiProcessInfo->dUniqueProcessId)) continue;

			if (GetProcessPath(spiProcessInfo -> dUniqueProcessId, process_path))
			{
				if (pfman -> IsPathProfile(process_path))
				{
					HANDLE hThread = IthCreateThread(InjectThread, spiProcessInfo -> dUniqueProcessId);
					NtWaitForSingleObject(hThread,0,0);
					NtClose(hThread);
				}
			}
		}
	}
	NtFreeVirtualMemory(NtCurrentProcess(), &addr, &size, MEM_RELEASE);
	return 0;
}

HookNameManager::HookNameManager()
{

}
HookNameManager::~HookNameManager()
{
	LPWSTR str;
	for (unsigned int i = 0; i < hookname_table.used; i++)
	{
		str = hookname_table[i];
		if (str) delete str;
	}
}
DWORD HookNameManager::InsertName(LPWSTR name)
{
	TreeNode<LPWSTR,DWORD>* node = hookname_tree.Insert(name, hookname_table.next);
	if (node->data == hookname_table.next)
	{
		LPWSTR name_new = new WCHAR[wcslen(name) + 1];
		wcscpy(name_new, name);
		hookname_table.Append(name_new);
	}
	return node->data;
}
LPWSTR HookNameManager::GetName(DWORD index)
{
	return hookname_table[index];
}
DWORD SaveSingleThread(Profile* pf, TextThread* thread, ProcessRecord* pr)
{
	DWORD i,j,retn;
	Hook* hks = (Hook*)pr->hookman_map;
	ThreadParameter* tpr = thread->GetThreadParameter();
	ThreadProfile tp = {-1, tpr -> retn, tpr -> spl, 0, -1 , THREAD_MASK_RETN | THREAD_MASK_SPLIT, 0};
	WCHAR hook_name[MAX_PATH];
	for (i = 0; i < MAX_HOOK; i++)
	{
		if (hks[i].Address()==0) continue;
		if (hks[i].Address() == tpr -> hook)
		{
			if (hks[i].NameLength() < MAX_PATH)
				if (NT_SUCCESS(NtReadVirtualMemory(pr->process_handle, 
					hks[i].Name(), hook_name, hks[i].NameLength()<<1, &retn)))
				{
					hook_name[hks[i].NameLength()] = 0;
					tp.hook_name_index = hnman->InsertName(hook_name);
				}
				break;
		}			
	}
	if (i < MAX_HOOK && tp.hook_name_index != -1)
	{
		j = pf -> thread_count;
		i = pf -> AddThread(&tp);
		if (i == j) //new thread.
		{
			WORD iw = i & 0xFFFF;
			LPCWSTR comment = thread->GetComment();
			if (comment)
			{
				pf->threads[i].comment = new WCHAR[wcslen(comment) + 1];
				wcscpy(pf->threads[i].comment, comment);
			}
			//pf -> AddComment(thread -> GetComment(), iw);
			if (thread -> Status()&CURRENT_SELECT) pf -> select_index = iw;
			if (thread -> Link())
			{
				LinkProfile lp;
				lp.from_index = iw;
				lp.to_index = SaveSingleThread(pf, thread -> Link(), pr) & 0xFFFF;
				if (lp.to_index >= 0) pf -> AddLink(&lp);
			}
		}
		return i; // in case more than one threads link to the same thread.
	}
	else return -1;
	
}
DWORD SaveProcessProfile(DWORD pid)
{
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == 0) return 0;
	WCHAR path[MAX_PATH];
	if (!GetProcessPath(pid,path)) return 0;
	Profile* pf = pfman->GetProfile(pid);
	if (pf)
	{
		pf->Release();
	}
	else
	{	
		pf = new Profile;		
		pfman->AddProfile(path, pf);
	}
	pf->title = SaveProcessTitle(pid); //New allocated from heap.

	NtWaitForSingleObject(pr->hookman_mutex, 0, 0);
	Hook* hook = (Hook*)pr->hookman_map;
	DWORD i,j,type;
	for (i = 0; i < MAX_HOOK; i++)
	{
		if (hook[i].Address() == 0) continue;
		type = hook[i].Type();
		if ((type & HOOK_ADDITIONAL) && (type & HOOK_ENGINE) == 0)
		{
			static WCHAR name[0x200];
			if (hook[i].NameLength() < 0x200)
			{
				NtReadVirtualMemory(pr->process_handle, hook[i].Name(), name, hook[i].NameLength()<<1, &j);
				name[hook[i].NameLength()] = 0;
				if (hook[i].hp.module)
				{
					HookParam hp = hook[i].hp;
					hp.function = 0;
					MEMORY_BASIC_INFORMATION info;
					DWORD retn;
					NtQueryVirtualMemory(pr->process_handle, (PVOID)hp.addr, 
						MemoryBasicInformation, &info, sizeof(info), &retn);
					hp.addr -= (DWORD)info.AllocationBase;
					pf->AddHook(hp, name);
				}
				else
					pf->AddHook(hook[i].hp, name);
			}
		}
	}
	NtReleaseMutant(pr->hookman_mutex, 0);

	man->LockHookman();
	ThreadTable* table = man->Table();
	
	j = table->Used();
	for (i = 0; i < j; i++)
	{
		TextThread* tt = table->FindThread(i);
		if (tt == 0 || tt->GetThreadParameter()->pid != pid) continue;
		if (tt->Status()&CURRENT_SELECT || tt->Link() || tt->GetComment())
			SaveSingleThread(pf, tt, pr);
	}
	pfman->RefreshProfileXml(path);
	man->UnlockHookman();
	return 0;
}
