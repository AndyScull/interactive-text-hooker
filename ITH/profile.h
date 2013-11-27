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
#include <ITH\AVL.h>
#include <ITH\common.h>
#include <ITH\tinyxml.h>
#include "PointerTable.h"
#define THREAD_MASK_RETN 1
#define THREAD_MASK_SPLIT 2
struct HookProfile
{
	HookParam hp;
	LPWSTR name;
};
struct ThreadProfile
{
	DWORD hook_name_index;	
	DWORD retn;
	DWORD split;
	DWORD hook_addr;
	WORD hm_index,flags;
	LPWSTR comment;
};
struct LinkProfile
{
	WORD from_index,to_index;
};
class Profile
{
public:
	Profile();
	Profile(const Profile& p);
	~Profile();
	bool XmlReadProfile(TiXmlElement* profile_node);
	bool XmlReadProfileHook(TiXmlElement* hooks_node);
	bool XmlReadProfileThread(TiXmlElement* threads_node);
	bool XmlReadProfileLink(TiXmlElement* links_node);
	bool XmlWriteProfile(TiXmlElement* profile_node);
	bool XmlWriteProfileHook(TiXmlElement* hooks_node);
	bool XmlWriteProfileThread(TiXmlElement* threads_node);
	bool XmlWriteProfileLink(TiXmlElement* links_node);
	void RemoveHook(int index);
	void RemoveThread(int index);
	void RemoveLink(int index);
	void Release();
	void ReleaseData();
	void ClearHooks();
	int AddHook(const HookParam& hp, LPWSTR name);
	int AddThread(ThreadProfile *tp);
	int AddLink(LinkProfile* lp);
	Profile& operator = (Profile& pf);

	WORD hook_count,thread_count,link_count;		
	WORD hook_allocate,thread_allocate,link_allocate;
	WORD select_index,engine_type;
	HookProfile* hooks;
	ThreadProfile* threads;
	LinkProfile* links;
	LPWSTR title;
};
typedef TreeNode<LPWSTR,DWORD> ProfileNode;
class ProfileManager
{
public:
	ProfileManager();
	~ProfileManager();
	bool AddProfile(TiXmlElement* node);
	DWORD AddProfile(LPWSTR path, Profile* p);
	void RefreshProfileXml(LPWSTR path);
	void RefreshProfileXml(DWORD index);
	void RefreshProfileXml(TreeNode<LPWSTR,DWORD>* node);
	void ClearProfile();
	void LoadProfile();
	void SaveProfile();
	void ExportProfile(LPWSTR file, DWORD index);
	void ExportProfile(LPWSTR file, LPWSTR path);
	void ExportProfile(LPWSTR file, TreeNode<LPWSTR,DWORD>* node);
	void ExportAllProfile(LPWSTR file);
	void DeleteProfile(int index);
	void DeleteProfile(LPWSTR path);
	void RefreshProfileAddr(DWORD pid,LPWSTR path);
	void SetProfileEngine(LPWSTR path, DWORD type);
	void LockProfileManager();
	void UnlockProfileManager();
	bool IsPathProfile(LPWSTR path);
	bool IsProfileCurrent(Profile* pf);
	Profile* GetProfile(LPWSTR path);	
	Profile* GetProfile(DWORD pid);
	Profile* GetProfileByIndex(DWORD index);
	TiXmlElement* GetProfileXmlByIndex(DWORD index);
	DWORD ProfileCount();
	DWORD GetCurrentPID();
private:
	//Locate profile with executable path.
	AVLTree<WCHAR,DWORD,WCMP,WCPY,WLEN> profile_tree;	

	PointerTable<Profile, 0x40> profile_table;
	PointerTable<TiXmlElement, 0x40> xml_table;
	TiXmlDocument doc;
	CRITICAL_SECTION pfcs;
	DWORD current_select_pid, current_select_profile, profile_changed;
	HANDLE hMonitorThread;

};
DWORD GetCode(const HookParam& hp, LPWSTR buffer, DWORD pid=0);
void GetThreadString(ThreadProfile* tp, LPWSTR str);

class HookNameManager
{
public:
	HookNameManager();
	~HookNameManager();
	DWORD InsertName(LPWSTR name);
	LPWSTR GetName(DWORD index);
private:
	//HookName of profiled threads turns to be same.
	//e.g. GetGlyphOutlineA, UserHook0
	AVLTree<WCHAR,DWORD,WCMP,WCPY,WLEN> hookname_tree; 
	PointerTable<WCHAR, 0x20> hookname_table;
};

extern ProfileManager* pfman;
extern HookNameManager* hnman;