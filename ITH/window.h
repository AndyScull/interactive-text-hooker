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
#include "profile.h"
#include <windows.h>
#include <ITH\main_template.h>
#include <ITH\common.h>
#include <ITH\CustomFilter.h>
int GetHookString(LPWSTR str, DWORD pid, DWORD hook_addr, DWORD status);
//SYSTEM_PROCESS_INFORMATION* GetBaseByPid(BYTE* pbBuffer,DWORD dwPid);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

enum ThreadOperation
{
	Suspend,
	Resume,
	Terminate,
	OutputInformation
};

#define IDC_CHECK_BIGENDIAN		IDC_CHECK1
#define IDC_CHECK_UNICODE			IDC_CHECK2
#define IDC_CHECK_STRING			IDC_CHECK3
#define IDC_CHECK_DATA_IND		IDC_CHECK4
#define IDC_CHECK_SPLIT				IDC_CHECK5
#define IDC_CHECK_SPLIT_IND		IDC_CHECK6
#define IDC_CHECK_MODULE			IDC_CHECK7
#define IDC_CHECK_FUNCTION		IDC_CHECK8
#define IDC_CHECK_HEX					IDC_CHECK9
#define IDC_CHECK_LASTCHAR		IDC_CHECK10
#define IDC_CHECK_NOCONTEXT	IDC_CHECK11

class ProcessWindow
{
public:
	ProcessWindow(HWND hDialog);
	void InitProcessDlg();
	void RefreshProcess();
	void AttachProcess();
	void DetachProcess();
	void OperateThread();
	void AddCurrentToProfile();
	void RefreshThread(int index);
	void RefreshThreadColumns(DWORD pid);
	bool PerformThread(DWORD pid, DWORD tid, ThreadOperation op=OutputInformation, DWORD addr=0);
	bool PerformThread(PVOID system_thread);
	DWORD GetSelectPID();
private:
	HWND hDlg;
	HWND hlProcess,hlThread;
	HWND hbRefresh,hbAttach,hbDetach,hbExecute,hbAddProfile;
	HWND heAddr,heOutput;
	HWND hrSuspend,hrResume,hrTerminate;
};

class ThreadWindow
{
public:
	ThreadWindow(HWND hDialog);
	void InitWindow();
	void InitThread(int index);
	void SetThreadInfo(int index);
	void RemoveLink(int index);
	void SetThread();
	void SetLastSentence(DWORD select);
	void ExportAllThreadText();
	void ExportSingleThreadText(DWORD index, LPCWSTR dir);
private:
	HWND hDlg;
	HWND hcCurrentThread,hcLinkThread;
	HWND hlFromThread;
	HWND heInfo,heSentence,heComment;
};

class HookWindow
{
public:
	HookWindow(HWND hDialog);
	inline bool IsBigEndian();
	inline bool IsUnicode();
	inline bool IsString();
	inline bool IsDataInd();
	inline bool IsSplit();
	inline bool IsSplitInd();
	inline bool IsModule();
	inline bool IsFunction();
	inline bool IsHex();
	inline bool IsLastChar();
	inline bool IsNoContext();
	void GenerateCode();
	void GenerateHash(int ID);
	void RemoveHook();
	void ModifyHook();
	void ResetDialog(const HookParam& hp);
	void ResetDialog(int index);
	void GetHookParam(HookParam& hp);
	void InitDlg();
	void ResetDlgHooks(DWORD pid, HookParam& hp);

private:
	void PrintSignDWORD(LPWSTR str, DWORD d);
	HWND hDlg,hCombo,hText;
	HWND	hcBigEndian,	hcUnicode,	hcString,		hcDataInd,
				hcSplit,			hcSplitInd,	hcModule,	hcFunction,
				hcHex,			hcLastChar,	hcNoContext;
	HWND	heAddr,		heData,			heDataInd,	heSplit,
				heSplitInd,	heModule,	heFunction,	heHash;
	HWND	hbModify,		hbRemove,	hbModule,	hbFunction,	hbCode;
};

class ProfileWindow
{
public:
	ProfileWindow(HWND hDialog);
	~ProfileWindow();
	void InitProfiles();
	void RefreshManifest();
	void RefreshManifestList();
	bool RefreshGames(DWORD index);
	bool RefreshGames(const char* name);
	bool RefreshGamesInMemory(LPVOID memory, DWORD size, const char* hash);
	void RefreshGamesList();
	void FindProperProfile();
	void ImportProfile();
	void RefreshProfile(DWORD index);
	void RefreshProfile(Profile* pf);
	void SetStatusText(LPCWSTR text);
	void SetStatusText(LPCSTR text);
	void ClearStatusText();
	void SetStatusSuccess();
	void ExportProfile();
	void ExportAllProfile();
	void DeleteProfile();
	Profile* GetCurrentProfile();
	DWORD GetCurrentSelect();
	HWND hDlg;
	HWND hlProfileList,hlManifest,hlGameList;
	HWND heProfile,heStatus;
	HWND hcbLink;
	char* base_link;
	TiXmlDocument manifest,game_list;
	AVLTree<char,DWORD,SCMP,SCPY,SLEN> hash_tree;
	PointerTable<char,0x10> hash_table;
	AVLTree<WCHAR,DWORD,WCMP,WCPY,WLEN> game_tree;
	PointerTable<TiXmlElement,0x10> game_table;
};

void ExportSingleProfile(ProfileNode* pfn, MyVector<WCHAR,0x1000,WCMP> &export_text);

class FilterWindow
{
public:
	FilterWindow(HWND hDialog);
	~FilterWindow();
	void Init();
	void SetCurrentChar();
	void SelectCurrentChar(DWORD index);
	void InitWithChar(WCHAR);
	void DeleteCurrentChar();
	void AddNewChar();
	void DrawGlyph(WCHAR);
	void ClearGlyphArea();
	void SetUniChar(WCHAR);
	void SetMBChar(WORD);
	void SetCommitFlag();
	UINT IsSJISCheck();
	UINT IsUnicodeCheck();
private:
	TEXTMETRIC tm;
	RECT rc;
	HWND hDlg;
	HWND hList;
	HWND hGlyph;
	HDC hGlyphDC;
	HBRUSH white;
	HFONT hGlyphFont;
	HWND hSJIS,hUnicode,hChar;
	DWORD init_x,init_y;
	BYTE modify,remove,commit;
	//CustomFilterMultiByte* mb_filter;
	//CustomFilterUnicode* uni_filter;
};

class TextBuffer : MyVector<WCHAR, 0x400>
{
public:
	TextBuffer(HWND edit);
	~TextBuffer();
	void Flush();
	void AddText(LPWSTR str, int len, bool line);
	void ClearBuffer();
	bool Running() {return running;}
private:
	bool line_break,running;
	HANDLE hThread;
	HWND hEdit;
};

