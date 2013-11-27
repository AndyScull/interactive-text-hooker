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
#include "window.h"
#include "resource.h"
#include "language.h"
#include <commctrl.h>
#include <intrin.h>
#include <ITH\IHF.h>
#include <ITH\IHF_SYS.h>
#include <ITH\Hash.h>
#include <ITH\HookManager.h>
#include <ITH\version.h>
#define CMD_SIZE 0x200

LPWSTR import_buffer;
int import_buffer_len;
static WNDPROC proc, proccmd, procChar;
static WCHAR last_cmd[CMD_SIZE];
static CRITICAL_SECTION update_cs;

HWND hMainWnd, hwndCombo, hwndProc, hwndEdit, hwndCmd;
HWND hwndProcess, hwndThread, hwndHook, hwndProfile;
HWND hwndOption, hwndTop, hwndClear, hwndSave;
HWND hProcDlg, hHookDlg, hProfileDlg, hOptionDlg, hThreadDlg, hEditProfileDlg;
HBITMAP hbmp, hBlackBmp;
BITMAP bmp;
HBRUSH hWhiteBrush;
HDC hCompDC, hBlackDC;
BLENDFUNCTION fn;
DWORD repeat_count, background;
HookWindow* hkwnd;
ProcessWindow* pswnd;
ThreadWindow* thwnd;
ProfileWindow* pfwnd;
FilterWindow* ftwnd;
ThreadProfile edit_tp;
LinkProfile edit_lp;
TextBuffer* texts;
extern HookManager* man;
extern ProfileManager* pfman;
extern CustomFilterMultiByte* mb_filter;
extern CustomFilterUnicode* uni_filter;
extern SettingManager* setman;
#define COMMENT_BUFFER_LENGTH 0x200
static WCHAR comment_buffer[COMMENT_BUFFER_LENGTH];

bool Parse(LPWSTR cmd, HookParam& hp);
void SaveSettings();
extern LPVOID DefaultHookAddr[];
extern LPWSTR EngineHookName[], HookNameInitTable[];
extern const DWORD EngineHookNameSize;
extern DWORD split_time,process_time,inject_delay,insert_delay,
	auto_inject,auto_insert,clipboard_flag,cyclic_remove,global_filter,
	window_left,window_right,window_top,window_bottom;
static int last_select, last_edit;
typedef BOOL (CALLBACK* EditFun)(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam);
typedef BOOL (*PostEditFun)(HWND hlEdit, HWND hcmb);
static HINSTANCE hIns;

ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;
	wcex.cbSize = sizeof(WNDCLASSEX);
	wcex.style			= 0;//CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= 0;
	wcex.hCursor		= 0;
	wcex.hbrBackground	= 0;//(HBRUSH)COLOR_BACKGROUND;
	wcex.lpszMenuName	= 0;
	wcex.lpszClassName	= ClassName;
	wcex.hIconSm		= LoadIcon(hInstance, (LPWSTR)IDI_ICON1);
	return RegisterClassEx(&wcex);
}
BOOL InitInstance(HINSTANCE hInstance, DWORD nAdmin, RECT* rc)
{
	hIns = hInstance;
	LPCWSTR name =  (nAdmin) ? ClassNameAdmin : ClassName;
	hMainWnd = CreateWindow(ClassName, name, WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
		rc  ->  left, rc -> top, rc -> right-rc -> left, rc -> bottom-rc -> top, 0, 0, hInstance, 0);
	if (!hMainWnd) return FALSE;
	ShowWindow(hMainWnd, SW_SHOW);
	UpdateWindow(hMainWnd);
	InitializeCriticalSection(&update_cs);

	return TRUE;
}

extern DWORD SaveProcessProfile(DWORD pid);

BOOL CALLBACK OptionDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			WCHAR str[0x80];
			swprintf(str, L"%d", split_time);
			SetWindowText(GetDlgItem(hDlg, IDC_EDIT1), str);
			swprintf(str, L"%d", process_time);
			SetWindowText(GetDlgItem(hDlg, IDC_EDIT2), str);
			swprintf(str, L"%d", inject_delay);
			SetWindowText(GetDlgItem(hDlg, IDC_EDIT3), str);
			swprintf(str, L"%d", insert_delay);
			SetWindowText(GetDlgItem(hDlg, IDC_EDIT4), str);
			swprintf(str, L"%d", repeat_count);
			SetWindowText(GetDlgItem(hDlg, IDC_EDIT5), str);
			CheckDlgButton(hDlg, IDC_CHECK1, auto_inject);
			CheckDlgButton(hDlg, IDC_CHECK2, auto_insert);
			CheckDlgButton(hDlg, IDC_CHECK3, clipboard_flag);
			CheckDlgButton(hDlg, IDC_CHECK4, cyclic_remove);
			CheckDlgButton(hDlg, IDC_CHECK5, global_filter);
			hOptionDlg = hDlg;
			ftwnd = new FilterWindow(hDlg);
			ftwnd -> Init();
		}
		return TRUE;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
				{
					DWORD st, pt, jd, sd, repeat;
					WCHAR str[0x80];
					GetWindowText(GetDlgItem(hDlg, IDC_EDIT1), str, 0x80);
					swscanf(str, L"%d", &st);
					split_time = st > 100?st:100;
					GetWindowText(GetDlgItem(hDlg, IDC_EDIT2), str, 0x80);
					swscanf(str, L"%d", &pt);
					process_time = pt > 50?pt:50;
					GetWindowText(GetDlgItem(hDlg, IDC_EDIT3), str, 0x80);
					swscanf(str, L"%d", &jd);
					inject_delay = jd > 1000?jd:1000;
					GetWindowText(GetDlgItem(hDlg, IDC_EDIT4), str, 0x80);
					swscanf(str, L"%d", &sd);
					insert_delay = sd > 200?sd:200;
					GetWindowText(GetDlgItem(hDlg, IDC_EDIT5), str, 0x80);

					swscanf(str, L"%d", &repeat);
					if (repeat!=repeat_count)
					{
						repeat_count = repeat;
						man -> ResetRepeatStatus();
					}
					auto_inject = IsDlgButtonChecked(hDlg, IDC_CHECK1);
					auto_insert = IsDlgButtonChecked(hDlg, IDC_CHECK2);
					clipboard_flag = IsDlgButtonChecked(hDlg, IDC_CHECK3);
					cyclic_remove = IsDlgButtonChecked(hDlg, IDC_CHECK4);
					global_filter = IsDlgButtonChecked(hDlg, IDC_CHECK5);
					setman->SetValue(SETTING_CLIPFLAG, clipboard_flag);
					setman->SetValue(SETTING_SPLIT_TIME,split_time);
					if (auto_inject == 0) auto_insert = 0;
					ftwnd -> SetCommitFlag();
				}
			case IDCANCEL:
				delete ftwnd;
				EndDialog(hDlg, 0);
				hOptionDlg = 0;
				
				ftwnd = 0;
				break;
			case IDC_BUTTON1: //delete
				ftwnd -> DeleteCurrentChar();
				break;
			case IDC_BUTTON2: //Set
				ftwnd -> SetCurrentChar();
				break;
			case IDC_BUTTON3: //Add
				ftwnd -> AddNewChar();
				break;
			case IDC_EDIT8:
				if (wmEvent == WM_PASTE)
				{
					WCHAR uni_char[4];
					if (GetDlgItemText(hDlg, IDC_EDIT8, uni_char, 8)>=1)
						ftwnd -> InitWithChar(uni_char[0]);				
				}				
				break;
			}
			return TRUE;
		}
	case WM_NOTIFY:
		{
			LPNMHDR dr = (LPNMHDR)lParam;
			switch (dr -> code)
			{
			case NM_CLICK: 
			case LVN_ITEMCHANGED:
				if (dr -> idFrom == IDC_LIST1)
				{
					NMLISTVIEW *nmlv = (LPNMLISTVIEW)lParam;
					if (nmlv -> uNewState == 3)
					{
						ftwnd -> SelectCurrentChar(nmlv -> iItem);
						return TRUE;
					}
						//pswnd -> RefreshThread(nmlv -> iItem);
				}
				
			}
		}
	default:
		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK ThreadDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			thwnd = new ThreadWindow(hDlg);
			hThreadDlg = hDlg;
		}
		return TRUE;
	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDOK:
			case IDCANCEL:
				EndDialog(hDlg, 0);
				hThreadDlg = 0;
				delete thwnd;
				thwnd = 0;
				break;
			case IDC_COMBO1:
				if (wmEvent == CBN_SELENDOK)
					thwnd -> InitThread(SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0));
				break;
			case IDC_COMBO2:
				if (wmEvent == CBN_SELENDOK)
					thwnd -> SetThreadInfo(SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0));
				break;
			case IDC_BUTTON1:
				thwnd -> SetThread();
				break;
			case IDC_BUTTON2:
				{
					HWND combo = GetDlgItem(hDlg, IDC_COMBO1);
					thwnd -> ExportSingleThreadText(SendMessage(combo, CB_GETCURSEL, 0, 0), 0);
				}
				
				break;
			case IDC_BUTTON3:
				thwnd -> ExportAllThreadText();
				break;
			}
			return TRUE;
		}
	default:
		return FALSE;
	}
	return FALSE;
}
BOOL CALLBACK ProcessDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		{
			pswnd = new ProcessWindow(hDlg);
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
				hProcDlg = 0;
				delete pswnd;
				pswnd = 0;
				break;
			case IDC_BUTTON1:
				pswnd -> RefreshProcess();
				break;
			case IDC_BUTTON2:
				pswnd -> AttachProcess();
				break;
			case IDC_BUTTON3:
				pswnd -> DetachProcess();
				break;
			case IDC_BUTTON4:
				pswnd -> OperateThread();
				break;
			case IDC_BUTTON5:
				pswnd -> AddCurrentToProfile();
				break;
			}
		}
		return TRUE;
	case WM_NOTIFY:
		{
			LPNMHDR dr = (LPNMHDR)lParam;
			switch (dr -> code)
			{
			case NM_CLICK: 
			case LVN_ITEMCHANGED:
				if (dr -> idFrom == IDC_LIST1)
				{
					NMLISTVIEW *nmlv = (LPNMLISTVIEW)lParam;
					if (nmlv -> uNewState == 3)
						pswnd -> RefreshThread(nmlv -> iItem);
				}
				break;
			}
		}
		return TRUE;
	default:
		return FALSE;
	}
}
BOOL CALLBACK HookDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		hkwnd = new HookWindow(hDlg);
		hkwnd -> InitDlg();
		break;
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
				delete hkwnd;
				hHookDlg = 0;
				hkwnd = 0;
				break;
			case IDC_COMBO1:
				if (wmEvent == CBN_SELENDOK)
					hkwnd -> ResetDialog(SendMessage((HWND)lParam, CB_GETCURSEL, 0, 0));
				break;
			case IDC_CHECK_HEX:
				CheckDlgButton(hDlg, IDC_CHECK_BIGENDIAN, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_UNICODE, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_STRING, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_LASTCHAR, BST_UNCHECKED);
				break;
			case IDC_CHECK_BIGENDIAN:
				CheckDlgButton(hDlg, IDC_CHECK_STRING, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_LASTCHAR, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_HEX, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_UNICODE, BST_UNCHECKED);

				break;
			case IDC_CHECK_STRING:
				CheckDlgButton(hDlg, IDC_CHECK_BIGENDIAN, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_LASTCHAR, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_HEX, BST_UNCHECKED);
				break;
			case IDC_CHECK_UNICODE:
				CheckDlgButton(hDlg, IDC_CHECK_HEX, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_BIGENDIAN, BST_UNCHECKED);
				break;
			case IDC_CHECK_LASTCHAR:
				CheckDlgButton(hDlg, IDC_CHECK_STRING, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_HEX, BST_UNCHECKED);
				CheckDlgButton(hDlg, IDC_CHECK_BIGENDIAN, BST_UNCHECKED);

				break;
			case IDC_CHECK_SPLIT_IND:
				if (!hkwnd -> IsSplit())
				{
					CheckDlgButton(hDlg, wmId, BST_UNCHECKED);
					SetDlgItemText(hDlg, IDC_EDIT9, L"Need to enable split first!");
					break;
				}
				goto common_route;
			case IDC_CHECK_SPLIT:
				if (hkwnd -> IsSplitInd())
				{
					CheckDlgButton(hDlg, IDC_CHECK_SPLIT_IND, BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg, IDC_EDIT5), FALSE);
				}
				goto common_route;
			case IDC_CHECK_FUNCTION:
				if (!hkwnd -> IsModule())
				{
					CheckDlgButton(hDlg, wmId, BST_UNCHECKED);
					SetDlgItemText(hDlg, IDC_EDIT9, L"Need to enable module first!");
					break;
				}
				goto common_route;
			case IDC_CHECK_MODULE:
				if (hkwnd -> IsFunction())
				{
					CheckDlgButton(hDlg, IDC_CHECK8, BST_UNCHECKED);
					EnableWindow(GetDlgItem(hDlg, IDC_EDIT7), FALSE);
				}
common_route:
			case IDC_CHECK_DATA_IND:
				{
				int off = IDC_EDIT3-IDC_CHECK4; 
				if (IsDlgButtonChecked(hDlg, wmId))
					EnableWindow(GetDlgItem(hDlg, wmId + off), TRUE);
				else
					EnableWindow(GetDlgItem(hDlg, wmId + off), FALSE);
				break;
				}
			case IDC_BUTTON1:
				hkwnd -> ModifyHook();
				break;
			case IDC_BUTTON2:
				hkwnd -> RemoveHook();
				break;
			case IDC_BUTTON3:
			case IDC_BUTTON4:
				hkwnd -> GenerateHash(wmId);
				break;
			case IDC_BUTTON5:
				hkwnd -> GenerateCode();
				break;
			}
		}
		return TRUE;
	case WM_SYSCOMMAND:
	default:
		return FALSE;
	}
	return TRUE;
}
BOOL CALLBACK ProfileDlgProc(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		pfwnd = new ProfileWindow(hDlg);
		hProfileDlg = hDlg;
			

		return TRUE;

	case WM_COMMAND:
		{
			DWORD wmId, wmEvent;
			wmId    = LOWORD(wParam);
			wmEvent = HIWORD(wParam);
			switch (wmId)
			{
			case IDCANCEL:
			case IDOK:
				EndDialog(hDlg, 0);
				hProfileDlg = 0;
				delete pfwnd;
				pfwnd = 0;
				break;
			case IDC_BUTTON2:
				pfwnd->FindProperProfile();
				break;
			case IDC_BUTTON3:
				pfwnd->DeleteProfile();
				break;
			case IDC_BUTTON4:
				pfwnd->ImportProfile();
				break;
			case IDC_BUTTON5:
				pfwnd->ExportProfile();
				break;
			case IDC_BUTTON6:
				pfwnd->ExportAllProfile();
				break;
			case IDC_LIST2:
				if (wmEvent == LBN_SELCHANGE)
				{
					int index = SendMessage((HWND)lParam,LB_GETCURSEL, 0, 0);
					if (index != LB_ERR)
					{
						
						if (pfwnd->RefreshGames(index))
							pfwnd->RefreshGamesList();
					}
				}
				break;
			case IDC_LIST3:
				if (wmEvent == LBN_SELCHANGE)
				{
					int index = SendMessage((HWND)lParam,LB_GETCURSEL, 0, 0);
					if (index != LB_ERR)
					{
						if (pfwnd->GetCurrentSelect() != -1)
						{
							EnableWindow(GetDlgItem(hDlg, IDC_BUTTON4), TRUE);

						}
						pfwnd->GetCurrentSelect();
						pfwnd->RefreshProfile(index);
					}
				}
				break;
			default:
				break;
			}
			return 1;
		}
	case WM_NOTIFY:
		{
			LPNMHDR dr = (LPNMHDR)lParam;
			LPNMLISTVIEW pnmv = (LPNMLISTVIEW) lParam; 
			switch (dr -> code)
			{
			case LVN_ITEMCHANGED:
				{
					if (dr->idFrom == IDC_LIST1)
					{
						if (pnmv->iItem != -1 && pnmv->uNewState == 3)
						{
							EnableWindow(GetDlgItem(hDlg, IDC_BUTTON2), TRUE);
							EnableWindow(GetDlgItem(hDlg, IDC_BUTTON3), TRUE);
							EnableWindow(GetDlgItem(hDlg, IDC_BUTTON5), TRUE);
							EnableWindow(GetDlgItem(hDlg, IDC_BUTTON6), TRUE);
							Profile* pf = pfman->GetProfileByIndex(pnmv->iItem);
							if (pf) pfwnd->RefreshProfile(pf);
						}	
					}
					break;
				}
			default:
				break;
			}
			break;
		}
	default:
		return FALSE;
	}
	return TRUE;
}
LRESULT CALLBACK EditProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_CHAR:  //Filter user input.
			if (GetKeyState(VK_CONTROL)&0xFF00)
			{
				if (wParam == 1)
				{
					SendMessage(hwndEdit, EM_SETSEL, 0, -1);
					SendMessage(hwndEdit, WM_COPY, 0, 0);
				}
			}
			return 0;
	case WM_ERASEBKGND:
		if (background)
		{
			RECT rc, rc2;
			HDC hDC = (HDC)wParam;
			GetClientRect(hwndEdit, &rc);
			rc2 = rc;
			rc2.right = rc2.right < bmp.bmWidth?rc2.right:bmp.bmWidth;
			rc2.bottom = rc2.bottom < bmp.bmHeight?rc2.bottom:bmp.bmHeight;
			//StretchBlt(hDC, 0, 0, rc.right, rc.bottom, hBlackDC, 0, 0, bmp.bmWidth, bmp.bmHeight, SRCCOPY);
			BitBlt(hDC, 0, 0, rc2.right, rc2.bottom, hBlackDC, 0, 0, SRCCOPY);
			if (rc2.right-rc.right < 0)
			{
				rc.left = rc2.right;
				FillRect(hDC, &rc, hWhiteBrush);
				rc.left = 0;
			}
			if (rc2.bottom-rc.bottom < 0)
			{
				rc.top = rc2.bottom;
				FillRect(hDC, &rc, hWhiteBrush);
			}
			
		}
		return 1;
		//else return proc(hWnd, message, wParam, lParam);
		
	case WM_LBUTTONUP:
			if (hwndEdit) SendMessage(hwndEdit, WM_COPY, 0, 0);
	default:
		{
			return proc(hWnd, message, wParam, lParam);	
		}
		
	}
	
}
LRESULT CALLBACK EditCmdProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_KEYDOWN:
		if (wParam == VK_UP)
		{
			SendMessage(hWnd, WM_SETTEXT, 0, (LPARAM)last_cmd);
			SetFocus(hWnd);
			return 0;
		}
		break;
	case WM_CHAR:
		if (wParam == VK_RETURN)
		{
			DWORD s = 0, pid = 0;
			WCHAR str[0x20];
			if (SendMessage(hWnd, WM_GETTEXTLENGTH, 0, 0)==0) break;
			SendMessage(hWnd, WM_GETTEXT, CMD_SIZE, (LPARAM)last_cmd);
			//IthBreak();
			if (GetWindowText(hwndProc, str, 0x20))
				swscanf(str, L"%d", &pid);
			ProcessCommand(last_cmd, pid);
			SendMessage(hWnd, EM_SETSEL, 0, -1);
			SendMessage(hWnd, EM_REPLACESEL, FALSE, (LPARAM)&s);
			SetFocus(hWnd);
			return 0;
		}
	default:
		break;
	}
	return CallWindowProc(proccmd, hWnd, message, wParam, lParam);
}
void CreateButtons(HWND hWnd)
{
	hwndProcess = CreateWindow(L"Button", L"Process", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndThread = CreateWindow(L"Button", L"Thread", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndHook = CreateWindow(L"Button", L"Hook", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndProfile = CreateWindow(L"Button", L"Profile", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndOption = CreateWindow(L"Button", L"Option", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndClear = CreateWindow(L"Button", L"Clear", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndSave = CreateWindow(L"Button", L"Save", WS_CHILD | WS_VISIBLE,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndTop = CreateWindow(L"Button", L"Top", WS_CHILD | WS_VISIBLE | BS_PUSHLIKE | BS_CHECKBOX,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);

	hwndProc = CreateWindow(L"ComboBox", NULL,
		WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | 
		CBS_SORT | WS_VSCROLL | WS_TABSTOP,
		0, 0, 0, 0, hWnd, 0, hIns, NULL); 
	hwndCmd = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL| ES_LEFT | ES_AUTOHSCROLL,
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
	hwndEdit = CreateWindowEx(WS_EX_CLIENTEDGE, L"Edit", NULL,
		WS_CHILD | WS_VISIBLE | ES_NOHIDESEL| WS_VSCROLL |
		ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL, 
		0, 0, 0, 0, hWnd, 0, hIns, NULL);
}
void ClickButton(HWND hWnd, HWND h)
{
	if (h == hwndProcess)
	{
		if(hProcDlg) SetForegroundWindow(hProcDlg);
		else hProcDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG2, 0, ProcessDlgProc);
	}
	else if (h == hwndThread)
	{
		if (hThreadDlg) SetForegroundWindow(hThreadDlg);
		else hThreadDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG5, 0, ThreadDlgProc);
	}
	else if (h == hwndHook)
	{
		if (hHookDlg) SetForegroundWindow(hHookDlg);
		else hHookDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG1, 0, HookDlgProc);
	}
	else if (h == hwndProfile)
	{

		if (hProfileDlg) SetForegroundWindow(hProfileDlg);
		else hProfileDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG3, 0, ProfileDlgProc);

	}
	else if (h == hwndOption)
	{
		if (hOptionDlg) SetForegroundWindow(hOptionDlg);
		else 
		{
			hOptionDlg = CreateDialog(hIns, (LPWSTR)IDD_DIALOG4, 0, OptionDlgProc);
			ftwnd -> ClearGlyphArea();
		}
	}
	else if (h == hwndClear)
	{
		WCHAR pwcEntry[0x80]={};
		DWORD dwId = SendMessage(hwndCombo, CB_GETCURSEL, 0, 0);
		int len = SendMessage(hwndCombo, CB_GETLBTEXT, dwId, (LPARAM)pwcEntry);
		swscanf(pwcEntry, L"%x", &dwId);
		if (dwId == 0) man -> ClearCurrent();
		else man -> RemoveSingleThread(dwId);
	}
	else if (h == hwndTop)
	{
		if (SendMessage(h, BM_GETCHECK , 0, 0)==BST_CHECKED)
		{
			SendMessage(h, BM_SETCHECK , BST_UNCHECKED, 0);
			SetWindowPos(hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProcDlg) SetWindowPos(hProcDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hThreadDlg) SetWindowPos(hThreadDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hHookDlg) SetWindowPos(hHookDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProfileDlg) SetWindowPos(hProfileDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hOptionDlg) SetWindowPos(hOptionDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		}
		else
		{
			SendMessage(h, BM_SETCHECK , BST_CHECKED, 0);
			SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProcDlg) SetWindowPos(hProcDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hThreadDlg) SetWindowPos(hThreadDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hHookDlg) SetWindowPos(hHookDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hProfileDlg) SetWindowPos(hProfileDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
			if (hOptionDlg) SetWindowPos(hOptionDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE | SWP_NOMOVE);
		}
	}
	else if (h == hwndSave)
	{
		WCHAR str[0x20];
		DWORD pid;
		if (GetWindowText(hwndProc, str, 0x10) > 0)
		{
			str[0x10] = 0;
			if (1 == swscanf(str,L"%d",&pid))
			{
				SaveProcessProfile(pid);
				if (pfwnd) pfwnd->InitProfiles();
				pfman->SaveProfile();
			}
		}
	}
}
void LoadBMP(HWND hWnd)
{
	HANDLE hFile = IthCreateFile(L"background.bmp", FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	HDC hDC = GetDC(hwndEdit);	
	if (INVALID_HANDLE_VALUE!=hFile)
	{
		IO_STATUS_BLOCK ios;
		BITMAPFILEHEADER header;
		BITMAPINFOHEADER info;
		LARGE_INTEGER size;
		LPVOID buffer1, buffer2;
		NtReadFile(hFile, 0, 0, 0, &ios, &header, sizeof(header), 0, 0);
		if (header.bfType!=0x4D42) //BM
			MessageBox(0, L"Not valid bmp file.", 0, 0);
		else
		{
			size.LowPart = sizeof(header);
			size.HighPart = 0;
			NtReadFile(hFile, 0, 0, 0, &ios, &info, sizeof(info), 0, 0);									
			hCompDC = CreateCompatibleDC(hDC);
			hBlackDC = CreateCompatibleDC(hDC);				
					
			size.LowPart = header.bfOffBits;

			if (info.biBitCount == 24)
			{
				info.biBitCount = 32;
				hBlackBmp = CreateDIBSection(hBlackDC, (BITMAPINFO*)&info, DIB_RGB_COLORS, &buffer2, 0, 0);		
				hbmp = CreateDIBSection(hCompDC, (BITMAPINFO*)&info, DIB_RGB_COLORS, &buffer1, 0, 0);
				NtReadFile(hFile, 0, 0, 0, &ios, buffer2, info.biWidth*info.biHeight*3, &size, 0);
				BYTE* ptr1 = (BYTE*)buffer1;
				BYTE* ptr2 = (BYTE*)buffer2;
				LONG i, j;
				for (i = 0; i < info.biHeight; i++)
					for (j = 0; j < info.biWidth; j++)
					{
						ptr1[0] = ptr2[0];
						ptr1[1] = ptr2[1];
						ptr1[2] = ptr2[2];
						ptr1[3] = 0xFF;
						ptr1 += 4;
						ptr2 += 3;
					}
				memset(buffer2, 0, info.biWidth*info.biHeight*3);
			}
			else 
			{
				hBlackBmp = CreateDIBSection(hBlackDC, (BITMAPINFO*)&info, DIB_RGB_COLORS, &buffer2, 0, 0);		
				hbmp = CreateDIBSection(hCompDC, (BITMAPINFO*)&info, DIB_RGB_COLORS, &buffer1, 0, 0);
				NtReadFile(hFile, 0, 0, 0, &ios, buffer1, info.biWidth*info.biHeight*info.biBitCount/8, &size, 0);
			}
			
			
			GetObject(hbmp, sizeof(bmp), &bmp);
			SelectObject(hCompDC, hbmp);		
			SelectObject(hBlackDC, hBlackBmp);

			fn.AlphaFormat = AC_SRC_ALPHA;
			fn.BlendOp = AC_SRC_OVER;
			fn.SourceConstantAlpha = 0x80;
			GdiAlphaBlend(hBlackDC, 0, 0, info.biWidth, info.biHeight, hCompDC, 0, 0, info.biWidth, info.biHeight, fn);
			background = 1;
			DeleteDC(hCompDC);
			DeleteObject(hbmp);
		}
		NtClose(hFile);
	}
	ReleaseDC(hwndEdit, hDC);
}
DWORD ThreadFilter(TextThread* thread, BYTE* out,DWORD len, DWORD new_line, PVOID data)
{
	DWORD status = thread->Status();

	if (global_filter && !new_line && thread->Number() != 0)
	{
		if (status & USING_UNICODE)
		{
			DWORD i, j;
			len >>= 1;
			WCHAR c, *str = (LPWSTR)out;
			for (i = 0, j = 0; i < len; i++)
			{
				c = str[i];
				if (!uni_filter->Check(c)) str[j++] = c;

			}
			memset(str + j, 0, (len - j) << 1);
			len = j << 1;
		}
		else
		{
			WORD c;
			DWORD i, j;
			for (i = 0, j = 0; i < len; i++)
			{
				c = out[i];
				if (LeadByteTable[c] == 1)
				{
					if (!mb_filter->Check(c)) out[j++] = c & 0xFF;
				}
				else if (i + 1 < len)
				{

					c = out[i + 1];
					c <<= 8;
					c |= out[i];
					if (!mb_filter->Check(c))
					{
						out[j++] = c & 0xFF;
						out[j++] = c >> 8;
					}
					i++;
				}
			}
			memset(out + j, 0, len - j);
			len = j;
		}
	}
	return len;
}
DWORD ThreadOutput(TextThread* thread, BYTE* out,DWORD len, DWORD new_line, PVOID data)
{
	DWORD status = thread->Status();

	if (status & CURRENT_SELECT)
	{
		if (new_line)
		{
			if (thread->Number() == 0) texts->AddText(L"\r\n",2,true);
			else texts->AddText(L"\r\n\r\n",4,true);
			return len;
		}
		if (status & USING_UNICODE)
		{
			texts->AddText((LPWSTR)out,len >> 1,false);
		}
		else
		{
			WCHAR buffer[0x40]; LPWSTR str;
			DWORD uni_len = MB_WC_count((char*)out,len);
			if (uni_len < 0x40) str = buffer;
			else str = new WCHAR[uni_len + 1];
			MB_WC((char*)out,str);
			str[uni_len] = 0;
			texts->AddText((LPWSTR)str,uni_len,false);
			if (str != buffer) delete str;
		}
	}
	return len;
}
DWORD AddToCombo(TextThread* thread)
{
	int i;
	WCHAR entry[0x200];
	thread->GetEntryString(entry);
	if (SendMessage(hwndCombo,CB_FINDSTRING,0,(LPARAM)entry)==CB_ERR)
	{
		i=SendMessage(hwndCombo,CB_ADDSTRING,0,(LPARAM)entry);
		if (thread->Status()&CURRENT_SELECT) SendMessage(hwndCombo,CB_SETCURSEL,0,(LPARAM)entry);
		return 0;
	}	
	return 1;
}
DWORD RemoveFromCombo(TextThread* thread)
{
	int i,j;
	WCHAR entry[0x200];
	thread->GetEntryString(entry);

	i=SendMessage(hwndCombo,CB_FINDSTRING,0,(LPARAM)entry);
	j=SendMessage(hwndCombo,CB_GETCURSEL,0,0);
	if (i==CB_ERR) return false;
	if (SendMessage(hwndCombo,CB_DELETESTRING,i,0)==CB_ERR) 
		ConsoleOutput(ErrorDeleteCombo);
	return (i==j);
}
DWORD ComboSelectCurrent(TextThread* thread)
{
	DWORD index = thread->Number();
	SendMessage(hwndCombo, CB_SETCURSEL, index , 0);
	return 0;
}
DWORD SetEditText(LPWSTR wc)
{
	DWORD line;
	SendMessage(hwndEdit, WM_SETTEXT, 0, (LPARAM)wc);
	line = SendMessage(hwndEdit, EM_GETLINECOUNT, 0, 0);
	SendMessage(hwndEdit, EM_LINESCROLL, 0, line);
	return 0;
}
DWORD ThreadReset(TextThread* thread)
{
	texts->ClearBuffer();
	man->SetCurrent(thread);
	thread->LockVector();
	DWORD uni = thread->Status() & USING_UNICODE;
	DWORD len = 0,tmp = 0,line = 0;
	LPWSTR wc;
	if (uni)
	{
		wc = (LPWSTR)thread->GetStore(&len);
		len >>= 1;
	}
	else
	{
		len = MB_WC_count((char*)thread->Storage(),thread->Used());
		wc = new WCHAR[len + 1];
		MB_WC((char*)thread->Storage(), wc);
		wc[len] = 0;
	}
	SetEditText(wc);

	if (uni == 0) delete wc;
	thread->UnlockVector();
	WCHAR buffer[0x10];
	swprintf(buffer, L"%.4X", thread->Number());
	tmp = SendMessage(hwndCombo, CB_FINDSTRING , 0 , (LPARAM)buffer);
	if (tmp != CB_ERR) SendMessage(hwndCombo, CB_SETCURSEL, tmp, 0);
	return 0;
}
DWORD ThreadCreate(TextThread* thread)
{
	thread->RegisterOutputCallBack(ThreadOutput,0);
	thread->RegisterFilterCallBack(ThreadFilter,0);
	AddToCombo(thread);
	DWORD i,j,k,t1,t2;
	ThreadParameter* tp = thread->GetThreadParameter();
	ProcessRecord* pr = man->GetProcessRecord(tp->pid);
	if (pr)
	{
		NtWaitForSingleObject(pr->hookman_mutex,0,0);
		Hook* hk = (Hook*)pr->hookman_map;
		for (i = 0; i < MAX_HOOK; i++)
		{
			if (hk[i].Address() == tp->hook)
			{
				if (hk[i].Type() & USING_UNICODE)
					thread->Status() |= USING_UNICODE;
				break;
			}
		}
		NtReleaseMutant(pr->hookman_mutex,0);
	}
	
	Profile* pf = pfman->GetProfile(tp->pid);
	if (pf)
	{
		
		j = pf->thread_count;

		for (i = 0; i < j; i++)
		{
			ThreadProfile* tpf = pf->threads + i;
			if (tpf->hook_addr == tp->hook)
			{
				t1 = tpf->retn;
				t2 = tp->retn;
				if (tpf->flags & THREAD_MASK_RETN)
				{
					t1 &= 0xFFFF; t2 &= 0xFFFF;
				}
				if (t1 == t2)
				{
					t1 = tpf->split;
					t2 = tp->spl;
					if (tpf->flags & THREAD_MASK_SPLIT)
					{
						t1 &= 0xFFFF; t2 &= 0xFFFF;
					}
					if (t1 == t2)
					{
						tpf->hm_index = thread->Number();
						if (tpf->comment)
						{
							RemoveFromCombo(thread);
							thread->SetComment(tpf->comment);
							AddToCombo(thread);						
						}
						for (k = 0; k < pf->link_count; k++)
						{
							LinkProfile* lp = pf->links + k;
							if (lp->from_index == i)
							{
								WORD to_index = pf->threads[lp->to_index].hm_index;
								if (to_index != 0)
									man->AddLink(thread->Number(), to_index);
							}
							if (lp->to_index == i)
							{
								WORD from_index = pf->threads[lp->from_index].hm_index;
								if (from_index != 0)
									man->AddLink(from_index, thread->Number());
							}
						}
						if (pf->select_index == i) ThreadReset(thread);
					}
				}
			}
		}
	}
	return 0;
}
DWORD ThreadRemove(TextThread* thread)
{
	RemoveFromCombo(thread);
	ThreadParameter* tp = thread->GetThreadParameter();
	Profile* pf = pfman->GetProfile(tp->pid);
	if (pf)
	{
		DWORD i,j,t1,t2;
		j = pf->thread_count;

		for (i = 0; i < j; i++)
		{
			ThreadProfile* tpf = pf->threads + i;
			if (tpf->hook_addr == tp->hook)
			{
				t1 = tpf->retn;
				t2 = tp->retn;
				if (tpf->flags & THREAD_MASK_RETN)
				{
					t1 &= 0xFFFF; t2 &= 0xFFFF;
				}
				if (t1 == t2)
				{
					t1 = tpf->split;
					t2 = tp->spl;
					if (tpf->flags & THREAD_MASK_SPLIT)
					{
						t1 &= 0xFFFF; t2 &= 0xFFFF;
					}
					if (t1 == t2)
					{
						tpf->hm_index = 0; //Reset hookman index number.
					}
				}
			}
		}
	}
	return 0;
}
DWORD RegisterProcessList(DWORD pid)
{
	WCHAR str[MAX_PATH],path[MAX_PATH];
	if (GetProcessPath(pid,path))
	{
		swprintf(str,L"%.4d:%s",pid,wcsrchr(path,L'\\')+1);
		SendMessage(hwndProc,CB_ADDSTRING,0,(LPARAM)str);
		if (SendMessage(hwndProc,CB_GETCOUNT,0,0)==1)
			SendMessage(hwndProc,CB_SETCURSEL,0,0);
	}
	pfman->RefreshProfileAddr(pid, path);
	return 0;
}
DWORD RemoveProcessList(DWORD pid)
{
	DWORD i,j,k;
	WCHAR str[MAX_PATH];
	swprintf(str,L"%.4d",pid);
	i=SendMessage(hwndProc,CB_FINDSTRING,0,(LPARAM)str);
	j=SendMessage(hwndProc,CB_GETCURSEL,0,0);
	if (i!=CB_ERR)
	{
		k=SendMessage(hwndProc,CB_DELETESTRING,i,0);
		if (i==j) SendMessage(hwndProc,CB_SETCURSEL,0,0);
	}
	pfman->RefreshProfileAddr(pid, 0);
	return 0;
}
DWORD RefreshProfileOnNewHook(DWORD pid)
{
	WCHAR path[MAX_PATH];
	if (GetProcessPath(pid,path))
		pfman->RefreshProfileAddr(pid, path);
	return 0;
}
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message) 
	{
		case WM_CREATE:
			CreateButtons(hWnd);
			// Add text to the window. 
			SendMessage(hwndEdit, EM_SETLIMITTEXT, -1, 0);
			SendMessage(hwndEdit, WM_INPUTLANGCHANGEREQUEST, 0, 0x411);
			proc = (WNDPROC)SetWindowLong(hwndEdit, GWL_WNDPROC, (LONG)EditProc);
			proccmd = (WNDPROC)SetWindowLong(hwndCmd, GWL_WNDPROC, (LONG)EditCmdProc);
			hwndCombo = CreateWindow(L"ComboBox", NULL,
									WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | 
									CBS_SORT | WS_VSCROLL | WS_TABSTOP,
									0, 0, 0, 0, hWnd, 0, hIns, NULL); 
			{
				HFONT hf = CreateFont(18, 0, 0, 0, FW_LIGHT, 0, 0, 0, SHIFTJIS_CHARSET, 0, 0, ANTIALIASED_QUALITY, 0,
					L"MS Gothic");
				hWhiteBrush = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF));
				SendMessage(hwndCmd, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndEdit, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndCombo, WM_SETFONT, (WPARAM)hf, 0);
				SendMessage(hwndProc, WM_SETFONT, (WPARAM)hf, 0);
				LoadBMP(hWnd);
				texts = new TextBuffer(hwndEdit);
				man->RegisterThreadCreateCallback(ThreadCreate);
				man->RegisterThreadRemoveCallback(ThreadRemove);
				man->RegisterThreadResetCallback(ThreadReset);

				TextThread* console = man->FindSingle(0);			
				console->RegisterOutputCallBack(ThreadOutput,0);
				AddToCombo(console);

				man->RegisterProcessAttachCallback(RegisterProcessList);
				man->RegisterProcessDetachCallback(RemoveProcessList);
				man->RegisterProcessNewHookCallback(RefreshProfileOnNewHook);
				IHF_Start();
				{
					static WCHAR version_info[0x100];
					static const WCHAR program_name[] = L"Interactive Text Hooker";
					static const WCHAR program_version[] = L"3.0";
					swprintf(version_info, L"%s %s (%s)", program_name, program_version, build_date);
					man->AddConsoleOutput(version_info);
					man->AddConsoleOutput(InitMessage);
				}

				if (background == 0) man->AddConsoleOutput(BackgroundMsg);
			}

			return 0; 
		case WM_COMMAND:
			{
				DWORD wmId, wmEvent, dwId;
				wmId    = LOWORD(wParam);
				wmEvent = HIWORD(wParam);
				switch (wmEvent)
				{
				case EN_VSCROLL:
					{
						SCROLLBARINFO info={sizeof(info)};
						GetScrollBarInfo(hwndEdit, OBJID_VSCROLL, &info);
						InvalidateRect(hwndEdit, 0, 1);
						ValidateRect(hwndEdit, &info.rcScrollBar);
						RedrawWindow(hwndEdit, 0, 0, RDW_ERASE);
					}
					break;
				case CBN_SELENDOK:
					{
						if ((HWND)lParam == hwndProc) return 0;

						LPWSTR pwcEntry; int len;
						DWORD num;
						dwId = SendMessage(hwndCombo, CB_GETCURSEL, 0, 0);
						len = SendMessage(hwndCombo, CB_GETLBTEXTLEN, dwId, 0);
						if (len > 0)
						{
							pwcEntry = new WCHAR[len + 1];
							len = SendMessage(hwndCombo, CB_GETLBTEXT, dwId, (LPARAM)pwcEntry);
							if (1 == swscanf(pwcEntry,L"%x",&num))
								man -> SelectCurrent(num);
							delete pwcEntry;
						}
					}
					return 0;
				case BN_CLICKED:
					ClickButton(hWnd, (HWND)lParam);
					break;
				default:
					break;
				}
			}
			break; 
		case WM_SETFOCUS: 
			SetFocus(hwndEdit); 
			return 0; 

		case WM_SIZE: 
			{
				DWORD l = LOWORD(lParam)>>3;
				WORD h = GetDialogBaseUnits()>>16;
				h = h + (h>>1);
				HDC hDC = GetDC(hWnd);
				RECT rc;
				GetClientRect(hWnd, &rc);
				FillRect(hDC, &rc, hWhiteBrush);
				ReleaseDC(hWnd, hDC);
				MoveWindow(hwndProcess, 0, 0, l, h, 1);
				MoveWindow(hwndThread, l, 0, l, h, 1);
				MoveWindow(hwndHook, l*2, 0, l, h, 1);
				MoveWindow(hwndProfile, l*3, 0, l, h, 1);
				MoveWindow(hwndOption, l*4, 0, l, h, 1);
				MoveWindow(hwndTop, l*5, 0, l, h, 1);
				MoveWindow(hwndClear, l*6, 0, l, h, 1);	
				MoveWindow(hwndSave, l*7, 0, LOWORD(lParam)-7*l, h, 1);	

				l<<=1;
				MoveWindow(hwndProc, 0, h, l, 200, 1);
				MoveWindow(hwndCmd, l, h, LOWORD(lParam)-l, h, 1);
				MoveWindow(hwndCombo, 0, h*2, LOWORD(lParam), 200, 1);
				h*=3;
				MoveWindow(hwndEdit, 0, h, LOWORD(lParam), HIWORD(lParam) - h, 0);
			}
			return 0; 
		case WM_ERASEBKGND:
			return 1;
		case WM_DESTROY:

			man->RegisterThreadCreateCallback(0);
			man->RegisterThreadRemoveCallback(0);
			man->RegisterThreadResetCallback(0);
			man->RegisterProcessAttachCallback(0);
			man->RegisterProcessDetachCallback(0);
			delete texts;
			SaveSettings();
			PostQuitMessage(0);
			return 0;
		case WM_CTLCOLOREDIT:
			if (background)
			if ((HWND)lParam == hwndEdit)
			{
				SetTextColor((HDC)wParam, RGB(0xFF, 0xFF, 0xFF));
				SetBkMode((HDC)wParam, TRANSPARENT);
				return 0;
			}

		default:
			return DefWindowProc(hWnd, message, wParam, lParam); 
	}
	return NULL; 
}

int GetHookNameByIndex(LPWSTR str, DWORD pid, DWORD index)
{
	if (pid==0) 
	{
		wcscpy(str,HookNameInitTable[0]);
		return wcslen(HookNameInitTable[0]);
	}
	DWORD len=0;
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == 0) return 0;
	Hook* hks=(Hook*)pr->hookman_map;
	if (hks[index].Address())
	{
		NtReadVirtualMemory(pr->process_handle,hks[index].Name(),str,hks[index].NameLength()<<1,&len);
		len=hks[index].NameLength();
	}
	return len;
}

HookWindow::HookWindow(HWND hDialog) : hDlg(hDialog)
{
	int i;
	HWND* t;
	t=&hcBigEndian;
	for (i = 0; i < 11; i++)
		t[i] = GetDlgItem(hDlg, IDC_CHECK1 + i);
	t=&heAddr;
	for (i = 0; i < 8; i++)
		t[i] = GetDlgItem(hDlg, IDC_EDIT1 + i);
	t=&hbModify;
	for (i = 0; i < 5; i++)
		t[i] = GetDlgItem(hDlg, IDC_BUTTON1 + i);
	hText = GetDlgItem(hDlg, IDC_EDIT9);
	hCombo = GetDlgItem(hDlg, IDC_COMBO1);
}
bool HookWindow::IsBigEndian(){return IsDlgButtonChecked(hDlg, IDC_CHECK_BIGENDIAN)==BST_CHECKED;}
bool HookWindow::IsUnicode(){return IsDlgButtonChecked(hDlg, IDC_CHECK_UNICODE)==BST_CHECKED;}
bool HookWindow::IsString(){return IsDlgButtonChecked(hDlg, IDC_CHECK_STRING)==BST_CHECKED;}
bool HookWindow::IsDataInd(){return IsDlgButtonChecked(hDlg, IDC_CHECK_DATA_IND)==BST_CHECKED;}
bool HookWindow::IsSplit(){return IsDlgButtonChecked(hDlg, IDC_CHECK_SPLIT)==BST_CHECKED;}
bool HookWindow::IsSplitInd(){return IsDlgButtonChecked(hDlg, IDC_CHECK_SPLIT_IND)==BST_CHECKED;}
bool HookWindow::IsModule(){return IsDlgButtonChecked(hDlg, IDC_CHECK_MODULE)==BST_CHECKED;}
bool HookWindow::IsFunction(){return IsDlgButtonChecked(hDlg, IDC_CHECK_FUNCTION)==BST_CHECKED;}
bool HookWindow::IsHex(){return IsDlgButtonChecked(hDlg, IDC_CHECK_HEX)==BST_CHECKED;}
bool HookWindow::IsLastChar(){return IsDlgButtonChecked(hDlg, IDC_CHECK_LASTCHAR)==BST_CHECKED;}
bool HookWindow::IsNoContext(){return IsDlgButtonChecked(hDlg, IDC_CHECK_NOCONTEXT)==BST_CHECKED;}
void HookWindow::GenerateCode()
{
	WCHAR code[0x200];
	DWORD pid, i, addr;
	if (CB_ERR == SendMessage(hCombo, CB_GETCURSEL, 0, 0)) return;
	GetWindowText(hCombo, code, 0x80);
	swscanf(code, L"%d:0x%x", &pid, &addr);
	HookParam hp;
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == 0) return;
	//Hook* hks = (Hook*)man -> RemoteHook(pid);
	Hook* hks = (Hook*)pr->hookman_map;

	for (i = 0; i < MAX_HOOK; i++)
	{
		if (hks[i].Address()==addr)
		{
			if (hks[i].Type()&EXTERN_HOOK)
				MessageBox(0, L"Special hook, no AGTH equivalent.", L"Warning", 0);
			else
			{
				GetHookParam(hp);
				GetCode(hp, code, pid);
				SetDlgItemText(hDlg, IDC_EDIT9, code);
			}
			break;
		}
	}
}
void HookWindow::GenerateHash(int ID)
{
	WCHAR str[0x20], text[0x80];
	GetDlgItemText(hDlg, IDC_EDIT8, text, 0x80);
	if (ID == IDC_BUTTON3) _wcslwr(text);
	swprintf(str, L"%X", Hash(text));
	SetDlgItemText(hDlg, ID-6, str);
}
void HookWindow::GetHookParam(HookParam& hp)
{
	WCHAR str[0x80], code[0x80], *ptr;
	memset(&hp, 0, sizeof(hp));
	ptr = code;
	if (IsNoContext()) hp.type |= NO_CONTEXT;
	if (IsHex()) {hp.type |= USING_UNICODE | PRINT_DWORD; hp.length_offset = 0;}
	else if (IsUnicode())
	{
		hp.type |= USING_UNICODE;
		if (IsString()) hp.type |= USING_STRING;
		else 
		{
			hp.length_offset = 1;
			if (IsLastChar()) hp.type |= STRING_LAST_CHAR;
		}
	}
	else
	{
		if (IsString()) hp.type |= USING_STRING;
		else
		{
			hp.length_offset = 1;
			if (IsBigEndian()) hp.type |= BIG_ENDIAN;
			if (IsLastChar()) hp.type |= STRING_LAST_CHAR;
		}
	}
	GetWindowText(heAddr, str, 0x80);
	swscanf(str, L"%x", &hp.addr);
	GetWindowText(heData, str, 0x80);
	swscanf(str, L"%x", &hp.off);
	if (IsDataInd())
	{
		hp.type |= DATA_INDIRECT;
		GetWindowText(heDataInd, str, 0x80);
		swscanf(str, L"%x", &hp.ind);
	}
	if (IsSplit())
	{
		hp.type |= USING_SPLIT;
		GetWindowText(heSplit, str, 0x80);
		swscanf(str, L"%x", &hp.split);
	}
	if (IsSplitInd())
	{
		hp.type |= SPLIT_INDIRECT;
		GetWindowText(heSplitInd, str, 0x80);
		swscanf(str, L"%x", &hp.split_ind);
	}
	if (IsModule())
		hp.type |= MODULE_OFFSET;
	GetWindowText(heModule, str, 0x80);
	swscanf(str, L"%x", &hp.module);
	if (IsFunction())
		hp.type |= FUNCTION_OFFSET;
	GetWindowText(heFunction, str, 0x80);
	swscanf(str, L"%x", &hp.function);
}
void HookWindow::ResetDialog(const HookParam &hp)
{
	WCHAR str[0x80];
	swprintf(str, L"%X", hp.addr);
	SetDlgItemText(hDlg, IDC_EDIT1, str);
	PrintSignDWORD(str, hp.off);
	SetDlgItemText(hDlg, IDC_EDIT2, str);
	PrintSignDWORD(str, hp.ind);
	SetDlgItemText(hDlg, IDC_EDIT3, str);
	PrintSignDWORD(str, hp.split);
	SetDlgItemText(hDlg, IDC_EDIT4, str);
	PrintSignDWORD(str, hp.split_ind);
	SetDlgItemText(hDlg, IDC_EDIT5, str);
	swprintf(str, L"%X", hp.module);
	SetDlgItemText(hDlg, IDC_EDIT6, str);
	swprintf(str, L"%X", hp.function);
	SetDlgItemText(hDlg, IDC_EDIT7, str);
	for (int i = 0; i < 11; i++)
		CheckDlgButton(hDlg, IDC_CHECK1 + i, BST_UNCHECKED);
	for (int i = 0; i < 5; i++)
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT3 + i), TRUE);
	if (hp.type&NO_CONTEXT)
		CheckDlgButton(hDlg, IDC_CHECK11, BST_CHECKED);	
	if (hp.type&PRINT_DWORD)
		CheckDlgButton(hDlg, IDC_CHECK9, BST_CHECKED);
	if (hp.type&DATA_INDIRECT)
		CheckDlgButton(hDlg, IDC_CHECK4, BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT3), FALSE);

	if (hp.type&USING_SPLIT)
		CheckDlgButton(hDlg, IDC_CHECK5, BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT4), FALSE);

	if (hp.type&SPLIT_INDIRECT)
		CheckDlgButton(hDlg, IDC_CHECK6, BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT5), FALSE);

	if (hp.type&MODULE_OFFSET)
		CheckDlgButton(hDlg, IDC_CHECK7, BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT6), FALSE);

	if (hp.type&FUNCTION_OFFSET)
		CheckDlgButton(hDlg, IDC_CHECK8, BST_CHECKED);
	else
		EnableWindow(GetDlgItem(hDlg, IDC_EDIT7), FALSE);

	if (hp.type&BIG_ENDIAN) CheckDlgButton(hDlg, IDC_CHECK1, BST_CHECKED);
	if (hp.type&USING_UNICODE) CheckDlgButton(hDlg, IDC_CHECK2, BST_CHECKED);
	if (hp.type&USING_STRING) CheckDlgButton(hDlg, IDC_CHECK3, BST_CHECKED);
}
void HookWindow::ResetDialog(int index)
{
	if (index < 0) return;
	DWORD pid, addr;
	WCHAR pwcEntry[0x100]={};
	int len = SendMessage(hCombo, CB_GETLBTEXT, index, (LPARAM)pwcEntry);
	swscanf(pwcEntry, L"%d:0x%x", &pid, &addr);
	//man -> LockProcessHookman(pid);
	ProcessRecord* pr = man->GetProcessRecord(pid);
	if (pr == 0) return;
	NtWaitForSingleObject(pr->hookman_mutex,0,0);
	Hook* hk = (Hook*)pr->hookman_map;
	while (hk -> Address()!=addr) hk++;
	HookParam hp;
	memcpy(&hp, hk, sizeof(hp));
	NtReleaseMutant(pr->hookman_mutex,0);
	//man -> UnlockProcessHookman(pid);
	ResetDialog(hp);
}
void HookWindow::RemoveHook()
{
	WCHAR str[0x80]; DWORD pid, addr;
	int k = SendMessage(hCombo, CB_GETCURSEL, 0, 0);
	if (k == CB_ERR) return;
	
	GetWindowText(hCombo, str, 0x80);
	swscanf(str, L"%d:0x%x", &pid, &addr);
	IHF_RemoveHook(pid,addr);
	SendMessage(hCombo, CB_DELETESTRING, k, 0);
	SendMessage(hCombo, CB_SETCURSEL, 0, 0);
	ResetDialog(0);
}
void HookWindow::ModifyHook()
{
	DWORD pid;
	WCHAR str[0x80];
	HookParam hp;
	int k = SendMessage(hCombo, CB_GETCURSEL, 0, 0);
	if (k == CB_ERR) return;
	GetWindowText(hCombo, str, 0x80);
	swscanf(str, L"%d", &pid);
	GetHookParam(hp);
	IHF_ModifyHook(pid, &hp);
	SendMessage(hCombo, CB_DELETESTRING, k, 0);
	SendMessage(hCombo, CB_SETCURSEL, 0, 0);
	ResetDlgHooks(pid, hp);
	ResetDialog(hp);
}
void HookWindow::ResetDlgHooks(DWORD pid, HookParam& hp)
	//hp.addr should be the target hook address.
{
	WCHAR str[0x200];
	LPWSTR ptr;
	DWORD len = 0x1000;
	ProcessRecord* record = man -> Records();
	SendMessage(hCombo, CB_RESETCONTENT, 0, 0);
	Hook *hks;
	int i, j, k;	
	for (j = 0; record[j].pid_register; j++)
	{
		NtWaitForSingleObject(record[j].hookman_mutex,0,0);
		//man -> LockProcessHookman(record[j].pid_register);
		//index = (Hook*)man -> RemoteHook(record[j].pid_register);
		hks = (Hook*)record[j].hookman_map;
		//hks = (Hook*)man -> RemoteHook(record[j].pid_register);
		for (i = 0; i < MAX_HOOK; i++)
		{
			if (hks[i].Address()==0) continue;
			ptr = str;
			ptr += swprintf(ptr, L"%4d:0x%08X:", record[j].pid_register, hks[i].Address());
			GetHookNameByIndex(ptr, record[j].pid_register, i);
			//GetHookString(str, record[j].pid_register, index -> Address(), index -> Type());
			if (SendMessage(hCombo, CB_FINDSTRING, 0, (LPARAM)str)==CB_ERR)
				k = SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)str);
			if (hp.addr == hks[i].Address()&&pid == record[j].pid_register)
			{
				memcpy(&hp, hks + i, sizeof(HookParam));
				SendMessage(hCombo, CB_SETCURSEL, k, 0);
			}
		}
		NtReleaseMutant(record[j].hookman_mutex,0);
		//man -> UnlockProcessHookman(record[j].pid_register);
	}
}
void HookWindow::InitDlg()
{
	HookParam hp={};
	DWORD pid=0;
	WCHAR str[0x20];
	if (GetWindowText(hwndProc,str,0x20))
	{
		swscanf(str,L"%d",&pid);
		hp.addr = man -> GetCurrentThread() -> Addr();
		ResetDlgHooks(pid, hp);
		ResetDialog(hp);
	}
}
void HookWindow::PrintSignDWORD(LPWSTR str, DWORD d)
{
	if (d&0x80000000)
	{
		str[0] = L'-';
		swprintf(str + 1, L"%X", -d);
	}
	else
		swprintf(str, L"%X", d);
}

ProcessWindow::ProcessWindow(HWND hDialog) : hDlg(hDialog)
{
	HWND* t;
	t=&hbRefresh;
	for (int i = 0; i < 5; i++)
		t[i] = GetDlgItem(hDlg, IDC_BUTTON1 + i);
	EnableWindow(hbAddProfile, 0);
	hlProcess = GetDlgItem(hDlg, IDC_LIST1);
	hlThread = GetDlgItem(hDlg, IDC_LIST2);
	heOutput = GetDlgItem(hDlg, IDC_EDIT1);
	heAddr = GetDlgItem(hDlg, IDC_EDIT2);
	t=&hrSuspend;
	for (int i = 0; i < 3; i++)
		t[i] = GetDlgItem(hDlg, IDC_RADIO1 + i);
	ListView_SetExtendedListViewStyleEx(hlProcess, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	InitProcessDlg();
	RefreshProcess();
	
	ListView_SetExtendedListViewStyleEx(hlThread, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
}
void ProcessWindow::InitProcessDlg()
{
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_RIGHT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"PID";	
	ListView_InsertColumn(hlProcess, 0, &lvc);
	lvc.cx = 60;
	lvc.pszText = L"Memory";	
	ListView_InsertColumn(hlProcess, 1, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Name";	
	ListView_InsertColumn(hlProcess, 2, &lvc);

	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"TID";	
	ListView_InsertColumn(hlThread, 0, &lvc);
	lvc.cx = 80;
	lvc.pszText = L"Start";	
	ListView_InsertColumn(hlThread, 1, &lvc);
	lvc.cx = 100;
	lvc.pszText = L"Module";	
	ListView_InsertColumn(hlThread, 2, &lvc);
	lvc.cx = 100;
	lvc.pszText = L"State";	
	ListView_InsertColumn(hlThread, 3, &lvc);
}
void ProcessWindow::RefreshProcess() 
{ 
	ListView_DeleteAllItems(hlProcess);
	ListView_DeleteAllItems(hlThread);
	LVITEM item={};
	item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE; 
	MyStack <HANDLE, 0x100> stk;
	DWORD dwSize = 0, retn = 0;
	PVOID pBuffer = 0;
	NTSTATUS status = 0;
	status = NtQuerySystemInformation(SystemProcessInformation, &dwSize, dwSize, &dwSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) return;
	dwSize = (dwSize & 0xFFFFF000) + 0x4000;
	NtAllocateVirtualMemory(NtCurrentProcess(), &pBuffer, 0, &dwSize, MEM_COMMIT, PAGE_READWRITE);
	status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &retn);
	if (!NT_SUCCESS(status)) return;

	SYSTEM_PROCESS_INFORMATION *spiProcessInfo;
	HANDLE hProcess;
	DWORD ws, size, flag64, wow64;
	if (!NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &flag64, 4, 0)))
		flag64 = 0;
	OBJECT_ATTRIBUTES attr={};
	CLIENT_ID id;
	WCHAR pwcBuffer[0x100];
	attr.uLength = sizeof(attr);
	id.UniqueThread = 0;
	item.pszText = pwcBuffer;
	for (spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)pBuffer; spiProcessInfo -> dNext;)
	{
		spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*)
			((DWORD)spiProcessInfo + spiProcessInfo -> dNext);
		id.UniqueProcess = spiProcessInfo -> dUniqueProcessId;
		if (NT_SUCCESS(NtOpenProcess(&hProcess,
			PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ|
			PROCESS_VM_WRITE | PROCESS_VM_OPERATION, &attr, &id)))
		{
			if (flag64)
			{
				if (NT_SUCCESS(NtQueryInformationProcess(hProcess, ProcessWow64Information, &wow64, 4, 0)))
				{
					if (wow64 == 0) 
					{
						NtClose(hProcess);
						continue;
					}
				}
			}
			stk.push_back(hProcess);
			swprintf(pwcBuffer, L"%d", spiProcessInfo -> dUniqueProcessId);
			item.lParam = spiProcessInfo -> dUniqueProcessId;
			ListView_InsertItem(hlProcess, &item);
			ListView_SetItemText(hlProcess, item.iItem, 2, spiProcessInfo -> usName.Buffer);
		}
	}
	while (stk.size())
	{
		GetProcessMemory(stk.back(), size, ws);
		swprintf(pwcBuffer, L"%dK", size);
		ListView_SetItemText(hlProcess, item.iItem++, 1, pwcBuffer);
		NtClose(stk.back());
		stk.pop_back();
	}

	NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &dwSize, MEM_RELEASE);
	EnableWindow(hbDetach, FALSE);
}
void ProcessWindow::AttachProcess()
{			
	LVITEM item={};
	item.mask = LVIF_PARAM;
	item.iItem = ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess, &item);
	DWORD pid = item.lParam;
	if (IHF_InjectByPID(pid, ITH_DEFAULT_ENGINE) != -1) 
	{
		SetWindowText(heOutput, L"Attach ITH to process successfully.");
		EnableWindow(hbDetach, TRUE);
		WCHAR path[MAX_PATH];
		EnableWindow(hbAddProfile, TRUE);
		if (GetProcessPath(pid, path))
		{
			if (pfman -> IsPathProfile(path))
				EnableWindow(hbAddProfile, FALSE);
		}
		EnableWindow(hbAttach, FALSE);
		RefreshThreadColumns(item.lParam);
	}
	else 
		SetWindowText(heOutput, L"Failed to attach ITH to process.");
}
void ProcessWindow::DetachProcess()
{
	DWORD pid = GetSelectPID();
	if (IHF_ActiveDetachProcess(pid)==0) 
	{
		SetWindowText(heOutput, L"ITH detach from process.");
		EnableWindow(hbDetach, FALSE);
		EnableWindow(hbAddProfile, FALSE);
		EnableWindow(hbAttach, TRUE);
		RefreshThreadColumns(pid);
	}
	else SetWindowText(heOutput, L"Detach failed.");
}
void ProcessWindow::OperateThread()
{
	int i, e;
	for (i = 0; i < 3&&IsDlgButtonChecked(hDlg, IDC_RADIO1 + i)==BST_UNCHECKED; i++);
	if (i == 3) return;
	ThreadOperation op = (ThreadOperation)i;
	LVITEM item={};
	item.mask = LVIF_PARAM;
	item.iItem = ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess, &item);
	DWORD pid = item.lParam;
	if (GetWindowTextLength(heAddr))
	{
		WCHAR text[0x10];
		DWORD addr;
		GetWindowText(heAddr, text, 0xF);
		swscanf(text, L"%x", &addr);
		e = ListView_GetItemCount(hlThread);
		for (i = 0; i < e; i++)
		{
			item.iItem = i;
			ListView_GetItem(hlThread, &item);
			PerformThread(0, item.lParam, op, addr);
		}
	}
	else
	{
		LVITEM item={};
		item.mask = LVIF_PARAM;
		item.iItem = ListView_GetSelectionMark(hlThread);
		if (item.iItem == -1) return;
		ListView_GetItem(hlThread, &item);
		PerformThread(0, item.lParam, op, 0);
	}
	RefreshThreadColumns(pid);
}
void ProcessWindow::AddCurrentToProfile()
{
	LVITEM item={};
	item.mask = LVIF_PARAM;
	item.iItem = ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess, &item);
	WCHAR path[MAX_PATH];
	printf("GetProcessPath\n");
	if (GetProcessPath(item.lParam, path))
	{
		if (pfman -> IsPathProfile(path)) 
			SetWindowText(heOutput, L"Profile already exists.");
		else
		{
			Profile *pf = new Profile;		
			pf->title = SaveProcessTitle(item.lParam);
			if (-1 != pfman->AddProfile(path, pf))
			{
				pfman->RefreshProfileXml(path);
				pfman->RefreshProfileAddr(item.lParam, path);				
				SetWindowText(heOutput, L"Profile added");
				if (pfwnd) pfwnd->InitProfiles();
			}
			else
			{
				SetWindowText(heOutput, L"Already exist");
				delete pf;
			}
			EnableWindow(hbAddProfile, 0);
		}
	}
	else SetWindowText(heOutput, L"Fail to add profile");
}
void ProcessWindow::RefreshThread(int index)
{
	WCHAR path[MAX_PATH];
	LVITEM item={};
	item.mask = LVIF_PARAM;
	item.iItem = index;
	ListView_GetItem(hlProcess, &item);
	RefreshThreadColumns(item.lParam);
	BOOL enable = (man -> GetProcessRecord(item.lParam) != 0);
	EnableWindow(hbDetach, enable);
	EnableWindow(hbAttach, !enable);
	if (GetProcessPath(item.lParam, path))
		if (pfman -> IsPathProfile(path)) enable = 0;
	EnableWindow(hbAddProfile, enable);
	if (item.lParam == current_process_id) 
		EnableWindow(hbAttach, FALSE);
	SetWindowText(heOutput, L"");
}
void ProcessWindow::RefreshThreadColumns(DWORD pid)
{
	static LPWSTR StateString[StateUnknown+1]={
		L"Initialized",L"Ready",L"Running",L"Standby",
		L"Terminated",L"Wait",L"Transition",L"Unknown"
	};
	static LPWSTR WaitReasonString[MaximumWaitReason]={
		L"Executive",L"FreePage",L"PageIn",L"PoolAllocation",
		L"DelayExecution",L"Suspended",L"UserRequest",L"Executive",
		L"FreePage",L"PageIn",L"PoolAllocation",L"DelayExecution",
		L"Suspended",L"UserRequest",L"EventPair",L"Queue",
		L"LpcReceive",L"LpcReply",L"VirtualMemory",L"PageOut",
		L"Rendezvous",L"Spare2",L"Spare3",L"Spare4",
		L"Spare5",L"Spare6",L"Kernel"
	};
	ListView_DeleteAllItems(hlThread);

	DWORD dwSize = 0;
	PVOID pBuffer = 0;
	NTSTATUS status;

	status = NtQuerySystemInformation(SystemProcessInformation, &dwSize, 0, &dwSize);
	if (status != STATUS_INFO_LENGTH_MISMATCH) return;
	dwSize = (dwSize & 0xFFFFF000) + 0x4000;
	NtAllocateVirtualMemory(NtCurrentProcess(),&pBuffer, 0, &dwSize, MEM_COMMIT, PAGE_READWRITE);
	status = NtQuerySystemInformation(SystemProcessInformation, pBuffer, dwSize, &dwSize);
	if (!NT_SUCCESS(status)) return;

	SYSTEM_PROCESS_INFORMATION *spiProcessInfo = (SYSTEM_PROCESS_INFORMATION *)pBuffer;
	for (
		status = 0; 
		spiProcessInfo->dNext;
	)
	{
		spiProcessInfo = (SYSTEM_PROCESS_INFORMATION*) ((DWORD)spiProcessInfo + spiProcessInfo->dNext);
		if(pid == spiProcessInfo->dUniqueProcessId)
		{
			status = 1;
			break;
		}
	}
	if (status == 0) return;

	SYSTEM_THREAD* base = (SYSTEM_THREAD*)((DWORD)spiProcessInfo + sizeof(SYSTEM_PROCESS_INFORMATION));
	DWORD dwLimit = (DWORD)spiProcessInfo -> usName.Buffer;
	//int i = 0;
	while ((DWORD)base < dwLimit)
	{
		PerformThread(base);
		LPWSTR state= (base -> dThreadState == StateWait)?				
			WaitReasonString[base -> WaitReason] : StateString[base -> dThreadState];
		ListView_SetItemText(hlThread, 0, 3, state);
		base++;
		//i++;
	}
	NtFreeVirtualMemory(NtCurrentProcess(), &pBuffer, &dwSize, MEM_RELEASE);
}
bool ProcessWindow::PerformThread(PVOID system_thread)
{
	PSYSTEM_THREAD st = (PSYSTEM_THREAD)system_thread;
	HANDLE hThread, hProc;
	NTSTATUS status;
	PVOID address = 0;
	OBJECT_ATTRIBUTES oa = {sizeof(oa)};
	if (!NT_SUCCESS(NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &st->Cid))) return false;
	
	status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &address, sizeof(address), 0);
	if (!NT_SUCCESS(status)) return false;
	if (address == 0) address = st->pStartAddress;
	NtClose(hThread);
	LVITEM item={};
	item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE; 

	WCHAR name[0x100], str[0x100];
	item.pszText = str;
	if (!NT_SUCCESS(NtOpenProcess(&hProc, PROCESS_QUERY_INFORMATION, &oa, &st->Cid)))
		return false;

	swprintf(str, L"%d", st->Cid.UniqueThread);
	item.lParam = st->Cid.UniqueThread;
	ListView_InsertItem(hlThread, &item);
	swprintf(str, L"%X", address);
	ListView_SetItemText(hlThread, item.iItem, 1, str);
	if (NT_SUCCESS(NtQueryVirtualMemory(hProc, address,
		MemorySectionName, name, 0x200, 0)))
		ListView_SetItemText(hlThread, item.iItem, 2, wcsrchr(name, L'\\') + 1);
	NtClose(hProc);
	return true;
}
bool ProcessWindow::PerformThread(DWORD pid, DWORD tid, ThreadOperation op, DWORD addr)
{
	if (tid == 0) return false;
	HANDLE hThread, hProc;
	CLIENT_ID id;
	NTSTATUS status;
	OBJECT_ATTRIBUTES att={};
	att.uLength = sizeof(att);
	id.UniqueProcess = pid;
	id.UniqueThread = tid;
	DWORD right = THREAD_QUERY_INFORMATION;
	switch(op)
	{
	case Suspend:
	case Resume:
		right |= THREAD_SUSPEND_RESUME;
		break;
	case	Terminate:
		right |= THREAD_TERMINATE;
		break;
	}
	if (!NT_SUCCESS(NtOpenThread(&hThread, right, &att, &id))) return false;
	THREAD_WIN32_START_ADDRESS_INFORMATION address;
	status = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &address, sizeof(address), 0);
	if (!NT_SUCCESS(status)) return false;
	if (addr == 0||addr==(DWORD)address.Win32StartAddress)
	{
		switch (op)
		{
		case OutputInformation:
		{
			LVITEM item={};
			item.mask = LVIF_TEXT | LVIF_PARAM | LVIF_STATE; 

			WCHAR name[0x100], str[0x100];
			item.pszText = str;
			id.UniqueProcess = pid;
			id.UniqueThread = 0;
			if (!NT_SUCCESS(NtOpenProcess(&hProc, PROCESS_QUERY_INFORMATION, &att, &id)))
				return false;
			if (!NT_SUCCESS(NtQueryVirtualMemory(hProc, address.Win32StartAddress,
				MemorySectionName, name, 0x200, 0))) return false;

			swprintf(str, L"%d", tid);
			item.lParam = tid;
			ListView_InsertItem(hlThread, &item);
			swprintf(str, L"%X", address.Win32StartAddress);
			ListView_SetItemText(hlThread, item.iItem, 1, str);
			ListView_SetItemText(hlThread, item.iItem, 2, wcsrchr(name, L'\\') + 1);
			status = 0;
		}
		break;
		case Suspend:
			status = NtSuspendThread(hThread, 0);
			break;
		case Resume:
			status = NtResumeThread(hThread, 0);
			break;
		case Terminate:
			status = NtTerminateThread(hThread, 0);
			break;
		}
		NtClose(hThread);
		NtClose(hProc);
	}
	return true;
}
DWORD ProcessWindow::GetSelectPID()
{
	LVITEM item={};
	item.mask = LVIF_PARAM;
	item.iItem = ListView_GetSelectionMark(hlProcess);
	ListView_GetItem(hlProcess, &item);
	return item.lParam;
}

ThreadWindow::ThreadWindow(HWND hDialog)
{
	hDlg = hDialog;
	hcCurrentThread = GetDlgItem(hDlg, IDC_COMBO1);
	hcLinkThread = GetDlgItem(hDlg, IDC_COMBO2);
	hlFromThread = GetDlgItem(hDlg, IDC_LIST1);
	heSentence = GetDlgItem(hDlg, IDC_EDIT1);
	heInfo = GetDlgItem(hDlg, IDC_EDIT2);
	heComment = GetDlgItem(hDlg, IDC_EDIT3);
	InitWindow();
}
void ThreadWindow::InitWindow()
{
	WCHAR entry_string[0x200];
	entry_string[0] = 0;
	SetWindowText(heInfo, entry_string);
	SetWindowText(heSentence, entry_string);
	SendMessage(hcCurrentThread, CB_RESETCONTENT, 0, 0);
	SendMessage(hcLinkThread, CB_RESETCONTENT, 0, 0);
	SendMessage(hlFromThread, LB_RESETCONTENT, 0, 0);

	man -> LockHookman();
	TextThread* it;
	ThreadTable* table = man -> Table();
	for (int i = 0; i <= table -> Used(); i++)
	{

		it = table -> FindThread(i);
		if (it == 0) continue;
		it -> GetEntryString(entry_string);
		SendMessage(hcCurrentThread, CB_ADDSTRING, 0, (LPARAM)entry_string);		
	}
	man -> UnlockHookman();
	man -> GetCurrentThread() -> GetEntryString(entry_string);
	int i = SendMessage(hcCurrentThread, CB_FINDSTRING, 0, (LPARAM)entry_string);
	SendMessage(hcCurrentThread, CB_SETCURSEL, i, 0);
	InitThread(i);
}
void ThreadWindow::InitThread(int index)
{
	WCHAR entry_string[0x100]; WORD number, link_num;
	TextThread *it, *cur, *curl; DWORD num;
	SendMessage(hcCurrentThread, CB_GETLBTEXT, index, (LPARAM)entry_string);
	swscanf(entry_string, L"%X", &num);
	number = num&0xFFFF;
	man -> LockHookman();
	cur = man -> FindSingle(number);
	curl = cur -> Link();
	cur -> Link() = 0;
	link_num = cur -> LinkNumber();
	cur -> LinkNumber()=-1;
	SendMessage(hlFromThread, LB_RESETCONTENT, 0, 0);
	SendMessage(hcLinkThread, CB_RESETCONTENT, 0, 0);
	SendMessage(hcLinkThread, CB_ADDSTRING, 0, (LPARAM)L"_None");
	entry_string[0] = 0;
	SetWindowText(heInfo, entry_string);
	SetWindowText(heSentence, entry_string);
	ThreadTable* table = man -> Table();
	for (int i = 0; i <= table -> Used(); i++)
	{
		it = table -> FindThread(i);
		if (it == 0) continue;
		swprintf(entry_string, L"%.4X", it -> Number());
		if (it -> LinkNumber()==number)
			SendMessage(hlFromThread, LB_ADDSTRING, 0, (LPARAM)entry_string);
		if (!it -> CheckCycle(cur)) 
			SendMessage(hcLinkThread, CB_ADDSTRING, 0, (LPARAM)entry_string);
	}
	cur -> Link() = curl;
	cur -> LinkNumber() = link_num;
	if (curl)
	{
		swprintf(entry_string, L"%.4X", link_num);
		int i = SendMessage(hcLinkThread, CB_FINDSTRINGEXACT, 0, (LPARAM)entry_string);
		if (i!=CB_ERR) 
		{
			SendMessage(hcLinkThread, CB_SETCURSEL, i, 0);
			SetThreadInfo(i);
		}
	}
	else SendMessage(hcLinkThread, CB_SETCURSEL, 0, 0);
	SetLastSentence(number);
	man -> UnlockHookman();
	SetWindowText(heComment, cur -> GetComment());
}
void ThreadWindow::SetThreadInfo(int index)
{

	if (index == -1) return;
	WCHAR str[0x200]; 
	str[0] = 0;
	if (index == 0)
	{
		SetWindowText(heInfo, str);
		SetWindowText(heSentence, str);
		return;
	}
	int i, j = SendMessage(hcLinkThread, CB_GETLBTEXT, index, (LPARAM)str);
	swscanf(str, L"%X", &j);
	TextThread *it = man -> FindSingle(j);
	if (it)
	{
		it -> GetEntryString(str);
		SetWindowText(heInfo, str);
		str[0] = L'\r';
		str[1] = L'\n';
		while (it = it -> Link())
		{
			i = GetWindowTextLength(heInfo);
			SendMessage(heInfo, EM_SETSEL, i, i);
			it -> GetEntryString(str + 2);
			SendMessage(heInfo, EM_REPLACESEL, 0, (LPARAM)str + 2);
		}
	}
	//SetWindowText(heInfo, str);
	SetLastSentence(j);
}
void ThreadWindow::RemoveLink(int index)
{
	WCHAR str[0x80];
	DWORD number;
	SendMessage(hlFromThread, LB_GETTEXT, index, (LPARAM)str);
	swscanf(str, L"%x", &number);
	TextThread* it = man -> FindSingle(number);
	it -> Link() = 0;
	it -> LinkNumber()=-1;
	SendMessage(hlFromThread, LB_DELETESTRING, index, 0);
}
void ThreadWindow::SetThread()
{
	WCHAR str[0x280];
	DWORD from, to, index;
	index = SendMessage(hcCurrentThread, CB_GETCURSEL, 0, 0);
	SendMessage(hcCurrentThread, CB_GETLBTEXT, index, (LPARAM)str);
	swscanf(str, L"%x", &from);
	TextThread* it = man -> FindSingle(from);
	index = SendMessage(hcLinkThread, CB_GETCURSEL, 0, 0);
	SendMessage(hcLinkThread, CB_GETLBTEXT, index, (LPARAM)str);
	if (str[0]==L'_')
	{
		it -> Link() = 0;
		it -> LinkNumber()=-1;
	}
	else
	{
		swscanf(str, L"%x", &to);
		if (it->LinkNumber() != to)
			man -> AddLink(from&0xFFFF, to&0xFFFF);
	}
	if (GetWindowText(heComment, str, 0x200) > 0)
	{
		RemoveFromCombo(it);
		it->SetComment(str);
		AddToCombo(it);
		if (it->Status()&CURRENT_SELECT)
			ComboSelectCurrent(it);
	}
}
void ThreadWindow::SetLastSentence(DWORD number)
{
	TextThread* it = man -> FindSingle(number);
	WCHAR str[0x100];
	if (it)
	{
		it -> CopyLastSentence(str);
		str[0xFF] = 0;
		SetWindowText(heSentence, str);
	}
}
void ThreadWindow::ExportAllThreadText()
{
	WCHAR str_buffer[0x200];
	LPWSTR str, dir;
	DWORD len, count, i;
	len = GetWindowText(hwndProc, str_buffer, 0x200);
	if (len)
	{
		str_buffer[len] = L':';
		for (dir = str_buffer; *dir != L':'; dir++);
		if (dir - str_buffer == len) return;
		dir++;
		str_buffer[len] = L'.';		
		for (str = str_buffer; *str != L'.'; str++);
		*str = 0;
		HANDLE h = IthCreateDirectory(dir);
		if (INVALID_HANDLE_VALUE == h) return;
		NtClose(h);
	}
	else return;
	count = SendMessage(hcCurrentThread, CB_GETCOUNT, 0, 0);
	man->LockHookman();
	for (i = 0; i < count; i++)
	{
		ExportSingleThreadText(i, dir);
	}
	man->UnlockHookman();
}
//\/:*?"<>| are not allowed in file name.
static BYTE forbidden_table[0x10]=
{
	0,0,0,0, //0-1f
	0x4,0x84,0,0xD4, //20-3f
	0,0,0,0x10, //40-5f
	0,0,0,0x10, //60-7f
};

void ThreadWindow::ExportSingleThreadText(DWORD index, LPCWSTR dir)
{
	WCHAR entry_string[0x200]; 
	LPWSTR hook_name, p;
	LPCWSTR comment;
	DWORD num, len, len_hook, i;
	LARGE_INTEGER time;
	TIME_FIELDS tf;
	TextThread* it;
	ThreadTable* table = man -> Table();
	NtQuerySystemTime(&time);
	IthSystemTimeToLocalTime(&time);
	RtlTimeToTimeFields(&time, &tf);
	//index = SendMessage(hcCurrentThread, CB_GETCURSEL, 0, 0);
	len = SendMessage(hcCurrentThread, CB_GETLBTEXTLEN, index, 0);
	if (len >= 0x200)
	{
		MessageBox(0,L"Too long.",0,0);
		return;
	}
	SendMessage(hcCurrentThread, CB_GETLBTEXT, index, (LPARAM)entry_string);
	swscanf(entry_string, L"%X", &num);
	it = table -> FindThread(num);
	if (it == 0) return;
	i = 0;
	for (p = entry_string; *p; p++)
	{
		if (*p == L':') i++;
		if (i == 5) break;
	}
	if (i < 5) return;
	p++;
	comment = it->GetComment();
	if (comment)
	{
		len_hook = entry_string + len - wcslen(comment) - p - 1;
		p[len_hook] = 0;
	}
	else
	{
		len_hook = wcslen(p);
	}
	hook_name = new WCHAR[len_hook + 1];
	for (i = 0; i < len_hook; i++)
	{
		WCHAR c = hook_name[i];
		if (c >= 0x80) continue;
		if (forbidden_table[c >> 3] & (1 << (c & 7))) hook_name[i] = L'_';
	}
	wcscpy(hook_name, p);
	man -> LockHookman();
	tf.wYear = tf.wYear%100;

	p = entry_string;
	p += swprintf(p, L"%.2d%.2d%.2d-%.2d%.2d-%.4X-%s",
		tf.wYear, tf.wMonth, tf.wDay, tf.wHour, tf.wMinute, num, hook_name);
	delete hook_name;
	if (comment) p += swprintf(p,L"-%s",comment);
	if (p - entry_string < 0x1F0)
	{
		p[0] = L'.';
		p[1] = L't';
		p[2] = L'x';
		p[3] = L't';
		p[4] = 0;
		p += 4;
		LPWSTR file_path;
		if (dir)
		{
			int len_dir = wcslen(dir);
			file_path = new WCHAR[p - entry_string + len_dir + 2];
			memcpy(file_path, dir, len_dir << 1);
			file_path[len_dir] = L'\\';
			wcscpy(file_path + len_dir + 1, entry_string);
			it->ExportTextToFile(file_path);
			delete file_path;
		}
		else it -> ExportTextToFile(entry_string);
	}
	man -> UnlockHookman();

	//MessageBox(0, L"Success. Text saved in ITH folder.", L"Success", 0);
	//ShellExecute(0, L"open", L"", 0, 0, SW_SHOWNORMAL);
}

ProfileWindow::ProfileWindow(HWND hDialog)
{
	static const char default_link[] = "http://interactive-text-hooker.googlecode.com/svn/project/ITH3/Manifest/";
	base_link = new char[sizeof(default_link)]; //including the \0 mark.
	strcpy(base_link, default_link);
	hDlg = hDialog;
	hlProfileList = GetDlgItem(hDlg, IDC_LIST1);
	hlManifest = GetDlgItem(hDlg, IDC_LIST2);
	hlGameList = GetDlgItem(hDlg, IDC_LIST3);
	heProfile = GetDlgItem(hDlg, IDC_EDIT1);
	heStatus = GetDlgItem(hDlg, IDC_EDIT2);
	hcbLink = GetDlgItem(hDlg, IDC_COMBO1);
	ListView_SetExtendedListViewStyleEx(hlProfileList, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.cx = 40;
	lvc.pszText = L"Index";	
	ListView_InsertColumn(hlProfileList, 0, &lvc);
	lvc.cx = 100;
	lvc.pszText = L"Title";	
	ListView_InsertColumn(hlProfileList, 1, &lvc);
	InitProfiles();
	//sock = ITH_TLS_NewSocket(true);
	SendMessageA(hcbLink,CB_ADDSTRING, 0, (LPARAM)default_link);
	SendMessage(hcbLink, CB_SETCURSEL, 0, 0);
	HANDLE hFile = IthCreateDirectory(L"Profile");
	NtClose(hFile);
	hFile = IthCreateFile(L"Profile\\index.xml",GENERIC_READ, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE) return;
	FILE_STANDARD_INFO info;
	IO_STATUS_BLOCK ios;
	PVOID buffer = 0;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, &info.AllocationSize.LowPart, MEM_COMMIT, PAGE_READWRITE);
	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
	manifest.Parse((char*)buffer);
	if (!manifest.Error()) RefreshManifestList();
	NtClose(hFile);
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);

}
ProfileWindow::~ProfileWindow()
{
	delete base_link;
	hash_table.DeleteAll();
}
void ProfileWindow::InitProfiles()
{
	ListView_DeleteAllItems(hlProfileList);
	LVITEM item={};
	WCHAR buffer[0x20];
	item.mask = LVIF_TEXT; 
	item.pszText = buffer;

	pfman->LockProfileManager();
	DWORD i,count = pfman->ProfileCount();
	for (i = 0; i < count; i++)
	{
		Profile* pf = pfman->GetProfileByIndex(i);
		if (pf == 0) continue;
		item.iItem = i;
		swprintf(buffer,L"%d",i);
		ListView_InsertItem(hlProfileList,&item);
		if (pf->title)
			ListView_SetItemText(hlProfileList, i, 1, pf->title);
	}
	pfman->UnlockProfileManager();
	EnableWindow(GetDlgItem(hDlg, IDC_BUTTON2), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_BUTTON3), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_BUTTON4), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_BUTTON5), FALSE);
	EnableWindow(GetDlgItem(hDlg, IDC_BUTTON6), FALSE);	
}
void ProfileWindow::RefreshManifest()
{
	HANDLE hFile = IthCreateFile(L"Profile\\index.xml",FILE_READ_DATA, FILE_SHARE_READ, FILE_OPEN);
	if (hFile == INVALID_HANDLE_VALUE) return;
	FILE_STANDARD_INFORMATION info;
	IO_STATUS_BLOCK ios;
	LPVOID buffer = 0;
	NtQueryInformationFile(hFile, &ios, &info, sizeof(info), FileStandardInformation);
	NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, 
		&info.AllocationSize.LowPart, MEM_COMMIT, PAGE_READWRITE);

	NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0,0);
	NtClose(hFile);	
	if (ios.Status == STATUS_SUCCESS && ios.uInformation)
	{
		manifest.Clear();
		manifest.Parse((char*)buffer);
		if (!manifest.Error()) RefreshManifestList();
	}
	NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);

}
void ProfileWindow::RefreshManifestList()
{
	SendMessage(hlManifest, LB_RESETCONTENT, 0, 0);
	TiXmlElement* root = manifest.RootElement();
	if (root == 0) return;
	if (strcmp(root->Value(),"ITH_Manifest") != 0) return;
	const char* latset = root->Attribute("Latest");
	TiXmlElement* file = root->FirstChildElement("Files");
	if (file == 0) return;
	hash_tree.DeleteAll();
	hash_table.DeleteAll();
	for (file = file->FirstChildElement(); file; file = file->NextSiblingElement())
	{
		if (strcmp(file->Value(),"File") != 0) continue;
		const char* name1 = file->Attribute("Name");
		if (name1 == 0) continue;

		int name_len = strlen(name1);
		char* name = new char[name_len + 1];
		memcpy(name, name1, name_len);
		name[name_len] = '.';
		char* ptr;
		for (ptr = name; *ptr != '.'; ptr++);
		*ptr = 0;

		const char* hash_value = file->Attribute("SHA256");
		if (hash_value == 0) continue;

		TreeNode<char*,DWORD>* node;
		node = hash_tree.Insert(name,hash_table.next);
		if (node->data == hash_table.next)
		{
			int len = strlen(hash_value);
			char* hash_copy = new char[len + 1];
			memcpy(hash_copy, hash_value, len);
			hash_copy[len] = 0;
			hash_table.Append(hash_copy);
		}

		int index = SendMessageA(hlManifest, LB_ADDSTRING,0,(LPARAM)name);
		if (index != LB_ERR && latset)
		{
			if (strcmp(name,latset) == 0)
			{
				latset = 0;
				SendMessage(hlManifest, LB_SETCURSEL, index, 0);
				RefreshGames(name);
				RefreshGamesList();
			}
		}
		delete name;
	}
}
bool ProfileWindow::RefreshGames(DWORD index)
{
	char buffer[0x40],*b;
	int len = SendMessage(hlManifest, LB_GETTEXTLEN, index, 0);
	if (len <= 0) return false;
	if (len < 0x40) b = buffer;
	else b = new char[len + 1];
	SendMessageA(hlManifest, LB_GETTEXT, index, (LPARAM)b);
	b[len] = 0;
	bool flag = RefreshGames(b);
	if (b != buffer) delete b;
	return flag;
}
bool ProfileWindow::RefreshGames(const char* name)
{
	SendMessage(hlGameList, LB_RESETCONTENT, 0, 0);
	TreeNode<char*,DWORD>* node;
	node = hash_tree.Search(name);
	if (node == 0) return false;
	char* hash_value = hash_table[node->data];
	if (hash_value == 0) return false;
	int len = strlen(name);
	if (len + 9 >= MAX_PATH) return false;
	WCHAR file[MAX_PATH] = L"Profile\\";
	LPWSTR file_ptr = file;
	while (*++file_ptr);
	for (int i = 0; i < len; i++) file_ptr[i] = name[i]; //char -> wchar_t
	file_ptr += len;
	*file_ptr++ = L'.';
	*file_ptr++ = L'x';
	*file_ptr++ = L'm';
	*file_ptr++ = L'l';
	*file_ptr = 0;
	HANDLE hFile = IthCreateFile(file,GENERIC_READ, FILE_SHARE_READ, FILE_OPEN);
	IO_STATUS_BLOCK ios;
	if (hFile != INVALID_HANDLE_VALUE) //Check if we have a file cached locally.
	{
		FILE_STANDARD_INFO info;
		
		LPVOID buffer = 0;
		NtQueryInformationFile(hFile, &ios, &info, sizeof(info),FileStandardInformation);
		NtAllocateVirtualMemory(NtCurrentProcess(), &buffer, 0, 
			&info.AllocationSize.LowPart,MEM_COMMIT, PAGE_READWRITE);
		NtReadFile(hFile, 0,0,0, &ios, buffer, info.EndOfFile.LowPart, 0, 0);
		NtClose(hFile);
		bool flag = RefreshGamesInMemory(buffer, info.EndOfFile.LowPart, hash_value);
		NtFreeVirtualMemory(NtCurrentProcess(), &buffer, &info.AllocationSize.LowPart, MEM_RELEASE);
		if (flag) return flag;
	}
	return false;
}
bool ProfileWindow::RefreshGamesInMemory(LPVOID memory, DWORD size, const char* hash)
{
	SHA256Calc sha256;
	sha256.HashUpdate(memory,size);
	BYTE values[0x20];
	sha256.HashFinal(values);
	bool flag = CheckHashStr(values, sha256.HashValueSize(), hash);
	if (flag)
	{
		game_list.Clear();
		game_list.Parse((char*)memory);
		return !game_list.Error();
		//if (!game_list.Error()) RefreshGamesList();
	}
	return flag;
}
void ProfileWindow::RefreshGamesList()
{
	SendMessage(hlGameList, LB_RESETCONTENT, 0, 0);
	game_tree.DeleteAll();
	game_table.Reset();
	TiXmlElement* game = game_list.RootElement();
	if (game == 0) return;
	if (strcmp(game->Value(),"ITH_Profile") != 0) return;
	for (game = game->FirstChildElement(); game; game = game->NextSiblingElement())
	{
		const char* title = game->Attribute("Title");
		if (title == 0) continue;
		LPWSTR t = AllocateUTF16AndConvertUTF8(title);
		TreeNode<LPWSTR,DWORD>* node = game_tree.Insert(t, game_table.next);
		if (node->data == game_table.next)
			game_table.Append(game);
		SendMessage(hlGameList, LB_ADDSTRING, 0, (LPARAM)t);
		delete t;
	}
}
void ProfileWindow::FindProperProfile() //Simply sequential search. Plan to improve to a B-tree based index system. 
{
	ClearStatusText();
	int profile_select = ListView_GetSelectionMark(hlProfileList);
	TiXmlElement* node = pfman->GetProfileXmlByIndex(profile_select);
	if (node == 0) return;
	TiXmlElement* file = node->FirstChildElement("File");
	if (file == 0) return;
	TiXmlElement* hash = file->FirstChildElement("Hash");
	if (hash == 0) return;
	const char* hash_value = hash->Attribute("SHA256");
	int i,count = SendMessage(hlManifest, LB_GETCOUNT, 0, 0);
	for (i = 0; i < count; i++)
	{
		int len = SendMessageA(hlManifest, LB_GETTEXTLEN, i, 0);
		if (len > 0)
		{
			char* str = new char[len + 1];
			SendMessageA(hlManifest, LB_GETTEXT, i, (LPARAM)str);
			str[len] = 0;
			SetStatusText(str);
			RefreshGames(str);
			delete str;
			TiXmlElement* game = game_list.RootElement();
			if (game == 0) continue;
			if (strcmp(game->Value(),"ITH_Profile") != 0) continue;
			int j = 0;
			for (game = game->FirstChildElement(); game; game = game->NextSiblingElement())
			{
				TiXmlElement* file = game->FirstChildElement("File");
				if (file == 0) continue;
				TiXmlElement* hash = file->FirstChildElement("Hash");
				if (hash == 0) continue;
				const char* target_value = hash->Attribute("SHA256");
				if (CompareHashStr(hash_value, target_value)) break;
				j++;
			}
			if (game)
			{
				SendMessage(hlManifest, LB_SETCURSEL, i, 0);
				RefreshGamesList();
				const char* title = game->Attribute("Title");
				if (title)
				{
					LPWSTR search = AllocateUTF16AndConvertUTF8(title);
					int result = SendMessage(hlGameList, LB_SELECTSTRING, -1, (LPARAM)search);
					delete search;
					if (result != LB_ERR)
					{
						RefreshProfile(result);
						SetStatusSuccess();
						EnableWindow(GetDlgItem(hDlg,IDC_BUTTON4), TRUE);
					}
				}
				return;
			}
		}
	}
	SetStatusText(L"Not found.");
	//MessageBox(0,L"Not found",0,0);
}
void ProfileWindow::ImportProfile()
{
	ClearStatusText();
	int profile_select = ListView_GetSelectionMark(hlProfileList);
	int import_select = SendMessage(hlGameList, LB_GETCURSEL, 0, 0);
	if ((profile_select | import_select) == -1) return;
	Profile* pf = pfman->GetProfileByIndex(profile_select);
	
	if (pf == 0) return;
	int index = SendMessage(hlGameList, LB_GETCURSEL, 0, 0);
	int len = SendMessage(hlGameList, LB_GETTEXTLEN, index, 0);
	if (len <= 0) return;
	LPWSTR str = new WCHAR[len + 1];
	SendMessage(hlGameList, LB_GETTEXT, index, (LPARAM)str);
	str[len] = 0;
	TreeNode<LPWSTR,DWORD>* node = game_tree.Search(str);
	delete str;
	if (node == 0) return;
	TiXmlElement* target_profile = game_table[node->data];
	TiXmlElement* local_profile = pfman->GetProfileXmlByIndex(profile_select);
	if (target_profile == 0 || local_profile == 0) return;

	TiXmlElement* target_file = target_profile->FirstChildElement("File");
	TiXmlElement* local_file = local_profile->FirstChildElement("File");
	if (target_file == 0 || local_file == 0) return;

	TiXmlElement* local_hash = local_file->FirstChildElement("Hash");
	if (local_hash == 0) return;
	const char* local_value = local_hash->Attribute("SHA256");
	if (local_value == 0) return;
	TiXmlElement* target_hash;
	for (target_hash = target_file->FirstChildElement("Hash"); 
		target_hash; 
		target_hash = target_hash->NextSiblingElement("Hash"))
	{
		const char* target_value = target_hash->Attribute("SHA256");
		if (target_value == 0) continue;
		if (strcmp(target_value, local_value) == 0) break;
	}
	if (target_hash == 0)
	{
		if (IDNO == MessageBox(0, L"Hash mispatch, import anyway?", L"Hash mismatch", MB_YESNO))
			return;
	}
	TiXmlElement* profile = target_profile->FirstChildElement("Profile");
	if (profile == 0) return;
	pf->ReleaseData();
	pf->XmlReadProfile(profile);
	pfman->RefreshProfileXml(profile_select);
	if (pfman->IsProfileCurrent(pf))
	{
		if (pf->hook_count)
		{
			DWORD pid = pfman->GetCurrentPID();
			DWORD i,j;
			j = pf->hook_count;
			for (i = 0; i < j; i++)
				IHF_InsertHook(pid, &pf->hooks[i].hp, pf->hooks[i].name);
		}
	}
	SetStatusSuccess();
}
void ProfileWindow::SetStatusText(LPCWSTR text)
{
	SendMessage(heStatus, WM_SETTEXT, 0, (LPARAM)text);
}
void ProfileWindow::SetStatusText(LPCSTR text)
{
	SendMessage(heStatus, WM_SETTEXT, 0, (LPARAM)text);
}
void ProfileWindow::ClearStatusText()
{
	SendMessage(heStatus, WM_SETTEXT, 0, (LPARAM)L"");
}
void ProfileWindow::SetStatusSuccess()
{
	SendMessage(heStatus, WM_SETTEXT, 0, (LPARAM)L"Success");
}
DWORD ProfileWindow::GetCurrentSelect()
{
	return ListView_GetSelectionMark(hlProfileList);
}
#define STR_DEFAULT_SIZE 0x100
void AddString(MyVector<WCHAR, STR_DEFAULT_SIZE>& str, LPWSTR s)
{
	DWORD len = wcslen(s);
	str.AddToStore(s,len);
}
void AddNewLine(MyVector<WCHAR, STR_DEFAULT_SIZE>& str)
{
	str.AddToStore(L"\r\n",2);
}
void ProfileWindow::RefreshProfile(DWORD index)
{
	int len = SendMessage(hlGameList, LB_GETTEXTLEN, index, 0);
	if (len <= 0) return;
	LPWSTR str = new WCHAR[len + 1];
	SendMessage(hlGameList, LB_GETTEXT, index, (LPARAM)str);
	str[len] = 0;
	TreeNode<LPWSTR,DWORD>* node = game_tree.Search(str);
	//delete str;
	if (node)
	{
		TiXmlElement* profile = game_table[node->data];
		if (profile)
		{
			profile = profile->FirstChildElement("Profile");
			if (profile)
			{
				Profile pf;
				pf.title = str;
				pf.XmlReadProfile(profile);
				RefreshProfile(&pf);
				pf.title = 0; //prevent memory release in the destructor.
			}
		}
	}
	delete str;
}
void ProfileWindow::RefreshProfile(Profile* pf)
{
	MyVector<WCHAR,STR_DEFAULT_SIZE> str;
	WCHAR buffer[0x40], c = L':';
	DWORD len,i;
	if (pf->title)
	{
		AddString(str, L"Title:\r\n");
		AddString(str, pf->title);
		AddNewLine(str);
	}
	if (pf->hook_count)
	{
		AddString(str, L"Hooks:\r\n");
		for (i = 0; i < pf->hook_count; i++)
		{
			len = swprintf(buffer,L"%x:",i);
			str.AddToStore(buffer,len);
			if (pf->hooks[i].name) AddString(str, pf->hooks[i].name);
			str.AddToStore(&c,1);
			len = GetCode(pf->hooks[i].hp, buffer);
			str.AddToStore(buffer,len);
			AddNewLine(str);
		}
	}
	if (pf->thread_count)
	{
		AddString(str, L"Threads:\r\n");
		for (i = 0; i < pf->thread_count; i++)
		{		
			len = swprintf(buffer,L"%x:",i);
			str.AddToStore(buffer,len);
			ThreadProfile* tpf = pf->threads + i;
			if (tpf->flags & THREAD_MASK_RETN)
				len = swprintf(buffer,L"XXXX%.4X",tpf->retn & 0xFFFF);
			else len = swprintf(buffer,L"%.8X",tpf->retn);
			str.AddToStore(buffer,len);
			str.AddToStore(&c,1);
			if (tpf->flags & THREAD_MASK_SPLIT)
				len = swprintf(buffer,L"XXXX%.4X", tpf->split & 0xFFFF);
			else len = swprintf(buffer,L"%.8X",tpf->split);
			str.AddToStore(buffer,len);
			str.AddToStore(&c,1);
			AddString(str,hnman->GetName(tpf->hook_name_index));		
			if (tpf->comment)
			{
				str.AddToStore(&c,1);
				AddString(str,tpf->comment);
			}
			AddNewLine(str);
		}
	}
	if (pf->link_count)
	{
		AddString(str,L"Links:\r\n");
		for (i = 0; i <pf->link_count; i++)
		{
			LinkProfile* lpf = pf->links + i;
			len = swprintf(buffer,L"%x:",i);
			str.AddToStore(buffer,len);
			str.AddToStore(&c,1);
			len = swprintf(buffer,L"%.4X->%.4X\r\n",lpf->from_index,lpf->to_index);
			str.AddToStore(buffer,len);
		}
	}
	if (pf->select_index != 0xFFFF)
	{
		AddString(str, L"Select: ");
		len = swprintf(buffer, L"%x\r\n", pf->select_index);
		str.AddToStore(buffer,len);
	}
	buffer[0] = 0;
	str.AddToStore(buffer,1);
	SendMessage(heProfile, WM_SETTEXT, 0, (LPARAM)str.Storage());
}
void ProfileWindow::ExportProfile()
{
	int index = ListView_GetSelectionMark(hlProfileList);
	if (index == -1) return;
	pfman->ExportProfile(L"ITH_Profile_Export.xml", index);
}
void ProfileWindow::ExportAllProfile()
{
	pfman->ExportAllProfile(L"ITH_Profile_Export.xml");
}
void ProfileWindow::DeleteProfile()
{
	DWORD index = ListView_GetSelectionMark(hlProfileList);
	if (index == -1) return;
	pfman->DeleteProfile(index);
	InitProfiles();
}


class IthGlyph
{
public:
	IthGlyph(HDC hdc):hDC(hdc), glyph_buffer(0), hBmp(0)
	{
		hMemDC = CreateCompatibleDC(hdc);
	}
	~IthGlyph()
	{
		if (hBmp) DeleteObject(hBmp);
		if (hMemDC) DeleteDC(hMemDC);
		if (glyph_buffer) delete glyph_buffer;
		glyph_buffer = 0;
		glyph_char = 0;
		hMemDC = 0;
		hBmp = 0;
		hDC = 0;
	}
	int InitGlyph(wchar_t ch)
	{
		DWORD len, i, ii, j, k, t;
		BYTE *buffer, *bptr;
		LPVOID ptr;
		MAT2 mt={};
		glyph_char = ch;
		mt.eM11.value = 1;
		mt.eM22.value=-1;

		len = GetGlyphOutline(hDC, ch, GGO_GRAY8_BITMAP, &gm, 0, 0, &mt);
		if (len <= 0) return -1;
		glyph_buffer = new BYTE[len];
		len = GetGlyphOutline(hDC, ch, GGO_GRAY8_BITMAP, &gm, len, glyph_buffer, &mt);
		if (len == -1) return -1;	
		BITMAPINFOHEADER info={sizeof(info), gm.gmBlackBoxX, gm.gmBlackBoxY, 1, 32, BI_RGB, 0, 0, 0, 0, 0};
		hBmp = CreateDIBSection(hMemDC, (BITMAPINFO*)&info, DIB_RGB_COLORS, &ptr, 0, 0);
		buffer = (BYTE*)ptr;
		bptr = glyph_buffer;
		k = (gm.gmBlackBoxX + 3)&~3; t = 0; ii = 0;
		for (i = 0; i < gm.gmBlackBoxY; i++)
		{
			for (j = 0; j < gm.gmBlackBoxX; j++)
			{
				bptr[j] = 64-bptr[j];
				if (bptr[j]) 
					buffer[0] = buffer[1] = buffer[2] = (bptr[j]<<2)-1;
				buffer += 4;
			}
			bptr += k;
		}
		SelectObject(hMemDC, hBmp);
		return 0;
	}
	int DrawGlyph(HDC hdc, int x, int y, int height)
	{
		if (glyph_buffer == 0) return -1;
		return BitBlt(hdc, x + gm.gmptGlyphOrigin.x, y + height-gm.gmBlackBoxY + gm.gmptGlyphOrigin.y, 
			gm.gmBlackBoxX, gm.gmBlackBoxY, hMemDC, 0, 0, SRCCOPY);
	}
private:
	HDC hDC, hMemDC;
	HBITMAP hBmp;
	UINT glyph_char;
	GLYPHMETRICS gm;
	BYTE* glyph_buffer;
};

LRESULT CALLBACK EditCharProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_PASTE:
		{
			HGLOBAL   hglb; 
			LPWSTR    lpwstr; 

			if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) break;
			if (!OpenClipboard(0)) break;
			hglb = GetClipboardData(CF_UNICODETEXT); 
			if (hglb != NULL) 
			{ 
				lpwstr = (LPWSTR)GlobalLock(hglb); 
				if (lpwstr != NULL) 
				{ 
					// Call the application-defined ReplaceSelection 
					// function to insert the text and repaint the 
					// window. 
					ftwnd -> InitWithChar(lpwstr[0]);
					GlobalUnlock(hglb); 
				} 
			} 
			CloseClipboard(); 
			return 0;
		}
	case WM_CHAR:
		if (wParam >= 0x20)
		{
			ftwnd -> InitWithChar(wParam);
			return 0;
		}
	default:
		break;
	}
	return CallWindowProc(procChar, hWnd, message, wParam, lParam);
}
void InsertUniChar(WORD uni_char, PVOID ft)
{
	ftwnd -> SetUniChar(uni_char);
}
void InsertMBChar(WORD mb_char, PVOID ft)
{
	ftwnd -> SetMBChar(mb_char);
}

FilterWindow::FilterWindow(HWND hDialog)
{
	//IHF_GetFilters((PVOID*)&mb_filter,(PVOID*)&uni_filter);
	modify = remove = commit = 0;
	hDlg = hDialog;
	hList = GetDlgItem(hDlg, IDC_LIST1);
	hGlyph = GetDlgItem(hDlg, IDC_STATIC1);
	hSJIS = GetDlgItem(hDlg, IDC_EDIT6);
	hUnicode = GetDlgItem(hDlg, IDC_EDIT7);
	hChar = GetDlgItem(hDlg, IDC_EDIT8);
	procChar = (WNDPROC)SetWindowLongPtr(hChar, GWL_WNDPROC, (LONG_PTR)EditCharProc);
	ListView_SetExtendedListViewStyleEx(hList, LVS_EX_FULLROWSELECT, LVS_EX_FULLROWSELECT);
	ListView_DeleteAllItems(hList);
	LVCOLUMN lvc={}; 
	lvc.mask = LVCF_FMT | LVCF_TEXT | LVCF_WIDTH; 
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.cx = 35;
	lvc.pszText = L"Char";	
	ListView_InsertColumn(hList, 0, &lvc);
	lvc.cx = 50;
	lvc.pszText = L"SJIS";	
	ListView_InsertColumn(hList, 1, &lvc);
	lvc.cx = 100;
	lvc.fmt = LVCFMT_LEFT;  // left-aligned column
	lvc.pszText = L"Unicode";	
	ListView_InsertColumn(hList, 2, &lvc);

	hGlyphFont = CreateFont( 64, 0, 0, 0, FW_THIN, FALSE, FALSE, FALSE, SHIFTJIS_CHARSET, OUT_DEFAULT_PRECIS, 
		CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"MS Mincho" );
	hGlyphDC = GetDC(hGlyph);
	SelectObject(hGlyphDC, hGlyphFont);
	white = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF));
	GetTextMetrics(hGlyphDC, &tm);
	GetClientRect(hGlyph, &rc);
	init_x = (rc.right-tm.tmMaxCharWidth)/2;
	init_y = 0;
}
FilterWindow::~FilterWindow()
{
	WCHAR buffer[8];
	WCHAR filter_unichar[2];
	char filter_mbchar[4];
	ReleaseDC(hGlyph, hGlyphDC);
	DeleteObject(white);
	DeleteObject(hGlyphFont);
	if (uni_filter&&mb_filter&&commit)
	{
		if (modify)
		{
			LVITEM item={};
			LVITEM sub={};
			int i, count = ListView_GetItemCount(hList);
			item.mask = LVIF_TEXT;
			item.cchTextMax = 2;
			item.pszText = filter_unichar;
			sub.mask = LVIF_TEXT;
			sub.cchTextMax = 8;
			sub.pszText = buffer;
			if (remove)
			{
				uni_filter -> Reset();
				mb_filter -> Reset();
				for (i = 0; i < count; i++)
				{
					item.iItem = i;
					ListView_GetItem(hList, &item);
					filter_unichar[1] = 0;
					WC_MB(filter_unichar, filter_mbchar);
					sub.iSubItem = 1;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') uni_filter -> Set(filter_unichar[0]);
					sub.iSubItem = 2;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') mb_filter -> Set(*(WORD*)filter_mbchar);
				}
			}
			else
			{
				for (i = 0; i < count; i++)
				{
					item.iItem = i;
					ListView_GetItem(hList, &item);
					filter_unichar[1] = 0;
					filter_mbchar[WC_MB(filter_unichar, filter_mbchar)]=0;
					sub.iSubItem = 1;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') uni_filter -> Set(filter_unichar[0]);
					else uni_filter -> Clear(filter_unichar[0]);
					sub.iSubItem = 2;
					SendMessage(hList, LVM_GETITEMTEXT, (WPARAM)(i), (LPARAM)(LV_ITEM *)&sub);
					if (buffer[4]==L'+') mb_filter -> Set(*(WORD*)filter_mbchar);
					else mb_filter -> Clear(*(WORD*)filter_mbchar);
				}
			}
		}
	}
}
void FilterWindow::Init()
{
	WCHAR uni_char[8], buffer[8];
	union {DWORD mbd; WORD mbw[2]; char mbc[4]; BYTE mbb[4];};
	uni_filter -> Traverse(InsertUniChar, this);
	mb_filter -> Traverse(InsertMBChar, this);
	DWORD count, index;
	LVITEM item={};
	item.mask = LVIF_TEXT;
	item.cchTextMax = 8;
	item.pszText = buffer;
	mbd = 0;
	count = ListView_GetItemCount(hList);
	for (index = 0; index < count; index++)
	{
		ListView_GetItemText(hList, index, 0, uni_char, 8);
		item.iSubItem = 1;
		if (SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item)==0)
		{
			WC_MB(uni_char, mbc);
			mbw[0] = _rotl16(mbw[0], (LeadByteTable[mbb[0]]-1)<<3);
			swprintf(buffer, L"%.4X-", mbd);
			SendMessage(hList, LVM_SETITEMTEXT, index, (LPARAM)&item);
		}
		else
		{
			item.iSubItem = 2;
			if (SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item)==0)
			{
				swprintf(buffer, L"%.4X-", uni_char[0]);
				SendMessage(hList, LVM_SETITEMTEXT, index, (LPARAM)&item);
			}
		}

	}
}
void FilterWindow::DeleteCurrentChar()
{
	WCHAR buffer[4];
	DWORD index = ListView_GetSelectionMark(hList);
	if (-1==index) 
	{
		MessageBox(0, L"Select one item first.", 0, 0);
		return;
	}
	ListView_DeleteItem(hList, index);
	buffer[0] = 0;
	SetWindowText(hSJIS, buffer);
	SetWindowText(hUnicode, buffer);
	SetWindowText(hChar, buffer);
	FillRect(hGlyphDC, &rc, white);
	remove = 1; modify = 1;
}
void FilterWindow::AddNewChar()
{
	WCHAR buffer[8];
	DWORD uni, index;
	if (GetWindowText(hChar, buffer, 8)==0)
	{
		MessageBox(0, L"No character.", 0, 0);
		return;
	}
	uni = buffer[0];
	LVFINDINFO find={LVFI_STRING, buffer};
	index = ListView_FindItem(hList, 0, &find);
	if (index!=-1)
	{
		ListView_SetSelectionMark(hList, index);
		SetCurrentChar();
		return;
	}
	LVITEM item={};
	item.mask = LVIF_TEXT;
	item.cchTextMax = 2;
	item.pszText = buffer;
	index = ListView_InsertItem(hList, &item);
	if (-1==index) return;
	item.iItem = index;
	GetWindowText(hSJIS, buffer, 8);
	if (IsSJISCheck()) buffer[4] = L'+';
	else buffer[4] = L'-';
	buffer[5] = 0;
	ListView_SetItemText(hList, index, 1, buffer);
	GetWindowText(hUnicode, buffer, 8);
	if (IsUnicodeCheck()) buffer[4] = L'+';
	else buffer[4] = L'-';
	buffer[5] = 0;
	ListView_SetItemText(hList, index, 2, buffer);
	modify = 1;
}
void FilterWindow::SetCurrentChar()
{
	WCHAR buffer[8];
	DWORD unichar, index, index_duplicate, flag_uni, flag_mb;
	GetWindowText(hChar, buffer, 8);
	unichar = buffer[0];	
	index = ListView_GetSelectionMark(hList);
	if (-1==index) 
	{
		MessageBox(0, L"Select one item first.", 0, 0);
		return;
	}
	LVFINDINFO find={LVFI_STRING, buffer};
	index_duplicate = ListView_FindItem(hList, 0, &find);
	LV_ITEM item={};
	if (index_duplicate!=-1)
	{
		if (index!=index_duplicate)
		{
			DeleteCurrentChar();
			if (index < index_duplicate) index_duplicate--;
			index = index_duplicate;
		}

	}
	modify = 1;
	item.pszText = buffer + 4;
	item.cchTextMax = 8;
	SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item);
	if (buffer[0]!=buffer[4]) remove = 1;

	item.pszText = buffer;
	SendMessage(hList, LVM_SETITEMTEXT, index, (LPARAM)&item);

	GetWindowText(hUnicode, buffer, 8);
	flag_uni = IsUnicodeCheck();
	if (flag_uni) buffer[4] = L'+';
	else buffer[4] = L'-';
	buffer[5] = 0;
	item.iSubItem = 2;
	SendMessage(hList, LVM_SETITEMTEXT, index, (LPARAM)&item);
	//ListView_SetItemText(hList, index, 2, buffer);

	GetWindowText(hSJIS, buffer, 8);
	flag_mb = IsSJISCheck();
	if (flag_mb) buffer[4] = L'+';
	else buffer[4] = L'-';
	buffer[5] = 0;
	item.iSubItem = 1;
	SendMessage(hList, LVM_SETITEMTEXT, index, (LPARAM)&item);
	//ListView_SetItemText(hList, index, 1, buffer);
	if ((flag_mb | flag_uni)==0)
	{
		ListView_SetSelectionMark(hList, index);
		DeleteCurrentChar();
	}
}
void FilterWindow::SelectCurrentChar(DWORD index)
{
	WCHAR buffer[8], uni_char;
	LVITEM item={};
	item.mask = LVIF_TEXT;
	item.cchTextMax = 8;
	item.pszText = buffer;
	if (SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item)==1)
	{
		uni_char = buffer[0];
		DrawGlyph(uni_char);
		item.iSubItem = 1;
		SetWindowText(hChar, buffer);
		if (SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item)==5)
		{
			if (buffer[4]==L'+') CheckDlgButton(hDlg, IDC_CHECK6, BST_CHECKED);
			else CheckDlgButton(hDlg, IDC_CHECK6, BST_UNCHECKED);
			buffer[4] = 0;
			SetWindowText(hSJIS, buffer);
		}
		item.iSubItem = 2;
		if (SendMessage(hList, LVM_GETITEMTEXT, index, (LPARAM)&item)==5)
		{
			if (buffer[4]==L'+') CheckDlgButton(hDlg, IDC_CHECK7, BST_CHECKED);
			else CheckDlgButton(hDlg, IDC_CHECK7, BST_UNCHECKED);
			buffer[4] = 0;
			SetWindowText(hUnicode, buffer);
		}
	}

}
void FilterWindow::InitWithChar(WCHAR uni_char)
{
	WCHAR buffer[8];
	union {DWORD mbd; WORD mbw[2]; char mbc[4]; BYTE mbb[4];};
	mbd = 0;
	DrawGlyph(uni_char);
	buffer[0] = uni_char;
	buffer[1] = 0;
	SetWindowText(hChar, buffer);
	WC_MB(buffer, mbc);

	if (LeadByteTable[mbb[0]]==2) mbw[0] = _byteswap_ushort(mbw[0]);
	swprintf(buffer, L"%.4X", mbw[0]);
	SetWindowText(hSJIS, buffer);
	CheckDlgButton(hDlg, IDC_CHECK6, BST_CHECKED);

	swprintf(buffer, L"%.4X", uni_char);
	SetWindowText(hUnicode, buffer);
	CheckDlgButton(hDlg, IDC_CHECK7, BST_CHECKED);
}
void FilterWindow::DrawGlyph(WCHAR glyph)
{
	RECT rc;
	GetClientRect(hGlyph, &rc);
	FillRect(hGlyphDC, &rc, white);
	IthGlyph g(hGlyphDC);
	g.InitGlyph(glyph);
	g.DrawGlyph(hGlyphDC, init_x, init_y, tm.tmHeight);
}
void FilterWindow::SetUniChar(WCHAR uni_char)
{
	WCHAR buffer[8];
	DWORD index;
	buffer[0] = uni_char;
	buffer[1] = 0;
	LVFINDINFO find={LVFI_STRING, buffer};
	index = ListView_FindItem(hList, 0, &find);
	if (index == -1) 
	{
		LVITEM item={};
		item.mask = LVIF_TEXT;
		item.cchTextMax = 2;
		item.pszText = buffer;
		index = ListView_InsertItem(hList, &item);
		if (-1==index) return;
	}
	swprintf(buffer, L"%.4X+", uni_char);
	ListView_SetItemText(hList, index, 2, buffer);
}
void FilterWindow::SetMBChar(WORD mb_char)
{
	WCHAR buffer[8];
	char mb[4]={};
	DWORD index;
	*(WORD*)mb = mb_char;
	MB_WC(mb, buffer);
	buffer[1] = 0;
	LVFINDINFO find={LVFI_STRING, buffer};
	index = ListView_FindItem(hList, -1, &find);
	if (index == -1) 
	{
		LVITEM item={};
		item.mask = LVIF_TEXT;
		item.cchTextMax = 2;
		item.pszText = buffer;
		index = ListView_InsertItem(hList, &item);
		if (-1==index) return;
	}
	if (LeadByteTable[(BYTE)mb[0]]==2) 
		mb_char = _byteswap_ushort(mb_char);
	swprintf(buffer, L"%.4X+", mb_char);
	ListView_SetItemText(hList, index, 1, buffer);
}
void FilterWindow::SetCommitFlag() {commit = 1;}
void FilterWindow::ClearGlyphArea()
{
	FillRect(hGlyphDC, &rc, white);
}
UINT FilterWindow::IsSJISCheck(){ return IsDlgButtonChecked(hDlg, IDC_CHECK6);}
UINT FilterWindow::IsUnicodeCheck(){ return IsDlgButtonChecked(hDlg, IDC_CHECK7);}
DWORD WINAPI FlushThread(LPVOID lParam)
{
	LARGE_INTEGER sleep_interval={-100000,-1};
	TextBuffer* t = (TextBuffer*)lParam;
	while (t->Running())
	{
		t->Flush();
		NtDelayExecution(0,&sleep_interval);
	}
	return 0;
}
TextBuffer::TextBuffer(HWND edit)
{
	hEdit = edit;
	running = true;
	hThread = IthCreateThread(FlushThread,(DWORD)this);

}
TextBuffer::~TextBuffer()
{
	running = false;
	NtWaitForSingleObject(hThread,0,0);
	NtClose(hThread);
}
void TextBuffer::AddText(LPWSTR str, int len, bool line)
{
	if (len > 0)
		AddToStore(str,len);
	line_break = line;
}
void TextBuffer::Flush()
{
	if (line_break||used==0) return;
	DWORD t;
	t=SendMessage(hEdit,WM_GETTEXTLENGTH,0,0);
	SendMessage(hEdit,EM_SETSEL,t,-1);
	EnterCriticalSection(&cs_store);
	storage[used]=0;
	SendMessage(hEdit,EM_REPLACESEL,FALSE,(LPARAM)storage);
	used=0;
	LeaveCriticalSection(&cs_store);
}
void TextBuffer::ClearBuffer()
{
	Reset();
	line_break = false;
}
MK_BASIC_TYPE(WCHAR);
