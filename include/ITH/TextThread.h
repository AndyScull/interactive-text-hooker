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
#include <ITH\main_template.h>
#include <ITH\common.h>
#include <ITH\SettingManager.h>

struct RepeatCountNode
{
	short repeat;
	short count;
	RepeatCountNode* next;
};
struct ThreadParameter
{
	DWORD pid;
	DWORD hook;
	DWORD retn;
	DWORD spl;
};
#define CURRENT_SELECT 0x1000
#define REPEAT_NUMBER_DECIDED	0x2000
#define BUFF_NEWLINE 0x4000
#define CYCLIC_REPEAT 0x8000
#define COUNT_PER_FOWARD 0x200
#define REPEAT_DETECT 0x10000
#define REPEAT_SUPPRESS 0x20000
#define REPEAT_NEWLINE 0x40000
class TextThread;
typedef DWORD (*ThreadOutputFilterCallback) (TextThread*, BYTE*,DWORD,DWORD,PVOID);
typedef DWORD (*ThreadEventCallback) (TextThread*);

//extern DWORD split_time,repeat_count,global_filter,cyclic_remove;

class TextThread : public MyVector<BYTE, 0x200>
{
public:
	TextThread(DWORD pid, DWORD hook, DWORD retn, DWORD spl, WORD num);
	virtual ~TextThread();	
	virtual void CopyLastSentence(LPWSTR str);
	virtual void SetComment(LPWSTR);	
	virtual void ExportTextToFile(LPWSTR filename);
	
	virtual bool CheckCycle(TextThread* start);
	virtual DWORD GetThreadString(LPWSTR str, DWORD max);
	virtual DWORD GetEntryString(LPWSTR str, DWORD max = 0x200);

	void Reset();
	void AddText(BYTE* con,int len, bool new_line=false, bool console=false);
	void AddTextDirect(BYTE* con, int len);
	void RemoveSingleRepeatAuto(BYTE* con, int &len);
	void RemoveSingleRepeatForce(BYTE* con, int &len);
	void RemoveCyclicRepeat(BYTE* &con, int &len);
	void ResetRepeatStatus();
	void AddLineBreak();
	void ResetEditText();
	void ComboSelectCurrent();
	void UnLinkAll();
	void CopyLastToClipboard();
	
	//void AdjustPrevRepeat(DWORD len);
	//void PrevRepeatLength(DWORD &len);
	
	//bool AddToCombo();
	bool RemoveFromCombo();
	
	void SetNewLineFlag();
	void SetNewLineTimer();
	BYTE* GetStore(DWORD* len) {if (len) *len = used; return storage;}
	inline DWORD LastSentenceLen() {return used - last_sentence;}
	inline DWORD PID() const {return tp.pid;}
	inline DWORD Addr() const {return tp.hook;}
	inline DWORD& Status() {return status;}
	inline WORD Number() const {return thread_number;}
	inline WORD& Last() {return last;}
	inline WORD& LinkNumber() {return link_number;}
	inline UINT_PTR& Timer() {return timer;}
	inline ThreadParameter* GetThreadParameter() {return &tp;}
	inline TextThread*& Link() {return link;}
	inline 	ThreadOutputFilterCallback RegisterOutputCallBack(ThreadOutputFilterCallback cb, PVOID data)
	{
		app_data = data;
		return (ThreadOutputFilterCallback)_InterlockedExchange((long*)&output,(long)cb);
	}
	inline 	ThreadOutputFilterCallback RegisterFilterCallBack(ThreadOutputFilterCallback cb, PVOID data)
	{
		app_data = data;
		return (ThreadOutputFilterCallback)_InterlockedExchange((long*)&filter,(long)cb);
	}
	inline void SetRepeatFlag() {status|=CYCLIC_REPEAT;}
	inline void ClearNewLineFlag() {status&=~BUFF_NEWLINE;}
	inline void ClearRepeatFlag() {status&=~CYCLIC_REPEAT;}
	inline LPCWSTR GetComment() {return comment;}
private:
	ThreadParameter tp;
	
	WORD thread_number,link_number;
	WORD last,align_space;
	WORD repeat_single;
	WORD repeat_single_current;
	WORD repeat_single_count;
	WORD repeat_detect_count;
	RepeatCountNode* head;

	TextThread *link;
	ThreadOutputFilterCallback filter,output;
	PVOID app_data;
	LPWSTR comment,thread_string;
	UINT_PTR timer;
	DWORD status,repeat_detect_limit;
	DWORD last_sentence,prev_sentence,sentence_length,repeat_index,last_time;
};
