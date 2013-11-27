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
#include <ITH\TextThread.h>
#include <ITH\AVL.h>

#define MAX_REGISTER 0xF
#define MAX_PREV_REPEAT_LENGTH 0x20
struct ProcessRecord {
	DWORD pid_register;
	DWORD hookman_register;
	DWORD module_register;
	DWORD engine_register;
	HANDLE process_handle;
	HANDLE hookman_mutex;
	HANDLE hookman_section;
	LPVOID hookman_map;
};

class ThreadTable : public MyVector<TextThread*,0x40>
{
public:
	virtual void SetThread(DWORD number, TextThread* ptr);
	virtual TextThread* FindThread(DWORD number);
};
class TCmp
{
public:
	char operator()(const ThreadParameter* t1,const ThreadParameter* t2);
};
class TCpy
{
public:
	void operator()(ThreadParameter* t1,const ThreadParameter* t2);
};
class TLen
{
public:
	int operator()(const ThreadParameter* t);
};
typedef DWORD (*ProcessEventCallback)(DWORD pid);
class HookManager : public AVLTree<ThreadParameter,DWORD,TCmp,TCpy,TLen>
{
public:
	HookManager();
	~HookManager();
	virtual TextThread* FindSingle(DWORD pid, DWORD hook, DWORD retn, DWORD split);
	virtual TextThread* FindSingle(DWORD number);
	virtual ProcessRecord* GetProcessRecord(DWORD pid);
	virtual DWORD GetProcessIDByPath(LPWSTR str);
	virtual void RemoveSingleThread(DWORD number);
	virtual void LockHookman();
	virtual void UnlockHookman();
	virtual void ResetRepeatStatus();
	virtual void ClearCurrent();
	virtual void AddLink(WORD from, WORD to);
	virtual void UnLink(WORD from);
	virtual void UnLinkAll(WORD from);
	virtual void SelectCurrent(DWORD num);
	virtual void DetachProcess(DWORD pid);
	virtual void SetCurrent(TextThread* it);
	virtual void AddConsoleOutput(LPCWSTR text);

	void DispatchText(DWORD pid, BYTE* text, DWORD hook, DWORD retn, DWORD split, int len);	
	void ClearText(DWORD pid, DWORD hook, DWORD retn, DWORD split);
	void RemoveProcessContext(DWORD pid);
	void RemoveSingleHook(DWORD pid, DWORD addr);
	void RegisterThread(TextThread*, DWORD);
	void RegisterPipe(HANDLE text, HANDLE cmd, HANDLE thread);
	void RegisterProcess(DWORD pid, DWORD hookman, DWORD module, DWORD engine);
	void UnRegisterProcess(DWORD pid);
	void SetName(DWORD);

	DWORD GetCurrentPID();
	HANDLE GetCmdHandleByPID(DWORD pid);

	inline ThreadEventCallback RegisterThreadCreateCallback(ThreadEventCallback cf)
	{
		return (ThreadEventCallback)_InterlockedExchange((long*)&create,(long)cf);
	}
	inline ThreadEventCallback RegisterThreadRemoveCallback(ThreadEventCallback cf)
	{
		return (ThreadEventCallback)_InterlockedExchange((long*)&remove,(long)cf);
	}
	inline ThreadEventCallback RegisterThreadResetCallback(ThreadEventCallback cf)
	{
		return (ThreadEventCallback)_InterlockedExchange((long*)&reset,(long)cf);
	}
	inline ProcessEventCallback RegisterProcessAttachCallback(ProcessEventCallback cf)
	{
		return (ProcessEventCallback)_InterlockedExchange((long*)&attach,(long)cf);
	}
	inline ProcessEventCallback RegisterProcessDetachCallback(ProcessEventCallback cf)
	{
		return (ProcessEventCallback)_InterlockedExchange((long*)&detach,(long)cf);
	}
	inline ProcessEventCallback RegisterProcessNewHookCallback(ProcessEventCallback cf)
	{
		return (ProcessEventCallback)_InterlockedExchange((long*)&hook,(long)cf);
	}
	inline ProcessEventCallback ProcessNewHook() {return hook;}
	inline TextThread* GetCurrentThread() {return current;}
	inline ProcessRecord* Records() {return record;}
	inline ThreadTable* Table() {return thread_table;}
	/*inline DWORD& SplitTime() {return split_time;}
	inline DWORD& RepeatCount() {return repeat_count;}
	inline DWORD& CyclicRemove() {return cyclic_remove;}
	inline DWORD& GlobalFilter() {return global_filter;}*/
private:

	CRITICAL_SECTION hmcs;
	TextThread *current;
	ThreadEventCallback create,remove,reset;
	ProcessEventCallback attach,detach,hook;
	DWORD current_pid;
	ThreadTable *thread_table;
	HANDLE destroy_event;
	ProcessRecord record[MAX_REGISTER+1];
	HANDLE text_pipes[MAX_REGISTER+1];
	HANDLE cmd_pipes[MAX_REGISTER+1];
	HANDLE recv_threads[MAX_REGISTER+1];
	WORD register_count, new_thread_number; 
};

