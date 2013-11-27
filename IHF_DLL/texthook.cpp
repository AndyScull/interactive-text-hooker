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

#include "IHF_CLIENT.h"
#include <ITH\ntdll.h>
TextHook *hookman,*current_available;

FilterRange filter[8];
static const int size_hook=sizeof(TextHook);
DWORD flag, enter_count;
//provide const time hook entry.
static int userhook_count;
static const BYTE common_hook2[]={
	0x89, 0x3C, 0xE4, //mov [esp],edi
	0x60, //pushad
	0x9C, //pushfd
	0x8D,0x54,0x24,0x28, //lea edx,[esp+0x28] --- esp value
	0x8B,0x32, //mov esi,[edx] --- return address
	0xB9, 0,0,0,0, //mov ecx, $ --- pointer to TextHook
	0xE8, 0,0,0,0, //call @hook
	0x9D, //popfd
	0x61, //popad
	0x5F, //pop edi ---skip return address on stack
}; //...
static const BYTE common_hook[]={
	0x9C,
	0x60, //pushad
	0x9C, //pushfd
	0x8D,0x54,0x24,0x28, //lea edx,[esp+0x28] --- esp value
	0x8B,0x32, //mov esi,[edx] --- return address
	0xB9, 0,0,0,0, //mov ecx, $ --- pointer to TextHook
	0xE8, 0,0,0,0, //call @hook
	0x9D, //popfd
	0x61, //popad
	0x9D
}; //...
//copy original instruction
//jmp back
DWORD GetModuleBase(DWORD hash)
{
	__asm
	{
		mov eax,fs:[0x30]
		mov eax,[eax+0xC]
		mov esi,[eax+0x14]
		mov edi,_wcslwr
listfind:
		mov edx,[esi+0x28]
		test edx,edx
		jz notfound
		push edx
		call edi
		pop edx
		xor eax,eax
calc:
		movzx ecx, word ptr [edx]
		test cl,cl
		jz fin
		ror eax,7
		add eax,ecx
		add edx,2
		jmp calc
fin:
		cmp eax,[hash]	
		je found
		mov esi,[esi]
		jmp listfind
notfound:		
		xor eax,eax
		jmp termin
found:
		mov eax,[esi+0x10]
termin:
	}
}
/*void NotifyHookInsert()
{
	if (live)
	{
		BYTE buffer[0x10];
		*(DWORD*)buffer=-1;
		*(DWORD*)(buffer+4)=1;
		IO_STATUS_BLOCK ios;
		NtWriteFile(hPipe,0,0,0,&ios,buffer,0x10,0,0);
	}
}*/

typedef void (*DataFun)(DWORD, const HookParam*, DWORD*, DWORD*, DWORD*);
static DWORD recv_esp, recv_addr;
static EXCEPTION_DISPOSITION ExceptHandler(EXCEPTION_RECORD *ExceptionRecord,
	void * EstablisherFrame, CONTEXT *ContextRecord, void * DispatcherContext )
{
	WCHAR str[0x40],name[0x100];
	
	OutputConsole(L"Exception raised during hook processing.");
	swprintf(str,L"Exception code: 0x%.8X", ExceptionRecord->ExceptionCode);
	OutputConsole(str);
	MEMORY_BASIC_INFORMATION info;
	if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)ContextRecord->Eip,
		MemoryBasicInformation,&info,sizeof(info),0)))
	{
		if (NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),(PVOID)ContextRecord->Eip,
			MemorySectionName,name,0x200,0)))
		{
			swprintf(str,L"Exception offset: 0x%.8X:%s",
				ContextRecord->Eip-(DWORD)info.AllocationBase,
				wcsrchr(name,L'\\')+1);
			OutputConsole(str);
		}
	}
	ContextRecord->Esp=recv_esp;
	ContextRecord->Eip=recv_addr;
	return ExceptionContinueExecution;
}
__declspec (naked) void SafeExit() //Return to eax
{
	__asm
	{
		mov [esp + 0x24], eax
		popfd
		popad
		retn
	}
}
__declspec(naked) int ProcessHook(DWORD dwDataBase, DWORD dwRetn,TextHook *hook)
	//Use SEH to ensure normal execution even bad hook inserted.
{
	__asm
	{
		mov eax,seh_recover
		mov recv_addr,eax
		push ExceptHandler
		push fs:[0]
		mov recv_esp,esp
		mov fs:[0],esp
		push esi
		push edx
		call TextHook::Send
		test eax,eax
		jz seh_recover
		mov ecx,SafeExit
		mov [esp + 0x8], ecx //change exit point.
seh_recover:
		pop dword ptr fs:[0]
		pop ecx
		retn
	}
}

bool HookFilter(DWORD retn)
{
	DWORD i;
	for (i=0;filter[i].lower;i++)
	if (retn>filter[i].lower&&retn<filter[i].upper) return true;
	return false;
}
#define SMALL_BUFF_SIZE 0x80
DWORD TextHook::Send(DWORD dwDataBase, DWORD dwRetn)
{
	DWORD dwCount,dwAddr,dwDataIn,dwSplit=0;
	BYTE *pbData, pbSmallBuff[SMALL_BUFF_SIZE];
	DWORD dwType=hp.type;
	if (!live) return 0;
	if ((dwType&NO_CONTEXT)==0)
		if (HookFilter(dwRetn)) return 0;
	dwCount=0;
	dwAddr=hp.addr;
	if (trigger)
	{
		if (InsertDynamicHook)
			trigger=InsertDynamicHook((LPVOID)dwAddr,*(DWORD*)(dwDataBase-0x1C),*(DWORD*)(dwDataBase-0x18));
		else trigger=0;
	}
	if (dwType & HOOK_AUXILIARY)
	{
		//Clean hook when dynamic hook finished.
		//AUX hook is only used for a foothold of dynamic hook.
		if (trigger == 0)
		{
			ClearHook();
			return dwAddr;
		}
		return 0;
	}
	dwDataIn=*(DWORD*)(dwDataBase+hp.off);
	if (dwType&EXTERN_HOOK) 
	{
		DataFun fun=(DataFun)hp.extern_fun;
		fun(dwDataBase,&hp,&dwDataIn,&dwSplit,&dwCount);
		if (dwCount==0 || dwCount > 0x10000) return 0;
	}
	else
	{
		dwSplit=0;
		if (dwDataIn==0) return 0;
		if (dwType&USING_SPLIT)
		{
			dwSplit=*(DWORD*)(dwDataBase+hp.split);
			if (dwType&SPLIT_INDIRECT) 
			{
				if (IthGetMemoryRange((LPVOID)(dwSplit+hp.split_ind),0,0))
					dwSplit=*(DWORD*)(dwSplit+hp.split_ind);
				else return 0;
			}
		}
		if (dwType&DATA_INDIRECT)
		{
			if (IthGetMemoryRange((LPVOID)(dwDataIn+hp.ind),0,0))
				dwDataIn=*(DWORD*)(dwDataIn+hp.ind);
			else return 0;
		}
		if (dwType&PRINT_DWORD) 
		{
			swprintf((WCHAR*)(pbSmallBuff+HEADER_SIZE),L"%.8X ",dwDataIn);
			dwDataIn=(DWORD)pbSmallBuff+HEADER_SIZE;
		}
		dwCount=GetLength(dwDataBase, dwDataIn);
	}
	if (dwCount+HEADER_SIZE>=SMALL_BUFF_SIZE) pbData=new BYTE[dwCount+HEADER_SIZE];
	else pbData=pbSmallBuff;
	if (hp.length_offset==1)
	{
		if (dwType&STRING_LAST_CHAR)
		{
			LPWSTR ts=(LPWSTR)dwDataIn;
			dwDataIn=ts[wcslen(ts)-1];
		}
		dwDataIn&=0xFFFF;
		if (dwType&BIG_ENDIAN) 
			if (dwDataIn>>8)
				dwDataIn=_byteswap_ushort(dwDataIn&0xFFFF);
		if (dwCount==1) dwDataIn&=0xFF;
		*(WORD*)(pbData+HEADER_SIZE)=dwDataIn&0xFFFF;
	}
	else memcpy(pbData+HEADER_SIZE,(void*)dwDataIn,dwCount);
	*(DWORD*)pbData=dwAddr;
	if (dwType&NO_CONTEXT) dwRetn=0;
	*((DWORD*)pbData+1)=dwRetn;
	*((DWORD*)pbData+2)=dwSplit;
	if (dwCount)
	{
		IO_STATUS_BLOCK ios={0};
		if (STATUS_PENDING==NtWriteFile(hPipe,0,0,0,&ios,pbData,dwCount+HEADER_SIZE,0,0))
		{
			NtWaitForSingleObject(hPipe,0,0);
			NtFlushBuffersFile(hPipe,&ios);
		}
	}
	if (pbData!=pbSmallBuff) delete pbData;
	return 0;
}
int MapInstruction(DWORD original_addr, DWORD new_addr, BYTE& hook_len, BYTE& original_len)
{
	int flag=0;
	DWORD l=0;
	BYTE *r,*c;
	r=(BYTE*)original_addr;
	c=(BYTE*)new_addr;
	while((r-(BYTE*)original_addr)<5)
	{
		l=disasm(r);
		if (l==0) return -1;
		memcpy(c,r,l);
		if (*r>=0x70&&*r<0x80)
		{
			c[0]=0xF;
			c[1]=*r+0x10;
			c+=6;
			__asm
			{
				mov eax,r
				add eax,2
				movsx edx,byte ptr [eax-1]
				add edx,eax
				mov eax,c
				sub edx,eax
				mov [eax-4],edx
			}
		}
		else if (*r==0xEB)
		{
			c[0]=0xE9;
			c+=5;
			__asm
			{
				mov eax,r
				add eax,2
				movsx edx,[eax-1]
				add edx,eax
				mov eax,c
				sub edx,eax
				mov [eax-4],edx
			}
			if (r-(BYTE*)original_addr<5-l) return -1; //Not safe to move intruction right after short jmp.
			else flag=1;
		}
		else if (*r==0xE8||*r==0xE9)
		{
			c[0]=*r;
			c+=5;
			flag=(*r==0xE9);
			__asm
			{
				mov eax,r
				add eax,5
				mov edx,[eax-4]
				add edx,eax
				mov eax,c
				sub edx,eax
				mov [eax-4],edx
			}
		}
		else if (*r==0xF && (*(r+1)>>4)==0x8)
		{
			c+=6;
			__asm
			{
				mov eax,r
				mov edx,dword ptr [eax+2]
				add eax,6
				add eax,edx
				mov edx,c
				sub eax,edx
				mov [edx-4],eax
			}
		}
		else c+=l;
		r+=l;
	}
	original_len=r-(BYTE*)original_addr;
	hook_len=c-(BYTE*)new_addr;
	return flag;
}
int TextHook::InsertHook()
{
	NtWaitForSingleObject(hmMutex,0,0);
	int k=InsertHookCode();
	IthReleaseMutex(hmMutex);	
	if (hp.type&HOOK_ADDITIONAL) 
	{
		NotifyHookInsert(hp.addr);
		OutputConsole(hook_name);
		//RegisterHookName(hook_name,hp.addr);
	}
	return k;
}
int TextHook::InsertHookCode()
{
	if (hp.module&&(hp.type&MODULE_OFFSET)) //Map hook offset to real address. 
	{
		
		DWORD base=GetModuleBase(hp.module);
		if (base) 
		{
			if (hp.function&&(hp.type&(FUNCTION_OFFSET)))
			{
				base=GetExportAddress(base,hp.function);
				if (base) 
					hp.addr+=base;
				else 
				{
					OutputConsole(L"Function not found in the export table.");
					current_hook--;
					return 1;
				}
			}
			else
				hp.addr+=base;
			hp.type&=~(MODULE_OFFSET|FUNCTION_OFFSET);
		}
		else 
		{
			OutputConsole(L"Module not present.");
			current_hook--;
			return 1;
		}
	}
	TextHook* it;
	int i;
	for (i=0,it=hookman;i<current_hook;it++) //Check if there is a collision.
	{
		if (it->Address()) i++;
		//it=hookman+i;
		if (it==this) continue;
		if (it->Address()<=hp.addr && it->Address()+it->Length()>hp.addr)
		{
			it->ClearHook();
			break;
		}
	}
	//Verify hp.addr. 
	MEMORY_BASIC_INFORMATION info;
	NtQueryVirtualMemory(NtCurrentProcess(),(LPVOID)hp.addr,MemoryBasicInformation,&info,sizeof(info),0);
	if (info.Type&PAGE_NOACCESS) return 1; 
	//Initialize common routine.
	memcpy(recover,common_hook,sizeof(common_hook));
	BYTE* c=(BYTE*)hp.addr;
	BYTE* r=recover;
	BYTE inst[8];
	inst[0]=0xE9;
	__asm
	{
		mov edx,r
		mov eax,this
		mov [edx+0xA],eax //push TextHook*, resolve to correspond hook.
		lea eax,[edx+0x13]
		mov edx,ProcessHook
		sub edx,eax
		mov [eax-4],edx //call ProcessHook
		mov eax,c
		add eax,5
		mov edx,r
		sub edx,eax
		lea eax,inst+1
		mov [eax],edx
	}
	r+=sizeof(common_hook);
	hp.hook_len=5;
	bool jmpflag=false;
	//Copy original code.
	switch (MapInstruction(hp.addr,(DWORD)r,hp.hook_len,hp.recover_len))
	{
	case -1:
		return 1;
	case 0:
		__asm
		{
			mov ecx,this
			movzx eax,[ecx]hp.hook_len
			movzx edx,[ecx]hp.recover_len
			add edx,[ecx]hp.addr
			add eax,r
			add eax,5
			sub edx,eax
			mov [eax-5],0xE9
			mov [eax-4],edx
		}
	}
	memcpy(original,(LPVOID)hp.addr,hp.recover_len);
	//Check if the new hook range conflict with existing ones. Clear older if conflict.
	for (i=0,it=hookman;i<current_hook;it++)
	{
		if (it->Address()) i++;
		if (it==this) continue;
		if (it->Address()>=hp.addr && it->Address()<hp.hook_len+hp.addr)
		{
			it->ClearHook();
			break;
		}
	}
	//Insert hook and flush instruction cache.
	DWORD int3[2]={0xCCCCCCCC,0xCCCCCCCC};
	DWORD t=0x100,old,len;
	DWORD addr=hp.addr;
	NtProtectVirtualMemory(NtCurrentProcess(),(PVOID*)&addr,&t,PAGE_EXECUTE_READWRITE,&old);
	NtWriteVirtualMemory(NtCurrentProcess(),(BYTE*)hp.addr,inst,5,&t);
	len=hp.recover_len-5;
	if (len) NtWriteVirtualMemory(NtCurrentProcess(),(BYTE*)hp.addr+5,int3,len,&t);
	NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hp.addr,hp.recover_len);
	NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hookman,0x1000);
	return 0;
}
int TextHook::InitHook(LPVOID addr, DWORD data, DWORD data_ind, 
	DWORD split_off, DWORD split_ind, WORD type, DWORD len_off)
{
	NtWaitForSingleObject(hmMutex,0,0);
	hp.addr=(DWORD)addr;
	hp.off=data;
	hp.ind=data_ind;
	hp.split=split_off;
	hp.split_ind=split_ind;
	hp.type=type;
	hp.hook_len=0;
	hp.module=0;
	hp.length_offset=len_off&0xFFFF;
	current_hook++;
	if (current_available>=this)
		for (current_available=this+1;current_available->Address();current_available++);
	IthReleaseMutex(hmMutex);
	return this-hookman;
}
int TextHook::InitHook(const HookParam& h, LPWSTR name, WORD set_flag)
{
	NtWaitForSingleObject(hmMutex,0,0);
	hp=h;
	hp.type|=set_flag;
	if (name&&name!=hook_name)
	{
		if (hook_name) delete hook_name;
		name_length=wcslen(name)+1;
		hook_name=new WCHAR[name_length];
		wcscpy(hook_name,name);
	}
	current_hook++;
	current_available=this+1;
	while (current_available->Address()) current_available++;
	IthReleaseMutex(hmMutex);
	return 1;
}
int TextHook::RemoveHook()
{
	if (hp.addr)
	{
		NtWaitForSingleObject(hmMutex,0,0);
		DWORD l=hp.hook_len;
		NtWriteVirtualMemory(NtCurrentProcess(),(LPVOID)hp.addr,original,hp.recover_len,&l);
		NtFlushInstructionCache(NtCurrentProcess(),(LPVOID)hp.addr,hp.recover_len);
		hp.hook_len=0;
		IthReleaseMutex(hmMutex);
		return 1;
	}
	return 0;
}
int TextHook::ClearHook()
{
	NtWaitForSingleObject(hmMutex,0,0);
	int k=RemoveHook();
	if (hook_name) {delete hook_name;hook_name=0;}
	memset(this,0,sizeof(TextHook));
	//if (current_available>this) current_available=this;
	current_hook--;
	IthReleaseMutex(hmMutex);
	return k;
}
int TextHook::ModifyHook(const HookParam& hp)
{
	//WCHAR name[0x40];
	DWORD len = 0;
	if (hook_name) len = wcslen(hook_name);
	LPWSTR name = 0;
	if (len)
	{
		name = new WCHAR[len + 1];
		wcscpy(name,hook_name);
	}
	ClearHook();
	InitHook(hp,name);
	InsertHook();
	if (name) delete name;
	return 0;
}
int TextHook::RecoverHook()
{
	if (hp.addr)
	{
		InsertHook();
		return 1;
	}
	return 0;
}
int TextHook::SetHookName(LPWSTR name)
{
	name_length=wcslen(name)+1;
	if (hook_name) delete hook_name;
	hook_name=new WCHAR[name_length];
	wcscpy(hook_name,name);
	return 0;
}
int TextHook::GetLength(DWORD base, DWORD in)
{
	if (base==0) return 0;
	int len;
	switch (hp.length_offset)
	{
	default:
		len = *((int*)base+hp.length_offset);
		if (len>=0) 
		{
			if (hp.type&USING_UNICODE) len<<=1;
			break;
		}
		else if (len != -1) break;
		//len == -1 then continue to case 0.
	case 0:
		if (hp.type&USING_UNICODE) len=wcslen((LPWSTR)in)<<1;
		else len=strlen((char*)in);
		break;
	case 1:
		if (hp.type&USING_UNICODE) len=2;
		else 
		{
			if (hp.type&BIG_ENDIAN) in>>=8;
			len=LeadByteTable[in&0xFF];  //Slightly faster than IsDBCSLeadByte
		}
		break;
	}
	return len;
}

static LPVOID fun_table[14];
//#define DEFAULT_SPLIT
#ifdef DEFAULT_SPLIT
#define SPLIT_SWITCH USING_SPLIT
#else
#define SPLIT_SWITCH 0
#endif
LPWSTR HookNameInitTable[]={
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
void InitDefaultHook()
{
	fun_table[0]=GetTextExtentPoint32A;
	fun_table[1]=GetGlyphOutlineA;
	fun_table[2]=ExtTextOutA;
	fun_table[3]=TextOutA;
	fun_table[4]=GetCharABCWidthsA;
	fun_table[5]=DrawTextA;
	fun_table[6]=DrawTextExA;
	fun_table[7]=GetTextExtentPoint32W;
	fun_table[8]=GetGlyphOutlineW;
	fun_table[9]=ExtTextOutW;
	fun_table[10]=TextOutW;
	fun_table[11]=GetCharABCWidthsW;
	fun_table[12]=DrawTextW;
	fun_table[13]=DrawTextExW;

	hookman[0].InitHook(  fun_table[0],   8,0,4,0,USING_STRING|SPLIT_SWITCH ,3);
	hookman[1].InitHook(  fun_table[1],   8,0,4,0,BIG_ENDIAN|SPLIT_SWITCH, 1);
	hookman[2].InitHook(  fun_table[2],   0x18,0,4,0,USING_STRING|SPLIT_SWITCH, 7);
	hookman[3].InitHook(  fun_table[3],   0x10,0,4,0,USING_STRING|SPLIT_SWITCH, 5);
	hookman[4].InitHook(  fun_table[4],   0x8,0,4,0,BIG_ENDIAN|SPLIT_SWITCH, 1);
	hookman[5].InitHook(  fun_table[5],   0x8,0,4,0,USING_STRING|SPLIT_SWITCH, 3);
	hookman[6].InitHook(  fun_table[6],   0x8,0,4,0,USING_STRING|SPLIT_SWITCH, 3);
	hookman[7].InitHook(  fun_table[7],   8,0,4,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	hookman[8].InitHook(  fun_table[8],   8,0,4,0,USING_UNICODE|SPLIT_SWITCH, 1);
	hookman[9].InitHook(  fun_table[9],   0x18,0,4,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 7);
	hookman[10].InitHook(fun_table[10], 0x10,0,4,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 5);
	hookman[11].InitHook(fun_table[11], 0x8,0,4,0,USING_UNICODE|SPLIT_SWITCH, 1);
	hookman[12].InitHook(fun_table[12], 0x8,0,4,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	hookman[13].InitHook(fun_table[13], 0x8,0,4,0,USING_UNICODE | USING_STRING|SPLIT_SWITCH, 3);
	for (int i=0;i<sizeof(HookNameInitTable)/4;i++)
		hookman[i].SetHookName(HookNameInitTable[i]);
}
