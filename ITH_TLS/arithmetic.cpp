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

#include "arithmetic.h"

#include <memory.h>
#include <intrin.h>

int count;
u32 next_pow2(u32 n)
{
	if (n == 0) return 1;
	n--;
	n |= n >> 1;
	n |= n >> 2;
	n |= n >> 4;
	n |= n >> 8;
	n |= n >> 16;
	n++;
	return n;
}
void mulasm(unsigned int* dest,unsigned int* left,unsigned int* right,unsigned int bit_size)
{
	__asm
	{
		cmp bit_size,64
		jbe _small
		xor eax,eax
		mov ebx,bit_size
		mov ecx,ebx
		sub esp,ecx
		mov edi,esp
		shr ecx,2
		rep stos dword ptr [edi]
		mov edi,esp

		mov ecx,ebx
		shr ecx,1
		push ecx
		mov eax,left ;left low
		push eax
		mov eax,right ;right low
		push eax
		push edi
		call mulasm ;left low*right lwo, z0
		add esp,0x10

		mov ecx,ebx
		shr ecx,1
		push ecx
		shr ecx,3
		lea edi,[edi+ecx*2]
		mov eax,left
		add eax,ecx ;left high
		push eax
		mov eax,right
		add eax,ecx ;right high
		push eax
		push edi
		call mulasm ;left high*right high; z2
		add esp,0x10

		xor edx,edx
		shr ebx,3
		add edi,ebx
		mov esi,left
		shr ebx,1
		mov ecx,ebx
		add ebx,esi
		push 0		
_add_left:
		mov eax,[esi+ecx]
		add eax,edx
		movs dword ptr [edi]
		adc [edi-4],eax
		setc dl
		cmp esi,ebx
		jne _add_left

		or [esp],dl
		mov esi,right
		mov ebx,esi
		add ebx,ecx
		xor edx,edx

_add_right:	
		mov eax,[esi+ecx]
		add eax,edx
		movs dword ptr [edi]
		adc [edi-4],eax
		setc dl
		cmp esi,ebx
		jne _add_right

		add edx,edx
		or [esp],edx

		mov ebx,bit_size
		shr ebx,1
		push ebx
		mov eax,edi
		sub eax,ecx
		push eax
		sub eax,ecx
		push eax
		push edi
		call mulasm ;(left low+left high)*(right low+right high);
		add esp,0x10

		mov ecx,bit_size
		shr ecx,4
		mov esi,edi
		sub esi,ecx
		sub esi,ecx
		add edi,ecx
		mov ebx,edi
		add ebx,ecx

		mov edx,[esp]
		mov eax,edx
		and eax,2
		shr eax,1
		sub eax,1
		not eax
		push eax
		mov eax,edx
		and eax,1
		sub eax,1
		not eax
		push eax
		push 0
		xor edx,edx
_carry_mul_add:
		mov eax,[esi]
		and eax,[esp+8]
		add eax,edx
		adc dh,0
		mov [esp],eax
		mov eax,[esi+ecx]
		and eax,[esp+4]
		add eax,[esp]
		adc dh,0
		add [edi],eax
		adc dh,0
		shr edx,8
		add esi,4
		add edi,4
		cmp ebx,edi
		jne _carry_mul_add

		add esp,0xC
		bt dword ptr [esp],1
		setc al
		and al,[esp]
		add dl,al
		mov [esp],edx

		lea esi,[esp+4]
		shl ecx,1
		lea ebx,[edi+ecx]
		xor edx,edx
_add_z0_z2:
		mov eax,[esi+ecx]
		add eax,edx
		movs dword ptr [edi]
		adc [edi-4],eax
		setc dl
		cmp edi,ebx
		jne _add_z0_z2
		sub [esp],edx

		lea esi,[esi+2*ecx]
		mov ebx,edi
		sub edi,ecx
		xor edx,edx
_form_z1:
		mov eax,[edi]
		bt edx,0
		sbb [esi],eax
		setc dl
		add esi,4
		add edi,4
		cmp edi,ebx
		jne _form_z1
		sub [esp],edx

		sub ebx,ecx
		sub esi,ecx
		shr ecx,1
		lea edi, [esp+ecx+4]
		xor edx,edx
_final_pack:
		lods dword ptr [esi]
		bt edx,0
		adc [edi],eax
		setc dl
		add edi,4
		cmp esi,ebx
		jne _final_pack

		add edx,[esp]
_add_carry:
		add [edi],edx
		setc dl
		add edi,4
		test dl,dl
		jne _add_carry

		pop eax
		mov esi,esp
		mov edi,dest
		rep movs dword ptr [edi]
		add esp,bit_size
		jmp _final

_small:
		mov esi,left
		mov edi,right
		mov ebx,dest
		mov eax,[esi]
		mov ecx,[edi]
		mul ecx
		mov [ebx],eax
		mov [ebx+4],edx

		mov eax,[esi+4]
		mul ecx
		add [ebx+4],eax
		adc edx,0
		mov [ebx+8],edx

		mov ecx,[edi+4]
		mov eax,[esi]
		mul ecx
		add [ebx+4],eax
		adc [ebx+8],edx
		push 0
		setc [esp]

		mov eax,[esi+4]
		mul ecx
		add [ebx+8],eax
		adc edx,[esp]
		mov [ebx+0xC],edx
		pop eax
_final:
	}
}
/*void __declspec(naked) mulmnu_asm(u8* w, u8* u, u8* v, u32 m)
{
	__asm
	{
		push ebx
		push ebp
		push esi
		push edi
		mov ecx,[esp+0x20] ; mov ecx,m
		shr ecx,1
		xor eax,eax
		mov edi,[esp+0x14] ; mov edi,w
		rep stos ; memset(w,0,2*m);

		xor ebx,ebx; i
		xor ebp,ebp; j
		mov esi,[esp+0x18] ; mov esi,u
		mov edi,[esp+0x1C] ; mov edi,v
		xor edx,edx
		push 0
_mul_outer_loop:
		xor ebp,ebp
		mov [esp],ebp
_mul_inner_loop:
		mov eax, [esi+ebx]
		mul dword ptr [edi+ebp]
		add dword ptr [ecx+ebp],eax
		adc dword ptr [ecx+ebp+4],edx
		adc dword ptr [ecx+ebp+8],0
		mov eax, [esi+ebx]
		mul dword ptr [edi+ebp+4]
		add edx, [esp]
		add dword ptr [ecx+ebp+4],eax
		adc dword ptr [ecx+ebp+8],edx
		setc [esp]
		add ebp,8
		cmp ebp,[esp+0x24]
		jne _mul_inner_loop
		bt [esp],0
		adc [ecx+ebp+4],0
		add ebx,4
		add ecx,4
		cmp ebx,[esp+0x24]
		jne _mul_outer_loop
		pop eax
		pop edi
		pop esi
		pop ebp
		pop ebx
		retn
	}
}*/
void mulmnu(u16 w[], u16 u[], u16 v[], int m, int n)
{
	unsigned int k, t;
	int i, j;

	for (i = 0; i < m; i++)
		w[i] = 0;

	for (j = 0; j < n; j++) 
	{
		k = 0;
		for (i = 0; i < m; i++)
		{
			t = u[i]*v[j] + w[i + j] + k;
			w[i + j] = t;          // (I.e., t & 0xFFFF).
			k = t >> 16;
		}
		w[j + m] = k;
	}
	return;
}
int mulmnu(u8 w[], u8 u[], u8 v[], int m, int n)
{
	//mulmnu((u16*)w,(u16*)u,(u16*)v,m/2,n/2);
	//__asm int 3
	for (m--;m>=0 && u[m] == 0;m--);
	for (n--;n>=0 && v[n] == 0;n--);
	m = next_pow2(m);
	n = next_pow2(n);
	m = m > n ? m : n;

	mulasm((u32*)w,(u32*)u,(u32*)v,m << 3);
	return 0;
}
int nlz(unsigned x) {
	int n;

	if (x == 0) return(32);
	n = 0;
	if (x <= 0x0000FFFF) {n = n +16; x = x <<16;}
	if (x <= 0x00FFFFFF) {n = n + 8; x = x << 8;}
	if (x <= 0x0FFFFFFF) {n = n + 4; x = x << 4;}
	if (x <= 0x3FFFFFFF) {n = n + 2; x = x << 2;}
	if (x <= 0x7FFFFFFF) {n = n + 1;}
	return n;
}
unsigned char nlz_table[0x100] =
{
	8,7,6,6, 5,5,5,5, 4,4,4,4, 4,4,4,4,
	3,3,3,3, 3,3,3,3, 3,3,3,3, 3,3,3,3,
	2,2,2,2, 2,2,2,2, 2,2,2,2, 2,2,2,2,
	2,2,2,2, 2,2,2,2, 2,2,2,2, 2,2,2,2,
	1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
	1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
	1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
	1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1
};
__declspec(naked) int divasm(void* q, void* r, const void* u, const void* v, unsigned int m, unsigned int n)
{
	__asm
	{
		push ebp
		mov ebp,esp
		push esi
		push edi
		push ebx
		std
		
		mov edx,n
		mov esi,v
		lea esi,[esi+edx-4]
		mov eax,[esi]
		xor ecx,ecx
		test eax,0xFFFF0000
		jne _nlz1
		add ecx,0x10
		shl eax,0x10
_nlz1:
		test eax,0xFF000000
		jne _nlz2
		add ecx,8
		shl eax,8
_nlz2:	
		shr eax,24
		add cl,byte ptr [nlz_table+eax]

		push ecx
		lea edi,[esp-4]	
		sub esp,edx
		lodsd
		mov edx,eax
_normalize:
		lodsd
		shld edx,eax,cl
		xchg edx,eax
		stosd
		cmp esi,v
		jae _normalize
		mov eax,edx
		shl eax, cl
		stosd

		mov esi,u
		mov edx,m
		sub esp,edx
		sub esp,4
		lea esi,[esi+edx-4]

		xor edx,edx
_normalize2:
		lodsd
		shld edx,eax,cl
		xchg edx,eax
		stosd
		cmp esi,u
		jae _normalize2
		shl edx, cl
		mov [edi],edx
		cld

		sub esp, 0xC
		mov ecx, n
		mov ebx, m
		lea esi, [ebx+edi+4] ; v
		sub ebx, ecx

		mov [esp], ebx
		xor eax,eax
		mov [esp+4],eax
		mov [esp+8],eax

_div_test:
		mov ebx, [esp]; j
		mov ecx, n
		add ebx, ecx
		mov edx, [edi + ebx] ; u(j+n)
		mov eax, [edi + ebx - 4]; u(j+n-1)
		mov ebx, [esi + ecx - 4]; v(n-1)
		cmp edx, ebx ;q >= b?
		setae cl
		jb _no_over_div
		sub edx, ebx ;q = b + q`
_no_over_div:
		div ebx
		mov [esp + 4], eax ;q`
		mov [esp + 8], edx ;r
		test cl,cl; cl: q >= b
		jz _test_qob
_dec_quo:
		sub dword ptr [esp + 4], 1 ; q--
		mov ecx, n
		mov ebx, [esi + ecx - 4]
		jnc _qob
		add [esp + 8], ebx
		jmp _mul_sub
_qob:
		add [esp + 8], ebx ;r += v(n-1) > b (c) ?
		jc _mul_sub 
_test_qob: 
		mov eax, [esp + 4]
		mov ecx, n
		mul dword ptr [esi + ecx - 8]
		mov ebx, [esp]
		add ebx, ecx
		sub eax, [edi + ebx - 8] 
		sbb edx, [esp + 8] ; q*v(n-2) > b*r + u(j+n-2) (a)? 
		ja _dec_quo ; _dec_quo : $
_mul_sub:
		xor ebx, ebx
		mov ecx, [esp]
		add ecx, edi
		push 0
_mul_sub_loop:
		mov eax, [esp + 8] ; q
		mul dword ptr [esi + ebx]
		sub [ecx], eax
		sbb [ecx + 4], edx
		mov edx, [esp]
		setc byte ptr [esp]
		sub [ecx + 4], edx
		adc byte ptr [esp],0
		add ecx, 4
		add ebx, 4
		cmp ebx, n
		jb _mul_sub_loop

		pop eax
		test eax,eax
		jz  _loop_on_j

		xor ecx,ecx
		xor ebx,ebx
		mov edx, [esp]
		add edx, edi
_add_back:
		mov eax,[esi + ecx]
		bt ebx,0
		adc [edx], eax
		setc bl
		add ecx,4
		add edx,4
		cmp ecx,n
		jb _add_back
		add [edx], ebx
		dec dword ptr [esp + 4]
_loop_on_j:
		mov eax, [esp]
		mov edx, q
		mov ecx, [esp + 4]
		mov [edx + eax], ecx
		sub eax, 4
		mov [esp], eax
		jae _div_test

		add esp,0x10
		add esp,m
		add esp,n
		pop ecx
		mov esi, edi
		mov edi, r
		mov ebx, n
		add ebx, esi
		xor edx,edx
		lodsd
		mov edx,eax
_unnormalize:
		lodsd
		shrd edx,eax,cl
		xchg edx,eax
		stosd
		cmp esi, ebx
		jb _unnormalize
		shr edx, cl
		mov [edi],edx
		pop ebx
		pop edi
		pop esi
		mov esp,ebp
		pop ebp
		retn
	}
};

__declspec(naked) int divasm_s(void* q, void* r, const void* u, unsigned int v, unsigned int m)
{
	__asm
	{
		push ebp
		mov ebp,esp
		push esi
		push edi
		push ebx
		std
		
		mov ebx, m
		mov esi, u
		mov edi, q
		lea esi, [esi + ebx - 4]
		lea edi, [edi + ebx - 4]
		shr ebx, 4
		mov ecx, v
		xor edx,edx
		test ebx,ebx
		jz _remain
_div_loop:
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		lodsd
		div ecx
		stosd
		dec ebx
		jne _div_loop
_remain:
		mov ebx, m
		shr ebx, 2
		and ebx, 3
		jz _div_no_single
		dec ebx
		jz _div_one_single
		dec ebx
		jz _div_two_single
		lodsd
		div ecx
		stosd
_div_two_single:
		lodsd
		div ecx
		stosd
_div_one_single:
		lodsd
		div ecx
		stosd
_div_no_single:
		mov ebx, r
		mov [ebx], edx

		cld
		pop ebx
		pop edi
		pop esi
		pop ebp
		retn
	}
}
int div_long(void* q, void* r, const void* u, const void* v, unsigned m, unsigned n)
{
	if ((m|n)&3) return 1; //align 4 byte
	unsigned int *pu, *pv;
	unsigned int m1,n1;
	pu = (unsigned int*)u;
	pv = (unsigned int*)v;
	m1 = m / 4 - 1;
	n1 = n / 4 - 1;
	while (m1 && pu[m1] == 0) m1--;
	while (n1 && pv[n1] == 0) n1--;
	if (n1 == 0 && pv[0]) divasm_s(q,r,u,pv[0], (m1+1) << 2);
	else
	{
		divasm(q,r,u,v,(m1+1)*4,(n1+1)*4);
	}
	return 0;
}
int divmnu(u8 q[], u8 r[], const u8 u[], const u8 v[], int m, int n)
{
	return div_long(q,r,u,v,m<<1,n<<1);
	/*
	//m=(m+3)/4;n=(n+3)/4;
	//return divmnu32((u32*)q,(u32*)r,(u32*)u,(u32*)v,m,n);
	if ((m|n)&3) return 1;
	u8* u_copy = alloca(m+n);
	u8* v_copy = u_copy + m;
	memcpy(u_copy, u, m);
	memcpy(v_copy, v, n);
	divasm(q,r,u_copy,v_copy,m,n);
	return 0;*/
	//return divmnu((u16*)q,(u16*)r,(u16*)u,(u16*)v,m/2,n/2);
}
void exp_mod(u8* base, u8* exp, u8* mod,u8* res, u32 base_size, u32 exp_size, u32 mod_size)
{
	int i,j,exp_head;
	u8 t=0x80;
	for (exp_head=exp_size-1;exp_head>=0&&exp[exp_head]==0;exp_head--);
	if (exp_head<0) return;
	u8 *block;
	u8 *result[2];
	u8 *new_base[2];
	u8 *quotient;//=(u8 *)alloca(base_size*2);
	u8 *remainder;//=(u8 *)alloca(mod_size*2);
	block=(u8*)alloca(base_size*12);	
	quotient=block;
	remainder=block+base_size*2;
	result[0]=block+base_size*4;
	result[1]=block+base_size*6;
	new_base[0]=block+base_size*8;
	new_base[1]=block+base_size*10;
	memset(block,0,base_size*8);
	memcpy(new_base[0],base,base_size);//memset(new_base[0]+base_size,0,base_size);
	memcpy(new_base[1],base,base_size);//memset(new_base[1]+base_size,0,base_size);
	result[0][0]=1;
	for (i=0;i<exp_head;i++)
	{
		t=1;
		for (j=0;j<8;j++)
		{
			if (exp[i]&t)
			{
				mulmnu(result[1],result[0],new_base[0],base_size,base_size);
				//divmnu((u16*)quotient,(u16*)result[0],(u16*)result[1],(u16*)mod,base_size,mod_size/2);
				div_long(quotient,result[0],result[1],mod,base_size*2,mod_size);
			}
			mulmnu(new_base[1],new_base[0],new_base[0],base_size,base_size);
			//divmnu((u16*)quotient,(u16*)new_base[0],(u16*)new_base[1],(u16*)mod,base_size,mod_size/2);
			div_long(quotient,new_base[0],new_base[1],mod,base_size*2,mod_size);
			t<<=1;
		}
	}
	for (t=exp[exp_head]; t; t>>=1)
	{
		if (t&1)
		{
			mulmnu(result[1],result[0],new_base[0],base_size,base_size);
			//divmnu((u16*)quotient,(u16*)result[0],(u16*)result[1],(u16*)mod,base_size,mod_size/2);
			div_long(quotient,result[0],result[1],mod,base_size*2,mod_size);
		}
		mulmnu(new_base[1],new_base[0],new_base[0],base_size,base_size);
		//divmnu((u16*)quotient,(u16*)new_base[0],(u16*)new_base[1],(u16*)mod,base_size,mod_size/2);
		div_long(quotient,new_base[0],new_base[1],mod,base_size*2,mod_size);
	}
	memcpy(res,result[0],mod_size);
}
