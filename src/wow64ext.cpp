/**
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2012 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <Windows.h>
#include "internal.h"
#include "wow64ext.h"
#include "CMemPtr.h"

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	return TRUE;
}

#pragma warning(push)
#pragma warning(disable : 4409)
extern "C" __declspec(dllexport) DWORD64 X64Call(DWORD64 func, int argC, ...)
{
	va_list args;
	va_start(args, argC);
	DWORD64 _rcx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _rdx = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r8 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	DWORD64 _r9 = (argC > 0) ? argC--, va_arg(args, DWORD64) : 0;
	reg64 _rax;
	_rax.v = 0;

	DWORD64 restArgs = (DWORD64)&va_arg(args, DWORD64);
	
	// conversion to QWORD for easier use in inline assembly
	DWORD64 _argC = argC;

	DWORD back_esp = 0;

	__asm
	{
		;// keep original esp in back_esp variable
		mov    back_esp, esp
		
		;// align esp to 8, without aligned stack some syscalls may return errors !
		and    esp, 0xFFFFFFF8

		X64_Start();
		;// below inline assembly abuses x86 inline asm compiler to generate x64 code,
		;// it can be done because of x86/x64 assembly similarity

		;// fill first four arguments
		push   _rcx
		X64_Pop(_RCX);
		push   _rdx
		X64_Pop(_RDX);
		push   _r8
		X64_Pop(_R8);
		push   _r9
		X64_Pop(_R9);
	
		push   edi					;// rdi

		push   restArgs
		X64_Pop(_RDI);

		push   _argC
		X64_Pop(_RAX);

		;// put rest of arguments on the stack
		test   eax, eax
		jz     _ls_e
		lea    edi, dword ptr [edi + 8*eax - 8]

		_ls:
		test   eax, eax
		jz     _ls_e
		push   dword ptr [edi]		;// this pushes qword (in x64 mode)
		sub    edi, 8
		sub    eax, 1
		jmp    _ls
		_ls_e:

		;// create stack space for spilling registers
		sub    esp, 0x20

		call   func

		;// cleanup stack
		push   _argC
		X64_Pop(_RCX);
		lea    esp, dword ptr [esp + 8*ecx + 0x20]

		pop    edi					;// rdi

		// set return value
		X64_Push(_RAX);
		pop    _rax.dw[0]

		X64_End();

		mov    esp, back_esp
	}
	return _rax.v;
}
#pragma warning(pop)

void getMem64(void* dstMem, DWORD64 srcMem, size_t sz)
{
	reg64 _src;
	_src.v = srcMem;
	__asm
	{
		X64_Start();

		push   edi
		push   esi

		mov    edi, dstMem
		REX_W() 
		mov    esi, _src.dw[0]
		mov    ecx, sz				;// no need for REX.W, high part of RCX is zeroed anyway

		mov    eax, ecx
		and    eax, 3

		shr    ecx, 2
		rep    movsd

		test   eax, eax
		je     _move_0
		cmp    eax, 1
		je     _move_1

		movsw
		cmp    eax, 2
		je     _move_0

_move_1:
		movsb

_move_0:

		pop    esi
		pop    edi
		X64_End();
	}
}

TEB64* getTEB64()
{
	reg64 reg;
	reg.v = 0;
	
	X64_Start();
	// R12 register should always contain pointer to TEB64 in WoW64 processes
	X64_Push(_R12);
	// below pop will pop QWORD from stack, as we're in x64 mode now
	__asm pop reg.dw[0]
	X64_End();

	// upper 32 bits should be always 0 in WoW64 processes
	// TODO: check if it is true on Win8
	if (reg.dw[1] != 0)
		return 0;

	return (TEB64*)reg.dw[0];
}

extern "C" __declspec(dllexport) DWORD64 GetModuleHandle64(wchar_t* lpModuleName)
{
	TEB64* teb64 = getTEB64();
	if (nullptr == teb64)
		return 0;

	DWORD64 module = 0;
	PEB64* peb64 = (PEB64*)teb64->ProcessEnvironmentBlock;
	PEB_LDR_DATA64* ldr = (PEB_LDR_DATA64*)peb64->Ldr;

	LDR_DATA_TABLE_ENTRY64* head = (LDR_DATA_TABLE_ENTRY64*)ldr->InLoadOrderModuleList.Flink;
	do
	{
		if (memcmp((void*)head->BaseDllName.Buffer, lpModuleName, head->BaseDllName.Length) == 0)
			module = head->DllBase;
		head = (LDR_DATA_TABLE_ENTRY64*)head->InLoadOrderLinks.Flink;
	}
	while (head != (LDR_DATA_TABLE_ENTRY64*)&ldr->InLoadOrderModuleList);
	return module;
}

DWORD64 getNTDLL64()
{
	static DWORD64 ntdll64 = 0;
	if (0 != ntdll64)
		return ntdll64;

	ntdll64 = GetModuleHandle64(L"ntdll.dll");
	return ntdll64;
}

DWORD64 getLdrGetProcedureAddress()
{
	DWORD64 modBase = getNTDLL64();
	
	IMAGE_DOS_HEADER idh;
	getMem64(&idh, modBase, sizeof(idh));

	IMAGE_NT_HEADERS64 inh;
	getMem64(&inh, modBase + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));
	
	IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	
	if (0 == idd.VirtualAddress)
		return 0;

	IMAGE_EXPORT_DIRECTORY ied;
	getMem64(&ied, modBase + idd.VirtualAddress, sizeof(ied));

	DWORD* rvaTable = (DWORD*)malloc(sizeof(DWORD)*ied.NumberOfFunctions);
	if (nullptr == rvaTable)
		return 0;
	WATCH(rvaTable);
	getMem64(rvaTable, modBase + ied.AddressOfFunctions, sizeof(DWORD)*ied.NumberOfFunctions);
	
	WORD* ordTable = (WORD*)malloc(sizeof(WORD)*ied.NumberOfFunctions);
	if (nullptr == ordTable)
		return 0;
	WATCH(ordTable);
	getMem64(ordTable, modBase + ied.AddressOfNameOrdinals, sizeof(WORD)*ied.NumberOfFunctions);

	DWORD* nameTable = (DWORD*)malloc(sizeof(DWORD)*ied.NumberOfNames);
	if (nullptr == nameTable)
		return 0;
	WATCH(nameTable);
	getMem64(nameTable, modBase + ied.AddressOfNames, sizeof(DWORD)*ied.NumberOfNames);

	// lazy search, there is no need to use binsearch for just one function
	for (DWORD i = 0; i < ied.NumberOfFunctions; i++)
	{
		if (strcmp((char*)modBase + nameTable[i], "LdrGetProcedureAddress"))
			continue;
		else
			return (DWORD)(modBase + rvaTable[ordTable[i]]);
	}
	return 0;
}

extern "C" __declspec(dllexport) DWORD64 GetProcAddress64(DWORD64 hModule, char* funcName)
{
	static DWORD64 _LdrGetProcedureAddress = 0;
	if (0 == _LdrGetProcedureAddress)
	{
		_LdrGetProcedureAddress = getLdrGetProcedureAddress();
		if (0 == _LdrGetProcedureAddress)
			return 0;
	}

	_UNICODE_STRING_T<DWORD64> fName = { 0 };
	fName.Buffer = (DWORD64)funcName;
	fName.Length = strlen(funcName);
	fName.MaximumLength = fName.Length + 1;
	DWORD64 funcRet = 0;
	X64Call(_LdrGetProcedureAddress, 4, (DWORD64)hModule, (DWORD64)&fName, (DWORD64)0, (DWORD64)&funcRet);
	return (DWORD)funcRet;
}

extern "C" __declspec(dllexport) SIZE_T VirtualQueryEx64(HANDLE hProcess, DWORD64 lpAddress, MEMORY_BASIC_INFORMATION64* lpBuffer, SIZE_T dwLength)
{
	static DWORD64 ntqvm = 0;
	if (0 == ntqvm)
	{
		ntqvm = GetProcAddress64(getNTDLL64(), "NtQueryVirtualMemory");
		if (0 == ntqvm)
			return 0;
	}
	DWORD64 ret = 0;
	X64Call(ntqvm, 6, (DWORD64)hProcess, lpAddress, (DWORD64)0, (DWORD64)lpBuffer, (DWORD64)dwLength, (DWORD64)&ret);
	return (SIZE_T)ret;
}

extern "C" __declspec(dllexport) DWORD64 VirtualAllocEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	static DWORD64 ntavm = 0;
	if (0 == ntavm)
	{
		ntavm = GetProcAddress64(getNTDLL64(), "NtAllocateVirtualMemory");
		if (0 == ntavm)
			return 0;
	}

	DWORD64 tmpAddr = lpAddress;
	DWORD64 tmpSize = dwSize;
	DWORD64 ret = X64Call(ntavm, 6, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)0, (DWORD64)&tmpSize, (DWORD64)flAllocationType, (DWORD64)flProtect);
	if (STATUS_SUCCESS != ret)
		return 0;
	else
		return tmpAddr;
}

__declspec(dllexport) BOOL VirtualFreeEx64(HANDLE hProcess, DWORD64 lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	static DWORD64 ntfvm = 0;
	if (0 == ntfvm)
	{
		ntfvm = GetProcAddress64(getNTDLL64(), "NtFreeVirtualMemory");
		if (0 == ntfvm)
			return 0;
	}

	DWORD64 tmpAddr = lpAddress;
	DWORD64 tmpSize = dwSize;
	DWORD64 ret = X64Call(ntfvm, 4, (DWORD64)hProcess, (DWORD64)&tmpAddr, (DWORD64)&tmpSize, (DWORD64)dwFreeType);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

extern "C" __declspec(dllexport) BOOL ReadProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead)
{
	static DWORD64 nrvm = 0;
	if (0 == nrvm)
	{
		nrvm = GetProcAddress64(getNTDLL64(), "NtReadVirtualMemory");
		if (0 == nrvm)
			return 0;
	}
	DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)lpNumberOfBytesRead);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

extern "C" __declspec(dllexport) BOOL WriteProcessMemory64(HANDLE hProcess, DWORD64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten)
{
	static DWORD64 nrvm = 0;
	if (0 == nrvm)
	{
		nrvm = GetProcAddress64(getNTDLL64(), "NtWriteVirtualMemory");
		if (0 == nrvm)
			return 0;
	}
	DWORD64 ret = X64Call(nrvm, 5, (DWORD64)hProcess, lpBaseAddress, (DWORD64)lpBuffer, (DWORD64)nSize, (DWORD64)lpNumberOfBytesWritten);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

extern "C" __declspec(dllexport) BOOL GetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext)
{
	static DWORD64 gtc = 0;
	if (0 == gtc)
	{
		gtc = GetProcAddress64(getNTDLL64(), "NtGetContextThread");
		if (0 == gtc)
			return 0;
	}
	DWORD64 ret = X64Call(gtc, 2, (DWORD64)hThread, (DWORD64)lpContext);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}

extern "C" __declspec(dllexport) BOOL SetThreadContext64(HANDLE hThread, _CONTEXT64* lpContext)
{
	static DWORD64 stc = 0;
	if (0 == stc)
	{
		stc = GetProcAddress64(getNTDLL64(), "NtSetContextThread");
		if (0 == stc)
			return 0;
	}
	DWORD64 ret = X64Call(stc, 2, (DWORD64)hThread, (DWORD64)lpContext);
	if (STATUS_SUCCESS != ret)
		return FALSE;
	else
		return TRUE;
}
