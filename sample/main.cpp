#include <Windows.h>
#include <cstdio>
#include <winternl.h>
#include "../src/wow64ext.h"

#define FNFAIL(a) printf(a " failed\n")

void AllocTest(HANDLE hProcess)
{
	printf("Requesting 0x1000 bytes of memory at 0x70000020000 ...\n");
	DWORD64 mem = VirtualAllocEx64(hProcess, 0x70000020000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (0 == mem)
	{
		printf("VirtualAllocEx64 failed.\n");
		return;
	}
	printf("Memory allocated at: %016I64X\n", mem);

	MEMORY_BASIC_INFORMATION64 mbi64 = { 0 };
	VirtualQueryEx64(hProcess, mem, &mbi64, sizeof(mbi64));
	printf("Query memory: %016I64X %016I64X %08X %08X %08X\n", mbi64.BaseAddress, mbi64.RegionSize, mbi64.Protect, mbi64.Type, mbi64.State);
	printf("Freeing memory: %s\n", VirtualFreeEx64(hProcess, mem, 0, MEM_RELEASE) ? "success" : "failure");
	VirtualQueryEx64(hProcess, mem, &mbi64, sizeof(mbi64));
	printf("Query memory: %016I64X %016I64X %08X %08X %08X\n", mbi64.BaseAddress, mbi64.RegionSize, mbi64.Protect, mbi64.Type, mbi64.State);
}

int main (int argc, char* argv[])
{
	if (2 != argc)
	{
		printf("Usage:\n\t%s hex_process_ID\n", argv[0]);
		return 0;
	}

	DWORD procID = 0;
	if (1 != sscanf_s(argv[1], "%X", &procID))
	{
		printf("Invalid process ID.\n");
		return 0;
	}

	printf("Process ID: %08X\n", procID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procID);
	if (0 == hProcess)
	{
		printf("Can't open process %08X.\n", procID);
		return 0;
	}

	MEMORY_BASIC_INFORMATION64 mbi64 = { 0 };
	DWORD64 crAddr = 0;
	bool printMemMap = true;
	while (VirtualQueryEx64(hProcess, crAddr, &mbi64, sizeof(mbi64)))
	{
		if (mbi64.Protect && !(mbi64.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		{
			if (printMemMap)
				printf("[D] : ");

			BYTE* mem = (BYTE*)VirtualAlloc(0, (SIZE_T)mbi64.RegionSize, MEM_COMMIT, PAGE_READWRITE);
			if (mem == 0)
			{
				FNFAIL("VirtualAlloc");
				crAddr = crAddr + mbi64.RegionSize;
				continue;
			}
			if (0 == ReadProcessMemory64(hProcess, mbi64.BaseAddress, mem, (SIZE_T)mbi64.RegionSize, 0))
			{
				if (printMemMap)
					printf("%016I64X : %016I64X : %08X : ", mbi64.BaseAddress, mbi64.RegionSize, mbi64.Protect);
				FNFAIL("ReadProcessMemory");
				VirtualFree(mem, 0, MEM_RELEASE);
				crAddr = crAddr + mbi64.RegionSize;
				continue;
			}

 			wchar_t fName[0x200];
 			swprintf_s(fName, L"%08X_%016I64X.bin", procID, mbi64.BaseAddress);
 			HANDLE hFile = CreateFile(fName, GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
 			DWORD tmp = 0;
 			WriteFile(hFile, mem, (DWORD)mbi64.RegionSize, &tmp, 0);
 			CloseHandle(hFile);

			VirtualFree(mem, 0, MEM_RELEASE);
		}
		else
		{
			if (printMemMap)
				printf("[ ] : ");
		}

		if (printMemMap)
			printf("%016I64X : %016I64X : %08X\n", mbi64.BaseAddress, mbi64.RegionSize, mbi64.Protect);
		crAddr = crAddr + mbi64.RegionSize;
	}

	DWORD64 ntdll64 = GetModuleHandle64(L"ntdll.dll");
	printf("NTDLL64: %016I64X\n", ntdll64);

	DWORD64 rtlcrc32 = GetProcAddress64(ntdll64, "RtlComputeCrc32");
	printf("RtlComputeCrc32 address: %016I64X\n", rtlcrc32);

	if (0 != rtlcrc32)
	{
		DWORD64 ret = X64Call(rtlcrc32, 3, (DWORD64)0, (DWORD64)"ReWolf", (DWORD64)6);
		printf("CRC32(\"ReWolf\") = %016I64X\n", ret);
	}

	printf("Alloc/Free test:\n");
	AllocTest(hProcess);
	
	printf("\nAlloc/Free over 4GB inside WoW64 test:\n");
	AllocTest(GetCurrentProcess());
	
	printf("\n\nGet/Set Context test:\n");

	_CONTEXT64 ctx = { 0 };
	ctx.ContextFlags = CONTEXT64_ALL;
	GetThreadContext64(GetCurrentThread(), &ctx);

	printf("rsp: %016I64X\n", ctx.Rsp);
	printf("rip: %016I64X\n", ctx.Rip);
	printf("r8 : %016I64X\n", ctx.R8);
	printf("r9 : %016I64X\n", ctx.R9);
	printf("r12: %016I64X\n", ctx.R12);

	//below code will crash application, it is sufficient prove that SetThreadContext64 is working fine :)
	//ctx.Rip = 0;
	//SetThreadContext64(GetCurrentThread(), &ctx);

	CloseHandle(hProcess);
	return 0;
}
