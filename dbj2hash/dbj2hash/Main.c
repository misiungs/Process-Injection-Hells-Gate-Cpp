#include <stdio.h>
#include <Windows.h>

// djb2 hash function
DWORD64 djb2(PBYTE str) {
    DWORD64 dwHash = 0x7114953477341234;
    INT c;

    while (c = *str++)
        dwHash = ((dwHash << 0x2) + dwHash) + c;

    return dwHash;
}

int main() {
    const char* strings[] = { "NtOpenProcess", "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx", "NtWaitForSingleObject"};
    size_t numStrings = sizeof(strings) / sizeof(strings[0]);

    for (size_t i = 0; i < numStrings; ++i) {
        DWORD64 hashValue = djb2(strings[i]);
        printf("Hash of \"%s\" is: 0x%llx\n", strings[i], hashValue);
    }

    return 0;
}