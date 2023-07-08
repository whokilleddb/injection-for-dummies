#include "injector.h"

NtCreateSection_t pNtCreateSection;
NtMapViewOfSection_t pNtMapViewOfSection;
RtlCreateUserThread_t pRtlCreateUserThread;

// Resolve Addresses
PVOID _resolve_addr(PSTR lib_name, PSTR proc_name) {
    HMODULE hModule = GetModuleHandleA(lib_name);

    if (hModule == NULL) {
        fprintf("[!] Failed to get handle to:\t%s (0x%x)\n", lib_name, GetLastError());
        return NULL;
    }

    PVOID addr = (PVOID)GetProcAddress(hModule, proc_name);
    if (addr == NULL) {
        printf("[!] Failed to resolve:\t%s (0x%x)\n", proc_name, GetLastError());
        return NULL;
    }
    printf("[i] Resolved Function:\t%s(0x%p)\n", proc_name, addr);
    return addr;
}

// Initialize all functions
BOOL resolve_funcs() {
    pNtCreateSection = (NtCreateSection_t)_resolve_addr("ntdll.dll", "NtCreateSection");
    pNtMapViewOfSection = (NtMapViewOfSection_t)_resolve_addr("ntdll.dll", "NtMapViewOfSection");
    pRtlCreateUserThread = (RtlCreateUserThread_t)_resolve_addr("ntdll.dll", "NtMapViewOfSection");
    if (pNtCreateSection == NULL || pNtMapViewOfSection == NULL || pRtlCreateUserThread == NULL) {
        return FALSE;
    }
    return TRUE;
}

// Find PID from a Process Name
DWORD find_pid(const char* procname) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32;
    
    // Take Snapshot all processes on the system
    // See: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    HANDLE hProcSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, //  Take a snapshot of the processes
        0                   //  Capture a snapshot of all processes in the system
    );

    // Check if handle is valid
    if (INVALID_HANDLE_VALUE == hProcSnap) {
        fprintf(stderr, "[!] CreateToolhelp32Snapshot() failed (0x%x)\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);   // Store size of strcut

    // Retrieves information about the first 
    // process encountered in a system snapshot.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    BOOL result = Process32First(hProcSnap, &pe32);

    if (!result) {
        fprintf(stderr, "[!] Process32First() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcSnap);
        return 0;
    }

    // Loop through Snapshot entries
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    return pid;
}

// Find thread ID in a process
DWORD find_threadid(DWORD pid) {
    THREADENTRY32 thEntry;
    thEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    BOOL result = Thread32First(hThreadSnap, &thEntry);
    if (!result) {
        fprintf(stderr, "[!] Thread32First() failed (0x%x)\n", GetLastError());
        CloseHandle(hThreadSnap);
        return 0;
    }

    while (Thread32Next(hThreadSnap, &thEntry)) {
        if (thEntry.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID); 
            if (hThread != INVALID_HANDLE_VALUE) {
                CloseHandle(hThread);
                CloseHandle(hThreadSnap);
                return thEntry.th32ThreadID;
            }
            CloseHandle(hThread);
        }
    }
    CloseHandle(hThreadSnap);
    return 0;
}

int main() {
    DWORD pid = find_pid(TARGET);
    
    if (pid == 0) {
        fprintf(stderr, "[!] No %s found\n", TARGET);
        return -1;
    }
    printf("[i] Found %s:\t%d\n", TARGET, pid);

    // Resolve Functions before beginning 
    DWORD bResult = resolve_funcs();
    if (!bResult) {
        fprintf(stderr, "[!] Failed to resolve NT functions!\n");
        return -1;
    }

    return 0;
}