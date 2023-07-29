Before we get into the `inject_apc()` function, there is another function we need to take a look at first: `find_threadid()`.

The `find_threadid()` function has the following code:
```c
// Find thread ID in a process
DWORD find_threadid(DWORD pid) {
    THREADENTRY32 thEntry;
    thEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    BOOL result = Thread32First(hThreadSnap, &thEntry);
    while (Thread32Next(hThreadSnap, &thEntry)) {
        if (thEntry.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID); 
            if (!IS_HANDLE_INVALID(hThread)) {
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
```
It is _very_ similar to the `find_pid()` function we have been using so far. This time, we find the thread id associated with each Process and return the Thread ID. 

We use the `CreateToolhelp32Snapshot()` to create a system snapshot with the `TH32CS_SNAPTHREAD` parameter to includes all threads in the system in the snapshot. (See: [this MSDN post](https://learn.microsoft.com/en-us/windows/win32/toolhelp/traversing-the-thread-list))