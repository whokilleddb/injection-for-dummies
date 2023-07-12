# ShellCode Injection

Shellcode injection is one of the simplest injection technique out there. The idea here is to copy over a shellcode into a remote process's virtual memory and start a thread in the remote process to execute the payload. To better understand this in action, start by looking into the `main()` function for the program:

```c
int main(void) {
    DWORD pid = find_pid(TARGET);
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid)
    int result = inject_proc(hProc, payload, payload_len);
    CloseHandle(hProc);
    return 0;
}
```

First things first, we find the Process ID (PID) of the TARGET process(`"notepad.exe"`). Then we call `OpenProcess()` to fetch a handle to the remote process with the following permissions:

Since we do not want to inherit the handle we set the second parameter to `OpenProcess()` as `FALSE` (but seriously, changing it to TRUE does not change the execution behavior because not child processes are created), and finally, we provide the PID of the process we want to inject into. This should give us a handle to the process (hProc) which we then pass onto the `inject_proc()` function along with the Message Box payload and the length of the payload buffer. 

The `inject_proc()` function is where the injection happens. The primary code of the function looks like:
```c
int inject_proc(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {
    DWORD bWritten = 0; 
    LPVOID pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    BOOL result = WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)&bWritten);
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
    WaitForSingleObject(hThread, -1);
    CloseHandle(hThread);
    return 0;
}
```
We begin with allocating memory in the target process's memory by using the `VirtualAllocEx()` function and store it's value in the `pRemoteCode` variable. The parameters passed to the function, in order, are:
 the handle to the remote process(hProc)
A NULL value to indicate that we have no desired starting address
Length of payload (payload_len) aka the size of memory to allocate
Set the allocation type by passing the value MEM_COMMIT to make the specified memory range available for use by the process
Set permissions of the memory region as PAGE_EXECUTE_READ to be able to execute our shell code

Next up, we write our payload into the process's address space with WriteProcessMemory() by passing to it the handler to the target process(hProc), the address of the allocated memory (pRemoteCode), the address of the buffer containing our payload (paylod_len), the size of the payload buffer (payload_len), and the address to a variable to store the total number of bytes actually written to the buffer(&bWritten).
With the payload now written in the target process's memory, we create a thread to run the target process's virtual address space with CreateRemoteThread() , to which we pass the parameters:
Handle of the target process (hProc)
- A NULL value to signify that the thread gets a default security descriptor and the handle cannot be inherited
- A 0 to signify that we will be using the default stack size
- Set the thread function as the address to the payload in the process's virtual address space (pRemoteCode)
- A NULL to signify that no variables are to be passed to the the thread function
- A 0 to signify to run the thread immediately after creation
- A NULL to ignore the thread identifier

If the function runs successfully, a handle to the remote thread (hThread) is returned, which we pass to WaitForSingleObject() to spawn the the thread and wait till it finishes execution.
This should inject our shellcode and we should have a Hello World! message running under Notepad.exe 
Therefore, we are successfully able to inject code into notepad.exe and run it in the context of the program.