# injection-for-dummies
Injection is one of the most common techniques malware authors use to run malicious code on a victim system in the context of another program. This is very useful because it can often help to avoid a defender's prying eyes. 

For example, Explorer making web requests to an external server is considered normal behavior, whereas a rogue executable or C2 payload doing the same raises alerts all around.

In this repository, we discuss some of the most popular injection techniques and look into some code for each. The different kinds of injection techniques we talk of in this blog are as follows:

| Name | Description |
|---|--|
|Shellcode Injection | Inject shellcode directly into a process's memory |
| Dll Path Injection | Force remote process to load a malicious Dll |
| Thread Context | Hijack remote process's thread to execute malicious shellcode |
| APC | Use APC calls to run Remote payload Asynchronously |
| Earlybird | A modification of the APC technique |gi 
| Section Views | Use shared memory sections to deliver payloads |

## Pre-requisites
Though I have tried to be verbose with the techniques here, it is highly recommended that the reader is familiar with the basics of C programming on Windows and is familiar with the commonly used functions like `VirtualAlloc()`, `VirtualProctect()`, `GetProcAddress()`, `GetModuleHandle()`, etc.

I have also tried to be as descriptive as possible with the different parameters I pass to functions but I would still suggest looking up MSDN for each new function you come across. 

## Notes
- The payload used in most cases here is a `Windows Message Box` payload which says `"Hello World!"`, unless mentioned otherwise. 
- The provided PoCs depicted in the respective `README` files are not "clean codes", and lack error checking mechanisms for the sake of simplicity. Refer to the source files for more robust code.
- Some functions like `find_pid()` and `find_threadid()` have been reused over and over again.
- Most WinAPI functions have been commented to explain the parameters. In case any function lacks comments, refer to the WinAPI documentation. 
- The `TARGET` macro expands to `notepad.exe`, unless specifies, and denotes the target process to inject into.
- The `IS_HANDLE_INVALID` macro checks if a `HANDLE` value is invalid , i.e, if it is equal to `NULL` or `INVALID_HANDLE_VALUE`