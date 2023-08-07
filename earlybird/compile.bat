@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DEBUG /Tcinjector.c /link /OUT:injector.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

del *.obj