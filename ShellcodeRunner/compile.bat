@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp *.cpp /link /OUT:ShellcodeRunner.exe /SUBSYSTEM:WINDOWS
del *.obj