# Windows Exploit

## Windows Token Privileges
Tokens are static; therefore, we cannot add/delete but we can enable/disable the current privileges (set by default).
* https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

| | Privilege Value | Description | 
| :--- | :--- | :--- |
| 1 | SeDebugPrivilege | Required to debug and adjust the memory of a process owned by another account. User Right: Debug programs. |

## Python - WinAPI

| | Name | WinAPI | WinDLL | Note |
| :--- | :--- | :--- | :--- | :-- |
| 1 | messageBox.py | MessageBoxW | User32.dll | |
| 2 | openProcHandler.py | OpenProcess | Kernel32.dll | |
| 3 | procKiller.py | FindWindowA, GetWindowThreadProcessId, OpenProcess, TerminateProcess | User32.dll, Kernel32.dll | Find the Windows & Kill the Process |
| 4 | createProc.py | CreateProcessW, PROCESS_INFORMATION, STARTUPINFOA | Kernel32.dll | Start a New Process (e.g., cmd.exe) |
| 5 | dnsCacheEntry.py | DnsGetCacheDataTable | Kernel32.dll, DNSAPI.dll | Undocumented API |
| 6 | openToken.py | FindWindowA, GetWindowThreadProcessId, OpenProcess, OpenProcessToken | User32.dll, Kernel32.dll | |
| 7 | checkToeknPriv.py | LookUpSystemName, PrivilegeCheck | User32.dll, Kernel32.dll, Advapi32.dll | Check for the Token Privilege (e.g., SEDebugPrivilege) |
| 8 | modifyTokenPriv.py | AdjustTokenPrivileges | User32.dll, Kernel32.dll, Advapi32.dll | Modify the Token Privilege (e.g., SEDebugPrivilege) |
| 9 | impersonator.py | CreateProcessWithTokenW | User32.dll, Kernel32.dll, Advapi32.dll | 1) Find the Handle & Token for the given Windows Name, 2) Modify the Token SEDebugPrivilege Privilege if necessary, 3) Spawn a Process (cmd.exe) as the impersonated Token | 



