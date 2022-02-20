# Windows Exploit

## Windows Token Privileges

Tokens are static; therefore, we cannot add/delete but we can enable/disable the current privileges (set by default).

- https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants

|     | Privilege Value  | Description                                                                                                |
| :-- | :--------------- | :--------------------------------------------------------------------------------------------------------- |
| 1   | SeDebugPrivilege | Required to debug and adjust the memory of a process owned by another account. User Right: Debug programs. |

## Python - WinAPI

- Python --> EXE

```
pip3 install pyinstaller
pyinstaller <XXX.py>
```

|     | Name               | WinAPI                                                               | WinDLL                                 | Note                                                                                                                                                                       |
| :-- | :----------------- | :------------------------------------------------------------------- | :------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | messageBox.py      | MessageBoxW                                                          | User32.dll                             |                                                                                                                                                                            |
| 2   | openProcHandler.py | OpenProcess                                                          | Kernel32.dll                           |                                                                                                                                                                            |
| 3   | procKiller.py      | FindWindowA, GetWindowThreadProcessId, OpenProcess, TerminateProcess | User32.dll, Kernel32.dll               | Find the Windows & Kill the Process                                                                                                                                        |
| 4   | createProc.py      | CreateProcessW, PROCESS_INFORMATION, STARTUPINFOA                    | Kernel32.dll                           | Start a New Process (e.g., cmd.exe)                                                                                                                                        |
| 5   | dnsCacheEntry.py   | DnsGetCacheDataTable                                                 | Kernel32.dll, DNSAPI.dll               | Undocumented API                                                                                                                                                           |
| 6   | openToken.py       | FindWindowA, GetWindowThreadProcessId, OpenProcess, OpenProcessToken | User32.dll, Kernel32.dll               |                                                                                                                                                                            |
| 7   | checkToeknPriv.py  | LookUpSystemName, PrivilegeCheck                                     | User32.dll, Kernel32.dll, Advapi32.dll | Check for the Token Privilege (e.g., SEDebugPrivilege)                                                                                                                     |
| 8   | modifyTokenPriv.py | AdjustTokenPrivileges                                                | User32.dll, Kernel32.dll, Advapi32.dll | Modify the Token Privilege (e.g., SeDebugPrivilege)                                                                                                                        |
| 9   | impersonator.py    | CreateProcessWithTokenW                                              | User32.dll, Kernel32.dll, Advapi32.dll | 1) Find the Handle & Token for the given Windows Name, 2) Modify the Token SeDebugPrivilege Privilege if necessary, 3) Spawn a Process (cmd.exe) as the impersonated Token |

![Screenshot](https://github.com/bigb0sss/RedTeam-OffensiveSecurity/blob/master/02-Windows_Security/python/impersonator.png)


## Basics of Windows DLLs
| | Type | Characteristics | 
| :-- | :-- | :-- |
| 1 | `kernel32.dll` | Provides the ability to access basic resources, such as threads, file system, devices, processes |
| 2 | `user32.dll` | Provides the ability to change the user interface, including creating and managing windows, receiving window messages, displaying text on the screen, and presenting a message box |
| 3 | `advapi32.dll` | Provides the ability to modify the registry, shutdown and restart the system, also provides support functions to start / end / generate Windows services, account management |
| 4 | `gdi32.dll` | Manages functions for the printer, monitor and other output devices |
| 5 | `comdlg32.dll` | Openafile,saveafile,managethestandarddialog window associated with the selected color and font |
| 6 | `comctl32.dll` | Status bar, progress bar, access to applications that are supported by the operating system, such as the toolbar |
| 7 | `shell32.dll` | Provides the functionality of the shell of the operating system so that the applications can have access |
| 8 | `netapi32.dll` | Provides a variety of communication features that are supported by the operating system to the applications |