# createProc.py

import ctypes

from ctypes.wintypes import HANDLE,DWORD,LPSTR,WORD,LPBYTE

k_handle = ctypes.WinDLL("Kernel32.dll")

# Structure for Process Info
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ]

# Structure for Star        
class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPSTR),
        ("lpDesktop", LPSTR),
        ("lpTitle", LPSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
        ]
        
# BOOL CreateProcessW(
#   LPCWSTR               lpApplicationName,
#   LPWSTR                lpCommandLine,
#   LPSECURITY_ATTRIBUTES lpProcessAttributes,
#   LPSECURITY_ATTRIBUTES lpThreadAttributes,
#   BOOL                  bInheritHandles,
#   DWORD                 dwCreationFlags,
#   LPVOID                lpEnvironment,
#   LPCWSTR               lpCurrentDirectory,
#   LPSTARTUPINFOW        lpStartupInfo,
#   LPPROCESS_INFORMATION lpProcessInformation
# );
        
# CreateProcessW
lpApplicationName = "C:\\Windows\System32\cmd.exe"
lpCommandLine = None
lpProcessAttributes = None
lpThreadAttributes = None
bInheritHandles = False
dwCreationFlags = 0x00000010 # Process Creation Flag = CREATE_NEW_CONSOLE
lpEnvironment = None     
lpCurrentDirectory = None

# StartupInfo (*If I don't sepcify the value, it will return as NULL)
lpStartupInfo = STARTUPINFOA()
lpStartupInfo.wShowWindow = 0x1 # Showing up Windows
lpStartupInfo.dwFlags = 0x1

# ProcessInformation (*If I don't sepcify the value, it will return as NULL)
lpProcessInformation = PROCESS_INFORMATION()   
        
response = k_handle.CreateProcessW(
    lpApplicationName,
    lpCommandLine,
    lpProcessAttributes,
    lpThreadAttributes,
    bInheritHandles,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo), # Pointer to STARTUPINFOA
    ctypes.byref(lpProcessInformation) # Pointer to PROCESS_INFORMATION
    )

if response > 0:
    print("[+] Process Created!")
else:
    print("[-] Failed... Error Code: {0}".format(k_handle.GetLastError()))
