# procKiller.py
#
# Description: The script to kill the process by its name (e.g., Task Manager)
#
# FindWindowA - Find the process by its name
# GetWindowThreadProcessId - Grab the process ID (PID)
# OpenProcess - Grab the handle of the process (*Checking if you have a right priv to do the job)
# TerminateProcess - Kill the process
#

import ctypes

u_handle = ctypes.WinDLL("user32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")

# Access Rights (Full Access Right Shortcut)
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# FindWindowA
#
#HWND FindWindowA(
#  LPCSTR lpClassName,
#  LPCSTR lpWindowName
#);
#
# LP = Pointer

lpClassName = None
lpWindowName = ctypes.c_char_p((input("[*] Enter Window Name to Kill: ").encode('utf-8')))

hWnd = u_handle.FindWindowA(lpClassName, lpWindowName)

error = k_handle.GetLastError()
if hWnd == 0:
    print("[-] Error Code: {0} - No Handle Obtained...".format(error))
else:
    print("[+] FindWindow Handle Obtained:", hWnd)
    
# GetWindowThreadProcessId
#
# DWORD GetWindowThreadProcessId(
#  HWND    hWnd,
#  LPDWORD lpdwProcessId
# );

lpdwProcessId = ctypes.c_ulong()

response = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

if hWnd == 0:
    print("[-] Error Code: {0} - No PID Obtained...".format(error))
else:
    pid = str(lpdwProcessId)
    print("[+] PID:", pid.strip("c_ulong()"))

# OpenProcess
# 
# HANDLE OpenProcess(
# DWORD dwDesiredAccess,
# BOOL bInheritHandle,
# DWAORD dwProcessId
# );

dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = lpdwProcessId 

hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) 

if hProcess <= 0:
    print("[-] Error Code: {0} - No Privilieged Handle Obtained...".format(error))
else:
    print("[+] OpenProcess Handle Obtained:", hProcess)

# TerminateProcess
#
# BOOL TerminateProcess(
#   HANDLE hProcess,
#   UINT   uExitCode
# );

uExitCode = 0x1
termResponse = k_handle.TerminateProcess(hProcess, uExitCode)

if termResponse == 0:
    print("[-] Error Code: {0} - Could Not Terminate Process...".format(error))
else:
    print("[+] Process Successfully Terminated!")
