# openToken.py

import ctypes

u_handle = ctypes.WinDLL("user32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")

# Access Rights (Full Access Right Shortcut)
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = ( STANDARD_RIGHTS_REQUIRED |
                     TOKEN_ASSIGN_PRIMARY     |
                     TOKEN_DUPLICATE          |
                     TOKEN_IMPERSONATION      |
                     TOKEN_QUERY              |
                     TOKEN_QUERY_SOURCE       |
                     TOKEN_ADJUST_PRIVILEGES  |
                     TOKEN_ADJUST_GROUPS      |
                     TOKEN_ADJUST_DEFAULT     |
                     TOKEN_ADJUST_SESSIONID)
        
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

# OpenProcessToken
#
# BOOL OpenProcessToken(
#   HANDLE  ProcessHandle,
#   DWORD   DesiredAccess,
#   PHANDLE TokenHandle
# );

ProcessHandle = hProcess
DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = ctypes.c_void_p()

response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

if response > 0:
    print("[+] OpenProcess Token Obtained:", TokenHandle)
else:
    print("[-] Error Code: {0} - No Privilieged Token Obtained...".format(error))   
