# checkTokenPriv.py

import ctypes

from ctypes.wintypes import DWORD

u_handle = ctypes.WinDLL("user32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")

# Access Rights (Full Access Right Shortcut)
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000

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

# LUID Structure
class LUID(ctypes.Structure):
    _fields_ = [
    ("LowPart", DWORD),
    ("HighPart", DWORD),
    ]

# LUID and ATTRIBUTES
class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
    ("Luid", LUID),
    ("Attributes", DWORD),
    ]

# Privilege Set
class PRIVILEGE_SET(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount", DWORD),
    ("Control", DWORD),
    ("Privileges", LUID_AND_ATTRIBUTES),
    ]
        
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

# LookUpSystemName
#
# BOOL LookupPrivilegeValueW(
#   LPCWSTR lpSystemName,
#   LPCWSTR lpName,
#   PLUID   lpLuid
# );

lpSystemName = None
lpName = "SEDebugPrivilege"
lpLuid = LUID()

response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(lpLuid))

if response > 0:
    print("[+] LUID Found.")
else:
    print("[-] Error Code: {0} - No Privilieged Token Obtained...".format(error))
    
print("[+] LUID High: {0}, LUID Low: {1}".format(lpLuid.HighPart, lpLuid.LowPart))

# PrivilegeCheck
#
# BOOL PrivilegeCheck(
#   HANDLE         ClientToken,
#   PPRIVILEGE_SET RequiredPrivileges,
#   LPBOOL         pfResult
# );

requiredPrivileges = PRIVILEGE_SET()
requiredPrivileges.PrivilegeCount = 1
requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()
requiredPrivileges.Privileges.Luid = lpLuid
requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED

pfResult = ctypes.c_long()

response = a_handle.PrivilegeCheck(TokenHandle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

if response > 0:
    print("[+] Checking Privilege Check...")
else:
    print("[-] Error Code: {0} - No Privilieged Token Obtained...".format(error))

if pfResult:
    print("[+] {0} Privilege Enabled!".format(lpName))
else:
    print("[-] {0} Privilege Not Enabled!".format(lpName))
