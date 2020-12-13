# openProcHandler.py

import ctypes
import sys

if len(sys.argv) != 2:
    print("[*] Usage: {0} <PID>".format(sys.argv[0]))
    sys.exit(1)

pid = int(sys.argv[1])
print("[+] Process ID Entered:", pid)

k_handle = ctypes.WinDLL("Kernel32.dll")

# Win API Call
# HANDLE OpenProcess(
# DWORD dwDesiredAccess,
# BOOL bInheritHandle,
# DWAORD dwProcessId
# );

# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Setting Up The Params
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = pid 

# Calling the Windows API Call
response = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

# Check For Errors
#
# Search for error: https://docs.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
#
error = k_handle.GetLastError()
if error != 0:
    print("[-] No AccessRight. Handle was not created.")
    print("[-] Error Code: {0}".format(error))
	exit(1)
   
if response <= 0:
    print("[-] Handle was not created.")
else:
    print("[+] You have AccessRight! Handle was created.")
