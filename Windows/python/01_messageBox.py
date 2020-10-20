# messageBox.py

import ctypes

user_handle = ctypes.WinDLL("User32.dll")       # Handle to User32.dll
kernel_handle = ctypes.WinDLL("kernel32.dll")   # Handle to Kernel32.dll

# WinAPI: MessageBoxW
hWnd = None
lpText = "Message Box"
lpCaption = "Pop Up"
uType = 0x00000001

response = user_handle.MessageBoxW(hWnd, lpText, lpCaption, uType)

# Error Handling
error = kernel_handle.GetLastError()
if error != 0:
    print("[-] Error Code: {0}".format(error))
    
if response == 1:
    print("[+] User Clicked OK")
elif response == 2:
    print("[+] User Clicked CANCEL")
