<p align="center">
  <img width="500" height="500" src="https://github.com/bigb0sss/RedTeam/blob/master/redteam_logo.png">
</p>

## OSINT
### Passive Discovery
* Amass - https://github.com/OWASP/Amass (Attack Surface Mapping)
* Metabigor - https://github.com/j3ssie/metabigor (Non-API OSINT)
* AsINT_Collection - https://start.me/p/b5Aow7/asint_collection (Massive OSINT Collection)
* Email --> Phone# - https://github.com/iansangaji/email2phonenumber
* MFASweep - https://github.com/dafthack/MFASweep (MFA Check for Microsoft endpoints)

### Active Discovery
* ZGrab - https://github.com/zmap/zgrab (Banner grabber)
* Hardenize - https://www.hardenize.com/ (Domain Lookup)

### Target User Population Collection
* Linkedin UserEnum - https://github.com/bigb0sss/LinkedinMama

### Public Site Lookup (Github, Gitlab, etc.)
* Gitrob - https://github.com/michenriksen/gitrob/ (Github Search)
* truffleHog - https://github.com/dxa4481/truffleHog (Github Regex Search)

### Cloud Recon
* cloud_enum - https://github.com/initstring/cloud_enum
* MicroBurst - https://github.com/NetSPI/MicroBurst (AZURE)
* pacu - https://github.com/RhinoSecurityLabs/pacu (AWS)
* FestIn - https://github.com/cr0hn/festin (AWS)
* s3viewer - https://github.com/SharonBrizinov/s3viewer (AWS)
* Cloud_Pentest_Cheatsheet - https://github.com/dafthack/CloudPentestCheatsheets
* endgame - https://github.com/salesforce/endgame (AWS)

### Microsoft (ADFS)
* ADFSpoof - https://github.com/fireeye/ADFSpoof (Forge ADFS security tokens)

### Web App
* Wordpress-Exploit-Framework - https://github.com/rastating/wordpress-exploit-framework
* Awesome-Web-Security - https://github.com/qazbnm456/awesome-web-security
* Java Deserialization - https://github.com/frohoff/ysoserial
* PHP Deserialization - https://github.com/ambionics/phpggc
* Kubernetes - https://github.com/loodse/kubectl-hacking
* SSRF - https://github.com/jdonsec/AllThingsSSRF

<br /> 

## Password-Spray
### Tools  
  * MSOLSpray - https://github.com/dafthack/MSOLSpray
  * o365enum.py - https://github.com/gremwell/o365enum (Microsoft ActiveSync)
  * goPassGen - https://github.com/bigb0sss/goPassGen (*PasswordSpray List Generator)
  * go365 - https://github.com/optiv/Go365 (Microsoft SOAP API endpoint on login.microsoftonline.com) 
  * Okta - https://github.com/Rhynorater/Okta-Password-Sprayer

### IP Rotators
  * Burp IPRotate - https://github.com/PortSwigger/ip-rotate (Utilizes AWS IP Gateway)
  * ProxyCannon-NG - https://github.com/proxycannon/proxycannon-ng
  * Cloud-proxy - https://github.com/tomsteele/cloud-proxy
  * Proxy-NG - https://github.com/jamesbcook/proxy-ng
  * Mubeng - https://github.com/kitabisa/mubeng#proxy-ip-rotator

### Default Password Check
  * CIRT - https://cirt.net/passwords
  * DefaultCreds-cheat-sheet - https://github.com/ihebski/DefaultCreds-cheat-sheet
<br />

## C2 Infrastructure
### Cobal Strike
  * Malleable C2 (Guideline) - [CS4.0_guideline.profile](https://github.com/bigb0sss/RedTeam/blob/master/CobaltStrike/malleable_C2_profile/CS4.0_guideline.profile)
  * Beacon Command Cheatsheet - [CS Commands](https://github.com/bigb0sss/RedTeam/tree/master/CobaltStrike)
  * Cobalt Strike Training Review 
    * [Part 1](https://medium.com/@bigb0ss/red-team-review-of-red-team-operations-with-cobalt-strike-2019-training-course-part-1-962c510565aa)

  * SharpeningCobaltStrike - https://github.com/cube0x0/SharpeningCobaltStrike
  * Malleable C2 Randomizer - https://fortynorthsecurity.com/blog/introducing-c2concealer/
  
### Redirectors
  * Domain Fronting - https://www.bamsoftware.com/papers/fronting/
  
### Proxy Infrastructure Setup
  * Cloud-proxy - https://github.com/tomsteele/cloud-proxy
  * Proxy-ng - https://github.com/jamesbcook/proxy-ng
  * ProxyCannon - https://github.com/proxycannon/proxycannon-ng
<br />  


## Post-Exploitation
### AD Recon/Survey
 * Seatbelt - https://github.com/GhostPack/Seatbelt (*Ghostpack)
 * DNS Enum - https://github.com/dirkjanm/adidnsdump

### User Phishing
  * pickl3 - https://github.com/hlldz/pickl3
  * CredPhisher - https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher

### Browser Scripping
  * SharpChromium - https://github.com/djhohnstein/SharpChromium

### Lateral Movement
  * SpectorOps - https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
  * Pypykatz - https://github.com/skelsec/pypykatz (Pyhton implementation of Mimikatz)
  * Internal-Monologue - https://github.com/eladshamir/Internal-Monologue
  * MSSQL - https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/

### Offensive C#
  * OffensiveCSharp - https://github.com/matterpreter/OffensiveCSharp
  * C# Collection - https://github.com/midnightslacker/Sharp/blob/master/README.md

### LiveOffTheLand
  * LOLBAS - https://lolbas-project.github.io/#

### AV/AMSI Evasion
 * xencrypt - https://github.com/the-xentropy/xencrypt (*PowerShell)
 * FalconStrike - https://github.com/slaeryan/FALCONSTRIKE
 * AV_Bypass - https://github.com/Techryptic/AV_Bypass
 * DotNetToJScript - https://github.com/tyranid/DotNetToJScript
 * GadgetToJScript - https://github.com/med0x2e/GadgetToJScript | https://github.com/rasta-mouse/GadgetToJScript
 * Shellcodeloader - https://github.com/knownsec/shellcodeloader (ShellcodeLoader of windows can bypass AV)
 
### EDR Evasion
 * SharpBlock - https://github.com/CCob/SharpBlock 
 
### PowerShell
  * p3nt4 - https://github.com/p3nt4
<br />


## Exploit Dev
### Windows
  * https://github.com/Ondrik8/exploit
  * Undocumented Func (Win NT/2000/XP/Win7) - http://undocumented.ntinternals.net/
  * Windows Syscall - https://j00ru.vexillium.org/syscalls/nt/64/
  * Windows Undocumented Func - http://undocumented.ntinternals.net/
  * Windows Kernel Exploit Training - https://codemachine.com/

### Nix
<br />

##  RedTeam Researchers/Githubs
  * Vincent Yiu - https://vincentyiu.com
  * Outflank - https://github.com/outflanknl
  * Bank Security - https://github.com/BankSecurity/Red_Team
  * Infosecn1nja - https://github.com/infosecn1nja (Redteam-Toolkit = AWESOME)
  * Yeyintminthuhtut - https://github.com/yeyintminthuhtut
  * RedCanary (Atomic RedTeam) - https://github.com/redcanaryco/atomic-red-team
  * kmkz - https://github.com/kmkz/Pentesting (Good cheat-sheets)
  * Rastamouse - https://offensivedefence.co.uk/authors/rastamouse/
<br />
  

##  Lab Resources
  * Windows Server VMs - https://www.microsoft.com/en-us/evalcenter
  * Windows 10 - https://www.microsoft.com/en-us/software-download/windows10ISO
  * Archive of WinVMs - https://archive.org/search.php?query=subject%3A%22IEVM%22
  * Public MSDN - [Link](https://the-eye.eu/public/MSDN/?__cf_chl_jschl_tk__=46c681e6ae5287aaf2dbd8ef86f7f8cef8814957-1598278564-0-AbrrKkEDy4QEcQU5Md-yugSbmcD6dvwxzHhVHeFss8es0BlwT2XlPw8dsv5VdDzFdnhgWSr06ih_Rx8aoVFZ-FLSoQcJXZ_L1TrQZPC2rDdiH9WWau3AKVYnLjAn2gsLlLkug4iBVgACHMIachUurJCX2tPnjtZlKW3pgJmhkhZ3QyT3pGm-DDs1UYLbK1IiuZ6Ps8_kAPaGFMpYX8KAnHsYayhcic8Uhrpa7dcG4b_8PAc161ctecW3ZdqruEwsU06rPy2BvvX_3IyoyiGJnZILNEPIxFCXUAfQ3a6MbZ0e0Zwa920X9KmEapBFKr_cALjXG6H9jStvRhtm-3yUdCupFB6fAZYIIIPSap2sckdO)
  * Adversary Tactics: PowerShell - https://github.com/specterops/at-ps (Specterops)
<br />
  
## Sexy Resources
  * MITRE ATT&CK - https://attack.mitre.org/
  * MalwareNews - https://malware.news/
  * CWE - http://cwe.mitre.org/top25/archive/2019/2019_cwe_top25.html
  * CTID - https://github.com/center-for-threat-informed-defense
  * SpritesMods - http://spritesmods.com/?art=main (Product Security)
  * Joeware - http://www.joeware.net/ (Windows AD Guru - Many AD Recon bins and amazing blogs)
  * Tenable - https://github.com/tenable/poc (Exploit POCs)
  * MalwareUnicorn - https://malwareunicorn.org/ (Malware/Reversing)
<br />

## Security Testing Practice Lab
  * Hackthebox - https://www.hackthebox.eu/
  * Cyberseclab - https://www.cyberseclabs.co.uk/ (AD Focus)
<br />

## BlueTeam
### Lab Resources
  * Detection Lab - https://github.com/clong/DetectionLab
<br />

### Threat Detection
  * KQL - https://github.com/DebugPrivilege/KQL
  * Sigma - https://github.com/Neo23x0/sigma (Generic Signature Format for SIEM)
  * Splunk Security Essential Docs - https://docs.splunksecurityessentials.com/content-detail/ (Various IOCs)
<br />

### Windows Security (What will BlueTeam look for?)
#### LDAP (Lightweight Directory Access Protocol)
  * [Hunting for reconnaissance activities using LDAP search filter (Microsoft)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726)

## Disclaimer 
All the credits belong to the original authors and publishers. 
