<p align="center">
  <img width="500" height="500" src="./images/redteam_logo.png">
</p>


## OSINT
### Passive Discovery
- Amass - https://github.com/OWASP/Amass (Attack Surface Mapping)
- Metabigor - https://github.com/j3ssie/metabigor (Non-API OSINT)
- AsINT_Collection - https://start.me/p/b5Aow7/asint_collection (Massive OSINT Collection)
- Email --> Phone# - https://github.com/iansangaji/email2phonenumber
- MFASweep - https://github.com/dafthack/MFASweep (MFA Check for Microsoft endpoints)
- Fast-Google-Dorks-Scan - https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan?mc_cid=70cff8af7c&mc_eid=eff0f218d6 (Google Dork)

### Target User Population Collection
- Linkedin UserEnum - https://github.com/bigb0sss/LinkedinMama
- US Staff UserEnum - https://github.com/bigb0sss/USStaffMama
- NameSpi - https://github.com/waffl3ss/NameSpi

### Public Site Lookup (Github, Gitlab, etc.)
- Gitrob - https://github.com/michenriksen/gitrob/ (Github Search)
- truffleHog - https://github.com/dxa4481/truffleHog (Github Regex Search)

### Cloud Recon
- Cloud_Security_Wiki - https://cloudsecwiki.com/azure_cloud.html (Awesome cloud resources)
- cloud_enum - https://github.com/initstring/cloud_enum
- MicroBurst - https://github.com/NetSPI/MicroBurst (AZURE)
- pacu - https://github.com/RhinoSecurityLabs/pacu (AWS)
- FestIn - https://github.com/cr0hn/festin (AWS)
- s3viewer - https://github.com/SharonBrizinov/s3viewer (AWS)
- Cloud_Pentest_Cheatsheet - https://github.com/dafthack/CloudPentestCheatsheets
- endgame - https://github.com/salesforce/endgame (AWS)

### Microsoft / Windows
#### Active Discovery
- ZGrab - https://github.com/zmap/zgrab (Banner grabber)
- Hardenize - https://www.hardenize.com/ (Domain Lookup) 

#### ADFS
- ADFSpoof - https://github.com/fireeye/ADFSpoof (Forge ADFS security tokens)

### Web App
- Wordpress-Exploit-Framework - https://github.com/rastating/wordpress-exploit-framework
- Awesome-Web-Security - https://github.com/qazbnm456/awesome-web-security
- Java Deserialization - https://github.com/frohoff/ysoserial
- PHP Deserialization - https://github.com/ambionics/phpggc
- Kubernetes - https://github.com/loodse/kubectl-hacking
- SSRF - https://github.com/jdonsec/AllThingsSSRF
- Skf-labs - https://owasp-skf.gitbook.io/asvs-write-ups/ (Great Write-ups)
  <br />


## Phishing
### Phishing Techniques - https://blog.sublimesecurity.com/
#### Microsfot 365 Device Code Phishing
- devicePhish - https://github.com/bigb0sss/Microsoft365_devicePhish
- TokenTactics - https://github.com/rvrsh3ll/TokenTactics
  <br />

## 2FA bypass
- Evilnginx2 - https://github.com/kgretzky/evilginx2
- EvilnoVNC - https://github.com/JoelGMSec/EvilnoVNC

## Password Spray
### Tools
- MSOLSpray - https://github.com/dafthack/MSOLSpray
- o365enum.py - https://github.com/gremwell/o365enum (Microsoft ActiveSync)
- goPassGen - https://github.com/bigb0sss/goPassGen (PasswordSpray List Generator)
- go365 - https://github.com/optiv/Go365 (Microsoft SOAP API endpoint on login.microsoftonline.com)
- Okta - https://github.com/Rhynorater/Okta-Password-Sprayer
- o365Spray - https://github.com/0xZDH/o365spray
- Spray365 - https://github.com/MarkoH17/Spray365 (Microsoft365 / Azure AD)

### IP Rotators
- Burp IPRotate - https://github.com/PortSwigger/ip-rotate (Utilizes AWS IP Gateway)
- ProxyCannon-NG - https://github.com/proxycannon/proxycannon-ng
- Cloud-proxy - https://github.com/tomsteele/cloud-proxy
- Proxy-NG - https://github.com/jamesbcook/proxy-ng
- Mubeng - https://github.com/kitabisa/mubeng#proxy-ip-rotator

### Default Password Check
- CIRT - https://cirt.net/passwords
- DefaultCreds-cheat-sheet - https://github.com/ihebski/DefaultCreds-cheat-sheet


## Infrastructure
### Cobal Strike
- Beacon Command Cheatsheet - [CS Commands](https://github.com/bigb0sss/RedTeam/tree/master/CobaltStrike)
- Cobalt Strike Training Review
  - [Part 1](https://medium.com/@bigb0ss/red-team-review-of-red-team-operations-with-cobalt-strike-2019-training-course-part-1-962c510565aa)
- SharpeningCobaltStrike - https://github.com/cube0x0/SharpeningCobaltStrike
- Alternative ExecuteAssembly - https://github.com/med0x2e/ExecuteAssembly
- Inline ExecuteAssembly - https://github.com/anthemtotheego/InlineExecute-Assembly (Executing .NET Assembly in the same process unline CS's Execute-Assembly)
- BOF (Beacon Object Files) - https://github.com/trustedsec/CS-Situational-Awareness-BOF

#### Malleable C2
- Malleable C2 (Guideline) - [CS4.0_guideline.profile](https://github.com/bigb0sss/RedTeam/blob/master/CobaltStrike/malleable_C2_profile/CS4.0_guideline.profile)
- Malleable C2 Randomizer - https://fortynorthsecurity.com/blog/introducing-c2concealer/
- SourcePoint - https://github.com/Tylous/SourcePoint

### C2 (Opensource)
- OffensiveNotion - https://github.com/mttaggart/OffensiveNotion
- Havoc - https://github.com/HavocFramework/Havoc
- Merlin - https://github.com/Ne0nd0g/merlin
- Sliver -https://github.com/BishopFox/sliver

### Redirectors
- Domain Fronting - https://www.bamsoftware.com/papers/fronting/

### Proxy Infrastructure Setup
- Cloud-proxy - https://github.com/tomsteele/cloud-proxy
- Proxy-ng - https://github.com/jamesbcook/proxy-ng
- ProxyCannon - https://github.com/proxycannon/proxycannon-ng

### Living Off Trusted Sites
- LOTS - https://lots-project.com/ (Trusted sites for C2/Phishing/Downloading)


## Post-Exploitation
### Windows Active Directory Recon/Survey
- Seatbelt - https://github.com/GhostPack/Seatbelt (Ghostpack)
- DNS Enum - https://github.com/dirkjanm/adidnsdump

### Windows Active Directory Attacks
- Attacking & Securing Active Directory - https://rmusser.net/docs/index.html#/./Active_Directory?id=active-directory (Awesome references)

### Internal Phishing
- pickl3 - https://github.com/hlldz/pickl3
- CredPhisher - https://github.com/matterpreter/OffensiveCSharp/tree/master/CredPhisher

### Credential Theft 
#### Windows
- Mimikatz Command References - https://adsecurity.org/?page_id=1821

#### Internet Browsers
- SharpChromium - https://github.com/djhohnstein/SharpChromium (Chrome)
- EvilSeleium - https://github.com/mrd0x/EvilSelenium (Chrome)

#### LSASS
- SharpDump - https://github.com/GhostPack/SharpDump (Highly IOC'd)
- SharpMiniDump - https://github.com/b4rtik/SharpMiniDump (Uses dynamic API calls, direct syscall and Native API unhooking to evade the AV / EDR detection - Win10 - WinServer2016)
- Dumper2020 - https://github.com/gitjdm/dumper2020 
- Nanodump - https://github.com/helpsystems/nanodump



### Lateral Movement
- SpectorOps - https://posts.specterops.io/offensive-lateral-movement-1744ae62b14f
- Pypykatz - https://github.com/skelsec/pypykatz (Python implementation of Mimikatz)
- Internal-Monologue - https://github.com/eladshamir/Internal-Monologue
- MSSQL - https://research.nccgroup.com/2021/01/21/mssql-lateral-movement/
- LiquidSnake - https://github.com/RiccardoAncarani/LiquidSnake (Fileless LM using WMI Event Subscriptions and GadgetToJScript)

### Offensive C#
- OffensiveCSharp - https://github.com/matterpreter/OffensiveCSharp
- C# Collection - https://github.com/midnightslacker/Sharp/blob/master/README.md

### LiveOffTheLand
- LOLBAS - https://lolbas-project.github.io/

### AV/AMSI Evasion
- xencrypt - https://github.com/the-xentropy/xencrypt (PowerShell)
- FalconStrike - https://github.com/slaeryan/FALCONSTRIKE
- AV_Bypass - https://github.com/Techryptic/AV_Bypass
- DotNetToJScript - https://github.com/tyranid/DotNetToJScript
- GadgetToJScript - https://github.com/med0x2e/GadgetToJScript 
- GadgetToJScript - https://github.com/rasta-mouse/GadgetToJScript
- Shellcodeloader - https://github.com/knownsec/shellcodeloader (ShellcodeLoader of windows can bypass AV)

### EDR Evasion
- SharpBlock - https://github.com/CCob/SharpBlock
- ScareCrow - https://github.com/optiv/ScareCrow (EDR Bypass Payload Creation Framework)
- Cobalt Strike Tradecraft
  - https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/amp/?__twitter_impression=true
  - https://www.cobaltstrike.com/help-opsec

### PowerShell
- p3nt4 - https://github.com/p3nt4

### Log/Trace Deletion
- moonwalk - https://github.com/mufeedvh/moonwalk (Linux logs/filesystem timestamps deletion)


## Exploit Dev
### Windows
- https://github.com/Ondrik8/exploit
- Undocumented Func (Win NT/2000/XP/Win7) - http://undocumented.ntinternals.net/
- Windows Syscall - https://j00ru.vexillium.org/syscalls/nt/64/
- Windows Undocumented Func - http://undocumented.ntinternals.net/
- Windows Kernel Exploit Training - https://codemachine.com/
- Anti-Debug - https://anti-debug.checkpoint.com/

### Nix


## VulnDB
### Vulns - Cloud
- [The Open Cloud Vulnerability & Security Issue Database](https://www.cloudvulndb.org/)

### Vulns - WebApp


### Vulns - Windows / Active Directory 


## RedTeam Researchers (Githubs / Gitbooks)
- Vincent Yiu - https://vincentyiu.com
- Outflank - https://github.com/outflanknl
- Bank Security - https://github.com/BankSecurity/Red_Team
- Infosecn1nja - https://github.com/infosecn1nja (Redteam-Toolkit = AWESOME)
- Yeyintminthuhtut - https://github.com/yeyintminthuhtut
- RedCanary (Atomic RedTeam) - https://github.com/redcanaryco/atomic-red-team
- kmkz - https://github.com/kmkz/Pentesting (Good cheat-sheets)
- Rastamouse - https://offensivedefence.co.uk/authors/rastamouse/
- (Gitbook) dmcxblue - https://dmcxblue.gitbook.io/red-team-notes-2-0/

## Awesome Collections
- [Awesome-RCE-Techniques](https://github.com/p0dalirius/Awesome-RCE-techniques)

## Lab Resources
### Labs - Windows
- Windows Server VMs - https://www.microsoft.com/en-us/evalcenter
- Windows 10 - https://www.microsoft.com/en-us/software-download/windows10ISO
- Archive of WinVMs - https://archive.org/search.php?query=subject%3A%22IEVM%22
- Public MSDN - [Link](https://the-eye.eu/public/MSDN/)
- Adversary Tactics: PowerShell - https://github.com/specterops/at-ps (Specterops)

### Labs - Cloud
- AWS Threat Simulation and Detection - https://github.com/sbasu7241/AWS-Threat-Simulation-and-Detection
- Stratus Red Team - https://github.com/DataDog/stratus-red-team

### Labs - CTF / Security Testing Practice
- Hackthebox - https://www.hackthebox.eu/
- Cyberseclab - https://www.cyberseclabs.co.uk/ (AD Focus)

## Sexy Resources
- MITRE ATT&CK - https://attack.mitre.org/
- MalwareNews - https://malware.news/
- CWE - http://cwe.mitre.org/top25/archive/2019/2019_cwe_top25.html
- CTID - https://github.com/center-for-threat-informed-defense
- SpritesMods - http://spritesmods.com/?art=main (Product Security)
- Joeware - http://www.joeware.net/ (Windows AD Guru - Many AD Recon bins and amazing blogs)
- Tenable - https://github.com/tenable/poc (Exploit POCs)
- MalwareUnicorn - https://malwareunicorn.org/ (Malware/Reversing)



## BlueTeam
### Lab Resources
- Detection Lab - https://github.com/clong/DetectionLab

### Threat Detection
- KQL - https://github.com/DebugPrivilege/KQL
- Sigma - https://github.com/Neo23x0/sigma (Generic Signature Format for SIEM)
- Splunk Security Essential Docs - https://docs.splunksecurityessentials.com/content-detail/ (Various IOCs)
- Cobalt Strike Defense - https://github.com/MichaelKoczwara/Awesome-CobaltStrike-Defence
- Dorothy - https://github.com/elastic/dorothy (Okta SSO Monitoring and Detection)

### Windows Security (What will BlueTeam look for?)

#### LDAP (Lightweight Directory Access Protocol)
- [Hunting for reconnaissance activities using LDAP search filter (Microsoft)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726)

## Disclaimer
All the credits belong to the original authors and publishers.

## Contributors
- @bigb0ss
- @T145
- @threat-punter
- @3isenHeiM
