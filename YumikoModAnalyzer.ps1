param(
    [switch]$SkipSystemCheck,
    [switch]$SkipModCheck,
    [string]$ModPath,
    [switch]$AutoFix,
    [switch]$Silent
)

$script:Config = @{
    Version = "3.2.0"
    Author = "Veridon"
    Name = "Yumiko Mod Analyzer"
    Edition = "FREE"
    ModrinthAPI = "https://api.modrinth.com/v2"
    MegabaseAPI = "https://megabase.vercel.app/api/query"
    CheatSignatures = "450+"
    SystemChecks = "28"
}

$script:Colors = @{
    Primary    = "Magenta"
    Secondary  = "Cyan"
    Success    = "Green"
    Warning    = "Yellow"
    Error      = "Red"
    Info       = "White"
    Dim        = "DarkGray"
    Accent     = "Blue"
}

function Write-Banner {
    Clear-Host
    $banner = @"

    ##    ## ##     ## ##     ## #### ##    ##  #######  
     ##  ##  ##     ## ###   ###  ##  ##   ## ##     ## 
      ####   ##     ## #### ####  ##  ##  ##  ##     ## 
       ##    ##     ## ## ### ##  ##  #####   ##     ## 
       ##    ##     ## ##     ##  ##  ##  ##  ##     ## 
       ##    ##     ## ##     ##  ##  ##   ## ##     ## 
       ##     #######  ##     ## #### ##    ##  #######  
                    M O D   A N A L Y Z E R
"@
    Write-Host $banner -ForegroundColor $script:Colors.Primary
    Write-Host "    ===========================================================" -ForegroundColor $script:Colors.Dim
    Write-Host "      Version $($script:Config.Version) " -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host "|" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host " $($script:Config.Edition) Edition" -ForegroundColor $script:Colors.Warning
    Write-Host "    ===========================================================" -ForegroundColor $script:Colors.Dim
    Write-Host "      $($script:Config.CheatSignatures) Cheat Signatures" -ForegroundColor $script:Colors.Accent
    Write-Host "    ===========================================================" -ForegroundColor $script:Colors.Dim
    Write-Host ""
}

function Write-Section {
    param([string]$Title, [string]$Icon = "*")
    Write-Host ""
    Write-Host "  [$Icon] " -NoNewline -ForegroundColor $script:Colors.Primary
    Write-Host $Title -ForegroundColor $script:Colors.Secondary
    Write-Host "  ----------------------------------------------------" -ForegroundColor $script:Colors.Dim
}

function Write-Result {
    param(
        [string]$Status,
        [string]$Message,
        [string]$Detail = ""
    )
    
    $statusColors = @{
        "PASS"     = $script:Colors.Success
        "FAIL"     = $script:Colors.Error
        "WARN"     = $script:Colors.Warning
        "INFO"     = $script:Colors.Info
        "FOUND"    = $script:Colors.Warning
        "CLEAN"    = $script:Colors.Success
        "CHEAT"    = $script:Colors.Error
        "UNKNOWN"  = $script:Colors.Warning
        "VERIFIED" = $script:Colors.Success
    }
    
    $statusIcons = @{
        "PASS"     = "+"
        "FAIL"     = "x"
        "WARN"     = "!"
        "INFO"     = ">"
        "FOUND"    = "!"
        "CLEAN"    = "+"
        "CHEAT"    = "X"
        "UNKNOWN"  = "?"
        "VERIFIED" = "+"
    }
    
    $color = $statusColors[$Status]
    $icon = $statusIcons[$Status]
    
    Write-Host "    [$icon] " -NoNewline -ForegroundColor $color
    Write-Host $Message -NoNewline -ForegroundColor $script:Colors.Info
    if ($Detail) {
        Write-Host " -> " -NoNewline -ForegroundColor $script:Colors.Dim
        Write-Host $Detail -ForegroundColor $script:Colors.Dim
    } else {
        Write-Host ""
    }
}

function Write-ProgressBar {
    param([int]$Current, [int]$Total, [string]$Activity)
    $percent = [math]::Round(($Current / $Total) * 100)
    $filled = [math]::Round($percent / 5)
    $empty = 20 - $filled
    $bar = "#" * $filled + "-" * $empty
    Write-Host "`r    [$bar] $percent% - $Activity" -NoNewline -ForegroundColor $script:Colors.Secondary
}

$script:SystemFindings = @()

function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Check-HostsFileManipulation {
    Write-Section "Hosts File Analysis" "NET"
    
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $suspiciousDomains = @(
        "github.com", "raw.githubusercontent.com", "api.github.com",
        "discord.com", "discordapp.com", "cdn.discordapp.com",
        "telegram.org", "api.telegram.org",
        "virustotal.com", "www.virustotal.com",
        "modrinth.com", "api.modrinth.com",
        "curseforge.com", "mediafilez.forgecdn.net",
        "pastebin.com", "hastebin.com"
    )
    
    $blockingIPs = @("0.0.0.0", "127.0.0.1", "127.0.1.1", "::1")
    $found = $false
    
    try {
        $hostsContent = Get-Content $hostsPath -ErrorAction Stop
        foreach ($line in $hostsContent) {
            if ($line -match "^\s*#" -or [string]::IsNullOrWhiteSpace($line)) { continue }
            
            foreach ($domain in $suspiciousDomains) {
                if ($line -match $domain) {
                    foreach ($ip in $blockingIPs) {
                        if ($line -match "^\s*$([regex]::Escape($ip))") {
                            Write-Result "FOUND" "Blocked: $domain" "-> $ip"
                            $script:SystemFindings += @{
                                Type = "Hosts"
                                Description = "Domain $domain blocked to $ip"
                                Path = $hostsPath
                                Line = $line
                            }
                            $found = $true
                        }
                    }
                }
            }
        }
        
        if (-not $found) {
            Write-Result "CLEAN" "No suspicious hosts file entries detected"
        }
    } catch {
        Write-Result "FAIL" "Could not read hosts file" $_.Exception.Message
    }
}

function Check-RegistryRestrictions {
    Write-Section "Registry Restrictions" "REG"
    
    $restrictions = @(
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableTaskMgr"; Desc = "Task Manager disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableRegistryTools"; Desc = "Registry Editor disabled" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\Windows\System"; Name = "DisableCMD"; Desc = "Command Prompt disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoRun"; Desc = "Run dialog disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoControlPanel"; Desc = "Control Panel disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoFind"; Desc = "Windows Search disabled" },
        @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name = "NoFolderOptions"; Desc = "Folder Options hidden" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell"; Name = "ExecutionPolicy"; Desc = "PowerShell ExecutionPolicy"; CheckValue = @("Restricted", "AllSigned") }
    )
    
    $found = $false
    
    foreach ($restriction in $restrictions) {
        try {
            $value = Get-ItemProperty -Path $restriction.Path -Name $restriction.Name -ErrorAction SilentlyContinue
            if ($value) {
                $val = $value.$($restriction.Name)
                if ($restriction.CheckValue) {
                    if ($val -in $restriction.CheckValue) {
                        Write-Result "FOUND" $restriction.Desc "Value: $val"
                        $script:SystemFindings += @{
                            Type = "Registry"
                            Description = $restriction.Desc
                            Path = "$($restriction.Path)\$($restriction.Name)"
                            Value = $val
                        }
                        $found = $true
                    }
                } elseif ($val -eq 1) {
                    Write-Result "FOUND" $restriction.Desc "Enabled"
                    $script:SystemFindings += @{
                        Type = "Registry"
                        Description = $restriction.Desc
                        Path = "$($restriction.Path)\$($restriction.Name)"
                        Value = $val
                    }
                    $found = $true
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious registry restrictions found"
    }
}

function Check-IFEOHijacking {
    Write-Section "Image File Execution Options" "IFEO"
    
    $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $suspiciousExes = @(
        "taskmgr.exe", "regedit.exe", "cmd.exe", "powershell.exe", "procexp.exe",
        "procmon.exe", "autoruns.exe", "ProcessHacker.exe", "wireshark.exe",
        "x64dbg.exe", "x32dbg.exe", "dnSpy.exe", "ILSpy.exe", "javaw.exe"
    )
    
    $found = $false
    
    foreach ($exe in $suspiciousExes) {
        $exePath = Join-Path $ifeoPath $exe
        try {
            $debugger = Get-ItemProperty -Path $exePath -Name "Debugger" -ErrorAction SilentlyContinue
            if ($debugger) {
                Write-Result "FOUND" "IFEO Debugger on $exe" $debugger.Debugger
                $script:SystemFindings += @{
                    Type = "IFEO"
                    Description = "Debugger hijacking on $exe"
                    Path = $exePath
                    Value = $debugger.Debugger
                }
                $found = $true
            }
            
            $globalFlag = Get-ItemProperty -Path $exePath -Name "GlobalFlag" -ErrorAction SilentlyContinue
            if ($globalFlag -and $globalFlag.GlobalFlag -ne 0) {
                Write-Result "FOUND" "GlobalFlag on $exe" "Value: $($globalFlag.GlobalFlag)"
                $script:SystemFindings += @{
                    Type = "IFEO"
                    Description = "GlobalFlag set on $exe"
                    Path = $exePath
                    Value = $globalFlag.GlobalFlag
                }
                $found = $true
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No IFEO hijacking detected"
    }
}

function Check-DisallowRun {
    Write-Section "DisallowRun Policies" "BAN"
    
    $disallowPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
    $found = $false
    
    try {
        $enabled = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -ErrorAction SilentlyContinue
        if ($enabled -and $enabled.DisallowRun -eq 1) {
            Write-Result "FOUND" "DisallowRun policy is ENABLED"
            
            if (Test-Path $disallowPath) {
                $blocked = Get-ItemProperty -Path $disallowPath -ErrorAction SilentlyContinue
                $blocked.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    Write-Result "INFO" "Blocked executable" $_.Value
                    $script:SystemFindings += @{
                        Type = "DisallowRun"
                        Description = "Executable blocked: $($_.Value)"
                        Path = $disallowPath
                    }
                }
            }
            $found = $true
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No DisallowRun restrictions found"
    }
}

function Check-FirewallRestrictions {
    Write-Section "Firewall Restrictions" "FW"
    
    $found = $false
    
    $fwPolicies = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall"; Name = "DisableFirewallUI" },
        @{ Path = "HKCU:\Software\Policies\Microsoft\WindowsFirewall"; Name = "DisableFirewallUI" }
    )
    
    foreach ($policy in $fwPolicies) {
        try {
            $val = Get-ItemProperty -Path $policy.Path -Name $policy.Name -ErrorAction SilentlyContinue
            if ($val -and $val.$($policy.Name) -eq 1) {
                Write-Result "FOUND" "Firewall UI disabled" $policy.Path
                $script:SystemFindings += @{
                    Type = "Firewall"
                    Description = "Firewall UI disabled"
                    Path = "$($policy.Path)\$($policy.Name)"
                }
                $found = $true
            }
        } catch {}
    }
    
    $cplPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowCpl"
    if (Test-Path $cplPath) {
        try {
            $blocked = Get-ItemProperty -Path $cplPath -ErrorAction SilentlyContinue
            $blocked.PSObject.Properties | Where-Object { $_.Value -match "firewall" } | ForEach-Object {
                Write-Result "FOUND" "firewall.cpl blocked via DisallowCpl"
                $script:SystemFindings += @{
                    Type = "Firewall"
                    Description = "firewall.cpl blocked"
                    Path = $cplPath
                }
                $found = $true
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No firewall restrictions detected"
    }
}

function Check-TaskkillAutorun {
    Write-Section "Taskkill Autorun Detection" "KILL"
    
    $found = $false
    $runPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $runPaths) {
        try {
            if (Test-Path $path) {
                $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                $items.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    if ($_.Value -match "taskkill|tskill") {
                        Write-Result "FOUND" "Taskkill in autorun" "$($_.Name): $($_.Value)"
                        $script:SystemFindings += @{
                            Type = "Autorun"
                            Description = "Taskkill command in $($_.Name)"
                            Path = $path
                            Value = $_.Value
                        }
                        $found = $true
                    }
                }
            }
        } catch {}
    }
    
    try {
        $cmdAutorun = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Command Processor" -Name "AutoRun" -ErrorAction SilentlyContinue
        if ($cmdAutorun -and $cmdAutorun.AutoRun) {
            Write-Result "FOUND" "CMD AutoRun detected" $cmdAutorun.AutoRun
            $script:SystemFindings += @{
                Type = "Autorun"
                Description = "CMD AutoRun command"
                Path = "HKCU:\Software\Microsoft\Command Processor\AutoRun"
                Value = $cmdAutorun.AutoRun
            }
            $found = $true
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious autorun entries found"
    }
}

function Check-URLBlocklist {
    Write-Section "Browser URL Blocklist" "WEB"
    
    $found = $false
    $browsers = @(
        @{ Name = "Chrome"; Path = "HKLM:\SOFTWARE\Policies\Google\Chrome" },
        @{ Name = "Edge"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Edge" },
        @{ Name = "Brave"; Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" },
        @{ Name = "Vivaldi"; Path = "HKLM:\SOFTWARE\Policies\Vivaldi" }
    )
    
    foreach ($browser in $browsers) {
        $blockPath = "$($browser.Path)\URLBlocklist"
        if (Test-Path $blockPath) {
            try {
                $blocked = Get-ItemProperty -Path $blockPath -ErrorAction SilentlyContinue
                $blocked.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    Write-Result "FOUND" "$($browser.Name) URL blocked" $_.Value
                    $script:SystemFindings += @{
                        Type = "URLBlocklist"
                        Description = "$($browser.Name): $($_.Value) blocked"
                        Path = $blockPath
                    }
                    $found = $true
                }
            } catch {}
        }
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No browser URL blocklists detected"
    }
}

function Check-CMDColorBypass {
    Write-Section "CMD Color Bypass" "CLR"
    
    $found = $false
    
    try {
        $defaultColor = Get-ItemProperty -Path "HKCU:\Console" -Name "ScreenColors" -ErrorAction SilentlyContinue
        if ($defaultColor) {
            $colors = $defaultColor.ScreenColors
            $fg = $colors -band 0x0F
            $bg = ($colors -band 0xF0) -shr 4
            
            if ($fg -eq $bg) {
                Write-Result "FOUND" "CMD text color matches background" "FG: $fg, BG: $bg (invisible text)"
                $script:SystemFindings += @{
                    Type = "CMDColor"
                    Description = "CMD colors make text invisible"
                    Path = "HKCU:\Console\ScreenColors"
                    Value = $colors
                }
                $found = $true
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "CMD colors are normal"
    }
}

function Check-PrefetchManipulation {
    Write-Section "Prefetch Analysis" "PF"
    
    $found = $false
    $prefetchPath = "$env:SystemRoot\Prefetch"
    
    try {
        $prefetcher = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name "EnablePrefetcher" -ErrorAction SilentlyContinue
        if ($prefetcher -and $prefetcher.EnablePrefetcher -in @(0, 1)) {
            Write-Result "FOUND" "Prefetcher disabled or limited" "Value: $($prefetcher.EnablePrefetcher)"
            $script:SystemFindings += @{
                Type = "Prefetch"
                Description = "EnablePrefetcher set to $($prefetcher.EnablePrefetcher)"
                Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher"
            }
            $found = $true
        }
    } catch {}
    
    if (Test-Path $prefetchPath) {
        $readOnlyPF = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | Where-Object { $_.IsReadOnly }
        if ($readOnlyPF.Count -gt 0) {
            Write-Result "FOUND" "Read-only prefetch files detected" "$($readOnlyPF.Count) files"
            foreach ($pf in $readOnlyPF | Select-Object -First 5) {
                Write-Result "INFO" "Read-only" $pf.Name
            }
            if ($readOnlyPF.Count -gt 5) {
                Write-Result "INFO" "...and $($readOnlyPF.Count - 5) more"
            }
            $script:SystemFindings += @{
                Type = "Prefetch"
                Description = "Read-only prefetch files"
                Path = $prefetchPath
                Value = $readOnlyPF.Count
            }
            $found = $true
        }
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "Prefetch configuration is normal"
    }
}

function Check-EventLogClearing {
    Write-Section "Event Log Analysis" "LOG"
    
    $found = $false
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    
    try {
        $securityCleared = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            ID = 1102
            StartTime = $bootTime
        } -ErrorAction SilentlyContinue
        
        if ($securityCleared) {
            Write-Result "FOUND" "Security log cleared this session" "$($securityCleared.Count) event(s)"
            $script:SystemFindings += @{
                Type = "EventLog"
                Description = "Security log cleared"
            }
            $found = $true
        }
    } catch {}
    
    try {
        $anyCleared = Get-WinEvent -FilterHashtable @{
            LogName = "System"
            ID = 104
            StartTime = $bootTime
        } -ErrorAction SilentlyContinue
        
        if ($anyCleared) {
            Write-Result "FOUND" "Event logs cleared this session" "$($anyCleared.Count) event(s)"
            $script:SystemFindings += @{
                Type = "EventLog"
                Description = "Event logs cleared"
            }
            $found = $true
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No log clearing detected this session"
    }
}

function Check-DisallowedCertificates {
    Write-Section "Certificate Store Analysis" "CERT"
    
    $found = $false
    
    $knownThumbprints = @{
        "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436" = "DigiCert Global Root CA"
        "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4" = "DigiCert Global Root G2"
    }
    
    try {
        $disallowed = Get-ChildItem -Path "Cert:\LocalMachine\Disallowed" -ErrorAction SilentlyContinue
        foreach ($cert in $disallowed) {
            if ($knownThumbprints.ContainsKey($cert.Thumbprint)) {
                Write-Result "FOUND" "Known cert blocked" "$($knownThumbprints[$cert.Thumbprint]) ($($cert.Thumbprint.Substring(0,8))...)"
                $script:SystemFindings += @{
                    Type = "Certificate"
                    Description = "Certificate $($cert.Thumbprint) in Disallowed store"
                }
                $found = $true
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious blocked certificates"
    }
}

function Check-SystemTimeChanges {
    Write-Section "System Time Analysis" "TIME"
    
    $found = $false
    $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    
    try {
        $timeChanges = Get-WinEvent -FilterHashtable @{
            LogName = "Security"
            ID = 4616
            StartTime = $bootTime
        } -ErrorAction SilentlyContinue
        
        foreach ($event in $timeChanges) {
            $xml = [xml]$event.ToXml()
            $newTime = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewTime" } | Select-Object -ExpandProperty "#text"
            $oldTime = $xml.Event.EventData.Data | Where-Object { $_.Name -eq "PreviousTime" } | Select-Object -ExpandProperty "#text"
            
            if ($newTime -and $oldTime) {
                $diff = [math]::Abs(([datetime]$newTime - [datetime]$oldTime).TotalSeconds)
                if ($diff -gt 30) {
                    Write-Result "FOUND" "Manual time change detected" "Delta: $([math]::Round($diff/60, 1)) minutes"
                    $script:SystemFindings += @{
                        Type = "TimeChange"
                        Description = "Time changed by $diff seconds"
                    }
                    $found = $true
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious time changes detected"
    }
}

function Check-WinRARSteganography {
    Write-Section "WinRAR Steganography Check" "RAR"
    
    $found = $false
    $winrarHistoryPath = "HKCU:\Software\WinRAR\ArcHistory"
    $archiveExtensions = @(".rar", ".zip", ".7z", ".tar", ".gz", ".bz2")
    
    if (Test-Path $winrarHistoryPath) {
        try {
            $history = Get-ItemProperty -Path $winrarHistoryPath -ErrorAction SilentlyContinue
            $history.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                $path = $_.Value
                $ext = [System.IO.Path]::GetExtension($path).ToLower()
                if ($ext -and $ext -notin $archiveExtensions) {
                    Write-Result "FOUND" "Non-archive in WinRAR history" $path
                    $script:SystemFindings += @{
                        Type = "Steganography"
                        Description = "Non-archive file: $path"
                        Path = $winrarHistoryPath
                    }
                    $found = $true
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No steganography indicators found"
    }
}

function Check-DefenderExclusions {
    Write-Section "Windows Defender Exclusions" "DEF"
    
    $found = $false
    $exclusionPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes",
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
    )
    
    foreach ($path in $exclusionPaths) {
        try {
            if (Test-Path $path) {
                $exclusions = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
                $exclusions.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                    $excl = $_.Name
                    if ($excl -match "\.minecraft|mods|java|\.jar|cheat|hack|client") {
                        Write-Result "FOUND" "Suspicious Defender exclusion" $excl
                        $script:SystemFindings += @{
                            Type = "DefenderExclusion"
                            Description = "Suspicious exclusion: $excl"
                            Path = $path
                        }
                        $found = $true
                    }
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Defender exclusions found"
    }
}

function Check-ScheduledTasks {
    Write-Section "Suspicious Scheduled Tasks" "TASK"
    
    $found = $false
    $suspiciousPatterns = @("taskkill", "del ", "rm ", "remove-item", "clear-eventlog", "wevtutil", "cipher /w")
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne "Disabled" }
        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                $actions = $task.Actions
                foreach ($action in $actions) {
                    $cmd = "$($action.Execute) $($action.Arguments)"
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($cmd -match [regex]::Escape($pattern)) {
                            Write-Result "FOUND" "Suspicious task" "$($task.TaskName): $cmd"
                            $script:SystemFindings += @{
                                Type = "ScheduledTask"
                                Description = "Suspicious: $($task.TaskName)"
                                Value = $cmd
                            }
                            $found = $true
                        }
                    }
                }
            } catch {}
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious scheduled tasks found"
    }
}

function Check-PowerShellLogging {
    Write-Section "PowerShell Logging Status" "PS"
    
    $found = $false
    $loggingPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; Name = "EnableScriptBlockLogging"; Desc = "Script Block Logging" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; Name = "EnableModuleLogging"; Desc = "Module Logging" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"; Name = "EnableTranscripting"; Desc = "Transcription" }
    )
    
    foreach ($logging in $loggingPaths) {
        try {
            $value = Get-ItemProperty -Path $logging.Path -Name $logging.Name -ErrorAction SilentlyContinue
            if ($value -and $value.$($logging.Name) -eq 0) {
                Write-Result "FOUND" "$($logging.Desc) is DISABLED" "(Potential bypass)"
                $script:SystemFindings += @{
                    Type = "PowerShellLogging"
                    Description = "$($logging.Desc) disabled"
                    Path = "$($logging.Path)\$($logging.Name)"
                }
                $found = $true
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "PowerShell logging configuration is normal"
    }
}

function Check-StartupFolder {
    Write-Section "Startup Folder Analysis" "START"
    
    $found = $false
    $startupPaths = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    $suspiciousExtensions = @(".bat", ".cmd", ".vbs", ".ps1", ".jar", ".exe")
    $suspiciousNames = @("java", "javaw", "cheat", "client", "hack", "inject", "loader")
    
    foreach ($path in $startupPaths) {
        try {
            if (Test-Path $path) {
                $items = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($item in $items) {
                    $ext = $item.Extension.ToLower()
                    $name = $item.BaseName.ToLower()
                    
                    $isSuspicious = $false
                    foreach ($pattern in $suspiciousNames) {
                        if ($name -match $pattern) { $isSuspicious = $true; break }
                    }
                    
                    if ($ext -in $suspiciousExtensions -or $isSuspicious) {
                        Write-Result "FOUND" "Suspicious startup item" $item.Name
                        $script:SystemFindings += @{
                            Type = "Startup"
                            Description = "Suspicious: $($item.Name)"
                            Path = $item.FullName
                        }
                        $found = $true
                    }
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious startup items found"
    }
}

function Check-RecentRunDialogs {
    Write-Section "Recent Run Commands" "RUN"
    
    $found = $false
    $runMRUPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
    $suspiciousPatterns = @("powershell", "cmd", "wscript", "cscript", "mshta", "reg ", "regedit", "taskkill", "del ", "cipher")
    
    try {
        if (Test-Path $runMRUPath) {
            $runHistory = Get-ItemProperty -Path $runMRUPath -ErrorAction SilentlyContinue
            $runHistory.PSObject.Properties | Where-Object { $_.Name -match "^[a-z]$" } | ForEach-Object {
                $cmd = $_.Value
                foreach ($pattern in $suspiciousPatterns) {
                    if ($cmd -match [regex]::Escape($pattern)) {
                        Write-Result "FOUND" "Suspicious run command" $cmd
                        $script:SystemFindings += @{
                            Type = "RunMRU"
                            Description = "Suspicious command: $cmd"
                            Path = $runMRUPath
                        }
                        $found = $true
                        break
                    }
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious run commands detected"
    }
}

function Check-USNJournalStatus {
    Write-Section "USN Journal Status" "USN"
    
    $found = $false
    
    try {
        $usnOutput = fsutil usn queryjournal C: 2>&1
        if ($usnOutput -match "Error|disabled|not enabled|not active") {
            Write-Result "FOUND" "USN Journal may be disabled" "Evidence deletion possible"
            $script:SystemFindings += @{
                Type = "USNJournal"
                Description = "USN Journal possibly disabled"
            }
            $found = $true
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "USN Journal appears active"
    }
}

function Check-RecycleBinBypass {
    Write-Section "Recycle Bin Configuration" "BIN"
    
    $found = $false
    $rbPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume"
    
    try {
        if (Test-Path $rbPath) {
            $volumes = Get-ChildItem -Path $rbPath -ErrorAction SilentlyContinue
            foreach ($vol in $volumes) {
                $nukeOnDelete = Get-ItemProperty -Path $vol.PSPath -Name "NukeOnDelete" -ErrorAction SilentlyContinue
                if ($nukeOnDelete -and $nukeOnDelete.NukeOnDelete -eq 1) {
                    Write-Result "FOUND" "Recycle Bin bypass enabled" $vol.PSChildName
                    $script:SystemFindings += @{
                        Type = "RecycleBin"
                        Description = "Files deleted permanently on $($vol.PSChildName)"
                        Path = $vol.PSPath
                    }
                    $found = $true
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "Recycle Bin configuration is normal"
    }
}

function Check-DriverSignatureEnforcement {
    Write-Section "Driver Signature Status" "DRV"
    
    $found = $false
    
    try {
        $bcdOutput = bcdedit /enum 2>&1
        if ($bcdOutput -match "testsigning\s+Yes|nointegritychecks\s+Yes") {
            Write-Result "FOUND" "Driver signing may be disabled" "Test-signing or no integrity checks"
            $script:SystemFindings += @{
                Type = "DriverSignature"
                Description = "Driver signature enforcement bypassed"
            }
            $found = $true
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "Driver signature enforcement active"
    }
}

function Check-SuspiciousProcesses {
    Write-Section "Suspicious Process Detection" "PROC"
    
    $found = $false
    $suspiciousNames = @(
        "cheat", "hack", "inject", "exploit", "bypass",
        "meteor", "wurst", "impact", "aristois", "liquidbounce",
        "vape", "rise", "novoline", "exhibition", "sigma"
    )
    
    try {
        $processes = Get-Process -ErrorAction SilentlyContinue
        foreach ($proc in $processes) {
            $name = $proc.ProcessName.ToLower()
            foreach ($sus in $suspiciousNames) {
                if ($name -match $sus) {
                    Write-Result "FOUND" "Suspicious process" "$($proc.ProcessName) (PID: $($proc.Id))"
                    $script:SystemFindings += @{
                        Type = "Process"
                        Description = "Suspicious process: $($proc.ProcessName)"
                    }
                    $found = $true
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious processes detected"
    }
}

function Check-DNSCache {
    Write-Section "DNS Cache Analysis" "DNS"
    
    $found = $false
    $suspiciousDomains = @(
        # Known Cheat Clients
        "vape.gg", "intent.store", "novoline.wtf", "rise.today",
        "astolfo.lgbt", "exhibition.org", "fdpclient.com",
        "sigmaclient.info", "pandaware.wtf", "drip.ac",
        "novaclient.lol", "novaclient.com", "api.novaclient.lol",
        "riseclient.com", "doomsdayclient.com", "prestigeclient.vip",
        "198macros.com", "dqrkis.xyz",
        # Additional Clients
        "konas.org", "rusherhack.org", "futureclient.net",
        "phobos.cc", "salhack.dev", "gamesense.pub",
        "thunderclient.org", "trollhack.xyz", "abyss.dev",
        "cosmos.rip", "ares.fyi", "tenacity.dev",
        "liquidbounce.net", "ccbluex.net", "wurstclient.net",
        "impactclient.net", "aristoismod.com", "meteorclient.com",
        # RAT / Malware Sources
        "grabify.link", "iplogger.org", "blasze.tk",
        "discord.gift", "discordgift.site", "steamcommunity.rip",
        # Cheat Forums
        "unknowncheats.me", "mpgh.net", "elitepvpers.com",
        "guidedhacking.com", "hackforums.net"
    )
    
    try {
        $dnsCache = Get-DnsClientCache -ErrorAction SilentlyContinue
        foreach ($entry in $dnsCache) {
            foreach ($domain in $suspiciousDomains) {
                if ($entry.Entry -match [regex]::Escape($domain)) {
                    Write-Result "FOUND" "Suspicious domain in DNS cache" $entry.Entry
                    $script:SystemFindings += @{
                        Type = "DNSCache"
                        Description = "Cheat domain accessed: $($entry.Entry)"
                    }
                    $found = $true
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious DNS cache entries"
    }
}

function Check-BAMRegistry {
    Write-Section "BAM/DAM Registry Analysis" "BAM"
    
    $found = $false
    $bamPath = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $damPath = "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    
    $suspiciousPatterns = @(
        "cheat", "hack", "inject", "meteor", "wurst", "impact", "vape", 
        "liquidbounce", "aristois", "sigma", "novoline", "rise", "ghost",
        "client", "loader", "bypass", "exploit"
    )
    
    foreach ($path in @($bamPath, $damPath)) {
        try {
            if (Test-Path $path) {
                $userSids = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                foreach ($sid in $userSids) {
                    $entries = Get-ItemProperty -Path $sid.PSPath -ErrorAction SilentlyContinue
                    $entries.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS|Version|SequenceNumber" } | ForEach-Object {
                        $exePath = $_.Name
                        $exeName = [System.IO.Path]::GetFileName($exePath).ToLower()
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($exeName -match $pattern) {
                                Write-Result "FOUND" "Suspicious exe in BAM/DAM" $exeName
                                $script:SystemFindings += @{
                                    Type = "BAM"
                                    Description = "Recently executed: $exeName"
                                    Path = $exePath
                                }
                                $found = $true
                                break
                            }
                        }
                    }
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious BAM/DAM entries"
    }
}

function Check-ShimCache {
    Write-Section "Shimcache Analysis" "SHIM"
    
    $found = $false
    $shimPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    
    $suspiciousPatterns = @(
        "cheat", "hack", "inject", "meteor", "wurst", "impact", "vape",
        "liquidbounce", "aristois", "sigma", "novoline", "rise", "ghost",
        "loader", "bypass", "client"
    )
    
    try {
        if (Test-Path $shimPath) {
            $shimData = Get-ItemProperty -Path $shimPath -Name "AppCompatCache" -ErrorAction SilentlyContinue
            if ($shimData) {
                $rawData = $shimData.AppCompatCache
                $asciiString = [System.Text.Encoding]::ASCII.GetString($rawData) -replace '[^\x20-\x7E]', ' '
                
                foreach ($pattern in $suspiciousPatterns) {
                    if ($asciiString -match "\\[^\\]*$pattern[^\\]*\.exe") {
                        $match = $matches[0]
                        Write-Result "FOUND" "Suspicious exe in Shimcache" $match
                        $script:SystemFindings += @{
                            Type = "Shimcache"
                            Description = "Cached execution: $match"
                        }
                        $found = $true
                    }
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Shimcache entries"
    }
}

function Check-Amcache {
    Write-Section "Amcache Analysis" "AMC"
    
    $found = $false
    $amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    
    $suspiciousPatterns = @(
        "cheat", "hack", "inject", "meteor", "wurst", "impact", "vape",
        "liquidbounce", "aristois", "sigma", "novoline", "rise", "ghost",
        "loader", "bypass", "client", "exploit"
    )
    
    try {
        $recentExePath = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
        $amcacheFiles = Get-ChildItem -Path $recentExePath -Filter "*.db" -ErrorAction SilentlyContinue
        
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\StateRepository\Cache\Application\Data"
        if (Test-Path $regPath) {
            $apps = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
            foreach ($app in $apps) {
                try {
                    $appName = (Get-ItemProperty -Path $app.PSPath -ErrorAction SilentlyContinue).PackageFullName
                    if ($appName) {
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($appName -match $pattern) {
                                Write-Result "FOUND" "Suspicious app in cache" $appName
                                $script:SystemFindings += @{
                                    Type = "Amcache"
                                    Description = "Installed app: $appName"
                                }
                                $found = $true
                                break
                            }
                        }
                    }
                } catch {}
            }
        }
        
        $uninstallPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        if (Test-Path $uninstallPath) {
            $programs = Get-ChildItem -Path $uninstallPath -ErrorAction SilentlyContinue
            foreach ($prog in $programs) {
                try {
                    $displayName = (Get-ItemProperty -Path $prog.PSPath -ErrorAction SilentlyContinue).DisplayName
                    if ($displayName) {
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($displayName -match $pattern) {
                                Write-Result "FOUND" "Suspicious program installed" $displayName
                                $script:SystemFindings += @{
                                    Type = "Amcache"
                                    Description = "Installed program: $displayName"
                                }
                                $found = $true
                                break
                            }
                        }
                    }
                } catch {}
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Amcache entries"
    }
}

function Check-JumpLists {
    Write-Section "Jump Lists Analysis" "JUMP"
    
    $found = $false
    $jumpListPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations",
        "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations"
    )
    
    $suspiciousPatterns = @(
        "cheat", "hack", "inject", "meteor", "wurst", "impact", "vape",
        "liquidbounce", "aristois", "client", "loader", "ghost"
    )
    
    foreach ($path in $jumpListPaths) {
        try {
            if (Test-Path $path) {
                $jumpFiles = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                             Sort-Object LastWriteTime -Descending | 
                             Select-Object -First 50
                
                foreach ($file in $jumpFiles) {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
                        $content = [System.Text.Encoding]::Unicode.GetString($bytes) -replace '[^\x20-\x7E]', ' '
                        
                        foreach ($pattern in $suspiciousPatterns) {
                            if ($content -match "$pattern.*\.(jar|exe)") {
                                Write-Result "FOUND" "Suspicious file in Jump List" "$pattern file accessed"
                                $script:SystemFindings += @{
                                    Type = "JumpList"
                                    Description = "Recent access: $pattern file"
                                    Path = $file.FullName
                                }
                                $found = $true
                                break
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Jump List entries"
    }
}

function Check-RecentJarFiles {
    Write-Section "Recently Accessed JAR Files" "JAR"
    
    $found = $false
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    $suspiciousPatterns = @("cheat", "hack", "client", "vape", "meteor", "wurst", "impact", "inject", "ghost")
    
    try {
        $recentJars = Get-ChildItem -Path $recentPath -Filter "*.jar.lnk" -ErrorAction SilentlyContinue | 
                      Sort-Object LastWriteTime -Descending | 
                      Select-Object -First 20
        
        foreach ($lnk in $recentJars) {
            $name = $lnk.BaseName.ToLower()
            foreach ($pattern in $suspiciousPatterns) {
                if ($name -match $pattern) {
                    Write-Result "FOUND" "Suspicious recent JAR" $lnk.BaseName
                    $script:SystemFindings += @{
                        Type = "RecentJAR"
                        Description = "Suspicious JAR accessed: $($lnk.BaseName)"
                        Path = $lnk.FullName
                    }
                    $found = $true
                }
            }
        }
    } catch {}
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious recent JAR files"
    }
}

function Check-JavaArguments {
    Write-Section "Java Launch Arguments" "JVM"
    
    $found = $false
    $mcLauncherProfiles = @(
        "$env:APPDATA\.minecraft\launcher_profiles.json",
        "$env:APPDATA\.minecraft\launcher_profiles_microsoft_store.json"
    )
    
    $suspiciousArgs = @("-javaagent", "-Xbootclasspath", "-agentlib", "-agentpath", "noverify", "-Djava.debug")
    
    foreach ($profilePath in $mcLauncherProfiles) {
        try {
            if (Test-Path $profilePath) {
                $content = Get-Content -Path $profilePath -Raw -ErrorAction SilentlyContinue
                foreach ($arg in $suspiciousArgs) {
                    if ($content -match [regex]::Escape($arg)) {
                        Write-Result "FOUND" "Suspicious JVM argument" "$arg in launcher profiles"
                        $script:SystemFindings += @{
                            Type = "JavaArgs"
                            Description = "Suspicious argument: $arg"
                            Path = $profilePath
                        }
                        $found = $true
                    }
                }
            }
        } catch {}
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Java arguments detected"
    }
}

function Invoke-JvmScan {
    $results = [System.Collections.Generic.List[string]]::new()
    
    $javaProc = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $javaProc) { $javaProc = Get-Process java -ErrorAction SilentlyContinue }
    if (-not $javaProc) { return $results }
    
    $javaPid = ($javaProc | Select-Object -First 1).Id
    
    try {
        $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $javaPid" -ErrorAction Stop
        $cmdLine = $wmi.CommandLine
        
        if ($cmdLine) {
            $agentMatches = [regex]::Matches($cmdLine, '-javaagent:([^\s"]+)')
            foreach ($m in $agentMatches) {
                $agentPath = $m.Groups[1].Value.Trim('"').Trim("'")
                $agentName = [System.IO.Path]::GetFileName($agentPath)
                $legitAgents = @("jmxremote", "yjp", "jrebel", "newrelic", "jacoco", "theseus")
                $isLegit = $false
                foreach ($la in $legitAgents) { 
                    if ($agentName -match $la) { $isLegit = $true; break }
                }
                if (-not $isLegit) {
                    $results.Add("JVM Agent: -javaagent:$agentName (path: $agentPath)")
                }
            }
            
            $suspiciousFlags = @(
                @{ Flag = "-Xbootclasspath/p:"; Desc = "prepends to bootstrap classpath" },
                @{ Flag = "-Xbootclasspath/a:"; Desc = "appends to bootstrap classpath" },
                @{ Flag = "-agentlib:jdwp"; Desc = "JDWP debug agent enabled" },
                @{ Flag = "-agentpath:"; Desc = "native agent loaded" },
                @{ Flag = "-XX:+DisableAttachMechanism"; Desc = "attach blocked" },
                @{ Flag = "-noverify"; Desc = "bytecode verification disabled" }
            )
            
            foreach ($sf in $suspiciousFlags) {
                if ($cmdLine -match [regex]::Escape($sf.Flag)) {
                    $results.Add("JVM Flag: $($sf.Flag) ($($sf.Desc))")
                }
            }
        }
    } catch {}
    
    return $results
}

function Invoke-BypassScan {
    param([string]$FilePath)
    
    $flags = [System.Collections.Generic.List[string]]::new()
    
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    
    $mavenPrefixes = @(
        "com_", "org_", "net_", "io_", "dev_", "gs_", "xyz_",
        "app_", "me_", "tv_", "uk_", "be_", "fr_", "de_"
    )
    
    function Test-SuspiciousJarName {
        param([string]$JarName)
        $base = [System.IO.Path]::GetFileNameWithoutExtension($JarName)
        if ($base -match '\d') { return $false }
        foreach ($pfx in $mavenPrefixes) {
            if ($base.ToLower().StartsWith($pfx)) { return $false }
        }
        if ($base.Length -gt 20) { return $false }
        return $true
    }
    
    try {
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        
        $nestedJars = @($zip.Entries | Where-Object { $_.FullName -match "^META-INF/jars/.+\.jar$" })
        $outerClasses = @($zip.Entries | Where-Object { $_.FullName -match "\.class$" })
        
        $suspiciousNestedJars = @()
        foreach ($nj in $nestedJars) {
            $njBase = [System.IO.Path]::GetFileName($nj.FullName)
            if (Test-SuspiciousJarName -JarName $njBase) {
                $suspiciousNestedJars += $njBase
            }
        }
        foreach ($sj in $suspiciousNestedJars) {
            $flags.Add("Suspicious nested JAR: $sj")
        }
        
        if ($nestedJars.Count -eq 1 -and $outerClasses.Count -lt 3) {
            $njName = [System.IO.Path]::GetFileName(($nestedJars | Select-Object -First 1).FullName)
            $flags.Add("Hollow shell mod - only $($outerClasses.Count) class(es), wraps: $njName")
        }
        
        $outerModId = ""
        $fmje = $zip.Entries | Where-Object { $_.FullName -eq "fabric.mod.json" } | Select-Object -First 1
        if ($fmje) {
            try {
                $s = $fmje.Open()
                $r = New-Object System.IO.StreamReader($s)
                $t = $r.ReadToEnd(); $r.Close(); $s.Close()
                if ($t -match '"id"\s*:\s*"([^"]+)"') { $outerModId = $matches[1] }
            } catch {}
        }
        
        $allEntries = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $zip.Entries) { $allEntries.Add($e) }
        
        $innerZips = [System.Collections.Generic.List[object]]::new()
        foreach ($nj in $nestedJars) {
            try {
                $ns = $nj.Open()
                $ms = New-Object System.IO.MemoryStream
                $ns.CopyTo($ms); $ns.Close()
                $ms.Position = 0
                $iz = [System.IO.Compression.ZipArchive]::new($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                $innerZips.Add($iz)
                foreach ($ie in $iz.Entries) { $allEntries.Add($ie) }
            } catch {}
        }
        
        $runtimeExecFound = $false
        $httpDownloadFound = $false
        $httpExfilFound = $false
        $obfuscatedCount = 0
        $numericClassCount = 0
        $unicodeClassCount = 0
        $totalClassCount = 0
        
        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            
            if ($name -match "\.class$") {
                $totalClassCount++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])
                
                if ($className -match "^\d+$") { $numericClassCount++ }
                if ($className -match "[^\x00-\x7F]") { $unicodeClassCount++ }
                
                $segs = ($name -replace "\.class$", "") -split "/"
                $consecutiveSingle = 0
                $maxConsecutive = 0
                foreach ($seg in $segs) {
                    if ($seg.Length -eq 1) {
                        $consecutiveSingle++
                        if ($consecutiveSingle -gt $maxConsecutive) { $maxConsecutive = $consecutiveSingle }
                    } else {
                        $consecutiveSingle = 0
                    }
                }
                if ($maxConsecutive -ge 3) { $obfuscatedCount++ }
                
                try {
                    $st = $entry.Open()
                    $ms2 = New-Object System.IO.MemoryStream
                    $st.CopyTo($ms2)
                    $st.Close()
                    $rawBytes = $ms2.ToArray()
                    $ms2.Dispose()
                    $ct = [System.Text.Encoding]::ASCII.GetString($rawBytes)
                    
                    if ($ct -match "java/lang/Runtime" -and $ct -match "getRuntime" -and $ct -match "exec") {
                        $runtimeExecFound = $true
                    }
                    
                    if ($ct -match "openConnection" -and $ct -match "HttpURLConnection" -and $ct -match "FileOutputStream") {
                        $httpDownloadFound = $true
                    }
                    
                    if ($ct -match "openConnection" -and $ct -match "setDoOutput" -and $ct -match "getOutputStream" -and $ct -match "getProperty") {
                        $httpExfilFound = $true
                    }
                } catch {}
            }
        }
        
        foreach ($iz in $innerZips) { try { $iz.Dispose() } catch {} }
        $zip.Dispose()
        
        $obfPct = if ($totalClassCount -ge 10) { [math]::Round(($obfuscatedCount / $totalClassCount) * 100) } else { 0 }
        $numPct = if ($totalClassCount -ge 5) { [math]::Round(($numericClassCount / $totalClassCount) * 100) } else { 0 }
        $uniPct = if ($totalClassCount -ge 5) { [math]::Round(($unicodeClassCount / $totalClassCount) * 100) } else { 0 }
        
        if ($runtimeExecFound -and $obfPct -ge 25) {
            $flags.Add("Runtime.exec() in obfuscated code - can run OS commands")
        }
        
        if ($httpDownloadFound) {
            $flags.Add("HTTP file download - fetches files from remote server")
        }
        
        if ($httpExfilFound) {
            $flags.Add("HTTP POST exfiltration - sends data to external server")
        }
        
        if ($totalClassCount -ge 10 -and $obfPct -ge 25) {
            $flags.Add("Heavy obfuscation - $obfPct% single-letter paths (a/b/c style)")
        }
        
        if ($numPct -ge 20) {
            $flags.Add("Numeric class names - $numPct% have numeric-only names")
        }
        
        if ($uniPct -ge 10) {
            $flags.Add("Unicode class names - $uniPct% use non-ASCII characters")
        }
        
        # Advanced obfuscator detection
        $obfResults = Test-Obfuscator -FilePath $FilePath
        if ($obfResults.Score -ge 20 -or $obfResults.Detected.Count -gt 0) {
            foreach ($obf in $obfResults.Detected) {
                $flags.Add("OBFUSCATOR: $($obf.Name) [$($obf.Severity)]")
            }
            foreach ($ind in $obfResults.Indicators) {
                $flags.Add("OBFUSCATION ($ind)")
            }
            if ($obfResults.ClassAnalysis.Japanese -gt 0) {
                $flags.Add("JAPANESE CLASS NAMES: $($obfResults.ClassAnalysis.Japanese) classes")
            }
        }
        
        $knownLegitModIds = @(
            "vmp-fabric", "vmp", "lithium", "sodium", "iris", "fabric-api",
            "modmenu", "ferrite-core", "lazydfu", "starlight", "entityculling",
            "memoryleakfix", "krypton", "c2me-fabric", "smoothboot-fabric",
            "immediatelyfast", "noisium", "threadtweak"
        )
        
        $dangerCount = ($flags | Where-Object {
            $_ -match "Runtime\.exec|HTTP file download|HTTP POST|Heavy obfuscation|Suspicious nested"
        }).Count
        
        if ($outerModId -and ($knownLegitModIds -contains $outerModId) -and $dangerCount -gt 0) {
            $flags.Add("FAKE MOD IDENTITY - claims to be '$outerModId' but contains dangerous code!")
        }
        
    } catch {}
    
    return $flags
}

function Get-DownloadSource {
    param([string]$FilePath)
    
    if ([string]::IsNullOrEmpty($FilePath)) { return $null }
    
    $zoneData = Get-Content -Raw -Stream Zone.Identifier $FilePath -ErrorAction SilentlyContinue
    if ($zoneData -match "HostUrl=(.+)") {
        $url = $matches[1].Trim()
        
        if ($url -match "modrinth\.com") { return @{ Source = "Modrinth"; Safe = $true } }
        if ($url -match "curseforge\.com") { return @{ Source = "CurseForge"; Safe = $true } }
        if ($url -match "github\.com") { return @{ Source = "GitHub"; Safe = $true } }
        
        if ($url -match "mediafire\.com") { return @{ Source = "MediaFire"; Safe = $false } }
        if ($url -match "discord\.com|discordapp\.com|cdn\.discordapp\.com") { return @{ Source = "Discord"; Safe = $false } }
        if ($url -match "dropbox\.com") { return @{ Source = "Dropbox"; Safe = $false } }
        if ($url -match "drive\.google\.com") { return @{ Source = "Google Drive"; Safe = $false } }
        if ($url -match "mega\.nz|mega\.co\.nz") { return @{ Source = "MEGA"; Safe = $false } }
        
        if ($url -match "doomsdayclient\.com") { return @{ Source = "DoomsdayClient"; Safe = $false; Cheat = $true } }
        if ($url -match "prestigeclient\.vip") { return @{ Source = "PrestigeClient"; Safe = $false; Cheat = $true } }
        if ($url -match "198macros\.com") { return @{ Source = "198Macros"; Safe = $false; Cheat = $true } }
        if ($url -match "dqrkis\.xyz") { return @{ Source = "Dqrkis"; Safe = $false; Cheat = $true } }
        if ($url -match "vape\.gg") { return @{ Source = "Vape"; Safe = $false; Cheat = $true } }
        if ($url -match "intent\.store") { return @{ Source = "Intent.Store"; Safe = $false; Cheat = $true } }
        if ($url -match "anydesk\.com") { return @{ Source = "AnyDesk"; Safe = $false; Cheat = $true } }
        # Nova Client & Additional Cheat Sites
        if ($url -match "novaclient\.lol|novaclient\.com") { return @{ Source = "NovaClient"; Safe = $false; Cheat = $true } }
        if ($url -match "rise\.today|riseclient\.com") { return @{ Source = "RiseClient"; Safe = $false; Cheat = $true } }
        if ($url -match "novoline\.wtf") { return @{ Source = "Novoline"; Safe = $false; Cheat = $true } }
        if ($url -match "astolfo\.lgbt") { return @{ Source = "Astolfo"; Safe = $false; Cheat = $true } }
        if ($url -match "pandaware\.wtf") { return @{ Source = "Pandaware"; Safe = $false; Cheat = $true } }
        if ($url -match "drip\.ac") { return @{ Source = "DripClient"; Safe = $false; Cheat = $true } }
        if ($url -match "exhibition\.org") { return @{ Source = "Exhibition"; Safe = $false; Cheat = $true } }
        
        if ($url -match "https?://(?:www\.)?([^/]+)") { 
            return @{ Source = $matches[1]; Safe = $false }
        }
        return @{ Source = $url; Safe = $false }
    }
    return $null
}

# === CHEAT SIGNATURE DATABASE (450+) ===
$script:CheatStrings = @(
    # Combat Cheats - Aura & Aim
    "KillAura", "ClickAura", "TriggerBot", "MultiAura", "ForceField", "SilentAura",
    "AimAssist", "AimBot", "AutoAim", "SilentAim", "AimLock", "LegitAura", "LegitAim",
    "CrystalAura", "AutoCrystal", "CrystalOptimize", "CEV", "CEVBreaker", "CrystalPlacer",
    "AnchorAura", "AutoAnchor", "AnchorTweaks", "BedAura", "AutoBed", "BedFucker",
    "BowAimbot", "BowSpam", "AutoBow", "ArrowDodge", "Quiver", "FastBow",
    "Criticals", "AutoCrit", "CritBypass", "Reach", "HitBox", "Hitboxes", "HitboxExpand",
    "AutoWeapon", "AutoSword", "AutoCity", "Burrow", "SelfTrap", "AutoTrap",
    "Surround", "HoleFiller", "AutoWeb", "AntiSurround", "AntiBurrow", "HoleSnap",
    "AntiAnvil", "AntiBed", "AntiAim", "AntiBot", "AutoLog", "AntiCrystal",
    "AutoTotem", "TotemPopCounter", "OffhandTotem", "LegitTotem", "HoverTotem", "InventoryTotem",
    "AutoGapple", "AutoGap", "AutoMend", "AutoTool", "SwordBlock", "Offhand",
    "AutoHitCrystal", "AutoDoubleHand", "ShieldBreaker", "ShieldDisabler", "AxeSwap",
    "JumpReset", "SprintReset", "AxeSpam", "MaceSwap", "StunSlam", "Donut", "DoubleClick",
    
    # Movement Cheats
    "Flight", "Fly", "FlyHack", "CreativeFlight", "BoatFly", "Jetpack", "AirJump",
    "NoFall", "Spider", "SpiderHack", "Step", "StepHack", "FastClimb", "WallClimb",
    "Jesus", "WaterWalk", "NoSlow", "NoSlowdown", "NoWeb", "NoClip", "PhaseFly",
    "Speed", "SpeedHack", "BHop", "BunnyHop", "Strafe", "Speed Mine", "GroundSpeed",
    "Velocity", "AntiKB", "NoKnockback", "Grim Velocity", "GrimDisabler", "Antiknockback",
    "Glide", "GlideHack", "Elytra", "ExtraElytra", "ElytraFly", "ElytraSwap", "FireworkFly",
    "Scaffold", "ScaffoldWalk", "FastBridge", "Tower", "BuildHelper", "Telly", "TellyBridge",
    "SafeWalk", "Parkour", "AntiHunger", "FastLadder", "BonemealAura", "NoJumpDelay",
    "LongJump", "HighJump", "AutoJump", "Strafe", "AirStrafe", "IceSpeed",
    
    # Visual Cheats
    "ESP", "PlayerESP", "MobESP", "ItemESP", "StorageESP", "ChestESP", "BlockESP",
    "Tracers", "Nametags", "NameTagsHack", "Chams", "MobSpawnESP", "HoleESP",
    "Xray", "XRayHack", "OreFinder", "CaveFinder", "Freecam", "FreeLook",
    "FullBright", "NightVision", "NoFog", "NoRender", "NoWeather", "Gamma",
    "NewChunks", "LightLevelOverlay", "TunnelFinder", "Trajectories", "LogoutSpot",
    "HealthTags", "ArmorHUD", "PotionHUD", "NameProtect", "StreamerMode",
    
    # Inventory & Automation
    "AutoArmor", "ChestStealer", "InvManager", "InventoryManager", "ChestSteal",
    "AutoPot", "AutoPotion", "AutoEat", "AutoSprint", "Sneak", "Refill", "AutoStore",
    "FakePlayer", "Blink", "NoRotation", "SilentRotation", "FastXP", "FastExp",
    "AntiAFK", "AutoRespawn", "DeathCoords", "PotionSaver", "AutoFirework",
    "FakeInv", "FakeLag", "FakeNick", "FakeItem", "PopSwitch", "LagReach",
    
    # Network & Packet Manipulation
    "PingSpoof", "FakeLatency", "FakePing", "Timer", "TimerHack", "PackSpoof",
    "PacketFly", "PacketMine", "Ghost", "GhostHand", "ReachHack", "PacketCancel",
    "BackTrack", "SilentClose", "Exploits", "ServerCrasher", "ChatSpam", "Crasher",
    "AntiVanish", "StaffAlert", "PortalGui", "PearlClip", "BoatClip", "EntityClip",
    "Phase", "VClip", "HClip", "EntityControl", "AutoMount", "AutoClicker",
    "Disabler", "AntiCheat", "GrimBypass", "VulcanBypass", "MatrixBypass", "ACDisabler",
    "TickShift", "TickTimer", "NoPacket", "PacketMod", "PacketSpeed",
    
    # Client UI
    "SelfDestruct", "Panic", "HideClient", "ClickGUI", "TabGUI", "HUDEditor",
    "ModuleList", "ArrayList", "Watermark", "Keybinds", "ModuleManager",
    
    # World Interaction
    "invsee", "ItemExploit", "AuthBypass", "LicenseCheckMixin", "obfuscatedAuth",
    "Nuker", "NukerLegit", "FastBreak", "InstantBreak", "AutoMine", "SpeedMine",
    "AutoFarm", "AutoFish", "Baritone", "PathFinder", "AutoWalk", "AutoPath",
    "AutoBuild", "InstaBuild", "BuildRandom", "TemplateTool", "Schematica",
    "AutoSign", "FastPlace", "PlaceAssist", "AirPlace", "AirAnchor", "InstantPlace",
    "AutoDisconnect", "AutoReconnect", "AutoCommand", "MacroSystem", "AutoTPA",
    
    # Known Cheat Clients
    "vape.gg", "vape v4", "vapeclient", "intent.store", "rise6", "riseClient",
    "novoline", "exhibition", "meteor-client", "meteorclient", "meteordev",
    "wurst", "wurstclient", "aristois", "impact", "impactclient",
    "liquidbounce", "fdp-client", "fdpclient", "azura", "drip", "dripClient",
    "entropy", "pandaware", "skilled", "moon", "moonClient", "astolfo",
    "future", "futureClient", "konas", "rusherhack", "inertia", "sigma",
    "cheatbreaker", "badlion bypass", "hacked client", "cheathub",
    "ghostclient", "ghost.jar", "vapeV4", "vapeV3", "vapeLite", "vape lite",
    "autoclicker", "double clicker", "jitter click", "butterfly click",
    "Asteria", "Prestige", "Xenon", "Argon", "Hellion", "hellion", "Virgin",
    "Dqrkis Client", "dev.krypton", "dev.gambleclient", "catlean", "gypsy",
    "WalksyOptimizer", "WalskyOptimizer", "WalksyCrystalOptimizerMod", "LWFH Crystal",
    "KeyPearl", "LootYeeter", "AutoBreach", "zeroday", "tenacity", "hanabi",
    "antic", "antic.ac", "remix", "remix client", "ares", "ares client",
    "phobos", "phobosplus", "salhack", "pyro", "pyroclient", "lambda",
    "gamesense", "gsplusplus", "gs++", "trollhack", "abyss", "abyssclient",
    "cosmos", "cosmosclient", "oyvey", "zerohack", "thunder", "thunderhack",
    "faxhax", "faxclient", "1.9hax", "guardian", "guardianplus",
    "opfern", "lavaHack", "lavaclient", "postman", "postmanclient",
    "bleach", "bleachhack", "cringehack", "horion", "horionclient",
    
    # Anti-Detection / SS-Bypass
    "HideCommands", "NoCommandBlock", "AntiFabricSequence",
    "AntiPacketKick", "NoServerCheck", "FakeWorld", "SpoofRotation",
    "SessionStealer", "CookieStealer", "Ratted", "TokenLogger",
    "AntiSS", "AntiScreenShare", "HideProcess", "FakeProcess",
    "RegistryCleaner", "TraceCleaner", "LogCleaner", "HideMods",
    
    # Package Signatures
    "net.wurstclient", "meteordevelopment.orbit", "meteordevelopment.meteorclient",
    "cc.novoline", "de.lifeofgaming", "wtf.moonlight", "com.alan.clients",
    "com.cheatbreaker", "net.ccbluex", "me.zeroeightsix.kami",
    "club.maxstats", "today.opai", "com.moonsworth", "org.spongepowered.asm.mixin",
    "org.chainlibs.module.impl.modules", "xyz.greaj", "phantom-refmap.json",
    "imgui", "imgui.gl3", "imgui.glfw", "jnativehook",
    "net.minecraft.client.mixin", "gg.essential.cosmetics",
    "com.github.lunatrius", "baritone.", "io.github.impactdevelopment",
    "club.minnced", "me.earth.phobos", "net.futureclient",
    
    # Mixin & Accessor Patterns
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown",
    "onBlockBreaking", "setItemUseCooldown", "setSelectedSlot",
    "invokeDoAttack", "invokeDoItemUse", "invokeOnMouseButton",
    "onTickMovement", "onPushOutOfBlocks", "onIsGlowing",
    "ClientPlayerInteractionManagerAccessor", "ClientPlayerEntityMixim",
    "MinecraftClientAccessor", "PlayerEntityAccessor", "LivingEntityAccessor",
    "WorldAccessor", "ChunkAccessor", "RenderAccessor", "ClientPlayNetworkHandlerAccessor",
    "invokeAttack", "invokeInteract", "invokeSendPacket", "invokeUpdatePosition",
    
    # PvP Modules
    "W-Tap", "WTap", "AutoW", "Combo", "AimCorrect", "TargetStrafe",
    "AutoGap", "Regen", "AutoPearl", "PearlPredict", "AutoEagle",
    "TargetHUD", "CPSDisplay", "ReachDisplay", "HitParticles", "TotemHit",
    "AntiMissClick", "Wtap", "DoubleAnchor", "SafeAnchor", "AutoPot32k",
    "32kKillAura", "32kAura", "TotemSpoof", "PopCounter",
    
    # Anarchy & 2b2t Modules
    "AutoHighway", "HighwayBuilder", "ElytraHighway", "MapDownloader",
    "CoordExploit", "BookBot", "ChunkLogger", "ChunkBan", "NewerNewChunks",
    "StashFinder", "TrailFinder", "BaseFinder", "EntityLogger", "ChunkDupe",
    "DonkeyDupe", "ItemDupe", "InventoryDupe", "BookDupe", "SignDupe",
    "AutoDupe", "DupeAlert", "BedrockBreaker", "BedrockClip",
    
    # Nova Client & SS-Tool Patterns
    "novaclient", "nova client", "nova.client", "api.novaclient.lol",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "addFri", "antiAttack", "/assets/font/font.ttf",
    "Lithium is not initialized! Skipping event:",
    "Error in hash", "argon client", "argonclient",
    "Auto Crystal", "Auto Anchor", "Auto Loot Yeeter",
    "CwCrystal.class", "ADH.class", "ModuleManager.class",
    
    # Advanced Patterns
    "obf_module", "cheat_module", "hack_module", "bypass_module",
    "antidetect", "bypassdetect", "evadedetect", "hidedetect",
    "ClickTotem", "PopLag", "BedBomb", "AnchorBomb", "CrystalBomb",
    "AutoPlacer", "AutoBreaker", "SmartHole", "SmartSurround",
    "FeetPlace", "AutoObsidian", "ObsidianPlacer", "WebFill",
    "HoleMiner", "SelfFill", "AutoTunneler", "AutoEscape"
)

# === OBFUSCATOR SIGNATURES ===
$script:ObfuscatorPatterns = @(
    # Common Obfuscators
    "ZKMFLOW", "com/zelix", "ZelixKlassMaster", "ZKM",
    "allatori", "ALLATORIxDEMO", "com/allatori",
    "proguard", "ProGuard", "-KSMD-",
    "skidfuscator", "Skidfuscator", "skid",
    "paramorphism", "Paramorphism",
    "itzsomebody/radon", "Radon Obfuscator",
    "StringerJavaObfuscator", "com/licel/stringer",
    "branchlock", "Branchlock",
    "dasho", "DashO", "com/dashingTech",
    "caesium", "Caesium",
    "yguard", "YGuard",
    "javaguard", "JavaGuard",
    "klassmaster", "Klassmaster",
    "dexguard", "DexGuard",
    "iprotect", "iProtect",
    "scuti", "ScutiObf",
    "superblaubeere", "sb27",
    "Obzcure", "obzcure",
    "smoke", "SmokeObf",
    "JNIC", "jnic"
)

$script:BypassMods = @()
$script:JvmFlags = @()

$script:LegitModSlugs = @(
    # Performance Mods
    "lithium", "sodium", "phosphor", "starlight", "indium", "iris",
    "optifine", "optifabric", "fabric-api", "modmenu", "cloth-config",
    "ferritecore", "krypton", "c2me", "lazydfu", "dashloader",
    "enhanced-block-entities", "memory-leak-fix", "smoothboot",
    "chunk-pregenerator", "dynamic-fps", "entityculling", "noisium",
    "immediatelyfast", "modernfix", "exordium", "ksyxis", "debugify",
    "badpackets", "threadtweak", "fastload", "fastanim", "fast-ip-ping",
    
    # Architecture & Libraries
    "architectury-api", "completeconfig", "iceberg", "quilted-fabric-api",
    "fabric-language-kotlin", "geckolib", "playeranimator", "midnightlib",
    "forge-config-api-port", "cardinal-components-api", "trinkets", "patchouli",
    
    # Utility Mods
    "replaymod", "simple-voice-chat", "voicechat", "worldedit", "litematica",
    "minihud", "tweakeroo", "itemscroller", "malilib", "ok-zoomer",
    "logical-zoom", "zoomify", "better-third-person", "mouse-wheelie",
    "spark", "carpet", "worldgen-debug", "carpet-extra", "carpet-tis-addition",
    "mod-loading-screen", "not-enough-crashes", "cullleaves", "cull-less-leaves",
    
    # Recipe & Inventory
    "emi", "jei", "rei", "roughly-enough-items", "waila", "jade", "hwyla",
    "inventory-hud", "shulkerbox-tooltip", "appleskin", "controlling",
    "search-plus", "inventory-profiles-next", "travelerstitles", "toast-control",
    
    # Maps & Navigation
    "xaeros-minimap", "xaeros-world-map", "journeymap", "voxelmap", "map-tooltip",
    "ftb-chunks", "bluemap", "dynmap", "pl3xmap",
    
    # Quality of Life
    "better-ping-display", "blur", "cleancut", "continuity", "effective",
    "falling-leaves", "lamb-dynamic-lights", "no-chat-reports", "presence-footsteps",
    "visuality", "waveycapes", "capes", "cosmetic-armor-reworked", "custom-player-models",
    "sodium-extra", "reeses-sodium-options", "puzzle", "animatica",
    
    # Gameplay
    "create", "mekanism", "applied-energistics-2", "botania", "thermal-expansion",
    "the-twilight-forest", "terralith", "waystones", "farmers-delight",
    "origins", "pehkui", "better-combat", "playerex", "levelz",
    
    # Building & Decoration
    "chisel-and-bits", "macaws-furniture", "decorative-blocks", "supplementaries",
    "adorn", "another-furniture", "building-wands", "effortless-building"
)

$script:VerifiedMods = @()
$script:UnknownMods = @()
$script:CheatMods = @()

function Get-SHA1Hash {
    param([string]$FilePath)
    return (Get-FileHash -Path $FilePath -Algorithm SHA1).Hash
}

function Get-ZoneIdentifier {
    param([string]$FilePath)
    try {
        $ads = Get-Content -Raw -Stream Zone.Identifier $FilePath -ErrorAction SilentlyContinue
        if ($ads -match "HostUrl=(.+)") {
            return $matches[1].Trim()
        }
        if ($ads -match "ZoneId=(\d)") {
            $zone = $matches[1]
            $zoneNames = @{
                "0" = "Local Machine"
                "1" = "Local Intranet"
                "2" = "Trusted Sites"
                "3" = "Internet"
                "4" = "Restricted Sites"
            }
            return "Zone: $($zoneNames[$zone])"
        }
    } catch {}
    return $null
}

function Test-ModrinthHash {
    param([string]$Hash)
    try {
        $response = Invoke-RestMethod -Uri "$($script:Config.ModrinthAPI)/version_file/$Hash" -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
        if ($response.project_id) {
            $projectData = Invoke-RestMethod -Uri "$($script:Config.ModrinthAPI)/project/$($response.project_id)" -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
            return @{
                Name = $projectData.title
                Slug = $projectData.slug
                Source = "Modrinth"
                URL = "https://modrinth.com/mod/$($projectData.slug)"
            }
        }
    } catch {}
    return $null
}

function Test-MegabaseHash {
    param([string]$Hash)
    try {
        $response = Invoke-RestMethod -Uri "$($script:Config.MegabaseAPI)?hash=$Hash" -Method Get -UseBasicParsing -ErrorAction Stop -TimeoutSec 10
        if (-not $response.error -and $response.data) {
            return @{
                Name = $response.data.name
                Slug = $response.data.slug
                Source = "Megabase"
            }
        }
    } catch {}
    return $null
}

function Test-CheatStrings {
    param([string]$FilePath)
    
    $found = [System.Collections.Generic.HashSet[string]]::new()
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $content = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        foreach ($cheatString in $script:CheatStrings) {
            if ($content -match [regex]::Escape($cheatString)) {
                $found.Add($cheatString) | Out-Null
            }
        }
        
        $suspiciousPackages = @(
            "net/wurstclient", "meteordevelopment", "cc/novoline",
            "com/alan/clients", "club/maxstats", "wtf/moonlight",
            "me/zeroeightsix/kami", "net/ccbluex", "today/opai",
            "de/florianmichael/viafabricplus", "net/minecraft/injection"
        )
        
        foreach ($pkg in $suspiciousPackages) {
            if ($content -match [regex]::Escape($pkg)) {
                $found.Add("PKG:$pkg") | Out-Null
            }
        }
    } catch {}
    
    return $found
}

function Test-SuspiciousManifest {
    param([string]$JarPath)
    
    $suspicious = @()
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.ToLower()
            
            if ($name -match "killaura|aimbot|cheat|hack|inject|bypass|freecam|xray|velocity|noclip") {
                $suspicious += $entry.FullName
            }
            
            if ($name -match "mixin.*player|mixin.*entity|mixin.*network|mixin.*render") {
            }
        }
        
        $archive.Dispose()
    } catch {}
    
    return $suspicious
}

# === ADVANCED OBFUSCATION DETECTION ===
function Get-StringEntropy {
    param([string]$InputString)
    
    if ([string]::IsNullOrEmpty($InputString)) { return 0 }
    
    $charCounts = @{}
    foreach ($char in $InputString.ToCharArray()) {
        if ($charCounts.ContainsKey($char)) {
            $charCounts[$char]++
        } else {
            $charCounts[$char] = 1
        }
    }
    
    $entropy = 0.0
    $length = $InputString.Length
    
    foreach ($count in $charCounts.Values) {
        $probability = $count / $length
        if ($probability -gt 0) {
            $entropy -= $probability * [math]::Log($probability, 2)
        }
    }
    
    return $entropy
}

function Test-Obfuscator {
    param([string]$FilePath)
    
    $results = @{
        Detected = @()
        Score = 0
        Indicators = @()
        ClassAnalysis = @{
            Total = 0
            Numeric = 0
            Unicode = 0
            SingleLetter = 0
            Japanese = 0
            VeryShort = 0
        }
        RiskLevel = "CLEAN"
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        
        $allEntries = @($archive.Entries)
        $contentSamples = @()
        
        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            
            if ($name -match "\.class$") {
                $results.ClassAnalysis.Total++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])
                
                # Class name pattern detection
                if ($className -match "^[\d]+$") { $results.ClassAnalysis.Numeric++ }
                if ($className -match "^[a-zA-Z]$") { $results.ClassAnalysis.SingleLetter++ }
                if ($className.Length -le 2) { $results.ClassAnalysis.VeryShort++ }
                if ($className -match "[\u3040-\u309F\u30A0-\u30FF]") { $results.ClassAnalysis.Japanese++ }
                if ($className -match "[^\x00-\x7F]") { $results.ClassAnalysis.Unicode++ }
                
                # Sample content
                if ($contentSamples.Count -lt 15 -and $entry.Length -lt 50000 -and $entry.Length -gt 100) {
                    try {
                        $stream = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $stream.CopyTo($ms)
                        $stream.Close()
                        $contentSamples += [System.Text.Encoding]::ASCII.GetString($ms.ToArray())
                        $ms.Dispose()
                    } catch {}
                }
            }
        }
        
        $archive.Dispose()
        
        # Calculate scores
        $total = [math]::Max(1, $results.ClassAnalysis.Total)
        $score = 0
        
        $numericPct = [math]::Round(($results.ClassAnalysis.Numeric / $total) * 100, 1)
        $unicodePct = [math]::Round(($results.ClassAnalysis.Unicode / $total) * 100, 1)
        $japanesePct = [math]::Round(($results.ClassAnalysis.Japanese / $total) * 100, 1)
        $singleLetterPct = [math]::Round(($results.ClassAnalysis.SingleLetter / $total) * 100, 1)
        $shortPct = [math]::Round(($results.ClassAnalysis.VeryShort / $total) * 100, 1)
        
        if ($numericPct -gt 30) { 
            $results.Indicators += "NUMERIC: $numericPct%"
            $score += 20
        }
        if ($unicodePct -gt 5) { 
            $results.Indicators += "UNICODE: $unicodePct%"
            $score += 25
        }
        if ($japanesePct -gt 0) { 
            $results.Indicators += "JAPANESE: $japanesePct%"
            $score += 30
        }
        if ($singleLetterPct -gt 30) { 
            $results.Indicators += "SINGLE-LETTER: $singleLetterPct%"
            $score += 15
        }
        if ($shortPct -gt 40) { 
            $results.Indicators += "SHORT NAMES: $shortPct%"
            $score += 10
        }
        
        # Check for known obfuscators
        $allContent = $contentSamples -join " "
        
        $knownObfuscators = @{
            "ZKM" = @("ZKMFLOW", "com/zelix", "ZelixKlassMaster")
            "Allatori" = @("allatori", "ALLATORIxDEMO", "com/allatori")
            "ProGuard" = @("proguard", "ProGuard", "-KSMD-")
            "Skidfuscator" = @("skidfuscator", "Skidfuscator", "skid")
            "Paramorphism" = @("paramorphism", "Paramorphism")
            "Radon" = @("itzsomebody/radon", "Radon Obfuscator")
            "Stringer" = @("StringerJavaObfuscator", "com/licel/stringer")
            "Branchlock" = @("branchlock", "Branchlock")
            "DashO" = @("dasho", "DashO", "com/dashingTech")
            "Caesium" = @("caesium", "Caesium")
            "YGuard" = @("yguard", "YGuard")
            "JavaGuard" = @("javaguard", "JavaGuard")
            "Klassmaster" = @("klassmaster", "Klassmaster")
            "DexGuard" = @("dexguard", "DexGuard")
            "iProtect" = @("iprotect", "iProtect")
            "Scuti" = @("scuti", "ScutiObf")
            "sb27" = @("superblaubeere", "sb27")
            "Obzcure" = @("Obzcure", "obzcure")
            "SmokeObf" = @("smoke", "SmokeObf")
            "JNIC" = @("JNIC", "jnic")
            "Native" = @("native_encrypt", "native_obf", "jni_obf")
        }
        
        foreach ($obfName in $knownObfuscators.Keys) {
            foreach ($pattern in $knownObfuscators[$obfName]) {
                if ($allContent -match [regex]::Escape($pattern)) {
                    $results.Detected += @{ Name = $obfName; Severity = "HIGH" }
                    $score += 25
                    break
                }
            }
        }
        
        # Base64/encrypted strings
        $base64Count = ([regex]::Matches($allContent, '[A-Za-z0-9+/]{30,}={0,2}')).Count
        if ($base64Count -gt 15) {
            $results.Indicators += "BASE64: $base64Count strings"
            $score += 15
        }
        
        $results.Score = [math]::Min(100, $score)
        
        if ($results.Score -ge 60) {
            $results.RiskLevel = "CRITICAL"
        } elseif ($results.Score -ge 40) {
            $results.RiskLevel = "HIGH"
        } elseif ($results.Score -ge 20) {
            $results.RiskLevel = "MEDIUM"
        } elseif ($results.Score -ge 10) {
            $results.RiskLevel = "LOW"
        }
        
        if ($results.Score -gt 30 -and $results.Detected.Count -eq 0) {
            $results.Detected += @{ Name = "Unknown Obfuscator"; Severity = $results.RiskLevel }
        }
        
    } catch {
        Write-Verbose "Error in obfuscator check: $_"
    }
    
    return $results
}

function Analyze-ModsFolder {
    param([string]$ModsPath)
    
    Write-Section "Mod Integrity Analysis" "MOD"
    
    if (-not (Test-Path $ModsPath -PathType Container)) {
        Write-Result "FAIL" "Mods folder not found" $ModsPath
        return
    }
    
    $jarFiles = Get-ChildItem -Path $ModsPath -Filter "*.jar" -ErrorAction SilentlyContinue
    
    if ($jarFiles.Count -eq 0) {
        Write-Result "INFO" "No JAR files found in mods folder"
        return
    }
    
    Write-Result "INFO" "Found $($jarFiles.Count) mod(s) to analyze"
    Write-Host ""
    
    $counter = 0
    $total = $jarFiles.Count
    
    foreach ($file in $jarFiles) {
        $counter++
        Write-ProgressBar -Current $counter -Total $total -Activity $file.Name
        
        $hash = Get-SHA1Hash -FilePath $file.FullName
        
        $modrinthResult = Test-ModrinthHash -Hash $hash
        if ($modrinthResult) {
            $script:VerifiedMods += @{
                FileName = $file.Name
                ModName = $modrinthResult.Name
                Source = $modrinthResult.Source
                URL = $modrinthResult.URL
            }
            continue
        }
        
        $megabaseResult = Test-MegabaseHash -Hash $hash
        if ($megabaseResult) {
            $script:VerifiedMods += @{
                FileName = $file.Name
                ModName = $megabaseResult.Name
                Source = $megabaseResult.Source
            }
            continue
        }
        
        $cheatStringsFound = Test-CheatStrings -FilePath $file.FullName
        if ($cheatStringsFound.Count -gt 0) {
            $script:CheatMods += @{
                FileName = $file.Name
                FilePath = $file.FullName
                StringsFound = $cheatStringsFound
                InDependency = $false
            }
            continue
        }
        
        $downloadSource = Get-DownloadSource -FilePath $file.FullName
        
        if ($downloadSource -and $downloadSource.IsCheatSite) {
            $script:CheatMods += @{
                FileName = $file.Name
                FilePath = $file.FullName
                StringsFound = @("Downloaded from cheat site: $($downloadSource.URL)")
                InDependency = $false
            }
            continue
        }
        
        $script:UnknownMods += @{
            FileName = $file.Name
            FilePath = $file.FullName
            ZoneId = if ($downloadSource) { $downloadSource.URL } else { $null }
            Hash = $hash
        }
    }
    
    if ($script:UnknownMods.Count -gt 0) {
        Write-Host "`r$(' ' * 80)`r" -NoNewline
        Write-Host ""
        Write-Result "INFO" "Deep scanning $($script:UnknownMods.Count) unknown mod(s) for hidden cheats..."
        
        $tempDir = Join-Path $env:TEMP "YumikoModAnalyzer_$(Get-Random)"
        
        try {
            New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            
            $toRemove = @()
            
            foreach ($mod in $script:UnknownMods) {
                try {
                    $extractPath = Join-Path $tempDir ([System.IO.Path]::GetFileNameWithoutExtension($mod.FileName))
                    [System.IO.Compression.ZipFile]::ExtractToDirectory($mod.FilePath, $extractPath)
                    
                    $depJarsPath = Join-Path $extractPath "META-INF\jars"
                    if (Test-Path $depJarsPath) {
                        $depJars = Get-ChildItem -Path $depJarsPath -Filter "*.jar" -ErrorAction SilentlyContinue
                        foreach ($depJar in $depJars) {
                            $depStrings = Test-CheatStrings -FilePath $depJar.FullName
                            if ($depStrings.Count -gt 0) {
                                $script:CheatMods += @{
                                    FileName = $mod.FileName
                                    FilePath = $mod.FilePath
                                    DependencyName = $depJar.Name
                                    StringsFound = $depStrings
                                    InDependency = $true
                                }
                                $toRemove += $mod
                                break
                            }
                        }
                    }
                } catch {}
            }
            
            $script:UnknownMods = @($script:UnknownMods | Where-Object { $_ -notin $toRemove })
            
        } catch {
            Write-Result "WARN" "Error during deep scan" $_.Exception.Message
        } finally {
            if (Test-Path $tempDir) {
                Remove-Item -Recurse -Force $tempDir -ErrorAction SilentlyContinue
            }
        }
    }
    
    if ($script:UnknownMods.Count -gt 0) {
        Write-Host "`r$(' ' * 80)`r" -NoNewline
        Write-Result "INFO" "Running advanced bypass scan on $($script:UnknownMods.Count) mod(s)..."
        
        $toMoveToCheat = @()
        foreach ($mod in $script:UnknownMods) {
            $bypassResult = Invoke-BypassScan -JarPath $mod.FilePath
            if ($bypassResult -and ($bypassResult.IsCheat -or $bypassResult.ObfuscationPercent -gt 50)) {
                $reasons = @()
                if ($bypassResult.IsHollowShell) { $reasons += "Hollow Shell Mod" }
                if ($bypassResult.HasRuntimeExec) { $reasons += "Runtime.exec() detected" }
                if ($bypassResult.HasHttpExfil) { $reasons += "HTTP exfiltration" }
                if ($bypassResult.ObfuscationPercent -gt 50) { $reasons += "Obfuscated ($($bypassResult.ObfuscationPercent)%)" }
                if ($bypassResult.CheatStrings.Count -gt 0) { $reasons += "Cheat: $($bypassResult.CheatStrings -join ', ')" }
                
                $script:CheatMods += @{
                    FileName = $mod.FileName
                    FilePath = $mod.FilePath
                    StringsFound = $reasons
                    InDependency = $false
                    BypassFlags = $bypassResult
                }
                $script:BypassMods += $bypassResult
                $toMoveToCheat += $mod
            }
        }
        $script:UnknownMods = @($script:UnknownMods | Where-Object { $_ -notin $toMoveToCheat })
    }
    
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    
    if ($script:VerifiedMods.Count -gt 0) {
        Write-Host ""
        Write-Host "  [+] " -NoNewline -ForegroundColor $script:Colors.Success
        Write-Host "VERIFIED MODS ($($script:VerifiedMods.Count))" -ForegroundColor $script:Colors.Success
        Write-Host "  ----------------------------------------------------" -ForegroundColor $script:Colors.Dim
        foreach ($mod in $script:VerifiedMods) {
            Write-Host "    [+] " -NoNewline -ForegroundColor $script:Colors.Success
            Write-Host ("{0,-35}" -f $mod.ModName) -NoNewline -ForegroundColor $script:Colors.Info
            Write-Host " $($mod.FileName)" -ForegroundColor $script:Colors.Dim
        }
    }
    
    if ($script:UnknownMods.Count -gt 0) {
        Write-Host ""
        Write-Host "  [?] " -NoNewline -ForegroundColor $script:Colors.Warning
        Write-Host "UNKNOWN MODS ($($script:UnknownMods.Count))" -ForegroundColor $script:Colors.Warning
        Write-Host "  ----------------------------------------------------" -ForegroundColor $script:Colors.Dim
        foreach ($mod in $script:UnknownMods) {
            Write-Host "    [?] " -NoNewline -ForegroundColor $script:Colors.Warning
            Write-Host $mod.FileName -NoNewline -ForegroundColor $script:Colors.Info
            if ($mod.ZoneId) {
                Write-Host " -> " -NoNewline -ForegroundColor $script:Colors.Dim
                Write-Host $mod.ZoneId -ForegroundColor $script:Colors.Dim
            } else {
                Write-Host ""
            }
        }
    }
    
    if ($script:CheatMods.Count -gt 0) {
        Write-Host ""
        Write-Host "  [X] " -NoNewline -ForegroundColor $script:Colors.Error
        Write-Host "CHEAT MODS DETECTED ($($script:CheatMods.Count))" -ForegroundColor $script:Colors.Error
        Write-Host "  ====================================================" -ForegroundColor $script:Colors.Error
        foreach ($mod in $script:CheatMods) {
            Write-Host "    [X] " -NoNewline -ForegroundColor $script:Colors.Error
            Write-Host $mod.FileName -ForegroundColor $script:Colors.Error
            if ($mod.InDependency -and $mod.DependencyName) {
                Write-Host "        Hidden in: " -NoNewline -ForegroundColor $script:Colors.Dim
                Write-Host $mod.DependencyName -ForegroundColor $script:Colors.Error
            }
        }
        Write-Host ""
        Write-Host "  [i] " -NoNewline -ForegroundColor $script:Colors.Accent
        Write-Host "Upgrade to PAID version to see detected cheat strings" -ForegroundColor $script:Colors.Dim
    }
}

function Get-MinecraftUptime {
    Write-Section "Minecraft Process Status" "MC"
    
    $process = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $process) {
        $process = Get-Process java -ErrorAction SilentlyContinue
    }
    
    if ($process) {
        try {
            $startTime = $process.StartTime
            $elapsed = (Get-Date) - $startTime
            Write-Result "INFO" "$($process.Name) (PID: $($process.Id))" "Running for $($elapsed.Hours)h $($elapsed.Minutes)m $($elapsed.Seconds)s"
            Write-Result "INFO" "Started at" $startTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Result "INFO" "Memory Usage" "$([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
        } catch {
            Write-Result "INFO" "Minecraft process found" "PID: $($process.Id)"
        }
    } else {
        Write-Result "WARN" "No Minecraft process detected"
    }
}

function Remove-SystemFindings {
    param([array]$Findings)
    
    Write-Section "Remediation" "FIX"
    
    foreach ($finding in $Findings) {
        switch ($finding.Type) {
            "Hosts" {
                Write-Result "INFO" "Would remove hosts entry" $finding.Line
            }
            "Registry" {
                try {
                    $pathParts = $finding.Path -split "\\"
                    $valueName = $pathParts[-1]
                    $keyPath = ($pathParts[0..($pathParts.Length-2)] -join "\")
                    Remove-ItemProperty -Path $keyPath -Name $valueName -ErrorAction Stop
                    Write-Result "PASS" "Removed" $finding.Description
                } catch {
                    Write-Result "FAIL" "Could not remove" "$($finding.Description): $($_.Exception.Message)"
                }
            }
            "IFEO" {
                try {
                    Remove-ItemProperty -Path $finding.Path -Name "Debugger" -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path $finding.Path -Name "GlobalFlag" -ErrorAction SilentlyContinue
                    Write-Result "PASS" "Removed IFEO entry" $finding.Path
                } catch {
                    Write-Result "FAIL" "Could not remove IFEO" $_.Exception.Message
                }
            }
            default {
                Write-Result "INFO" "Manual fix required" $finding.Description
            }
        }
    }
}

function Show-Menu {
    Write-Host ""
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor $script:Colors.Dim
    Write-Host "  |" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host "           YUMIKO MOD ANALYZER - FREE              " -NoNewline -ForegroundColor $script:Colors.Secondary
    Write-Host "|" -ForegroundColor $script:Colors.Dim
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor $script:Colors.Dim
    Write-Host "  |" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host "  [1] " -NoNewline -ForegroundColor $script:Colors.Primary
    Write-Host "Mod Analysis                                 " -NoNewline -ForegroundColor $script:Colors.Info
    Write-Host "|" -ForegroundColor $script:Colors.Dim
    Write-Host "  |" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host "  [2] " -NoNewline -ForegroundColor $script:Colors.Primary
    Write-Host "Exit                                         " -NoNewline -ForegroundColor $script:Colors.Info
    Write-Host "|" -ForegroundColor $script:Colors.Dim
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor $script:Colors.Dim
    Write-Host "  |" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host "  Upgrade to PAID for System Analysis + Details     " -NoNewline -ForegroundColor $script:Colors.Warning
    Write-Host "|" -ForegroundColor $script:Colors.Dim
    Write-Host "  +-----------------------------------------------------+" -ForegroundColor $script:Colors.Dim
    Write-Host ""
    Write-Host "  Enter choice: " -NoNewline -ForegroundColor $script:Colors.Secondary
    return Read-Host
}

function Run-SystemAnalysis {
    Write-Host ""
    Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
    Write-Host "            S Y S T E M   A N A L Y S I S" -ForegroundColor $script:Colors.Primary
    Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
    
    Check-HostsFileManipulation
    Check-RegistryRestrictions
    Check-IFEOHijacking
    Check-DisallowRun
    Check-FirewallRestrictions
    Check-TaskkillAutorun
    Check-URLBlocklist
    Check-CMDColorBypass
    Check-PrefetchManipulation
    Check-EventLogClearing
    Check-DisallowedCertificates
    Check-SystemTimeChanges
    Check-WinRARSteganography
    
    Check-DefenderExclusions
    Check-ScheduledTasks
    Check-PowerShellLogging
    Check-StartupFolder
    Check-RecentRunDialogs
    Check-USNJournalStatus
    Check-RecycleBinBypass
    Check-DriverSignatureEnforcement
    Check-SuspiciousProcesses
    Check-DNSCache
    Check-BAMRegistry
    Check-ShimCache
    Check-Amcache
    Check-JumpLists
    Check-RecentJarFiles
    Check-JavaArguments
    
    Invoke-JvmScan
    
    Write-Section "System Analysis Summary" "SUM"
    
    if ($script:JvmFlags.Count -gt 0) {
        Write-Result "WARN" "JVM Injection Flags" "$($script:JvmFlags.Count) suspicious flag(s) detected"
        foreach ($flag in $script:JvmFlags) {
            Write-Host "    [X] " -NoNewline -ForegroundColor $script:Colors.Error
            Write-Host "$($flag.Process): " -NoNewline -ForegroundColor $script:Colors.Warning
            Write-Host "$($flag.Type) flag detected" -ForegroundColor $script:Colors.Dim
        }
    }
    
    if ($script:SystemFindings.Count -gt 0) {
        Write-Result "WARN" "Total findings" "$($script:SystemFindings.Count) suspicious item(s) detected"
        
        Write-Host ""
        Write-Host "  Would you like to attempt automatic remediation? [Y/N]: " -NoNewline -ForegroundColor $script:Colors.Secondary
        $fix = Read-Host
        if ($fix -eq "Y" -or $fix -eq "y") {
            Remove-SystemFindings -Findings $script:SystemFindings
        }
    } else {
        Write-Result "PASS" "System appears clean" "No bypass techniques detected"
    }
}

function Run-ModAnalysis {
    Write-Host ""
    Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
    Write-Host "              M O D   A N A L Y S I S" -ForegroundColor $script:Colors.Primary
    Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
    
    Get-MinecraftUptime
    
    $defaultPath = "$env:USERPROFILE\AppData\Roaming\.minecraft\mods"
    
    Write-Host ""
    Write-Host "  Enter mods folder path " -NoNewline -ForegroundColor $script:Colors.Secondary
    Write-Host "(Enter for default):" -ForegroundColor $script:Colors.Dim
    Write-Host "  Default: $defaultPath" -ForegroundColor $script:Colors.Dim
    Write-Host "  Path: " -NoNewline -ForegroundColor $script:Colors.Secondary
    $inputPath = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($inputPath)) {
        $inputPath = $defaultPath
    }
    
    Analyze-ModsFolder -ModsPath $inputPath
    
    Write-Section "Mod Analysis Summary" "SUM"
    Write-Result "INFO" "Verified" "$($script:VerifiedMods.Count) mod(s)"
    Write-Result "INFO" "Unknown" "$($script:UnknownMods.Count) mod(s)"
    
    if ($script:BypassMods.Count -gt 0) {
        Write-Result "WARN" "Bypass Detection" "$($script:BypassMods.Count) mod(s) flagged by advanced scan"
    }
    
    if ($script:CheatMods.Count -gt 0) {
        Write-Result "WARN" "CHEATS DETECTED" "$($script:CheatMods.Count) suspicious mod(s)"
    } else {
        Write-Result "PASS" "No cheat mods detected"
    }
}

Write-Banner

$choice = Show-Menu

switch ($choice) {
    "1" {
        Run-ModAnalysis
    }
    "2" {
        Write-Host ""
        Write-Host "  Goodbye! Stay safe." -ForegroundColor $script:Colors.Secondary
        exit 0
    }
    default {
        Write-Host "  Invalid choice." -ForegroundColor $script:Colors.Error
        exit 1
    }
}

Write-Host ""
Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Dim
Write-Host "            Analysis Complete - Yumiko v$($script:Config.Version)" -ForegroundColor $script:Colors.Secondary
Write-Host "                      FREE Edition" -ForegroundColor $script:Colors.Warning
Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Dim
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor $script:Colors.Dim
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

