param(
    [switch]$SkipSystemCheck,
    [switch]$SkipModCheck,
    [string]$ModPath,
    [switch]$AutoFix,
    [switch]$Silent
)

$script:Config = @{
    Version = "4.3.0"
    Author = "Veridon"
    Name = "Yumiko Mod Analyzer"
    Edition = "FREE ULTIMATE"
    ModrinthAPI = "https://api.modrinth.com/v2"
    MegabaseAPI = "https://megabase.vercel.app/api/query"
    CheatSignatures = "600+"
    SystemChecks = "40+"
    Obfuscators = "20+"
    ObfuscationPatterns = "19+"
    Features = "JVM Scan, Bypass Detection, String Analysis, Advanced Obfuscation Detection, Doomsday Detection, Memory Forensics, Prefetch Analysis, Fabric/Forge Injection Detection, Disallowed Mods"
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

               M O D   A N A L Y Z E R   v$($script:Config.Version)
"@
    Write-Host $banner -ForegroundColor $script:Colors.Primary
    Write-Host "    ===========================================================" -ForegroundColor $script:Colors.Dim
    Write-Host "      $($script:Config.Edition) " -NoNewline -ForegroundColor $script:Colors.Success
    Write-Host "|" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host " $($script:Config.CheatSignatures) Signatures" -NoNewline -ForegroundColor $script:Colors.Warning
    Write-Host " |" -NoNewline -ForegroundColor $script:Colors.Dim
    Write-Host " $($script:Config.SystemChecks) Checks" -ForegroundColor $script:Colors.Secondary
    Write-Host "    ===========================================================" -ForegroundColor $script:Colors.Dim
    Write-Host "      $($script:Config.Obfuscators) Obfuscators | $($script:Config.ObfuscationPatterns) Patterns | Forensics" -ForegroundColor $script:Colors.Accent
    Write-Host "      Cheat Detection | Injection Scanner | Doomsday Finder" -ForegroundColor $script:Colors.Accent
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

# === WINDOWS API DEFINITIONS FOR MEMORY SCANNING (MeowDoomsdayFucker Style) ===
$script:MemoryAPILoaded = $false
try {
    Add-Type @"
    using System;
    using System.Runtime.InteropServices;
    
    public static class MemoryScanner {
        // Process access rights
        public const uint PROCESS_VM_READ = 0x0010;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        
        // Memory state constants
        public const uint MEM_COMMIT = 0x1000;
        
        // Memory protection constants
        public const uint PAGE_READONLY = 0x02;
        public const uint PAGE_READWRITE = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint PAGE_GUARD = 0x100;
        
        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }
        
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll")]
        public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);
        
        [DllImport("kernel32.dll")]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);
        
        public static bool IsReadableProtection(uint protect) {
            if ((protect & PAGE_GUARD) != 0) return false;
            return (protect == PAGE_READONLY || 
                    protect == PAGE_READWRITE || 
                    protect == PAGE_EXECUTE_READ || 
                    protect == PAGE_EXECUTE_READWRITE);
        }
    }
"@ -ErrorAction SilentlyContinue
    $script:MemoryAPILoaded = $true
} catch {
    $script:MemoryAPILoaded = $false
}

$script:SystemFindings = @()
$script:JvmFlags = @()
$script:BypassMods = @()
$script:VerifiedMods = @()
$script:UnknownMods = @()
$script:CheatMods = @()
$script:ObfuscatedModsList = @()
$script:DisallowedModsFound = @()

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
        @{ Name = "Brave"; Path = "HKLM:\SOFTWARE\Policies\BraveSoftware\Brave" }
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
            }
            $found = $true
        }
    } catch {}
    
    if (Test-Path $prefetchPath) {
        $readOnlyPF = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue | Where-Object { $_.IsReadOnly }
        if ($readOnlyPF.Count -gt 0) {
            Write-Result "FOUND" "Read-only prefetch files detected" "$($readOnlyPF.Count) files"
            $script:SystemFindings += @{
                Type = "Prefetch"
                Description = "Read-only prefetch files"
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
    
    if (-not $found) {
        Write-Result "CLEAN" "No log clearing detected this session"
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
                $actions = $task.Actions
                foreach ($action in $actions) {
                    $cmd = "$($action.Execute) $($action.Arguments)"
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($cmd -match [regex]::Escape($pattern)) {
                            Write-Result "FOUND" "Suspicious task" "$($task.TaskName)"
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
                Write-Result "FOUND" "$($logging.Desc) is DISABLED"
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
        "vape.gg", "intent.store", "novoline.wtf", "rise.today",
        "astolfo.lgbt", "exhibition.org", "fdpclient.com",
        "sigmaclient.info", "pandaware.wtf", "drip.ac",
        "novaclient.lol", "novaclient.com", "api.novaclient.lol",
        "riseclient.com", "doomsdayclient.com", "prestigeclient.vip",
        "198macros.com", "dqrkis.xyz"
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
        "client", "loader", "bypass", "exploit", "nova", "doomsday"
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
        "loader", "bypass", "client", "nova", "doomsday"
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
    
    $suspiciousPatterns = @(
        "cheat", "hack", "inject", "meteor", "wurst", "impact", "vape",
        "liquidbounce", "aristois", "sigma", "novoline", "rise", "ghost",
        "loader", "bypass", "client", "exploit", "nova", "doomsday"
    )
    
    try {
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
        "liquidbounce", "aristois", "client", "loader", "ghost", "nova", "doomsday"
    )
    
    foreach ($path in $jumpListPaths) {
        try {
            if (Test-Path $path) {
                $jumpFiles = Get-ChildItem -Path $path -ErrorAction SilentlyContinue | 
                             Sort-Object LastWriteTime -Descending | 
                             Select-Object -First 30
                
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
    $suspiciousPatterns = @("cheat", "hack", "client", "vape", "meteor", "wurst", "impact", "inject", "ghost", "nova", "doomsday")
    
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

function Check-AdvancedJVMArgs {
    Write-Section "Advanced JVM Args Analysis" "JVM+"
    
    $found = $false
    
    $launcherPaths = @(
        "$env:APPDATA\PrismLauncher\instances",
        "$env:APPDATA\MultiMC\instances",
        "$env:LOCALAPPDATA\Programs\PrismLauncher\instances",
        "$env:APPDATA\ATLauncher\instances",
        "$env:APPDATA\PolyMC\instances",
        "$env:APPDATA\gdlauncher_next\instances",
        "$env:APPDATA\ModrinthApp\profiles",
        "$env:USERPROFILE\.lunarclient",
        "$env:APPDATA\Badlion Client"
    )
    
    $suspiciousArgs = @(
        "-javaagent:",
        "-Xbootclasspath/p:",
        "-Xbootclasspath/a:",
        "-agentlib:jdwp",
        "-agentpath:",
        "-noverify",
        "-Xverify:none",
        "-XX:+DisableAttachMechanism",
        "-Djava.system.class.loader=",
        "-Djava.security.manager=allow"
    )
    
    foreach ($launcherPath in $launcherPaths) {
        try {
            if (Test-Path $launcherPath) {
                $configFiles = Get-ChildItem -Path $launcherPath -Recurse -Include "*.json", "*.cfg", "mmc-pack.json", "instance.cfg" -ErrorAction SilentlyContinue | 
                               Select-Object -First 50
                
                foreach ($configFile in $configFiles) {
                    try {
                        $content = Get-Content -Path $configFile.FullName -Raw -ErrorAction SilentlyContinue
                        foreach ($arg in $suspiciousArgs) {
                            if ($content -match [regex]::Escape($arg)) {
                                $launcherName = Split-Path -Leaf (Split-Path -Parent $launcherPath)
                                Write-Result "FOUND" "Suspicious JVM arg in $launcherName" "$arg"
                                $script:SystemFindings += @{
                                    Type = "AdvancedJVMArgs"
                                    Description = "Suspicious: $arg in $($configFile.Name)"
                                    Path = $configFile.FullName
                                }
                                $found = $true
                            }
                        }
                    } catch {}
                }
            }
        } catch {}
    }
    
    $envVars = @("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS")
    foreach ($var in $envVars) {
        $envValue = [Environment]::GetEnvironmentVariable($var, "User")
        if ($envValue) {
            foreach ($arg in $suspiciousArgs) {
                if ($envValue -match [regex]::Escape($arg)) {
                    Write-Result "FOUND" "JVM env var injection" "$var contains $arg"
                    $script:SystemFindings += @{
                        Type = "JVMEnvVar"
                        Description = "$var = $envValue"
                    }
                    $found = $true
                }
            }
        }
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious advanced JVM configurations"
    }
}

function Check-JavaProcessMemory {
    Write-Section "Java Process Memory Analysis (Doomsday Fucker)" "MEM"
    
    $found = $false
    
    # Extended Doomsday-specific signatures (obfuscated patterns from MeowDoomsdayFucker research)
    $doomsdaySignatures = @(
        "doomsday", "DoomsdayClient", "doomsdayclient.com",
        "com.doomsday", "net.doomsday", "doomsday.module",
        "DoomsdayMod", "DoomsdayCore", "DoomsdayLoader",
        "DOOMSDAY_HWID", "doomsday_config", "doomsday_auth",
        "DoomsdayKillAura", "DoomsdayESP", "DoomsdayFly",
        "doom_bypass", "DoomsdayAPI", "doomsday.bypass",
        "doomsday.aimbot", "doomsday.velocity", "DoomVelocity"
    )
    
    $cheatSignatures = @(
        "novaclient", "api.novaclient.lol", "NovaClient",
        "riseclient", "rise.today", "RiseClient",
        "vape.gg", "vapeclient", "VapeClient", "VapeLite",
        "intent.store", "IntentClient",
        "KillAura", "CrystalAura", "AnchorAura", "Scaffold",
        "PacketFly", "Velocity", "AntiKB", "Disabler"
    )
    
    $allSignatures = $doomsdaySignatures + $cheatSignatures
    
    try {
        $javaProcesses = @()
        $javaProcesses += Get-Process javaw -ErrorAction SilentlyContinue
        $javaProcesses += Get-Process java -ErrorAction SilentlyContinue
        
        if ($javaProcesses.Count -eq 0) {
            Write-Result "INFO" "No Java processes running"
            Write-Result "INFO" "Start Minecraft to scan for Doomsday in memory"
            return
        }
        
        Write-Result "INFO" "Found $($javaProcesses.Count) Java process(es) - deep memory scan..."
        
        foreach ($proc in $javaProcesses) {
            try {
                # Phase 1: Command line check (quick scan)
                $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                $cmdLine = if ($wmi) { $wmi.CommandLine } else { "" }
                
                foreach ($sig in $allSignatures) {
                    if ($cmdLine -match [regex]::Escape($sig)) {
                        Write-Result "FOUND" "CHEAT SIGNATURE in Java cmdline" "$sig (PID: $($proc.Id))"
                        $script:SystemFindings += @{
                            Type = "MemoryCheat"
                            Description = "Cheat signature in cmdline: $sig"
                            PID = $proc.Id
                            Severity = "CRITICAL"
                        }
                        $found = $true
                    }
                }
                
                # Phase 2: Deep memory scan using Windows API (MeowDoomsdayFucker style)
                if ($script:MemoryAPILoaded) {
                    $hProcess = [MemoryScanner]::OpenProcess(
                        [MemoryScanner]::PROCESS_VM_READ -bor [MemoryScanner]::PROCESS_QUERY_INFORMATION, 
                        $false, 
                        $proc.Id
                    )
                    
                    if ($hProcess -ne [IntPtr]::Zero) {
                        try {
                            Write-Result "INFO" "Deep scanning PID $($proc.Id) memory regions..."
                            
                            $address = [IntPtr]::Zero
                            $memInfo = New-Object MemoryScanner+MEMORY_BASIC_INFORMATION
                            $memInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf($memInfo)
                            $regionsScanned = 0
                            $chunkSize = 50 * 1024 * 1024  # 50MB chunks like MeowDoomsdayFucker
                            $maxRegionSize = 100 * 1024 * 1024  # Skip regions > 100MB
                            
                            while ([MemoryScanner]::VirtualQueryEx($hProcess, $address, [ref]$memInfo, $memInfoSize) -ne 0) {
                                # Check if region is committed and readable
                                if ($memInfo.State -eq [MemoryScanner]::MEM_COMMIT -and 
                                    [MemoryScanner]::IsReadableProtection($memInfo.Protect)) {
                                    
                                    $regionSize = $memInfo.RegionSize.ToInt64()
                                    
                                    # Skip very large regions for performance (like MeowDoomsdayFucker)
                                    if ($regionSize -lt $maxRegionSize -and $regionSize -gt 0) {
                                        $buffer = New-Object byte[] ([Math]::Min($regionSize, $chunkSize))
                                        $bytesRead = 0
                                        
                                        if ([MemoryScanner]::ReadProcessMemory($hProcess, $memInfo.BaseAddress, $buffer, $buffer.Length, [ref]$bytesRead)) {
                                            $regionsScanned++
                                            
                                            # Convert buffer to string for pattern matching
                                            $memString = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
                                            
                                            foreach ($sig in $doomsdaySignatures) {
                                                if ($memString.Contains($sig)) {
                                                    Write-Result "FOUND" "DOOMSDAY IN MEMORY" "$sig (PID: $($proc.Id)) - FUCKED!"
                                                    $script:SystemFindings += @{
                                                        Type = "DoomsdayMemory"
                                                        Description = "Doomsday signature in RAM: $sig"
                                                        PID = $proc.Id
                                                        Address = $memInfo.BaseAddress.ToString("X")
                                                        Severity = "CRITICAL"
                                                    }
                                                    $found = $true
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                # Move to next region
                                $nextAddress = $memInfo.BaseAddress.ToInt64() + $memInfo.RegionSize.ToInt64()
                                if ($nextAddress -le $address.ToInt64()) { break }
                                $address = [IntPtr]$nextAddress
                                
                                # Safety limit
                                if ($regionsScanned -gt 1000) { break }
                            }
                            
                            if ($regionsScanned -gt 0) {
                                Write-Result "INFO" "Scanned $regionsScanned memory regions for PID $($proc.Id)"
                            }
                        } finally {
                            [MemoryScanner]::CloseHandle($hProcess) | Out-Null
                        }
                    } else {
                        Write-Result "WARN" "Cannot access PID $($proc.Id) memory (run as admin)"
                    }
                } else {
                    # Fallback: Module name analysis
                    try {
                        $modules = $proc.Modules | ForEach-Object { $_.ModuleName.ToLower() }
                        foreach ($mod in $modules) {
                            foreach ($sig in $doomsdaySignatures) {
                                if ($mod -match $sig.ToLower()) {
                                    Write-Result "FOUND" "Doomsday module loaded" "$mod (PID: $($proc.Id))"
                                    $script:SystemFindings += @{
                                        Type = "DoomsdayModule"
                                        Description = "Module: $mod"
                                        PID = $proc.Id
                                        Severity = "CRITICAL"
                                    }
                                    $found = $true
                                }
                            }
                        }
                    } catch {}
                }
            } catch {
                Write-Verbose "Could not analyze process $($proc.Id): $_"
            }
        }
    } catch {
        Write-Result "WARN" "Memory analysis requires elevated privileges"
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No cheat signatures found in Java process memory"
    }
}

function Check-LocalhostWebServer {
    Write-Section "Localhost Web Server Detection (Doomsday GUI)" "WEB"
    
    $found = $false
    
    # Common ports used by cheat clients for their web GUI
    $suspiciousPorts = @(
        @{ Port = 80; Desc = "HTTP default" },
        @{ Port = 8080; Desc = "Alt HTTP" },
        @{ Port = 8888; Desc = "Common cheat port" },
        @{ Port = 3000; Desc = "Node/React dev" },
        @{ Port = 4000; Desc = "Common app port" },
        @{ Port = 5000; Desc = "Flask/Dev server" },
        @{ Port = 9000; Desc = "PHP-FPM/Dev" },
        @{ Port = 1337; Desc = "Leet port (cheat)" },
        @{ Port = 6969; Desc = "Meme port (cheat)" },
        @{ Port = 25565; Desc = "MC Server port" },
        @{ Port = 8443; Desc = "HTTPS alt" },
        @{ Port = 7777; Desc = "Game server" }
    )
    
    Write-Result "INFO" "Checking for Java-hosted localhost web servers..."
    
    try {
        # Get all listening TCP connections
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { $_.LocalAddress -eq "127.0.0.1" -or $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" }
        
        if ($null -eq $listeners -or $listeners.Count -eq 0) {
            # Fallback: use netstat
            $netstatOutput = netstat -an 2>$null | Select-String "LISTENING"
            $listeners = @()
            foreach ($line in $netstatOutput) {
                if ($line -match '(?:127\.0\.0\.1|0\.0\.0\.0|\[::\]):(\d+)') {
                    $listeners += @{ LocalPort = [int]$Matches[1]; OwningProcess = 0 }
                }
            }
        }
        
        # Get Java process PIDs
        $javaPids = @()
        $javaProcesses = @()
        $javaProcesses += Get-Process javaw -ErrorAction SilentlyContinue
        $javaProcesses += Get-Process java -ErrorAction SilentlyContinue
        $javaPids = $javaProcesses | ForEach-Object { $_.Id }
        
        if ($javaPids.Count -eq 0) {
            Write-Result "INFO" "No Java processes running"
        } else {
            Write-Result "INFO" "Found $($javaPids.Count) Java process(es)"
        }
        
        # Check each suspicious port
        foreach ($portInfo in $suspiciousPorts) {
            $port = $portInfo.Port
            $desc = $portInfo.Desc
            
            # Check if port is listening
            $listening = $listeners | Where-Object { $_.LocalPort -eq $port }
            
            if ($listening) {
                $ownerPid = if ($listening.OwningProcess) { $listening.OwningProcess } else { 0 }
                $isJava = $javaPids -contains $ownerPid
                
                # Try HTTP request to check if web server responds
                try {
                    $webRequest = [System.Net.WebRequest]::Create("http://127.0.0.1:$port/")
                    $webRequest.Timeout = 1000
                    $webRequest.Method = "GET"
                    
                    try {
                        $response = $webRequest.GetResponse()
                        $statusCode = [int]$response.StatusCode
                        $contentType = $response.ContentType
                        $response.Close()
                        
                        $severity = if ($isJava) { "CRITICAL" } else { "WARN" }
                        $javaText = if ($isJava) { " [JAVA PROCESS!]" } else { "" }
                        
                        Write-Result "FOUND" "Web server on localhost:$port$javaText" "$desc (HTTP $statusCode)"
                        
                        if ($isJava) {
                            Write-Result "WARN" "  Java PID $ownerPid is hosting a web server - possible cheat GUI!"
                        }
                        
                        $script:SystemFindings += @{
                            Type = "LocalhostWebServer"
                            Description = "Web server on port $port ($desc)"
                            Port = $port
                            IsJava = $isJava
                            PID = $ownerPid
                            StatusCode = $statusCode
                            Severity = $severity
                        }
                        $found = $true
                        
                    } catch [System.Net.WebException] {
                        # Server responded but with error - still a web server
                        $errorResponse = $_.Exception.Response
                        if ($null -ne $errorResponse) {
                            $statusCode = [int]$errorResponse.StatusCode
                            $javaText = if ($isJava) { " [JAVA!]" } else { "" }
                            
                            Write-Result "FOUND" "Web server on localhost:$port$javaText" "$desc (HTTP $statusCode)"
                            
                            if ($isJava) {
                                Write-Result "WARN" "  Java PID $ownerPid hosting web server!"
                            }
                            
                            $script:SystemFindings += @{
                                Type = "LocalhostWebServer"
                                Description = "Web server on port $port"
                                Port = $port
                                IsJava = $isJava
                                PID = $ownerPid
                                Severity = if ($isJava) { "HIGH" } else { "MEDIUM" }
                            }
                            $found = $true
                        }
                    }
                } catch {
                    # Port is listening but not HTTP - could be other protocol
                    if ($isJava) {
                        Write-Result "INFO" "Java listening on port $port (non-HTTP)"
                    }
                }
            }
        }
        
        # Additional check: Look for any Java process with listening ports
        foreach ($pid in $javaPids) {
            $javaListeners = $listeners | Where-Object { $_.OwningProcess -eq $pid }
            foreach ($l in $javaListeners) {
                $port = $l.LocalPort
                # Skip already checked ports
                if ($suspiciousPorts.Port -notcontains $port) {
                    Write-Result "INFO" "Java PID $pid listening on port $port"
                    
                    # Try HTTP check
                    try {
                        $webRequest = [System.Net.WebRequest]::Create("http://127.0.0.1:$port/")
                        $webRequest.Timeout = 500
                        $response = $webRequest.GetResponse()
                        $response.Close()
                        
                        Write-Result "FOUND" "Java web server on localhost:$port" "PID $pid"
                        $script:SystemFindings += @{
                            Type = "LocalhostWebServer"
                            Description = "Java web server on port $port"
                            Port = $port
                            IsJava = $true
                            PID = $pid
                            Severity = "HIGH"
                        }
                        $found = $true
                    } catch {}
                }
            }
        }
        
    } catch {
        Write-Result "WARN" "Could not enumerate network connections"
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious localhost web servers detected"
    }
}

function Check-PrefetchFiles {
    Write-Section "Windows Prefetch Forensics (JAR Parser)" "PF"
    
    $found = $false
    $prefetchPath = "$env:SystemRoot\Prefetch"
    
    # Extended suspicious patterns for cheat clients
    $suspiciousPatterns = @(
        "DOOMSDAY", "NOVACLIENT", "VAPECLIENT", "RISECLIENT",
        "METEOR", "WURST", "IMPACT", "ARISTOIS", "LIQUIDBOUNCE",
        "SIGMA", "FUTURE", "KONAS", "RUSHERHACK", "PHOBOS",
        "SALHACK", "ABYSS", "COSMOS", "THUNDER", "ARES",
        "CHEAT", "HACK", "INJECT", "LOADER", "CLIENT", "GHOST",
        "AUTOCLICKER", "GHOSTCLIENT", "VAPE", "NOVA", "INTENT"
    )
    
    # Patterns indicating JAR file execution (like MeowDoomsdayFucker JAR Parser)
    $jarPatterns = @(
        "JAVA", "JAVAW", "JAR"
    )
    
    try {
        if (-not (Test-Path $prefetchPath)) {
            Write-Result "WARN" "Prefetch folder not accessible (requires admin)"
            return
        }
        
        $prefetchFiles = Get-ChildItem -Path $prefetchPath -Filter "*.pf" -ErrorAction SilentlyContinue
        
        if ($prefetchFiles.Count -eq 0) {
            Write-Result "INFO" "No Prefetch files found (may be disabled)"
            return
        }
        
        Write-Result "INFO" "Analyzing $($prefetchFiles.Count) Prefetch files..."
        
        $javaExecutions = @()
        
        foreach ($pf in $prefetchFiles) {
            $name = $pf.BaseName.ToUpper()
            
            # Track Java executions for timeline
            foreach ($jarPattern in $jarPatterns) {
                if ($name -like "*$jarPattern*") {
                    $javaExecutions += @{
                        Name = $pf.BaseName
                        LastRun = $pf.LastWriteTime
                    }
                }
            }
            
            # Check for suspicious cheat patterns
            foreach ($pattern in $suspiciousPatterns) {
                if ($name -match $pattern) {
                    $lastRun = $pf.LastWriteTime
                    Write-Result "FOUND" "Suspicious prefetch entry" "$($pf.BaseName) (Last: $lastRun)"
                    $script:SystemFindings += @{
                        Type = "Prefetch"
                        Description = "Executed: $($pf.BaseName)"
                        LastRun = $lastRun
                        Severity = "HIGH"
                    }
                    $found = $true
                    break
                }
            }
        }
        
        # Report Java execution timeline
        if ($javaExecutions.Count -gt 0) {
            $recentJava = $javaExecutions | Sort-Object -Property LastRun -Descending | Select-Object -First 3
            foreach ($java in $recentJava) {
                Write-Result "INFO" "Java execution trace" "$($java.Name) (Last: $($java.LastRun))"
            }
        }
        
        # Look for recently accessed JAR files in common cheat paths
        $suspiciousJarPaths = @(
            "$env:APPDATA\.minecraft\mods",
            "$env:APPDATA\doomsday",
            "$env:TEMP"
        )
        
        foreach ($jarPath in $suspiciousJarPaths) {
            if (Test-Path $jarPath) {
                $recentJars = Get-ChildItem -Path $jarPath -Filter "*.jar" -ErrorAction SilentlyContinue | 
                              Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
                              
                foreach ($jar in $recentJars) {
                    foreach ($pattern in $suspiciousPatterns) {
                        if ($jar.Name.ToUpper() -match $pattern) {
                            Write-Result "FOUND" "Suspicious recent JAR file" "$($jar.FullName)"
                            $script:SystemFindings += @{
                                Type = "SuspiciousJAR"
                                Description = "Recent JAR: $($jar.Name)"
                                Path = $jar.FullName
                                LastModified = $jar.LastWriteTime
                                Severity = "HIGH"
                            }
                            $found = $true
                        }
                    }
                }
            }
        }
        
    } catch {
        Write-Result "WARN" "Prefetch analysis error: $_"
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No suspicious Prefetch entries"
    }
}

function Check-DoomsdayRegistry {
    Write-Section "Doomsday Registry & Folder Analysis" "REG"
    
    $found = $false
    
    # Extended registry keys for Doomsday detection
    $doomsdayKeys = @(
        "HKCU:\Software\Doomsday",
        "HKCU:\Software\DoomsdayClient",
        "HKLM:\Software\Doomsday",
        "HKCU:\Software\DoomsdayMod",
        "HKCU:\Software\DoomsdayLoader"
    )
    
    foreach ($key in $doomsdayKeys) {
        if (Test-Path $key) {
            Write-Result "FOUND" "DOOMSDAY REGISTRY KEY" $key
            $script:SystemFindings += @{
                Type = "DoomsdayRegistry"
                Description = "Registry key: $key"
                Severity = "CRITICAL"
            }
            $found = $true
        }
    }
    
    # Extended Doomsday folder paths
    $doomsdayPaths = @(
        "$env:APPDATA\Doomsday",
        "$env:APPDATA\.doomsday",
        "$env:LOCALAPPDATA\Doomsday",
        "$env:APPDATA\doomsdayclient",
        "$env:APPDATA\DoomsdayClient",
        "$env:TEMP\Doomsday",
        "$env:TEMP\doomsday",
        "$env:USERPROFILE\.doomsday",
        "$env:APPDATA\.minecraft\doomsday"
    )
    
    foreach ($path in $doomsdayPaths) {
        if (Test-Path $path) {
            Write-Result "FOUND" "DOOMSDAY FOLDER DETECTED" $path
            $script:SystemFindings += @{
                Type = "DoomsdayFolder"
                Description = "Folder: $path"
                Severity = "CRITICAL"
            }
            $found = $true
            
            # List files in Doomsday folder for additional info
            try {
                $doomsdayFiles = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
                foreach ($file in $doomsdayFiles) {
                    Write-Result "INFO" "  Doomsday file" $file.Name
                }
            } catch {}
        }
    }
    
    # Check Recent Files for Doomsday traces (forensic persistence like MeowDoomsdayFucker)
    $recentPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentPath) {
        $recentFiles = Get-ChildItem -Path $recentPath -Filter "*.lnk" -ErrorAction SilentlyContinue
        foreach ($lnk in $recentFiles) {
            if ($lnk.Name -match "(?i)doomsday|doom.?client") {
                Write-Result "FOUND" "Doomsday in Recent Files" $lnk.Name
                $script:SystemFindings += @{
                    Type = "DoomsdayRecent"
                    Description = "Recent file: $($lnk.Name)"
                    LastAccess = $lnk.LastWriteTime
                    Severity = "HIGH"
                }
                $found = $true
            }
        }
    }
    
    # Check for Doomsday config files in common locations
    $configLocations = @(
        "$env:APPDATA\.minecraft\config\doomsday*",
        "$env:APPDATA\.minecraft\*doomsday*",
        "$env:USERPROFILE\Downloads\*doomsday*"
    )
    
    foreach ($configPattern in $configLocations) {
        $configFiles = Get-ChildItem -Path $configPattern -ErrorAction SilentlyContinue
        foreach ($cfg in $configFiles) {
            Write-Result "FOUND" "Doomsday config/file detected" $cfg.FullName
            $script:SystemFindings += @{
                Type = "DoomsdayConfig"
                Description = "Config: $($cfg.Name)"
                Path = $cfg.FullName
                Severity = "HIGH"
            }
            $found = $true
        }
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No Doomsday traces found"
    }
}

function Check-FabricForgeInjection {
    Write-Section "Fabric/Forge JVM Injection Scanner" "INJ"
    
    $found = $false
    
    $javaProcesses = Get-Process -Name javaw -ErrorAction SilentlyContinue
    
    if ($javaProcesses.Count -eq 0) {
        Write-Result "INFO" "No javaw.exe processes found"
        Write-Result "INFO" "Make sure Minecraft is running"
        return
    }
    
    Write-Result "INFO" "Scanning $($javaProcesses.Count) Java process(es)..."
    
    $fabricPatterns = @{
        "fabric.addMods" = '-Dfabric\.addMods='
        "fabric.loadMods" = '-Dfabric\.loadMods='
        "fabric.classPathGroups" = '-Dfabric\.classPathGroups='
        "fabric.gameJarPath" = '-Dfabric\.gameJarPath='
        "fabric.remapClasspathFile" = '-Dfabric\.remapClasspathFile='
        "fabric.mixin.configs" = '-Dfabric\.mixin\.configs='
        "fabric.customModList" = '-Dfabric\.customModList='
        "forge.addMods" = '-Dforge\.addMods='
        "forge.mods" = '-Dforge\.mods='
        "fml.coreMods.load" = '-Dfml\.coreMods\.load='
        "forge.coreMods.dir" = '-Dforge\.coreMods\.dir='
        "forge.modDir" = '-Dforge\.modDir='
        "fml.customModList" = '-Dfml\.customModList='
        "javaSecurityManager" = '-Djava\.security\.manager='
        "javaSecurityPolicy" = '-Djava\.security\.policy='
        "bootClasspath" = '-Xbootclasspath'
        "systemClassLoader" = '-Djava\.system\.class\.loader='
        "javaClassPath" = '-Djava\.class\.path='
        "cheatClientBrand" = '-D(client|launcher)\.brand=(Wurst|Aristois|Impact|Kilo|Future|Lambda|Rusher|Konas|Phobos|Salhack|ForgeHax|Mathax|Meteor|Async|Seppuku|Xatz|Wolfram|Huzuni|Jigsaw|Zamorozka|Moon|Rage|Exhibition|Virtue|Novoline|Rekt|Skid|Ares|Abyss|Thunder|Tenacity|Rise|Flux|Gamesense|Intent|Remix|Sight|Vape|Shield|Ghost|Crispy|Inertia)'
        "cheatPattern" = '-D(xray|fly|speed|killaura|reach|esp|wallhack|noclip|autoclick|aimbot|triggerbot|antiknockback|nofall|timer|step|fullbright|nightvision|cavefinder)\.'
    }
    
    $cheatClients = @('Wurst', 'Aristois', 'Impact', 'Kilo', 'Future', 'Lambda', 'Rusher', 'Konas', 'Phobos', 
                      'Salhack', 'ForgeHax', 'Mathax', 'Meteor', 'Async', 'Seppuku', 'Xatz', 'Wolfram', 
                      'Huzuni', 'Jigsaw', 'Zamorozka', 'Moon', 'Rage', 'Exhibition', 'Virtue', 'Novoline', 
                      'Rekt', 'Skid', 'Ares', 'Abyss', 'Thunder', 'Tenacity', 'Rise', 'Flux', 'Gamesense', 
                      'Intent', 'Remix', 'Sight', 'Vape', 'Shield', 'Ghost', 'Crispy', 'Inertia', 'Nova', 'Doomsday')
    
    foreach ($proc in $javaProcesses) {
        try {
            $wmiProcess = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop
            $commandLine = $wmiProcess.CommandLine
            
            if ($commandLine) {
                $detectedPatterns = @()
                
                foreach ($patternName in $fabricPatterns.Keys) {
                    $regexPattern = $fabricPatterns[$patternName]
                    if ($commandLine -match $regexPattern) {
                        if ($patternName -eq "addOpens" -or $patternName -eq "addExports") {
                            continue
                        }
                        $detectedPatterns += $patternName
                        $found = $true
                    }
                }
                
                foreach ($cheatClient in $cheatClients) {
                    if ($commandLine -match "(?i)\b$cheatClient\b") {
                        if ("CheatClient-$cheatClient" -notin $detectedPatterns) {
                            $detectedPatterns += "CheatClient-$cheatClient"
                            $found = $true
                        }
                    }
                }
                
                if ($commandLine -match '(%3B|%26%26|%7C%7C|%7C|%60|%24|%3C|%3E)') {
                    $detectedPatterns += "EncodedInjection"
                    $found = $true
                }
                
                if ($detectedPatterns.Count -gt 0) {
                    Write-Result "FOUND" "JVM INJECTION DETECTED (PID: $($proc.Id))"
                    foreach ($pattern in $detectedPatterns) {
                        Write-Host "        - $pattern" -ForegroundColor $script:Colors.Error
                        $script:SystemFindings += @{
                            Type = "JVMInjection"
                            Description = "Pattern: $pattern"
                            PID = $proc.Id
                        }
                    }
                }
            }
        } catch {
            Write-Result "WARN" "Could not read cmdline for PID $($proc.Id)" "Run as Administrator"
        }
    }
    
    if (-not $found) {
        Write-Result "CLEAN" "No JVM injection patterns detected"
    }
}

$script:CheatStrings = @(
    "KillAura", "ClickAura", "TriggerBot", "MultiAura", "ForceField", "LegitAura", "TPAura", "SwitchAura",
    "AimAssist", "AimBot", "AutoAim", "SilentAim", "AimLock", "AimCorrect", "SmoothAim", "TargetAim", "LockOn", "HeadSnap",
    "CrystalAura", "AutoCrystal", "AutoHitCrystal", "CrystalOptimize", "CrystalPvP", "CrystalPlace", "dontPlaceCrystal", "dontBreakCrystal", "canPlaceCrystalServer", "autoCrystalPlaceClock",
    "AnchorAura", "AutoAnchor", "AnchorTweaks", "AnchorFill", "AnchorPlace", "DoubleAnchor", "SafeAnchor", "AirAnchor",
    "BedAura", "AutoBed", "BedBomb", "BedPlace", "BedBreak", "BedWars",
    "BowAimbot", "BowSpam", "AutoBow", "ArrowDodge", "Quiver", "BowRelease", "FastBow", "InstaBow",
    "Criticals", "AutoCrit", "CritBypass", "CritHit", "AlwaysCrit", "CriticalHit", "JumpCrit",
    "ReachHack", "ExtendReach", "LongReach", "HitboxExpand", "LagReach",
    "AntiKB", "NoKnockback", "Antiknockback", "GrimVelocity", "GrimDisabler", "VelocitySpoof", "KBReduce", "Velocity",
    "AutoTotem", "TotemPopCounter", "OffhandTotem", "LegitTotem", "HoverTotem", "InventoryTotem", "TotemSwitch", "PopCounter",
    "AutoWeapon", "AutoSword", "AutoCity", "Burrow", "SelfTrap", "Surround", "HoleFiller", "AutoWeb", "AntiSurround", "AntiBurrow",
    "W-Tap", "WTap", "AutoW", "Combo", "TargetStrafe", "AutoGap", "AutoPearl", "PearlPredict", "AutoEagle", "BackTrack", "ShieldBreaker", "ShieldDisabler", "JumpReset", "SprintReset", "AxeSpam", "MaceSwap", "StunSlam", "Donut",
    
    "FlyHack", "CreativeFlight", "BoatFly", "Jetpack", "GlitchFly", "VanillaFly", "PacketFly", "AirJump", "InfiniteFly",
    "SpeedHack", "BHop", "BunnyHop", "Strafe", "SpeedMine", "FastWalk", "SprintBypass", "TimerSpeed", "GroundSpeed",
    "NoFall", "AntiFall", "NoFallDamage", "SafeFall",
    "StepHack", "FastClimb", "AutoStep", "HighStep", "BlockStep",
    "WaterWalk", "WalkOnWater", "LiquidWalk", "LavaWalk", "Jesus",
    "NoSlow", "NoSlowdown", "NoWeb", "NoSoulSand", "NoHoney", "SlowBypass",
    "NoClip", "Phase", "VClip", "HClip", "WallHack", "GhostMode", "Phaser", "FreezePlayer",
    "SpiderHack", "WallClimb", "ClimbWalls",
    "GlideHack", "ExtraElytra", "ElytraFly", "ElytraSwap", "ElytraBoost", "ElytraSpeed", "InstantElytra", "ElytraReplace",
    
    "Scaffold", "ScaffoldWalk", "FastBridge", "BuildHelper", "AutoBridge", "BlockFly", "AirBridge", "TowerAssist",
    "Nuker", "NukerLegit", "FastBreak", "InstantBreak", "AutoMine", "SpeedMine", "InstaMine", "BlockBreaker", "MassBreak",
    "GhostHand", "GhostBlock", "GhostPick", "NoSwing",
    "FastPlace", "PlaceAssist", "AirPlace", "AutoPlace", "InstantPlace", "SpeedPlace",
    
    "PlayerESP", "MobESP", "ItemESP", "StorageESP", "ChestESP", "BlockESP", "EntityESP", "BoxESP", "HealthESP", "ArmorESP",
    "Tracers", "NameTagsHack", "Chams", "MobSpawnESP", "HandESP", "HitColor",
    "XRayHack", "OreFinder", "CaveFinder", "OreESP", "XrayMod", "BlockHighlight",
    "Freecam", "FreeLook", "ThirdPersonCamera", "CameraClip", "DeathCam", "SpectatorCam",
    "FullBright", "NoFog", "NoRender", "NoWeather", "AmbientOcclusion", "NoParticle",
    "NewChunks", "ChunkBorders", "TunnelFinder", "ChunkAnalyzer", "LoadedChunks", "ChunkTracer",
    "TargetHUD", "CPSDisplay", "ReachDisplay", "HitParticles", "TotemHit", "ArrayDisplay", "WaterMark", "ModuleList",
    
    "AutoClicker", "DoubleClicker", "JitterClick", "ButterflyClick", "AutoLeftClick", "AutoRightClick", "ClickSpam", "CPSBoost",
    "AutoArmor", "ChestStealer", "InvManager", "InventoryManager", "ChestSteal", "InvMovebypass", "InventoryCleaner", "AutoSort", "InvWalk",
    "AutoPot", "AutoPotion", "AutoEat", "AutoSprint", "FastXP", "FastExp", "AntiAFK", "AutoRespawn", "DeathCoords", "PotionSaver", "AutoFirework", "SafeWalk", "AntiHunger", "NoJumpDelay",
    "FakePlayer", "Blink", "NoRotation", "SilentRotation", "FakeInv", "FakeLag", "FakeNick", "FakeItem", "PopSwitch", "PingSpoof", "FakeLatency", "FakePing", "PackSpoof", "SpoofRotation", "PositionSpoof",
    "TimerHack", "GameSpeed", "SpeedTimer", "SlowTimer",
    
    "Disabler", "GrimBypass", "VulcanBypass", "MatrixBypass", "AACBypass", "VerusDisabler", "IntaveBypass", "WatchdogBypass", "SpartanBypass", "KarhuBypass", "PolarBypass",
    "PacketFly", "PacketMine", "PacketWalk", "PacketSneak", "PacketCancel", "PacketDupe", "InvalidPacket", "PacketSpam",
    "ServerCrasher", "ChatSpam", "BookBot", "ChunkBan", "ItemBan", "NBTExploit", "CreativeExploit", "OpExploit", "ConsoleSpam",
    "PearlClip", "BoatClip", "EntityClip", "MinecartClip", "HorseClip", "VehicleClip",
    "AntiVanish", "StaffAlert", "PortalGui", "EntityControl", "AutoMount", "AuthBypass", "LicenseCheckMixin", "obfuscatedAuth", "ItemExploit", "Exploits", "SilentClose",
    
    "AutoFarm", "AutoFish", "Baritone", "PathFinder", "AutoWalk", "AutoMiner", "AutoFarmer", "CropAura", "AutoHarvest", "TreeAura", "AutoBreed",
    "AutoBuild", "InstaBuild", "BuildRandom", "TemplateTool", "AutoSign", "Printer", "SchematicaPrinter", "LitematicaPrinter",
    "AutoHighway", "HighwayBuilder", "ElytraHighway", "HighwayTools", "AutoDigger", "TunnelBot",
    "AutoDisconnect", "AutoReconnect", "AutoCommand", "MacroSystem", "AutoTPA", "AutoQueue", "AutoLogin",
    
    "ClickGUI", "TabGUI", "HUDEditor", "ModuleManager", "ConfigManager", "ThemeManager", "KeybindManager",
    "SelfDestruct", "Panic", "HideClient", "ClientHider", "ScreenshotProtection", "StreamerMode", "StaffMode",
    
    "vape.gg", "vape v4", "vapeclient", "vapeV4", "vapeV3", "vapeLite", "vape lite", "manthe.dev",
    "rise6", "riseClient", "rise.today", "riseclient.com", "intent.store",
    "meteor-client", "meteorclient", "meteordev", "meteordevelopment.orbit", "meteordevelopment.meteorclient", "meteoraddon",
    "wurstclient", "net.wurstclient", "WurstClient", "wurst-client",
    "liquidbounce", "fdp-client", "fdpclient", "net.ccbluex", "ccbluex.liquidbounce", "NextGen",
    "novoline", "cc.novoline", "novoline.wtf", "NovoLine",
    "doomsdayclient", "doomsday.client", "doomsdayclient.com", "DoomsdayClient", "DoomsdayMod", "doomsday.jar",
    "novoware", "novoclient", "novo.client", "novoware.net", "NovowareClient", "NovoFucker",
    "aristois", "impactclient", "azura", "drip", "dripClient", "entropy", "pandaware", "skilled", "moonClient", "astolfo", "futureClient", "konas", "rusherhack", "inertia", "sigma", "exhibition",
    "novaclient", "nova client", "api.novaclient.lol",
    "WalksyOptimizer", "WalskyOptimizer", "WalksyCrystalOptimizerMod", "LWFH Crystal",
    
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==", "addFri", "antiAttack",
    "/assets/font/font.ttf", "Lithium is not initialized! Skipping event:", "Error in hash",
    
    "setBlockBreakingCooldown", "getBlockBreakingCooldown", "blockBreakingCooldown", "invokeDoAttack", "invokeDoItemUse", "onAttackEntity", "attackCooldown",
    "onTickMovement", "onPushOutOfBlocks", "onIsGlowing", "onMove", "setVelocity", "jumpMovementFactor", "moveEntityWithHeading",
    "onMouseButton", "ClientPlayerInteractionManagerAccessor", "ClientPlayerEntityMixin", "WorldRendererMixin", "GameRendererMixin", "InGameHudMixin",
    
    "net/wurstclient", "meteordevelopment", "cc/novoline", "com/alan/clients", "club/maxstats", "wtf/moonlight", "me/zeroeightsix/kami", "net/ccbluex", "today/opai", "net/minecraft/injection", "org/chainlibs/module/impl/modules", "xyz/greaj", "com/cheatbreaker", "com/moonsworth",
    
    "?.class", "??.class", "?.class", "??.class", "??.class", "?.class", "?.class", "?.class", "?.class", "??.class",
    
    "AutoCrystal", "Auto Crystal", "AutoHitCrystal", "AutoAnchor", "Auto Anchor",
    "AutoTotem", "AimAssist", "TriggerBot", "FakeLag", "Freecam",
    
    "-javaagent:", "agentmain", "premain", "Instrumentation", "ClassFileTransformer", "redefineClasses", "retransformClasses",
    "System.loadLibrary", "System.load", "Runtime.load", "JNI_OnLoad",
    "Unsafe.getUnsafe", "sun.misc.Unsafe", "putInt", "putLong", "allocateMemory", "freeMemory", "copyMemory",
    "defineClass", "URLClassLoader", "SecureClassLoader", "loadClass", "findClass",
    
    "SessionStealer", "CookieStealer", "Ratted", "TokenLogger", "TokenGrabber", "CredentialStealer", "DiscordToken", "SessionToken", "MinecraftToken", "BrowserStealer", "PasswordStealer",
    "RemoteAccess", "ReverseShell", "C2Server", "CommandControl", "BotNet", "Backdoor", "TrojanHorse", "KeyLogger",
    
    "KeyPearl", "LootYeeter", "AutoBreach", "HideCommands", "NoCommandBlock", "AntiFabricSequence", "AntiPacketKick", "NoServerCheck", "FakeWorld",
    "StashFinder", "TrailFinder", "BaseFinder", "EntityLogger", "CoordExploit", "MapDownloader", "ChunkLogger", "NewerNewChunks",
    
    "imgui.gl3", "imgui.glfw", "imgui-java", "imgui.binding",
    "jnativehook", "JNativeHook", "GlobalScreen", "NativeKeyListener", "NativeMouseListener",
    "phantom-refmap.json", "client-refmap.json", "cheat-refmap.json"
)

$script:DisallowedMods = @{
    "xeros-minimap" = @{ Names = @("Xero's Minimap", "Xeros Minimap", "xeros-minimap", "XerosMinimap") }
    "freecam" = @{ Names = @("Freecam", "freecam", "FreeCam", "Free Cam") }
    "health-indicators" = @{ Names = @("Health Indicators", "health indicators", "HealthIndicators") }
    "clickcrystals" = @{ Names = @("ClickCrystals", "clickcrystals", "ClickCrystals Mod") }
    "mousetweaks" = @{ Names = @("Mouse Tweaks", "mousetweaks", "MouseTweaks") }
    "itemscroller" = @{ Names = @("Item Scroller", "itemscroller", "ItemScroller") }
    "tweakeroo" = @{ Names = @("Tweakeroo", "tweakeroo", "Tweakeroo") }
}

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
            TwoLetter = 0
            Japanese = 0
            Chinese = 0
            RandomPattern = 0
            VeryShort = 0
            Suspicious = 0
            AlphaNumMix = 0
            Sequential = 0
            HashLike = 0
            ConfusionChars = 0
            DummyClasses = 0
            GibberishNames = 0
            NoVowelNames = 0
            ConsonantCluster = 0
            FullwidthChars = 0
        }
        PackageAnalysis = @{
            RandomPaths = 0
            SingleCharPaths = 0
            TotalPaths = 0
        }
        RiskLevel = "LOW"
    }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        
        $allEntries = @($archive.Entries)
        $contentSamples = @()
        $classNames = @()
        $packagePaths = @()
        $classSizes = @()
        
        foreach ($entry in $allEntries) {
            $name = $entry.FullName
            
            if ($name -match "\.class$") {
                $results.ClassAnalysis.Total++
                $className = [System.IO.Path]::GetFileNameWithoutExtension(($name -split "/")[-1])
                $classNames += $className
                $classSizes += $entry.Length
                
                $pathParts = ($name -replace "\.class$", "") -split "/"
                $packagePath = ($pathParts[0..($pathParts.Count-2)]) -join "/"
                if ($packagePath -and $packagePath -ne "") { 
                    $packagePaths += $packagePath 
                    $results.PackageAnalysis.TotalPaths++
                }
                
                if ($className -match "^[\d]+$") { 
                    $results.ClassAnalysis.Numeric++ 
                }
                
                if ($className -match "^[a-zA-Z]$") { 
                    $results.ClassAnalysis.SingleLetter++ 
                }
                
                if ($className -match "^[a-zA-Z]{2}$") { 
                    $results.ClassAnalysis.TwoLetter++ 
                }
                
                if ($className.Length -le 3 -and $className -notmatch "^\d+$") { 
                    $results.ClassAnalysis.VeryShort++ 
                }
                
                if ($className -match "[\u3040-\u309F\u30A0-\u30FF]") { 
                    $results.ClassAnalysis.Japanese++ 
                }
                
                if ($className -match "[\u4E00-\u9FFF]") { 
                    $results.ClassAnalysis.Chinese++ 
                }
                
                if ($className -match "[^\x00-\x7F]") { 
                    $results.ClassAnalysis.Unicode++ 
                }
                
                # Fullwidth Unicode character detection (ａ-ｚ, Ａ-Ｚ, ０-９)
                if ($className -match "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]") {
                    $results.ClassAnalysis.FullwidthChars++
                }
                
                if ($className -match "^[a-zA-Z]+\d+[a-zA-Z0-9]*$" -or 
                    $className -match "^[a-zA-Z]\d[a-zA-Z0-9]+$" -or
                    $className -match "^\d+[a-zA-Z]+\d*$" -or
                    $className -match "^[A-Z][0-9]{2,}[a-zA-Z]*$") {
                    $results.ClassAnalysis.AlphaNumMix++
                }
                
                if ($className -match "^[a-fA-F0-9]{6,}$" -or
                    $className -match "^[A-Z]{2,4}[0-9]{4,}$") {
                    $results.ClassAnalysis.HashLike++
                }
                
                if ($className -match "^[Il1O0]+$" -or 
                    $className -match "^[_]+$" -or 
                    $className -match "^\$+\d*$" -or
                    $className -match "^[lI]{3,}$") {
                    $results.ClassAnalysis.ConfusionChars++
                }
                
                if ($className -match "^[a-z]{5,}$" -and $className -notmatch "(client|module|config|util|helper|manager|handler|mixin|accessor|event|render|player|entity|world|block|item|gui|screen|network|packet)") {
                    $uniqueChars = ($className.ToCharArray() | Sort-Object -Unique).Count
                    $entropy = $uniqueChars / $className.Length
                    if ($entropy -gt 0.5) { 
                        $results.ClassAnalysis.RandomPattern++ 
                    }
                }
                
                if ($className -match "^[a-zA-Z]\d$" -or
                    $className -match "^class\d+$" -or
                    $className -match "^[A-Z]{1,2}\d{1,2}$" -or
                    $className -match "^func\d+$" -or
                    $className -match "^[a-z]{1,2}\d{1,3}$") {
                    $results.ClassAnalysis.Suspicious++
                }
                
                if ($className -match "^[a-z]{3,8}$") {
                    $vowels = ($className.ToCharArray() | Where-Object { $_ -match "[aeiou]" }).Count
                    $consonants = $className.Length - $vowels
                    $vowelRatio = $vowels / $className.Length
                    
                    $hasConsonantCluster = $className -match "[bcdfghjklmnpqrstvwxyz]{3,}"
                    
                    $hasRareCombos = $className -match "(xq|qx|zx|xz|vw|wv|jq|qj|qz|zq|vx|xv|bx|xb|kq|qk|wx|jx|zv|vz|qw|wq)"
                    
                    if ($vowelRatio -lt 0.2) {
                        $results.ClassAnalysis.NoVowelNames++
                    }
                    
                    if ($hasConsonantCluster) {
                        $results.ClassAnalysis.ConsonantCluster++
                    }
                    
                    if (($hasRareCombos -or $hasConsonantCluster) -and $vowelRatio -lt 0.4) {
                        $results.ClassAnalysis.GibberishNames++
                    }
                    
                    if ($className.Length -le 5 -and $vowels -eq 0) {
                        $results.ClassAnalysis.GibberishNames++
                    }
                }
                
                if ($className -match "^[A-Z]{3,6}$" -and $className -notmatch "(HTTP|JSON|XML|HTML|API|GUI|URL|URI|SQL|TCP|UDP|JVM|JAR|ZIP)") {
                    $vowels = ($className.ToCharArray() | Where-Object { $_ -match "[AEIOU]" }).Count
                    if ($vowels -eq 0 -or ($vowels / $className.Length) -lt 0.2) {
                        $results.ClassAnalysis.GibberishNames++
                    }
                }
                
                if ($className -match "^[a-zA-Z]{3,6}$" -and $className -cmatch "[a-z]" -and $className -cmatch "[A-Z]") {
                    if ($className -cmatch "^[a-z][A-Z]" -or $className -cmatch "[A-Z][a-z][A-Z]") {
                        $vowels = ($className.ToLower().ToCharArray() | Where-Object { $_ -match "[aeiou]" }).Count
                        if ($vowels -le 1) {
                            $results.ClassAnalysis.GibberishNames++
                        }
                    }
                }
                
                if ($contentSamples.Count -lt 50 -and $entry.Length -lt 100000 -and $entry.Length -gt 100) {
                    try {
                        $stream = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $stream.CopyTo($ms)
                        $stream.Close()
                        $bytes = $ms.ToArray()
                        $ms.Dispose()
                        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
                        $contentSamples += $ascii
                    } catch {}
                }
            }
        }
        
        $smallClasses = ($classSizes | Where-Object { $_ -lt 200 }).Count
        $results.ClassAnalysis.DummyClasses = $smallClasses
        
        $sortedNames = $classNames | Sort-Object
        $sequentialCount = 0
        for ($i = 1; $i -lt $sortedNames.Count; $i++) {
            $prev = $sortedNames[$i-1]
            $curr = $sortedNames[$i]
            if ($prev.Length -eq $curr.Length -and $prev.Length -le 3) {
                $prevLast = [int][char]$prev[-1]
                $currLast = [int][char]$curr[-1]
                if ($currLast -eq $prevLast + 1) {
                    $sequentialCount++
                }
            }
        }
        $results.ClassAnalysis.Sequential = $sequentialCount
        
        $uniquePackages = $packagePaths | Sort-Object -Unique
        foreach ($pkg in $uniquePackages) {
            $parts = $pkg -split "/"
            foreach ($part in $parts) {
                if ($part -match "^[a-zA-Z]$") {
                    $results.PackageAnalysis.SingleCharPaths++
                }
                if ($part -match "^[a-z]{1,2}\d+$" -or $part -match "^[a-zA-Z]\d[a-zA-Z0-9]+$") {
                    $results.PackageAnalysis.RandomPaths++
                }
            }
        }
        
        $archive.Dispose()
        
        $total = [math]::Max(1, $results.ClassAnalysis.Total)
        
        $numericPct = [math]::Round(($results.ClassAnalysis.Numeric / $total) * 100, 1)
        $unicodePct = [math]::Round(($results.ClassAnalysis.Unicode / $total) * 100, 1)
        $japanesePct = [math]::Round(($results.ClassAnalysis.Japanese / $total) * 100, 1)
        $singleLetterPct = [math]::Round(($results.ClassAnalysis.SingleLetter / $total) * 100, 1)
        $twoLetterPct = [math]::Round(($results.ClassAnalysis.TwoLetter / $total) * 100, 1)
        $shortPct = [math]::Round(($results.ClassAnalysis.VeryShort / $total) * 100, 1)
        $alphaNumPct = [math]::Round(($results.ClassAnalysis.AlphaNumMix / $total) * 100, 1)
        $hashLikePct = [math]::Round(($results.ClassAnalysis.HashLike / $total) * 100, 1)
        $confusionPct = [math]::Round(($results.ClassAnalysis.ConfusionChars / $total) * 100, 1)
        $dummyPct = [math]::Round(($results.ClassAnalysis.DummyClasses / $total) * 100, 1)
        $sequentialPct = [math]::Round(($results.ClassAnalysis.Sequential / $total) * 100, 1)
        $suspiciousPct = [math]::Round(($results.ClassAnalysis.Suspicious / $total) * 100, 1)
        $gibberishPct = [math]::Round(($results.ClassAnalysis.GibberishNames / $total) * 100, 1)
        $noVowelPct = [math]::Round(($results.ClassAnalysis.NoVowelNames / $total) * 100, 1)
        $consonantClusterPct = [math]::Round(($results.ClassAnalysis.ConsonantCluster / $total) * 100, 1)
        $fullwidthPct = [math]::Round(($results.ClassAnalysis.FullwidthChars / $total) * 100, 1)
        
        $score = 0
        
        if ($numericPct -gt 20) { 
            $results.Indicators += "NUMERIC CLASSES: $numericPct% ($($results.ClassAnalysis.Numeric) files)"
            $score += [math]::Min(25, $numericPct * 0.8)
        }
        
        if ($unicodePct -gt 3) { 
            $results.Indicators += "UNICODE CLASSES: $unicodePct%"
            $score += [math]::Min(30, $unicodePct * 3)
        }
        
        if ($japanesePct -gt 0) { 
            $results.Indicators += "JAPANESE OBFUSCATION: $japanesePct% ($($results.ClassAnalysis.Japanese) classes)"
            $score += [math]::Min(40, $japanesePct * 4 + 20)
        }
        
        if ($singleLetterPct -gt 15) { 
            $results.Indicators += "SINGLE-LETTER CLASSES: $singleLetterPct% ($($results.ClassAnalysis.SingleLetter) files)"
            $score += [math]::Min(25, $singleLetterPct * 0.8)
        }
        
        if ($twoLetterPct -gt 20) { 
            $results.Indicators += "TWO-LETTER CLASSES: $twoLetterPct% ($($results.ClassAnalysis.TwoLetter) files)"
            $score += [math]::Min(20, $twoLetterPct * 0.6)
        }
        
        if ($shortPct -gt 30) { 
            $results.Indicators += "SHORT CLASS NAMES: $shortPct%"
            $score += [math]::Min(20, $shortPct * 0.4)
        }
        
        if ($alphaNumPct -gt 10) { 
            $results.Indicators += "ALPHANUMERIC MIX: $alphaNumPct% ($($results.ClassAnalysis.AlphaNumMix) files like 'C8394k')"
            $score += [math]::Min(35, $alphaNumPct * 2)
        }
        
        if ($hashLikePct -gt 5) { 
            $results.Indicators += "HASH-LIKE NAMES: $hashLikePct%"
            $score += [math]::Min(20, $hashLikePct * 2)
        }
        
        if ($confusionPct -gt 3) { 
            $results.Indicators += "CONFUSION CHARS (Il1O0): $confusionPct%"
            $score += [math]::Min(30, $confusionPct * 5)
        }
        
        if ($dummyPct -gt 25) { 
            $results.Indicators += "DUMMY CLASSES (<200B): $dummyPct% ($($results.ClassAnalysis.DummyClasses) files)"
            $score += [math]::Min(20, $dummyPct * 0.5)
        }
        
        if ($sequentialPct -gt 10) { 
            $results.Indicators += "SEQUENTIAL NAMING: $sequentialPct% (a->b->c pattern)"
            $score += [math]::Min(25, $sequentialPct * 1.5)
        }
        
        if ($suspiciousPct -gt 15) { 
            $results.Indicators += "SUSPICIOUS PATTERNS: $suspiciousPct%"
            $score += [math]::Min(20, $suspiciousPct * 0.8)
        }
        
        if ($gibberishPct -gt 5) {
            $results.Indicators += "GIBBERISH NAMES: $gibberishPct% ($($results.ClassAnalysis.GibberishNames) files like 'ruwj', 'xkqp')"
            $score += [math]::Min(40, $gibberishPct * 3)
        }
        
        if ($noVowelPct -gt 8) {
            $results.Indicators += "NO-VOWEL NAMES: $noVowelPct% ($($results.ClassAnalysis.NoVowelNames) files without vowels)"
            $score += [math]::Min(30, $noVowelPct * 2)
        }
        
        if ($consonantClusterPct -gt 10) {
            $results.Indicators += "CONSONANT CLUSTERS: $consonantClusterPct% ($($results.ClassAnalysis.ConsonantCluster) files with 'bcdfg' patterns)"
            $score += [math]::Min(25, $consonantClusterPct * 1.5)
        }
        
        if ($fullwidthPct -gt 0 -or $results.ClassAnalysis.FullwidthChars -gt 0) {
            $results.Indicators += "FULLWIDTH UNICODE CHARS: $fullwidthPct% ($($results.ClassAnalysis.FullwidthChars) files with ａｂｃ/ＡＢＣ/０１２ chars)"
            $score += [math]::Min(50, 30 + ($results.ClassAnalysis.FullwidthChars * 5))
        }
        
        if ($results.PackageAnalysis.SingleCharPaths -gt 5) {
            $results.Indicators += "SINGLE-CHAR PACKAGES: $($results.PackageAnalysis.SingleCharPaths) (a/b/c paths)"
            $score += [math]::Min(15, $results.PackageAnalysis.SingleCharPaths * 2)
        }
        if ($results.PackageAnalysis.RandomPaths -gt 3) {
            $results.Indicators += "RANDOM PACKAGE PATHS: $($results.PackageAnalysis.RandomPaths)"
            $score += [math]::Min(15, $results.PackageAnalysis.RandomPaths * 3)
        }
        
        $allContent = $contentSamples -join " "
        
        # Fullwidth Unicode character detection in content (ａ-ｚ, Ａ-Ｚ, ０-９)
        # These characters are often used to bypass string detection/filters
        $fullwidthPattern = "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]+"
        $fullwidthMatches = [regex]::Matches($allContent, $fullwidthPattern)
        if ($fullwidthMatches.Count -gt 0) {
            $uniqueFullwidth = @{}
            foreach ($match in $fullwidthMatches) {
                $uniqueFullwidth[$match.Value] = $true
            }
            $fullwidthExamples = ($uniqueFullwidth.Keys | Select-Object -First 5) -join ", "
            $results.Indicators += "FULLWIDTH STRINGS IN CONTENT: $($fullwidthMatches.Count) matches (e.g. $fullwidthExamples)"
            $results.Detected += @{
                Name = "Fullwidth Unicode Obfuscation"
                Pattern = "Content contains $($fullwidthMatches.Count) fullwidth character sequences"
                Severity = "HIGH"
            }
            $score += [math]::Min(40, 20 + ($fullwidthMatches.Count * 3))
        }
        
        $cheatObfuscators = @{
            "Skidfuscator" = @("dev/skidfuscator", "Skidfuscator", "skidfuscator.dev", "dev.skidfuscator")
            "Paramorphism" = @("Paramorphism", "paramorphism-", "dev/paramorphism", "paramorphism.dev")
            "Radon" = @("ItzSomebody/Radon", "me/itzsomebody/radon", "Radon Obfuscator", "radon.obf")
            "Caesium" = @("sim0n/Caesium", "Caesium Obfuscator", "dev/sim0n/caesium", "caesium.obf")
            "Bozar" = @("vimasig/Bozar", "Bozar Obfuscator", "com/bozar", "bozar.dev")
            "Branchlock" = @("Branchlock", "branchlock.dev", "com/branchlock")
            "Binscure" = @("Binscure", "com/binscure", "binscure.dev")
            "SuperBlaubeere" = @("superblaubeere", "superblaubeere27", "sb27.obf")
            "Qprotect" = @("Qprotect", "QProtect", "mdma.dev/qprotect", "qprotect.dev")
            "Zelix" = @("ZKMFLOW", "ZKM", "ZelixKlassMaster", "com/zelix")
            "Stringer" = @("StringerJavaObfuscator", "com/licel/stringer", "stringer.obf")
            "JNIC" = @("JNIC", "jnic.obf", "jnic-obfuscator")
            "Scuti" = @("ScutiObf", "scuti.obf", "scutijava")
            "Smoke" = @("SmokeObf", "smoke.obf", "smokeobfuscator")
        }
        
        $legitObfuscators = @{
            "ProGuard" = @("proguard", "ProGuard")
            "Allatori" = @("allatori", "ALLATORIxDEMO", "com/allatori")
            "yGuard" = @("yGuard", "yworks", "com/yworks")
            "DashO" = @("DashO", "PreEmptive", "preemptive")
            "R8" = @("com.android.tools.r8", "r8.mapping")
        }
        
        foreach ($obfName in $cheatObfuscators.Keys) {
            foreach ($pattern in $cheatObfuscators[$obfName]) {
                if ($allContent -match [regex]::Escape($pattern)) {
                    $results.Detected += @{
                        Name = $obfName
                        Pattern = $pattern
                        Severity = "CRITICAL"
                    }
                    $score += 45
                    break
                }
            }
        }
        
        foreach ($obfName in $legitObfuscators.Keys) {
            foreach ($pattern in $legitObfuscators[$obfName]) {
                if ($allContent -match [regex]::Escape($pattern)) {
                    $results.Detected += @{
                        Name = "$obfName (Legit)"
                        Pattern = $pattern
                        Severity = "INFO"
                    }
                    break
                }
            }
        }
        
        $results.Score = [math]::Min(100, [int]$score)
        
        if ($results.Score -ge 70) { $results.RiskLevel = "CRITICAL" }
        elseif ($results.Score -ge 50) { $results.RiskLevel = "HIGH" }
        elseif ($results.Score -ge 30) { $results.RiskLevel = "MEDIUM" }
        elseif ($results.Score -ge 15) { $results.RiskLevel = "LOW" }
        else { $results.RiskLevel = "CLEAN" }
        
        if ($results.Score -gt 35 -and ($results.Detected | Where-Object { $_.Severity -eq "CRITICAL" }).Count -eq 0) {
            $results.Detected += @{
                Name = "Unknown/Custom Obfuscator"
                Pattern = "Heuristic detection (score: $($results.Score))"
                Severity = $results.RiskLevel
            }
        }
        
    } catch {}
    
    return $results
}

$script:LegitModSlugs = @(
    "lithium", "sodium", "phosphor", "starlight", "indium", "iris",
    "optifine", "optifabric", "fabric-api", "modmenu", "cloth-config",
    "replaymod", "simple-voice-chat", "worldedit", "litematica",
    "minihud", "malilib", "ok-zoomer", "logical-zoom", "zoomify",
    "emi", "jei", "rei", "waila", "jade", "hwyla",
    "xaeros-minimap", "xaeros-world-map", "journeymap",
    "dynamic-fps", "ferritecore", "entityculling", "krypton", "c2me",
    "lazydfu", "dashloader", "memory-leak-fix", "smoothboot", "spark"
)

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
    
    $foundStrings = [System.Collections.Generic.HashSet[string]]::new()
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $content = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        foreach ($cheatString in $script:CheatStrings) {
            if ($content -match [regex]::Escape($cheatString)) {
                $foundStrings.Add($cheatString) | Out-Null
            }
        }
        
        # Check for fullwidth Unicode characters (ａ-ｚ, Ａ-Ｚ, ０-９)
        # These are often used to bypass string filters
        $fullwidthPattern = "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}"
        if ($content -match $fullwidthPattern) {
            $fullwidthMatches = [regex]::Matches($content, $fullwidthPattern)
            foreach ($match in $fullwidthMatches) {
                $foundStrings.Add("FULLWIDTH_UNICODE: $($match.Value)") | Out-Null
            }
        }
        
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $entries = $zip.Entries | Where-Object { $_.Name -match '\.(class|json|jar)$' }
        
        foreach ($entry in $entries) {
            if ($entry.Name -like "*.jar") {
                try {
                    $ms = New-Object System.IO.MemoryStream
                    $entry.Open().CopyTo($ms)
                    $ms.Position = 0
                    $nestedZip = New-Object System.IO.Compression.ZipArchive($ms, [System.IO.Compression.ZipArchiveMode]::Read)
                    foreach ($nestedEntry in $nestedZip.Entries) {
                        if ($nestedEntry.Name -match '\.(class|json)$') {
                            $reader = New-Object System.IO.StreamReader($nestedEntry.Open(), [System.Text.Encoding]::UTF8)
                            $nestedContent = $reader.ReadToEnd().ToLower()
                            $reader.Close()
                            foreach ($string in $script:CheatStrings) {
                                if ($nestedContent -match [regex]::Escape($string.ToLower())) {
                                    $foundStrings.Add($string) | Out-Null
                                }
                            }
                        }
                    }
                } catch {}
                continue
            }
            
            try {
                $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
                $entryContent = $reader.ReadToEnd()
                $reader.Close()
                foreach ($string in $script:CheatStrings) {
                    if ($entryContent -match [regex]::Escape($string)) {
                        $foundStrings.Add($string) | Out-Null
                    }
                }
                
                # Check for fullwidth Unicode characters (ａ-ｚ, Ａ-Ｚ, ０-９) in content
                $fullwidthPattern = "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}"
                if ($entryContent -match $fullwidthPattern) {
                    $matches = [regex]::Matches($entryContent, $fullwidthPattern)
                    foreach ($match in $matches) {
                        $foundStrings.Add("FULLWIDTH_UNICODE: $($match.Value)") | Out-Null
                    }
                }
            } catch {}
        }
        $zip.Dispose()
    } catch {}
    
    return $foundStrings
}

function Get-ModInfoFromJar {
    param([string]$JarPath)
    
    $modInfo = @{ ModId = ""; Name = ""; Version = ""; ModLoader = "" }
    
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($JarPath)
        
        if ($entry = $zip.Entries | Where-Object { $_.Name -eq 'fabric.mod.json' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
            $fabricData = $reader.ReadToEnd() | ConvertFrom-Json -ErrorAction SilentlyContinue
            $reader.Close()
            $modInfo.ModId = $fabricData.id
            $modInfo.Name = $fabricData.name
            $modInfo.Version = $fabricData.version
            $modInfo.ModLoader = "Fabric"
            $zip.Dispose()
            return $modInfo
        }
        
        if ($entry = $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/mods.toml' } | Select-Object -First 1) {
            $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
            $tomlContent = $reader.ReadToEnd()
            $reader.Close()
            if ($tomlContent -match 'modId\s*=\s*"([^"]+)"') { $modInfo.ModId = $matches[1] }
            if ($tomlContent -match 'displayName\s*=\s*"([^"]+)"') { $modInfo.Name = $matches[1] }
            if ($tomlContent -match 'version\s*=\s*"([^"]+)"') { $modInfo.Version = $matches[1] }
            $modInfo.ModLoader = "Forge/NeoForge"
            $zip.Dispose()
            return $modInfo
        }
        
        $zip.Dispose()
    } catch {}
    
    return $modInfo
}

function Check-DisallowedMods {
    param([string]$ModsPath)
    
    $jarFiles = Get-ChildItem -Path $ModsPath -Filter *.jar -ErrorAction SilentlyContinue
    
    foreach ($file in $jarFiles) {
        $fileName = $file.Name.ToLower()
        $modInfo = Get-ModInfoFromJar -JarPath $file.FullName
        
        foreach ($modSlug in $script:DisallowedMods.Keys) {
            $modData = $script:DisallowedMods[$modSlug]
            $isDisallowed = $false
            
            foreach ($name in $modData.Names) {
                if ($fileName -match [regex]::Escape($name.ToLower()) -or 
                    $fileName -match [regex]::Escape($modSlug.ToLower())) {
                    $isDisallowed = $true
                    break
                }
            }
            
            if (-not $isDisallowed) {
                if ($modInfo.ModId -and $modInfo.ModId.ToLower() -match $modSlug.ToLower()) {
                    $isDisallowed = $true
                }
            }
            
            if ($isDisallowed) {
                $script:DisallowedModsFound += @{
                    FileName = $file.Name
                    ModName = $modData.Names[0]
                }
                break
            }
        }
    }
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
    
    Check-DisallowedMods -ModsPath $ModsPath
    
    $counter = 0
    $total = $jarFiles.Count
    
    foreach ($file in $jarFiles) {
        $counter++
        Write-ProgressBar -Current $counter -Total $total -Activity $file.Name
        
        $hash = Get-SHA1Hash -FilePath $file.FullName
        $obfResult = Test-Obfuscator -FilePath $file.FullName
        $hasCriticalObfuscator = ($obfResult.Detected | Where-Object { $_.Severity -eq "CRITICAL" }).Count -gt 0
        $isObfuscated = ($obfResult.Score -gt 60) -or $hasCriticalObfuscator
        
        if ($isObfuscated) {
            $script:ObfuscatedModsList += @{
                FileName = $file.Name
                FilePath = $file.FullName
                Score = $obfResult.Score
                Detected = $obfResult.Detected
            }
        }
        
        $modrinthResult = Test-ModrinthHash -Hash $hash
        if ($modrinthResult) {
            $script:VerifiedMods += @{
                FileName = $file.Name
                ModName = $modrinthResult.Name
                Source = $modrinthResult.Source
                URL = $modrinthResult.URL
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
            }
            continue
        }
        
        $megabaseResult = Test-MegabaseHash -Hash $hash
        if ($megabaseResult) {
            $script:VerifiedMods += @{
                FileName = $file.Name
                ModName = $megabaseResult.Name
                Source = $megabaseResult.Source
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
            }
            continue
        }
        
        $cheatStringsFound = Test-CheatStrings -FilePath $file.FullName
        if ($cheatStringsFound.Count -gt 0) {
            $script:CheatMods += @{
                FileName = $file.Name
                FilePath = $file.FullName
                StringsFound = @($cheatStringsFound)
                InDependency = $false
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
            }
            continue
        }
        
        $downloadSource = Get-ZoneIdentifier -FilePath $file.FullName
        
        $script:UnknownMods += @{
            FileName = $file.Name
            FilePath = $file.FullName
            ZoneId = $downloadSource
            Hash = $hash
            IsObfuscated = $isObfuscated
            ObfuscatorInfo = $obfResult
        }
    }
    
    $toMoveToCheat = @()
    foreach ($mod in $script:UnknownMods) {
        $hasCritical = ($mod.ObfuscatorInfo.Detected | Where-Object { $_.Severity -eq "CRITICAL" }).Count -gt 0
        if (($mod.IsObfuscated -and $mod.ObfuscatorInfo.Score -gt 80) -or $hasCritical) {
            $reasons = @("HEAVY OBFUSCATION (Score: $($mod.ObfuscatorInfo.Score)%)")
            if ($hasCritical) {
                $critObf = ($mod.ObfuscatorInfo.Detected | Where-Object { $_.Severity -eq "CRITICAL" } | Select-Object -First 1).Name
                $reasons += "Cheat Obfuscator: $critObf"
            }
            if ($mod.ObfuscatorInfo.Indicators.Count -gt 0) {
                $reasons += $mod.ObfuscatorInfo.Indicators | Select-Object -First 3
            }
            
            $script:CheatMods += @{
                FileName = $mod.FileName
                FilePath = $mod.FilePath
                StringsFound = $reasons
                InDependency = $false
                IsObfuscated = $true
                ObfuscatorInfo = $mod.ObfuscatorInfo
            }
            $toMoveToCheat += $mod
        }
    }
    $script:UnknownMods = @($script:UnknownMods | Where-Object { $_ -notin $toMoveToCheat })
    
    Write-Host "`r$(' ' * 80)`r" -NoNewline
    
    if ($script:VerifiedMods.Count -gt 0) {
        Write-Host ""
        Write-Host "  [+] " -NoNewline -ForegroundColor $script:Colors.Success
        Write-Host "VERIFIED MODS ($($script:VerifiedMods.Count))" -ForegroundColor $script:Colors.Success
        Write-Host "  ----------------------------------------------------" -ForegroundColor $script:Colors.Dim
        foreach ($mod in $script:VerifiedMods) {
            Write-Host "    [+] " -NoNewline -ForegroundColor $script:Colors.Success
            Write-Host ("{0,-35}" -f $mod.ModName) -NoNewline -ForegroundColor $script:Colors.Info
            Write-Host " $($mod.FileName)" -NoNewline -ForegroundColor $script:Colors.Dim
            if ($mod.IsObfuscated) {
                Write-Host " (Obfuscated)" -ForegroundColor $script:Colors.Warning
            } else {
                Write-Host " (Clean)" -ForegroundColor $script:Colors.Success
            }
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
            if ($mod.IsObfuscated) {
                Write-Host " (Obfuscated: $($mod.ObfuscatorInfo.Score)%)" -NoNewline -ForegroundColor $script:Colors.Error
                Write-Host " [$($mod.ObfuscatorInfo.RiskLevel)]" -ForegroundColor $(if ($mod.ObfuscatorInfo.RiskLevel -eq "CRITICAL") { "Red" } elseif ($mod.ObfuscatorInfo.RiskLevel -eq "HIGH") { "DarkRed" } else { "Yellow" })
                if ($mod.ObfuscatorInfo.Indicators.Count -gt 0) {
                    foreach ($indicator in $mod.ObfuscatorInfo.Indicators) {
                        Write-Host "        -> " -NoNewline -ForegroundColor $script:Colors.Dim
                        Write-Host $indicator -ForegroundColor $script:Colors.Warning
                    }
                }
            } else {
                Write-Host " (Clean)" -NoNewline -ForegroundColor $script:Colors.Success
                Write-Host ""
            }
            if ($mod.ZoneId) {
                Write-Host "        Source: " -NoNewline -ForegroundColor $script:Colors.Dim
                Write-Host $mod.ZoneId -ForegroundColor $script:Colors.Dim
            }
        }
    }
    
    if ($script:DisallowedModsFound.Count -gt 0) {
        Write-Host ""
        Write-Host "  [!] " -NoNewline -ForegroundColor $script:Colors.Error
        Write-Host "DISALLOWED MODS ($($script:DisallowedModsFound.Count))" -ForegroundColor $script:Colors.Error
        Write-Host "  ====================================================" -ForegroundColor $script:Colors.Error
        foreach ($mod in $script:DisallowedModsFound) {
            Write-Host "    [X] " -NoNewline -ForegroundColor $script:Colors.Error
            Write-Host "$($mod.FileName)" -NoNewline -ForegroundColor $script:Colors.Error
            Write-Host " ($($mod.ModName))" -ForegroundColor $script:Colors.Warning
        }
    }
    
    if ($script:CheatMods.Count -gt 0) {
        Write-Host ""
        Write-Host "  [X] " -NoNewline -ForegroundColor $script:Colors.Error
        Write-Host "CHEAT MODS DETECTED ($($script:CheatMods.Count))" -ForegroundColor $script:Colors.Error
        Write-Host "  ====================================================" -ForegroundColor $script:Colors.Error
        foreach ($mod in $script:CheatMods) {
            Write-Host ""
            Write-Host "    [X] " -NoNewline -ForegroundColor $script:Colors.Error
            Write-Host $mod.FileName -NoNewline -ForegroundColor $script:Colors.Error
            if ($mod.IsObfuscated -and $mod.ObfuscatorInfo) {
                Write-Host " (Obfuscated: $($mod.ObfuscatorInfo.Score)%)" -ForegroundColor $script:Colors.Warning
            } else {
                Write-Host ""
            }
            
            if ($mod.InDependency -and $mod.DependencyName) {
                Write-Host "        Hidden in: " -NoNewline -ForegroundColor $script:Colors.Dim
                Write-Host $mod.DependencyName -ForegroundColor $script:Colors.Error
            }
            
            Write-Host "        Detected strings:" -ForegroundColor $script:Colors.Warning
            foreach ($str in @($mod.StringsFound)) {
                Write-Host "          -> " -NoNewline -ForegroundColor $script:Colors.Dim
                Write-Host $str -ForegroundColor $script:Colors.Primary
            }
            
            if ($mod.IsObfuscated -and $mod.ObfuscatorInfo -and $mod.ObfuscatorInfo.Indicators.Count -gt 0) {
                Write-Host "        Obfuscation patterns:" -ForegroundColor $script:Colors.Warning
                foreach ($indicator in $mod.ObfuscatorInfo.Indicators) {
                    Write-Host "          -> $indicator" -ForegroundColor $script:Colors.Dim
                }
            }
        }
    }
}

function Get-MinecraftUptime {
    Write-Section "Minecraft Process Status" "MC"
    
    $process = Get-Process javaw -ErrorAction SilentlyContinue
    if (-not $process) { $process = Get-Process java -ErrorAction SilentlyContinue }
    
    if ($process) {
        try {
            $startTime = $process.StartTime
            $elapsed = (Get-Date) - $startTime
            Write-Result "INFO" "$($process.Name) (PID: $($process.Id))" "Running for $($elapsed.Hours)h $($elapsed.Minutes)m $($elapsed.Seconds)s"
            Write-Result "INFO" "Memory Usage" "$([math]::Round($process.WorkingSet64 / 1MB, 2)) MB"
        } catch {
            Write-Result "INFO" "Minecraft process found" "PID: $($process.Id)"
        }
    } else {
        Write-Result "WARN" "No Minecraft process detected"
    }
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
    Check-DefenderExclusions
    Check-ScheduledTasks
    Check-PowerShellLogging
    Check-StartupFolder
    Check-SuspiciousProcesses
    Check-DNSCache
    Check-BAMRegistry
    Check-ShimCache
    Check-Amcache
    Check-JumpLists
    Check-RecentJarFiles
    Check-JavaArguments
    Check-AdvancedJVMArgs
    
    Check-JavaProcessMemory
    Check-LocalhostWebServer
    Check-PrefetchFiles
    Check-DoomsdayRegistry
    
    Check-FabricForgeInjection
    
    Write-Section "System Analysis Summary" "SUM"
    
    if ($script:SystemFindings.Count -gt 0) {
        Write-Result "WARN" "Total findings" "$($script:SystemFindings.Count) suspicious item(s) detected"
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
    
    $defaultPath = "$env:APPDATA\.minecraft\mods"
    
    Write-Host ""
    Write-Host "  Enter mods folder path " -NoNewline -ForegroundColor $script:Colors.Secondary
    Write-Host "(Enter for default):" -ForegroundColor $script:Colors.Dim
    Write-Host "  Default: $defaultPath" -ForegroundColor $script:Colors.Dim
    Write-Host "  Path: " -NoNewline -ForegroundColor $script:Colors.Secondary
    $inputPath = Read-Host
    
    if ([string]::IsNullOrWhiteSpace($inputPath)) { $inputPath = $defaultPath }
    
    Analyze-ModsFolder -ModsPath $inputPath
    
    Write-Section "Mod Analysis Summary" "SUM"
    Write-Result "INFO" "Verified" "$($script:VerifiedMods.Count) mod(s)"
    Write-Result "INFO" "Unknown" "$($script:UnknownMods.Count) mod(s)"
    
    if ($script:DisallowedModsFound.Count -gt 0) {
        Write-Result "WARN" "Disallowed" "$($script:DisallowedModsFound.Count) mod(s)"
    }
    
    $totalMods = $script:VerifiedMods.Count + $script:UnknownMods.Count + $script:CheatMods.Count
    $obfuscatedVerified = ($script:VerifiedMods | Where-Object { $_.IsObfuscated }).Count
    $obfuscatedUnknown = ($script:UnknownMods | Where-Object { $_.IsObfuscated }).Count
    $obfuscatedCheat = ($script:CheatMods | Where-Object { $_.IsObfuscated }).Count
    $totalObfuscated = $obfuscatedVerified + $obfuscatedUnknown + $obfuscatedCheat
    
    Write-Host ""
    Write-Host "  [OBFUSCATION ANALYSIS]" -ForegroundColor $script:Colors.Secondary
    Write-Result "INFO" "Obfuscated" "$totalObfuscated / $totalMods mod(s)"
    if ($obfuscatedUnknown -gt 0) {
        Write-Result "WARN" "  Unknown (Obf)" "$obfuscatedUnknown mod(s) - SUSPICIOUS"
    }
    
    Write-Host ""
    
    if ($script:CheatMods.Count -gt 0) {
        Write-Result "WARN" "CHEATS DETECTED" "$($script:CheatMods.Count) suspicious mod(s)"
    } else {
        Write-Result "PASS" "No cheat mods detected"
    }
}

# === MAIN ENTRY POINT ===
# Skip auto-run if $env:YUMIKO_TEST is set (for unit testing)
if ($env:YUMIKO_TEST -eq "1") {
    Write-Host "[TEST MODE] Functions loaded - skipping auto-run" -ForegroundColor Cyan
    return
}

Write-Banner

if (-not (Test-AdminPrivileges)) {
    Write-Host "    [!] WARNING: Running without Administrator privileges" -ForegroundColor "Yellow"
    Write-Host "        Some system checks may return incomplete results." -ForegroundColor "DarkGray"
    Write-Host ""
}

Write-Host "  Select analysis mode:" -ForegroundColor $script:Colors.Secondary
Write-Host "    [1] Full System + Mod Analysis (Recommended)" -ForegroundColor $script:Colors.Info
Write-Host "    [2] Mod Analysis Only" -ForegroundColor $script:Colors.Info
Write-Host "    [3] System Bypass Detection Only" -ForegroundColor $script:Colors.Info
Write-Host "    [4] Exit" -ForegroundColor $script:Colors.Dim
Write-Host ""
Write-Host "  Choice [1-4]: " -NoNewline -ForegroundColor $script:Colors.Secondary
$choice = Read-Host

switch ($choice) {
    "1" {
        Run-SystemAnalysis
        Run-ModAnalysis
    }
    "2" {
        Run-ModAnalysis
    }
    "3" {
        Run-SystemAnalysis
    }
    "4" {
        Write-Host ""
        Write-Host "  Thank you for using Yumiko Mod Analyzer!" -ForegroundColor $script:Colors.Success
        exit 0
    }
    default {
        Write-Host ""
        Write-Host "    [!] Invalid choice. Running full analysis..." -ForegroundColor $script:Colors.Warning
        Run-SystemAnalysis
        Run-ModAnalysis
    }
}

Write-Host ""
Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
Write-Host "    ANALYSIS COMPLETE - Yumiko v$($script:Config.Version) $($script:Config.Edition)" -ForegroundColor $script:Colors.Success
Write-Host "  ===========================================================" -ForegroundColor $script:Colors.Primary
Write-Host ""
Write-Host "  Press any key to exit..." -ForegroundColor $script:Colors.Dim
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
