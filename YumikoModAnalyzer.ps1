param(
    [switch]$SkipSystemCheck,
    [switch]$SkipModCheck,
    [string]$ModPath,
    [switch]$AutoFix,
    [switch]$Silent
)
$script:Config = @{
    Version = "4.5.1"
    Author = "Veridon"
    Name = "Yumiko Mod Analyzer"
    Edition = "FREE ULTIMATE"
    ModrinthAPI = "https://api.modrinth.com/v2"
    MegabaseAPI = "https://megabase.vercel.app/api/query"
    CheatSignatures = "600+"
    SystemChecks = "40+"
    Obfuscators = "20+"
    ObfuscationPatterns = "19+"
    Features = "JVM Scan, Bypass Detection, String Analysis, Advanced Obfuscation Detection, Doomsday Detection, Memory Forensics, Prefetch Analysis, Fabric/Forge Injection Detection, Disallowed Mods, Bytecode Analysis, Entropy Analysis, Mixin Config Analysis, String Encoding Detection, Refmap Analysis, Native Library Detection, Advanced Bytecode Patterns"
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
    $isSelfDestructDetected = $Message -eq "Self Destruct Detected"
    if ($isSelfDestructDetected) {
        $color = $script:Colors.Error
    }
    Write-Host "    [$icon] " -NoNewline -ForegroundColor $color
    if ($isSelfDestructDetected) {
        $supportsAnsi = [bool]($env:WT_SESSION -or $env:TERM)
        if ($supportsAnsi) {
            $ansiBoldRed = "$([char]27)[1;31m"
            $ansiReset = "$([char]27)[0m"
            Write-Host "$ansiBoldRed$Message$ansiReset" -NoNewline
        } else {
            Write-Host $Message -NoNewline -ForegroundColor $script:Colors.Error
        }
    } else {
        Write-Host $Message -NoNewline -ForegroundColor $script:Colors.Info
    }
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
$script:ModURLFindings = @()
$script:BytecodeFindings = @()
$script:SelfDestructFindings = @()
$script:EntropyFindings = @()
$script:MixinFindings = @()
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
    # Only uniquely-Argon strings - generic Java/Minecraft strings removed to prevent false positives.
    # ("panic", "ImmediatelyFast", "Thread.sleep", "Runtime.getRuntime", "saveProfile" all appear in
    #  countless legitimate mods and would trigger constant false alarms.)
    $selfDestructSignatures = @(
        "dev/lvstrng/argon/module/modules/client/SelfDestruct",
        "dev.lvstrng.argon.module.modules.client.SelfDestruct",
        "dev/lvstrng/argon",
        "replaceModFile",
        "getCurrentJarPath",
        "resetModifiedDate",
        "5ZwdcRci",
        "cdn.modrinth.com/data/5ZwdcRci"
    )
    $allSignatures = $doomsdaySignatures + $cheatSignatures
    try {
        $javaProcesses = @()
        $javaProcesses += Get-Process javaw -ErrorAction SilentlyContinue
        $javaProcesses += Get-Process java -ErrorAction SilentlyContinue
        if ($javaProcesses.Count -eq 0) {
            Write-Result "INFO" "No Java processes running"
            Write-Result "INFO" "Start Minecraft to scan for Doomsday/Selfdestruct in memory"
            return
        }
        Write-Result "INFO" "Found $($javaProcesses.Count) Java process(es) - deep memory scan..."
        foreach ($proc in $javaProcesses) {
            try {
                $wmi = Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction SilentlyContinue
                $cmdLine = if ($wmi) { $wmi.CommandLine } else { "" }
                $selfCmdlineHit = $false
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
                foreach ($sig in $selfDestructSignatures) {
                    if ($cmdLine -match [regex]::Escape($sig)) {
                        Write-Result "FOUND" "Self Destruct Detected" "$sig (PID: $($proc.Id))"
                        $script:SystemFindings += @{
                            Type = "SelfDestructMemory"
                            Description = "Selfdestruct signature in cmdline: $sig"
                            PID = $proc.Id
                            Severity = "CRITICAL"
                        }
                        $selfCmdlineHit = $true
                        $found = $true
                        break
                    }
                }
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
                            $selfMemoryHit = $selfCmdlineHit
                            $chunkSize = 100 * 1024 * 1024  # 100MB chunks for thorough scanning
                            $maxRegionSize = 256 * 1024 * 1024  # Scan regions up to 256MB
                            while ([MemoryScanner]::VirtualQueryEx($hProcess, $address, [ref]$memInfo, $memInfoSize) -ne 0) {
                                if ($memInfo.State -eq [MemoryScanner]::MEM_COMMIT -and 
                                    [MemoryScanner]::IsReadableProtection($memInfo.Protect)) {
                                    $regionSize = $memInfo.RegionSize.ToInt64()
                                    if ($regionSize -lt $maxRegionSize -and $regionSize -gt 0) {
                                        $buffer = New-Object byte[] ([Math]::Min($regionSize, $chunkSize))
                                        $bytesRead = 0
                                        if ([MemoryScanner]::ReadProcessMemory($hProcess, $memInfo.BaseAddress, $buffer, $buffer.Length, [ref]$bytesRead)) {
                                            $regionsScanned++
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
                                            if (-not $selfMemoryHit) {
                                                foreach ($sig in $selfDestructSignatures) {
                                                    if ($memString.IndexOf($sig, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                                                        Write-Result "FOUND" "Self Destruct Detected" "$sig (PID: $($proc.Id))"
                                                        $script:SystemFindings += @{
                                                            Type = "SelfDestructMemory"
                                                            Description = "Selfdestruct signature in RAM: $sig"
                                                            PID = $proc.Id
                                                            Address = $memInfo.BaseAddress.ToString("X")
                                                            Severity = "CRITICAL"
                                                        }
                                                        $selfMemoryHit = $true
                                                        $found = $true
                                                        break
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                $nextAddress = $memInfo.BaseAddress.ToInt64() + $memInfo.RegionSize.ToInt64()
                                if ($nextAddress -le $address.ToInt64()) { break }
                                $address = [IntPtr]$nextAddress
                                if ($regionsScanned -gt 5000) { break }
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
                    try {
                        $modules = $proc.Modules | ForEach-Object { $_.ModuleName.ToLower() }
                        $selfModuleHit = $selfCmdlineHit
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
                            if (-not $selfModuleHit) {
                                foreach ($sig in $selfDestructSignatures) {
                                    if ($mod -match [regex]::Escape($sig.ToLower())) {
                                        Write-Result "FOUND" "Self Destruct Detected" "$mod (PID: $($proc.Id))"
                                        $script:SystemFindings += @{
                                            Type = "SelfDestructModule"
                                            Description = "Selfdestruct module: $mod"
                                            PID = $proc.Id
                                            Severity = "CRITICAL"
                                        }
                                        $selfModuleHit = $true
                                        $found = $true
                                        break
                                    }
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
    Write-Section "Localhost Web Server Detection (Cheat GUI)" "WEB"
    try {
        $javaPids = @()
        $javaProcesses = @()
        $javaProcesses += Get-Process javaw -ErrorAction SilentlyContinue
        $javaProcesses += Get-Process java -ErrorAction SilentlyContinue
        $javaPids = $javaProcesses | ForEach-Object { $_.Id }
        if ($javaPids.Count -eq 0) {
            Write-Result "CLEAN" "No Java processes running"
            return
        }
        Write-Result "INFO" "Found $($javaPids.Count) Java process(es) - scanning their ports..."
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
                     Where-Object { 
                         ($_.LocalAddress -eq "127.0.0.1" -or $_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::" -or $_.LocalAddress -eq "::1") -and
                         ($javaPids -contains $_.OwningProcess)
                     } |
                     Sort-Object LocalPort
        if ($null -eq $listeners -or $listeners.Count -eq 0) {
            Write-Result "CLEAN" "Java processes not listening on localhost"
            return
        }
        $foundServer = $false
        foreach ($listener in $listeners) {
            $port = $listener.LocalPort
            $bindAddr = $listener.LocalAddress
            $ownerPid = $listener.OwningProcess
            $processName = "Unknown"
            $processPath = ""
            try {
                $proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
                if ($proc) {
                    $processName = $proc.ProcessName
                    try { $processPath = $proc.Path } catch {}
                }
            } catch {}
            $isWebServer = $false
            $httpStatus = ""
            $serverHeader = ""
            $detectionMethod = ""
            # Probe HTTP on both 127.0.0.1 and the actual bind address
            $probeAddresses = @("127.0.0.1")
            if ($bindAddr -eq "0.0.0.0") { $probeAddresses += "0.0.0.0" }
            foreach ($probeAddr in $probeAddresses) {
                if ($isWebServer) { break }
                try {
                    $webRequest = [System.Net.WebRequest]::Create("http://${probeAddr}:$port/")
                    $webRequest.Timeout = 1500
                    $webRequest.Method = "HEAD"
                    try {
                        $response = $webRequest.GetResponse()
                        $httpStatus = "HTTP $([int]$response.StatusCode)"
                        $serverHeader = $response.Headers["Server"]
                        $response.Close()
                        $isWebServer = $true
                        $detectionMethod = "HTTP HEAD"
                    } catch [System.Net.WebException] {
                        $errorResponse = $_.Exception.Response
                        if ($null -ne $errorResponse) {
                            $httpStatus = "HTTP $([int]$errorResponse.StatusCode)"
                            $serverHeader = $errorResponse.Headers["Server"]
                            $isWebServer = $true
                            $detectionMethod = "HTTP HEAD (error response)"
                        }
                    }
                } catch {}
            }
            # If HEAD failed, try GET (some WS servers respond to GET with upgrade headers)
            if (-not $isWebServer) {
                try {
                    $webRequest = [System.Net.WebRequest]::Create("http://127.0.0.1:$port/")
                    $webRequest.Timeout = 1500
                    $webRequest.Method = "GET"
                    try {
                        $response = $webRequest.GetResponse()
                        $httpStatus = "HTTP $([int]$response.StatusCode)"
                        $serverHeader = $response.Headers["Server"]
                        $upgradeHeader = $response.Headers["Upgrade"]
                        $response.Close()
                        $isWebServer = $true
                        $detectionMethod = if ($upgradeHeader -match "(?i)websocket") { "WebSocket endpoint" } else { "HTTP GET" }
                    } catch [System.Net.WebException] {
                        $errorResponse = $_.Exception.Response
                        if ($null -ne $errorResponse) {
                            $httpStatus = "HTTP $([int]$errorResponse.StatusCode)"
                            $serverHeader = $errorResponse.Headers["Server"]
                            $isWebServer = $true
                            $detectionMethod = "HTTP GET (error response)"
                        }
                    }
                } catch {}
            }
            # TCP connect test: if HTTP probes all failed, at least verify the port accepts connections
            if (-not $isWebServer) {
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $connectResult = $tcp.BeginConnect("127.0.0.1", $port, $null, $null)
                    $connected = $connectResult.AsyncWaitHandle.WaitOne(1000)
                    if ($connected -and $tcp.Connected) {
                        $isWebServer = $true
                        $httpStatus = "TCP OPEN"
                        $detectionMethod = "TCP connect (non-HTTP)"
                    }
                    $tcp.Close()
                } catch {}
            }
            if ($isWebServer) {
                $bindInfo = if ($bindAddr -eq "0.0.0.0") { " [BOUND TO ALL INTERFACES!]" } else { "" }
                $serverInfo = if ($serverHeader) { " Server: $serverHeader" } else { "" }
                Write-Result "FOUND" "WEB SERVER localhost:$port [JAVA!]$bindInfo" "$processName (PID $ownerPid) - $httpStatus$serverInfo"
                Write-Result "WARN" "  SUSPICIOUS: Java hosting web server - possible Cheat GUI! ($detectionMethod)"
                if ($bindAddr -eq "0.0.0.0") {
                    Write-Result "WARN" "  CRITICAL: Bound to 0.0.0.0 - accessible from network!"
                }
                if ($processPath) {
                    Write-Result "INFO" "  Path: $processPath"
                }
                $script:SystemFindings += @{
                    Type = "LocalhostWebServer"
                    Description = "Java web server on port $port ($detectionMethod)"
                    Port = $port
                    BindAddress = $bindAddr
                    Process = $processName
                    ProcessPath = $processPath
                    IsJava = $true
                    PID = $ownerPid
                    HttpStatus = $httpStatus
                    Server = $serverHeader
                    Severity = "CRITICAL"
                }
                $foundServer = $true
            }
        }
        if (-not $foundServer) {
            Write-Result "CLEAN" "Java ports checked - no web servers"
        }
    } catch {
        Write-Result "WARN" "Could not enumerate network connections: $_"
    }
}
function Check-CustomFonts {
    Write-Section "Custom Font Analysis (Cheat UI Detection)" "FNT"
    $found = $false
    $cheatFontPatterns = @(
        "Doomsday", "DoomsdayFont", "NovaClient", "VapeClient", "RiseClient",
        "IntentClient", "GhostClient", "MeteorClient", "WurstClient",
        "LiquidBounce", "SigmaClient", "FutureClient", "KonasClient",
        "RusherHack", "PhobosClient", "SalhackFont", "AbyssClient",
        "CosmosClient", "ThunderClient", "AresClient", "ImpactClient",
        "CheatFont", "GhostFont", "HackFont", "InjectFont", "LoaderFont",
        "Comfortaa", "ProductSans", "Greycliff", "Ginto", "Whitney",
        "CustomFont", "mcfont", "mcpefont", "minefont", "craftfont",
        "ClientFont", "ModFont", "BypassFont", "HackedFont", "PremiumFont",
        "SmoothFont", "CleanFont", "ModernFont", "SleekFont", "SlickFont",
        "Roboto", "RobotoMono", "RobotoCondensed", "RobotoSlab",
        "Inter", "InterDisplay", "InterVariable",
        "Poppins", "PoppinsMedium", "PoppinsBold", "PoppinsLight",
        "Montserrat", "MontserratBold", "MontserratLight", "MontserratMedium",
        "OpenSans", "OpenSansBold", "OpenSansLight", "OpenSansSemiBold",
        "Lato", "LatoBold", "LatoLight", "LatoBlack",
        "SourceSansPro", "SourceCodePro", "SourceSerifPro",
        "Nunito", "NunitoSans", "NunitoBold", "NunitoLight",
        "Quicksand", "QuicksandBold", "QuicksandLight", "QuicksandMedium",
        "Rubik", "RubikMono", "RubikBold", "RubikLight",
        "Ubuntu", "UbuntuMono", "UbuntuBold", "UbuntuLight",
        "Exo", "Exo2", "ExoBold", "ExoLight",
        "Rajdhani", "RajdhaniBold", "RajdhaniLight", "RajdhaniMedium",
        "Oxanium", "OxaniumBold", "OxaniumLight",
        "Orbitron", "OrbitronBold", "OrbitronBlack",
        "Audiowide", "AudiowideBold",
        "Teko", "TekoBold", "TekoLight", "TekoMedium",
        "Barlow", "BarlowCondensed", "BarlowSemiCondensed",
        "Jost", "JostBold", "JostLight", "JostMedium",
        "Lexend", "LexendDeca", "LexendBold",
        "SpaceMono", "SpaceGrotesk", "SpaceMonoBold",
        "JetBrainsMono", "JetBrainsMonoBold", "JetBrainsMonoLight",
        "FiraCode", "FiraMono", "FiraSans", "FiraCodeBold",
        "CascadiaCode", "CascadiaMono", "CascadiaCodeBold",
        "Manrope", "ManropeBold", "ManropeLight", "ManropeMedium",
        "DM Sans", "DMSans", "DMSansBold", "DMSansLight",
        "Outfit", "OutfitBold", "OutfitLight", "OutfitMedium",
        "Sora", "SoraBold", "SoraLight", "SoraMedium",
        "Satoshi", "SatoshiBold", "SatoshiLight", "SatoshiMedium",
        "GeneralSans", "GeneralSansBold", "GeneralSansLight",
        "ClashDisplay", "ClashDisplayBold", "ClashDisplayLight",
        "Clash Grotesk", "ClashGrotesk", "ClashGroteskBold",
        "Neue Machina", "NeueMachina", "NeueMachinaBold",
        "Gilroy", "GilroyBold", "GilroyLight", "GilroyMedium",
        "Gotham", "GothamBold", "GothamLight", "GothamMedium",
        "Proxima Nova", "ProximaNova", "ProximaNovaBold",
        "Avenir", "AvenirNext", "AvenirBold", "AvenirLight",
        "Futura", "FuturaBold", "FuturaLight", "FuturaMedium",
        "Helvetica Neue", "HelveticaNeue", "HelveticaNeueBold",
        "SF Pro", "SFPro", "SFProBold", "SFProText", "SFProDisplay",
        "Apple SF", "SFMono", "SFMonoBold",
        "Segoe UI", "SegoeUI", "SegoeUIBold", "SegoeUILight",
        "Circular", "CircularStd", "CircularBold", "CircularLight",
        "Cereal", "AirbnbCereal", "CerealBold", "CerealLight",
        "Graphik", "GraphikBold", "GraphikLight", "GraphikMedium",
        "Akkurat", "AkkuratMono", "AkkuratBold", "AkkuratLight",
        "Monument Extended", "MonumentExtended", "MonumentExtendedBold",
        "Neue Haas", "NeueHaas", "NeueHaasGrotesk",
        "Apercu", "ApercuMono", "ApercuBold", "ApercuLight",
        "Basis Grotesque", "BasisGrotesque", "BasisGrotesqueBold",
        "Founders Grotesk", "FoundersGrotesk", "FoundersGroteskBold",
        "Neurial Grotesk", "NeurialGrotesk", "NeurialGroteskBold",
        "Roobert", "RoobertBold", "RoobertLight", "RoobertMedium",
        "Cabinet Grotesk", "CabinetGrotesk", "CabinetGroteskBold",
        "Clash Display", "ClashDisplayVariable",
        "Switzer", "SwitzerBold", "SwitzerLight", "SwitzerMedium",
        "Supreme", "SupremeBold", "SupremeLight", "SupremeMedium"
    )
    $suspiciousFontPaths = @(
        "$env:LOCALAPPDATA\Microsoft\Windows\Fonts",
        "$env:APPDATA\.minecraft\fonts",
        "$env:APPDATA\.minecraft\resourcepacks",
        "$env:TEMP\fonts",
        "$env:TEMP",
        "$env:USERPROFILE\Downloads"
    )
    Write-Result "INFO" "Scanning for custom fonts ($($cheatFontPatterns.Count) patterns)..."
    try {
        $userFontsPath = "$env:LOCALAPPDATA\Microsoft\Windows\Fonts"
        if (Test-Path $userFontsPath) {
            $userFonts = @()
            $userFonts += Get-ChildItem $userFontsPath -Filter "*.ttf" -ErrorAction SilentlyContinue
            $userFonts += Get-ChildItem $userFontsPath -Filter "*.otf" -ErrorAction SilentlyContinue
            foreach ($font in $userFonts) {
                foreach ($pattern in $cheatFontPatterns) {
                    if ($font.Name -match $pattern) {
                        Write-Result "FOUND" "Cheat font detected (user)" "$($font.Name)"
                        $script:SystemFindings += @{
                            Type = "CheatFont"
                            Description = "User font matching cheat pattern: $($font.Name)"
                            Path = $font.FullName
                            Pattern = $pattern
                            Severity = "HIGH"
                        }
                        $found = $true
                    }
                }
            }
        }
        $regUserFonts = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts" -ErrorAction SilentlyContinue
        if ($regUserFonts) {
            $userFontNames = $regUserFonts.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object { $_.Name }
            foreach ($fontName in $userFontNames) {
                foreach ($pattern in $cheatFontPatterns) {
                    if ($fontName -match $pattern) {
                        Write-Result "FOUND" "Cheat font registered" "$fontName"
                        $script:SystemFindings += @{
                            Type = "CheatFont"
                            Description = "Registered font matching cheat pattern: $fontName"
                            Pattern = $pattern
                            Severity = "HIGH"
                        }
                        $found = $true
                    }
                }
            }
        }
        foreach ($fontPath in $suspiciousFontPaths) {
            if (Test-Path $fontPath) {
                $fonts = Get-ChildItem $fontPath -Include "*.ttf","*.otf","*.woff","*.woff2" -Recurse -ErrorAction SilentlyContinue 2>$null
                foreach ($font in $fonts) {
                    $recentlyAdded = $font.CreationTime -gt (Get-Date).AddDays(-30)
                    foreach ($pattern in $cheatFontPatterns) {
                        if ($font.Name -match $pattern) {
                            $severity = if ($recentlyAdded) { "CRITICAL" } else { "HIGH" }
                            $recentTag = if ($recentlyAdded) { " [RECENT!]" } else { "" }
                            Write-Result "FOUND" "Cheat font in path$recentTag" "$($font.Name)"
                            Write-Result "INFO" "  Location: $($font.DirectoryName)"
                            $script:SystemFindings += @{
                                Type = "CheatFont"
                                Description = "Font in suspicious path: $($font.Name)"
                                Path = $font.FullName
                                Pattern = $pattern
                                RecentlyAdded = $recentlyAdded
                                Severity = $severity
                            }
                            $found = $true
                        }
                    }
                }
            }
        }
        $mcFontsPath = "$env:APPDATA\.minecraft\fonts"
        if (Test-Path $mcFontsPath) {
            $mcFonts = Get-ChildItem $mcFontsPath -Recurse -ErrorAction SilentlyContinue
            if ($mcFonts.Count -gt 0) {
                Write-Result "WARN" "Custom Minecraft fonts folder" "$($mcFonts.Count) file(s)"
                foreach ($font in $mcFonts | Select-Object -First 5) {
                    Write-Result "INFO" "  Font: $($font.Name)"
                }
                $script:SystemFindings += @{
                    Type = "MinecraftCustomFonts"
                    Description = "Custom fonts in .minecraft folder"
                    Path = $mcFontsPath
                    Count = $mcFonts.Count
                    Severity = "MEDIUM"
                }
                $found = $true
            }
        }
    } catch {
        Write-Result "WARN" "Font scan error: $_"
    }
    if (-not $found) {
        Write-Result "CLEAN" "No cheat fonts detected"
    }
}
function Check-PrefetchFiles {
    Write-Section "Windows Prefetch Forensics (JAR Parser)" "PF"
    $found = $false
    $prefetchPath = "$env:SystemRoot\Prefetch"
    $suspiciousPatterns = @(
        "DOOMSDAY", "NOVACLIENT", "VAPECLIENT", "RISECLIENT",
        "METEOR", "WURST", "IMPACT", "ARISTOIS", "LIQUIDBOUNCE",
        "SIGMA", "FUTURE", "KONAS", "RUSHERHACK", "PHOBOS",
        "SALHACK", "ABYSS", "COSMOS", "THUNDER", "ARES",
        "CHEAT", "HACK", "INJECT", "LOADER", "CLIENT", "GHOST",
        "AUTOCLICKER", "GHOSTCLIENT", "VAPE", "NOVA", "INTENT"
    )
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
            foreach ($jarPattern in $jarPatterns) {
                if ($name -like "*$jarPattern*") {
                    $javaExecutions += @{
                        Name = $pf.BaseName
                        LastRun = $pf.LastWriteTime
                    }
                }
            }
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
        if ($javaExecutions.Count -gt 0) {
            $recentJava = $javaExecutions | Sort-Object -Property LastRun -Descending | Select-Object -First 3
            foreach ($java in $recentJava) {
                Write-Result "INFO" "Java execution trace" "$($java.Name) (Last: $($java.LastRun))"
            }
        }
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
            try {
                $doomsdayFiles = Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5
                foreach ($file in $doomsdayFiles) {
                    Write-Result "INFO" "  Doomsday file" $file.Name
                }
            } catch {}
        }
    }
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
function Test-JarURLsAndDomains {
    param([string]$FilePath)
    $findings = @{
        URLs = [System.Collections.Generic.HashSet[string]]::new()
        Domains = [System.Collections.Generic.HashSet[string]]::new()
        IPs = [System.Collections.Generic.HashSet[string]]::new()
        SuspiciousTLDs = [System.Collections.Generic.HashSet[string]]::new()
    }
    # Known safe domains to filter out (common in legitimate mods)
    $safeDomains = @(
        "minecraft.net", "mojang.com", "minecraftforge.net", "fabricmc.net",
        "modrinth.com", "curseforge.com", "github.com", "githubusercontent.com",
        "gradle.org", "maven.org", "apache.org", "google.com", "googleapis.com",
        "oracle.com", "java.net", "java.com", "sun.com", "jetbrains.com",
        "w3.org", "xml.org", "schema.org", "json-schema.org", "xmlsoap.org",
        "xmlns.com", "purl.org", "semver.org", "spdx.org", "slf4j.org",
        "lwjgl.org", "ow2.io", "objectweb.org", "opengl.org", "khronos.org",
        "neoforged.net", "quiltmc.org", "spongepowered.org", "spongepowered.com",
        "mumfrey.liteloader.org", "liteloader.com"
    )
    # Suspicious TLDs commonly used by cheat clients
    $suspiciousTLDs = @(
        "\.wtf$", "\.gg$", "\.lol$", "\.today$", "\.store$", "\.xyz$",
        "\.top$", "\.club$", "\.vip$", "\.ac$", "\.lgbt$", "\.pw$",
        "\.tk$", "\.ml$", "\.ga$", "\.cf$", "\.gq$", "\.buzz$",
        "\.click$", "\.cricket$", "\.science$", "\.party$", "\.racing$",
        "\.download$", "\.win$", "\.bid$", "\.trade$", "\.webcam$"
    )
    $urlPattern = '(https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&''()*+,;=%]{4,200})'
    $domainPattern = '(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})'
    $ipPattern = '((?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?:/[^\s]*)?)'
    # Helper: check domain against suspicious TLDs
    function Test-SuspiciousTLD {
        param([string]$Domain)
        foreach ($tld in $suspiciousTLDs) {
            if ($Domain -match $tld) { return $true }
        }
        return $false
    }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($FilePath)
        $content = [System.Text.Encoding]::UTF8.GetString($bytes)
        # Extract URLs
        $urlMatches = [regex]::Matches($content, $urlPattern)
        foreach ($match in $urlMatches) {
            $url = $match.Groups[1].Value
            $isSafe = $false
            foreach ($safe in $safeDomains) {
                if ($url -match [regex]::Escape($safe)) { $isSafe = $true; break }
            }
            if (-not $isSafe) {
                $findings.URLs.Add($url) | Out-Null
                # Check for suspicious TLD
                if ($url -match '://([^/]+)') {
                    $urlDomain = $Matches[1].ToLower()
                    if (Test-SuspiciousTLD -Domain $urlDomain) {
                        $findings.SuspiciousTLDs.Add("$urlDomain (from $url)") | Out-Null
                    }
                }
            }
        }
        # Extract domains from URLs
        $domainMatches = [regex]::Matches($content, $domainPattern)
        foreach ($match in $domainMatches) {
            $domain = $match.Groups[1].Value.ToLower()
            if ($domain.Length -gt 4 -and $domain -match '\.') {
                $isSafe = $false
                foreach ($safe in $safeDomains) {
                    if ($domain -match [regex]::Escape($safe)) { $isSafe = $true; break }
                }
                if (-not $isSafe -and $domain -notmatch '^\d+\.\d+\.\d+' -and $domain -notmatch '\.class$' -and $domain -notmatch '\.json$' -and $domain -notmatch '\.jar$' -and $domain -notmatch '\.png$' -and $domain -notmatch '\.txt$' -and $domain -notmatch '\.cfg$' -and $domain -notmatch '\.toml$' -and $domain -notmatch '\.properties$') {
                    $findings.Domains.Add($domain) | Out-Null
                    if (Test-SuspiciousTLD -Domain $domain) {
                        $findings.SuspiciousTLDs.Add($domain) | Out-Null
                    }
                }
            }
        }
        # Extract IP addresses
        $ipMatches = [regex]::Matches($content, $ipPattern)
        foreach ($match in $ipMatches) {
            $ip = $match.Groups[1].Value
            if ($ip -notmatch '^(https?://)?127\.0\.0\.1' -and $ip -notmatch '^(https?://)?0\.0\.0\.0' -and $ip -notmatch '^(https?://)?10\.' -and $ip -notmatch '^(https?://)?192\.168\.' -and $ip -notmatch '^(https?://)?255\.') {
                $findings.IPs.Add($ip) | Out-Null
            }
        }
        # Also scan individual class/json entries for more precise results
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $entries = $zip.Entries | Where-Object { $_.Name -match '\.(class|json|properties|cfg|yml|yaml|txt)$' }
        foreach ($entry in $entries) {
            try {
                $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
                $entryContent = $reader.ReadToEnd()
                $reader.Close()
                $entryUrlMatches = [regex]::Matches($entryContent, $urlPattern)
                foreach ($match in $entryUrlMatches) {
                    $url = $match.Groups[1].Value
                    $isSafe = $false
                    foreach ($safe in $safeDomains) {
                        if ($url -match [regex]::Escape($safe)) { $isSafe = $true; break }
                    }
                    if (-not $isSafe) {
                        $findings.URLs.Add($url) | Out-Null
                        if ($url -match '://([^/]+)') {
                            $urlDomain = $Matches[1].ToLower()
                            if (Test-SuspiciousTLD -Domain $urlDomain) {
                                $findings.SuspiciousTLDs.Add("$urlDomain (from $url)") | Out-Null
                            }
                        }
                    }
                }
                $entryIpMatches = [regex]::Matches($entryContent, $ipPattern)
                foreach ($match in $entryIpMatches) {
                    $ip = $match.Groups[1].Value
                    if ($ip -notmatch '^(https?://)?127\.0\.0\.1' -and $ip -notmatch '^(https?://)?0\.0\.0\.0' -and $ip -notmatch '^(https?://)?10\.' -and $ip -notmatch '^(https?://)?192\.168\.' -and $ip -notmatch '^(https?://)?255\.') {
                        $findings.IPs.Add($ip) | Out-Null
                    }
                }
            } catch {}
        }
        $zip.Dispose()
    } catch {}
    return $findings
}
function Test-BytecodePatterns {
    param([string]$FilePath)
    $findings = @{
        Reflection = @()
        DynamicLoading = @()
        Networking = @()
        NativeAccess = @()
        AgentAttachment = @()
        Score = 0
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $classEntries = $zip.Entries | Where-Object { $_.Name -match '\.class$' -and $_.Length -gt 100 -and $_.Length -lt 500000 }
        $scanned = 0
        $reflectionPatterns = @(
            "java/lang/reflect/Method", "java/lang/reflect/Field", "java/lang/reflect/Constructor",
            "java/lang/Class;->forName", "java.lang.reflect.Proxy", "java/lang/invoke/MethodHandle",
            "java/lang/invoke/MethodHandles", "getDeclaredMethod", "getDeclaredField",
            "setAccessible", "invoke(Ljava/lang/Object",
            "java/lang/invoke/VarHandle", "java/lang/invoke/MethodHandles$Lookup"
        )
        $dynamicLoadPatterns = @(
            "java/lang/ClassLoader;->defineClass", "java/net/URLClassLoader",
            "java/security/SecureClassLoader", "java/lang/ClassLoader;->loadClass",
            "java/lang/ClassLoader;->findClass", "sun/misc/Unsafe",
            "java/lang/instrument/Instrumentation", "java/lang/instrument/ClassFileTransformer",
            "jdk/internal/misc/Unsafe", "java.lang.ClassLoader", "defineClass0",
            "java/lang/Runtime;->exec", "ProcessBuilder",
            "java/lang/invoke/MethodHandles$Lookup;->defineClass"
        )
        $networkPatterns = @(
            "java/net/Socket;-><init>", "java/net/HttpURLConnection",
            "java/net/URL;->openConnection", "java/net/URL;->openStream",
            "javax/net/ssl/HttpsURLConnection", "java/net/DatagramSocket",
            "java/net/ServerSocket;-><init>", "java/nio/channels/SocketChannel",
            "okhttp3/OkHttpClient", "okhttp3/Request", "org/apache/http",
            "discord.com/api/webhooks", "webhook", "hwid", "license"
        )
        $nativePatterns = @(
            "java/lang/System;->loadLibrary", "java/lang/System;->load(",
            "java/lang/Runtime;->loadLibrary", "JNI_OnLoad",
            "sun/misc/Unsafe;->allocateMemory", "sun/misc/Unsafe;->putInt",
            "sun/misc/Unsafe;->getObject", "sun/misc/Unsafe;->putObject"
        )
        # JVMTI / Agent Attachment patterns — runtime instrumentation & injection
        $agentPatterns = @(
            "com/sun/tools/attach/VirtualMachine",
            "com.sun.tools.attach.VirtualMachine",
            "VirtualMachine;->attach", "VirtualMachine;->loadAgent",
            "VirtualMachine;->loadAgentLibrary", "VirtualMachine;->loadAgentPath",
            "AgentInitializationException", "AgentLoadException",
            "AttachNotSupportedException",
            "com/sun/tools/attach/spi/AttachProvider",
            "java/lang/instrument/Instrumentation;->retransformClasses",
            "java/lang/instrument/Instrumentation;->redefineClasses",
            "java/lang/instrument/Instrumentation;->addTransformer",
            "java/lang/instrument/Instrumentation;->getAllLoadedClasses",
            "java/lang/instrument/Instrumentation;->getInitiatedClasses",
            "java/lang/instrument/Instrumentation;->appendToBootstrapClassLoaderSearch",
            "java/lang/instrument/Instrumentation;->appendToSystemClassLoaderSearch",
            "sun/jvmstat/monitor", "sun.jvmstat.monitor",
            "com/sun/jdi/VirtualMachine", "com.sun.jdi.VirtualMachine",
            "com/sun/jdi/connect/AttachingConnector",
            "java/lang/reflect/Module;->addOpens",
            "java/lang/reflect/Module;->addExports",
            "java/lang/reflect/Module;->addReads",
            "jdk/internal/module", "sun/reflect/ReflectionFactory",
            "net/bytebuddy/agent/ByteBuddyAgent",
            "javassist/ClassPool", "javassist/CtClass",
            "org/objectweb/asm/ClassWriter", "org/objectweb/asm/ClassVisitor",
            "org/objectweb/asm/MethodVisitor", "org/objectweb/asm/ClassReader",
            "net/bytebuddy/ByteBuddy", "net/bytebuddy/dynamic",
            "cglib/proxy/Enhancer", "net/sf/cglib"
        )
        foreach ($entry in $classEntries) {
            if ($scanned -ge 200) { break }
            try {
                $stream = $entry.Open()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $stream.Close()
                $bytes = $ms.ToArray()
                $ms.Dispose()
                $content = [System.Text.Encoding]::UTF8.GetString($bytes)
                $className = $entry.FullName -replace '\.class$', ''
                foreach ($p in $reflectionPatterns) {
                    if ($content.Contains($p)) {
                        $findings.Reflection += "$className -> $p"
                        break
                    }
                }
                foreach ($p in $dynamicLoadPatterns) {
                    if ($content.Contains($p)) {
                        $findings.DynamicLoading += "$className -> $p"
                        break
                    }
                }
                foreach ($p in $networkPatterns) {
                    if ($content.Contains($p)) {
                        $findings.Networking += "$className -> $p"
                        break
                    }
                }
                foreach ($p in $nativePatterns) {
                    if ($content.Contains($p)) {
                        $findings.NativeAccess += "$className -> $p"
                        break
                    }
                }
                foreach ($p in $agentPatterns) {
                    if ($content.Contains($p)) {
                        $findings.AgentAttachment += "$className -> $p"
                        break
                    }
                }
                $scanned++
            } catch {}
        }
        $zip.Dispose()
        # Score: many reflection + dynamic loading + native = very suspicious
        if ($findings.Reflection.Count -gt 10) { $findings.Score += 15 }
        elseif ($findings.Reflection.Count -gt 5) { $findings.Score += 8 }
        if ($findings.DynamicLoading.Count -gt 3) { $findings.Score += 25 }
        elseif ($findings.DynamicLoading.Count -gt 0) { $findings.Score += 12 }
        if ($findings.Networking.Count -gt 5) { $findings.Score += 20 }
        elseif ($findings.Networking.Count -gt 2) { $findings.Score += 10 }
        if ($findings.NativeAccess.Count -gt 2) { $findings.Score += 25 }
        elseif ($findings.NativeAccess.Count -gt 0) { $findings.Score += 15 }
        # Agent/JVMTI: any hit is highly suspicious — mods should NOT attach to the JVM
        if ($findings.AgentAttachment.Count -gt 5) { $findings.Score += 35 }
        elseif ($findings.AgentAttachment.Count -gt 2) { $findings.Score += 25 }
        elseif ($findings.AgentAttachment.Count -gt 0) { $findings.Score += 15 }
        # Combination bonus: reflection + dynamic loading = classic cheat pattern
        if ($findings.Reflection.Count -gt 3 -and $findings.DynamicLoading.Count -gt 0) {
            $findings.Score += 15
        }
        # Native + networking = very likely loader/injector
        if ($findings.NativeAccess.Count -gt 0 -and $findings.Networking.Count -gt 0) {
            $findings.Score += 15
        }
        # Agent + any other category = definite injection tool
        if ($findings.AgentAttachment.Count -gt 0 -and ($findings.DynamicLoading.Count -gt 0 -or $findings.NativeAccess.Count -gt 0)) {
            $findings.Score += 20
        }
    } catch {}
    return $findings
}
function Test-ClassEntropy {
    param([string]$FilePath)
    $findings = @{
        HighEntropyClasses = @()
        AverageEntropy = 0.0
        MaxEntropy = 0.0
        Score = 0
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $classEntries = $zip.Entries | Where-Object { $_.Name -match '\.class$' -and $_.Length -gt 500 -and $_.Length -lt 500000 }
        $entropyValues = @()
        $scanned = 0
        foreach ($entry in $classEntries) {
            if ($scanned -ge 150) { break }
            try {
                $stream = $entry.Open()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $stream.Close()
                $bytes = $ms.ToArray()
                $ms.Dispose()
                # Calculate Shannon entropy on the string constant pool area
                # Skip first 10 bytes (magic + version), focus on constant pool strings
                if ($bytes.Length -gt 100) {
                    $sampleStart = [math]::Min(10, $bytes.Length - 1)
                    $sampleLen = [math]::Min(4096, $bytes.Length - $sampleStart)
                    $sample = New-Object byte[] $sampleLen
                    [Array]::Copy($bytes, $sampleStart, $sample, 0, $sampleLen)
                    $freq = @{}
                    foreach ($b in $sample) {
                        if ($freq.ContainsKey($b)) { $freq[$b]++ } else { $freq[$b] = 1 }
                    }
                    $entropy = 0.0
                    $len = $sample.Length
                    foreach ($count in $freq.Values) {
                        $p = $count / $len
                        if ($p -gt 0) { $entropy -= $p * [math]::Log($p, 2) }
                    }
                    $entropyValues += $entropy
                    if ($entropy -gt 7.2) {
                        $findings.HighEntropyClasses += @{
                            Class = $entry.FullName -replace '\.class$', ''
                            Entropy = [math]::Round($entropy, 3)
                            Size = $entry.Length
                        }
                    }
                    if ($entropy -gt $findings.MaxEntropy) { $findings.MaxEntropy = $entropy }
                }
                $scanned++
            } catch {}
        }
        $zip.Dispose()
        if ($entropyValues.Count -gt 0) {
            $findings.AverageEntropy = [math]::Round(($entropyValues | Measure-Object -Average).Average, 3)
        }
        # Score based on high-entropy class percentage
        $highEntropyPct = if ($scanned -gt 0) { ($findings.HighEntropyClasses.Count / $scanned) * 100 } else { 0 }
        if ($highEntropyPct -gt 50) { $findings.Score += 30 }
        elseif ($highEntropyPct -gt 25) { $findings.Score += 20 }
        elseif ($highEntropyPct -gt 10) { $findings.Score += 10 }
        if ($findings.MaxEntropy -gt 7.5) { $findings.Score += 15 }
        if ($findings.AverageEntropy -gt 6.5) { $findings.Score += 10 }
    } catch {}
    return $findings
}
function Test-MixinConfigs {
    param([string]$FilePath)
    $findings = @{
        SuspiciousTargets = @()
        MixinConfigs = @()
        Score = 0
    }
    # Minecraft classes commonly targeted by cheat mixins
    $suspiciousTargets = @(
        # Combat/PvP
        "ClientPlayerInteractionManager", "PlayerEntity", "LivingEntity",
        "ClientPlayerEntity", "PlayerInventory", "ItemCooldownManager",
        "GameRenderer", "Camera", "WorldRenderer",
        "ItemStack", "CombatTracker", "ArmorItem",
        # Movement
        "Entity", "ClientPlayerEntity", "AbstractClientPlayerEntity",
        "FluidState", "Block", "VoxelShape", "BlockCollisionSpliterator",
        # Network/Packets
        "ClientConnection", "ClientPlayNetworkHandler", "NetworkState",
        "PacketByteBuf", "CustomPayloadC2SPacket", "CustomPayloadS2CPacket",
        "PlayerMoveC2SPacket", "PlayerInteractEntityC2SPacket",
        "EntityVelocityUpdateS2CPacket", "PlayerPositionLookS2CPacket",
        "KeepAliveC2SPacket", "ChatMessageC2SPacket", "HandSwingC2SPacket",
        "UpdateSelectedSlotC2SPacket", "CloseHandledScreenC2SPacket",
        "ClickSlotC2SPacket",
        # Rendering/ESP
        "InGameHud", "WorldRenderer", "BufferBuilder",
        "EntityRenderDispatcher", "BlockEntityRenderDispatcher",
        "LivingEntityRenderer", "ItemRenderer", "RenderLayer",
        "LightmapTextureManager", "BackgroundRenderer",
        # Input
        "KeyboardInput", "Mouse", "MinecraftClient",
        # Inventory/Interaction
        "HandledScreen", "GenericContainerScreen", "CreativeInventoryScreen",
        "ScreenHandler", "AbstractInventoryScreen", "SlotActionType",
        # World/Block interaction
        "ClientWorld", "WorldAccess", "ChunkBuilder",
        "BlockBreakingInfo", "AbstractBlock"
    )
    $suspiciousTargetsLower = $suspiciousTargets | ForEach-Object { $_.ToLower() } | Sort-Object -Unique
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $mixinEntries = $zip.Entries | Where-Object { $_.Name -match '\.mixins\.json$|mixin\.json$|mixins\..*\.json$' }
        foreach ($entry in $mixinEntries) {
            try {
                $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
                $content = $reader.ReadToEnd()
                $reader.Close()
                $json = $content | ConvertFrom-Json -ErrorAction SilentlyContinue
                if ($null -eq $json) { continue }
                $configInfo = @{
                    File = $entry.FullName
                    Package = ""
                    Targets = @()
                }
                if ($json.package) { $configInfo.Package = $json.package }
                $allMixinClasses = @()
                if ($json.client) { $allMixinClasses += @($json.client) }
                if ($json.server) { $allMixinClasses += @($json.server) }
                if ($json.mixins) { $allMixinClasses += @($json.mixins) }
                foreach ($mixinClass in $allMixinClasses) {
                    $classLower = $mixinClass.ToString().ToLower()
                    foreach ($target in $suspiciousTargetsLower) {
                        if ($classLower -match [regex]::Escape($target)) {
                            $configInfo.Targets += $mixinClass
                            $findings.SuspiciousTargets += "$($entry.FullName): $mixinClass"
                            break
                        }
                    }
                }
                $findings.MixinConfigs += $configInfo
            } catch {}
        }
        $zip.Dispose()
        # Score: many suspicious mixin targets = likely cheat
        $targetCount = $findings.SuspiciousTargets.Count
        if ($targetCount -gt 15) { $findings.Score += 30 }
        elseif ($targetCount -gt 8) { $findings.Score += 20 }
        elseif ($targetCount -gt 4) { $findings.Score += 10 }
        elseif ($targetCount -gt 0) { $findings.Score += 5 }
        # Targeting combat + movement + rendering together = classic cheat pattern
        $hasCombat = $findings.SuspiciousTargets | Where-Object { $_ -match "(?i)(PlayerInteraction|LivingEntity|ItemCooldown|PlayerEntity|CombatTracker|ItemStack|ArmorItem)" }
        $hasMovement = $findings.SuspiciousTargets | Where-Object { $_ -match "(?i)(Entity|FluidState|KeyboardInput|VoxelShape|BlockCollision)" }
        $hasRendering = $findings.SuspiciousTargets | Where-Object { $_ -match "(?i)(WorldRenderer|InGameHud|EntityRenderDispatcher|GameRenderer|LivingEntityRenderer|ItemRenderer|RenderLayer|BackgroundRenderer)" }
        $hasNetwork = $findings.SuspiciousTargets | Where-Object { $_ -match "(?i)(ClientConnection|NetworkHandler|PacketByteBuf|C2SPacket|S2CPacket|NetworkState)" }
        $hasInventory = $findings.SuspiciousTargets | Where-Object { $_ -match "(?i)(ScreenHandler|HandledScreen|SlotAction|ClickSlot|Inventory)" }
        $categoryCount = 0
        if ($hasCombat) { $categoryCount++ }
        if ($hasMovement) { $categoryCount++ }
        if ($hasRendering) { $categoryCount++ }
        if ($hasNetwork) { $categoryCount++ }
        if ($hasInventory) { $categoryCount++ }
        if ($categoryCount -ge 4) { $findings.Score += 25 }
        elseif ($categoryCount -ge 3) { $findings.Score += 20 }
        elseif ($categoryCount -ge 2) { $findings.Score += 10 }
    } catch {}
    return $findings
}
function Test-StringEncoding {
    param([string]$FilePath)
    $findings = @{
        Base64Strings = @()
        CharArrayPatterns = @()
        XorPatterns = 0
        DecodedCheatHits = @()
        Score = 0
    }
    $base64Pattern = '[A-Za-z0-9+/]{20,}={0,2}'
    $charArrayPattern = 'new\s+char\s*\[\s*\]\s*\{[^}]{10,}\}'
    $stringBuilderPattern = '(?:StringBuilder|StringBuffer).*?(?:append\([''"][a-zA-Z]{1,3}[''"]\)[\s.]*){4,}'
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $classEntries = $zip.Entries | Where-Object { $_.Name -match '\.class$' -and $_.Length -gt 200 -and $_.Length -lt 500000 }
        $scanned = 0
        $totalBase64Hits = 0
        $xorByteRepeatCount = 0
        foreach ($entry in $classEntries) {
            if ($scanned -ge 150) { break }
            try {
                $stream = $entry.Open()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $stream.Close()
                $bytes = $ms.ToArray()
                $ms.Dispose()
                $content = [System.Text.Encoding]::UTF8.GetString($bytes)
                $className = $entry.FullName -replace '\.class$', ''
                # Base64 detection: find long Base64 strings, try decode, check for cheat keywords
                $b64Matches = [regex]::Matches($content, $base64Pattern)
                foreach ($b64 in $b64Matches) {
                    $b64Value = $b64.Value
                    if ($b64Value.Length -ge 24 -and $b64Value.Length -le 500) {
                        try {
                            $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64Value))
                            if ($decoded -match "[\x20-\x7E]{6,}") {
                                $cheatKeywords = @("killaura", "aimbot", "triggerbot", "velocity", "scaffold", "noclip", "xray", "esp", "fly", "speed", "nuker", "disabler", "bypass", "webhook", "discord", "hwid", "license", "token", "steal", "inject", "loader", "client", "cheat", "hack", "aura", "reach", "freecam", "baritone", "doomsday", "nova", "vape", "rise", "meteor", "wurst")
                                foreach ($kw in $cheatKeywords) {
                                    if ($decoded.ToLower().Contains($kw)) {
                                        $findings.DecodedCheatHits += "$className -> Base64 decoded: '$($decoded.Substring(0, [Math]::Min(60, $decoded.Length)))...' matches '$kw'"
                                        break
                                    }
                                }
                                $totalBase64Hits++
                                if ($findings.Base64Strings.Count -lt 10) {
                                    $preview = $decoded.Substring(0, [Math]::Min(40, $decoded.Length))
                                    $findings.Base64Strings += "$className -> $preview"
                                }
                            }
                        } catch {}
                    }
                }
                # Char array construction: new char[]{'K','i','l','l'}
                if ($content -match $charArrayPattern) {
                    $caMatches = [regex]::Matches($content, $charArrayPattern)
                    foreach ($ca in $caMatches) {
                        $findings.CharArrayPatterns += "$className -> $($ca.Value.Substring(0, [Math]::Min(60, $ca.Value.Length)))"
                    }
                }
                # StringBuilder chained appends (single-char append chains = string hiding)
                if ($content -match $stringBuilderPattern) {
                    $findings.CharArrayPatterns += "$className -> StringBuilder chain (string construction)"
                }
                # XOR pattern detection: look for repeating XOR byte sequences
                # In .class constant pool, encrypted strings show repeating byte patterns
                if ($bytes.Length -gt 200) {
                    $sampleLen = [Math]::Min(2048, $bytes.Length)
                    $xorCandidates = @{}
                    for ($i = 100; $i -lt $sampleLen - 1; $i++) {
                        $xorByte = $bytes[$i] -bxor $bytes[$i+1]
                        if ($xorByte -ne 0 -and $xorByte -lt 128) {
                            if ($xorCandidates.ContainsKey($xorByte)) { $xorCandidates[$xorByte]++ }
                            else { $xorCandidates[$xorByte] = 1 }
                        }
                    }
                    # If any single XOR key appears very frequently, likely XOR encryption
                    $maxXorCount = ($xorCandidates.Values | Measure-Object -Maximum -ErrorAction SilentlyContinue).Maximum
                    if ($maxXorCount -gt ($sampleLen * 0.15)) {
                        $xorByteRepeatCount++
                    }
                }
                $scanned++
            } catch {}
        }
        $zip.Dispose()
        $findings.XorPatterns = $xorByteRepeatCount
        # Scoring
        if ($findings.DecodedCheatHits.Count -gt 0) { $findings.Score += 30 + [Math]::Min(20, $findings.DecodedCheatHits.Count * 10) }
        if ($totalBase64Hits -gt 20) { $findings.Score += 15 }
        elseif ($totalBase64Hits -gt 10) { $findings.Score += 8 }
        if ($findings.CharArrayPatterns.Count -gt 5) { $findings.Score += 15 }
        elseif ($findings.CharArrayPatterns.Count -gt 2) { $findings.Score += 8 }
        if ($xorByteRepeatCount -gt 10) { $findings.Score += 20 }
        elseif ($xorByteRepeatCount -gt 5) { $findings.Score += 10 }
        # Combo: Base64 decoded cheats + XOR = heavily encrypted cheat
        if ($findings.DecodedCheatHits.Count -gt 0 -and $xorByteRepeatCount -gt 3) {
            $findings.Score += 15
        }
    } catch {}
    return $findings
}
function Test-RefmapAnalysis {
    param([string]$FilePath)
    $findings = @{
        SuspiciousRefmaps = @()
        RefmapTargets = @()
        Score = 0
    }
    # Minecraft classes targeted by cheats via mixin refmaps
    $suspiciousRefmapTargets = @(
        # Combat/PvP
        "ClientPlayerInteractionManager", "PlayerEntity", "LivingEntity",
        "ClientPlayerEntity", "AbstractClientPlayerEntity",
        "ItemCooldownManager", "CombatTracker",
        "ItemStack;use", "ItemStack;damage", "ItemStack;finishUsing",
        "PlayerEntity;attack", "PlayerEntity;swingHand",
        "LivingEntity;swingHand", "LivingEntity;getAttackCooldownProgress",
        "PlayerInteractManager;clickBlock", "PlayerInteractManager;processRightClick",
        "ArmorItem", "PlayerEntity;getInventory",
        # Movement
        "Entity;move", "Entity;updateMovement", "ClientPlayerEntity;tickMovement",
        "LivingEntity;travel", "LivingEntity;jump", "Entity;pushOutOfBlocks",
        "FluidState", "LivingEntity;hasStatusEffect",
        "ClientPlayerEntity;sendMovementPackets", "Entity;setPos", "Entity;setPosRaw",
        "Entity;changeLookDirection", "Entity;updateVelocity",
        "LivingEntity;getMovementSpeed", "Entity;isOnGround", "Entity;fallDistance",
        "Entity;noClip", "Entity;stepHeight",
        # Network/Packets
        "ClientConnection", "ClientPlayNetworkHandler",
        "PlayerMoveC2SPacket", "PlayerInteractEntityC2SPacket",
        "EntityVelocityUpdateS2CPacket", "PlayerPositionLookS2CPacket",
        "KeepAliveC2SPacket", "ChatMessageC2SPacket", "HandSwingC2SPacket",
        "UpdateSelectedSlotC2SPacket", "CloseHandledScreenC2SPacket",
        "PacketByteBuf", "NetworkState",
        "ClickSlotC2SPacket", "PlayerActionC2SPacket",
        "ClientCommandC2SPacket", "TeleportConfirmC2SPacket",
        "CustomPayloadC2SPacket", "CustomPayloadS2CPacket",
        "PlayerAbilitiesS2CPacket", "GameJoinS2CPacket",
        # Rendering/ESP
        "WorldRenderer", "GameRenderer", "InGameHud",
        "EntityRenderDispatcher", "BlockEntityRenderDispatcher",
        "BufferBuilder", "Camera", "LightmapTextureManager",
        "LivingEntityRenderer", "ItemRenderer", "RenderLayer",
        "BackgroundRenderer", "EntityModel",
        # Input/Control
        "KeyboardInput", "Mouse", "MinecraftClient",
        # Inventory/Interaction
        "HandledScreen", "GenericContainerScreen", "PlayerInventory",
        "CreativeInventoryScreen", "AbstractInventoryScreen",
        "ScreenHandler;onSlotClick", "ScreenHandler;transferSlot",
        "PlayerInventory;selectedSlot", "PlayerInventory;swapOffhand",
        "SlotActionType", "CursorStackReference",
        # World/Block interaction
        "ClientWorld", "WorldAccess", "ChunkBuilder",
        "BlockBreakingInfo", "AbstractBlock",
        "NbtCompound", "Text"
    )
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        # Find refmap files
        $refmapEntries = $zip.Entries | Where-Object { $_.Name -match '-refmap\.json$|refmap.*\.json$' }
        foreach ($entry in $refmapEntries) {
            try {
                $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8)
                $content = $reader.ReadToEnd()
                $reader.Close()
                $contentLower = $content.ToLower()
                $refmapInfo = @{
                    File = $entry.FullName
                    Targets = @()
                }
                foreach ($target in $suspiciousRefmapTargets) {
                    if ($contentLower.Contains($target.ToLower())) {
                        $refmapInfo.Targets += $target
                        $findings.RefmapTargets += "$($entry.FullName): $target"
                    }
                }
                if ($refmapInfo.Targets.Count -gt 0) {
                    $findings.SuspiciousRefmaps += $refmapInfo
                }
                # Check for obfuscated intermediary mappings targeting suspicious classes
                if ($content -match "net/minecraft/class_\d+" -or $content -match "method_\d+" -or $content -match "field_\d+") {
                    # Count how many intermediary mappings exist
                    $intermediaryCount = ([regex]::Matches($content, "(?:class_|method_|field_)\d+")).Count
                    if ($intermediaryCount -gt 50) {
                        $findings.RefmapTargets += "$($entry.FullName): $intermediaryCount intermediary mappings (heavy Minecraft patching)"
                    }
                }
            } catch {}
        }
        $zip.Dispose()
        # Scoring
        $targetCount = $findings.RefmapTargets.Count
        if ($targetCount -gt 20) { $findings.Score += 25 }
        elseif ($targetCount -gt 10) { $findings.Score += 15 }
        elseif ($targetCount -gt 5) { $findings.Score += 8 }
        elseif ($targetCount -gt 0) { $findings.Score += 3 }
        # Category analysis on refmap targets
        $hasPacketTargets = $findings.RefmapTargets | Where-Object { $_ -match "(?i)(Packet|ClientConnection|NetworkHandler|NetworkState)" }
        $hasCombatTargets = $findings.RefmapTargets | Where-Object { $_ -match "(?i)(PlayerInteraction|CombatTracker|ItemCooldown|AttackEntity|ItemStack;use|swingHand|attack)" }
        $hasRenderTargets = $findings.RefmapTargets | Where-Object { $_ -match "(?i)(WorldRenderer|GameRenderer|EntityRenderDispatcher|BufferBuilder|Lightmap|LivingEntityRenderer|ItemRenderer|RenderLayer)" }
        $hasMovementTargets = $findings.RefmapTargets | Where-Object { $_ -match "(?i)(Entity;move|sendMovementPackets|setPos|travel|jump|noClip|stepHeight|isOnGround|fallDistance)" }
        $hasInventoryTargets = $findings.RefmapTargets | Where-Object { $_ -match "(?i)(ScreenHandler|SlotAction|ClickSlot|Inventory|CursorStack|HandledScreen)" }
        if ($hasPacketTargets -and $hasCombatTargets) { $findings.Score += 15 }
        if ($hasPacketTargets -and $hasRenderTargets) { $findings.Score += 10 }
        if ($hasMovementTargets -and $hasPacketTargets) { $findings.Score += 12 }
        if ($hasInventoryTargets -and $hasPacketTargets) { $findings.Score += 10 }
        # 4+ categories = classic full cheat client
        $refCatCount = 0
        if ($hasCombatTargets) { $refCatCount++ }
        if ($hasMovementTargets) { $refCatCount++ }
        if ($hasPacketTargets) { $refCatCount++ }
        if ($hasRenderTargets) { $refCatCount++ }
        if ($hasInventoryTargets) { $refCatCount++ }
        if ($refCatCount -ge 4) { $findings.Score += 15 }
    } catch {}
    return $findings
}
function Test-NativeLibraries {
    param([string]$FilePath)
    $findings = @{
        NativeFiles = @()
        JniMethods = @()
        Score = 0
    }
    $nativeExtensions = @("\.dll$", "\.so$", "\.dylib$", "\.jnilib$", "\.exe$", "\.bat$", "\.cmd$", "\.ps1$", "\.sh$", "\.vbs$")
    # JNI naming convention: Java_com_package_ClassName_methodName
    $jniPattern = "Java_[a-zA-Z0-9_]{10,}"
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.ToLower()
            foreach ($ext in $nativeExtensions) {
                if ($name -match $ext) {
                    $severity = "HIGH"
                    if ($name -match '\.(exe|bat|cmd|ps1|sh|vbs)$') { $severity = "CRITICAL" }
                    $findings.NativeFiles += @{
                        Path = $entry.FullName
                        Size = $entry.Length
                        Severity = $severity
                    }
                    # For DLL/SO, try to scan for JNI method names
                    if ($name -match '\.(dll|so|dylib|jnilib)$' -and $entry.Length -lt 5000000 -and $entry.Length -gt 100) {
                        try {
                            $stream = $entry.Open()
                            $ms = New-Object System.IO.MemoryStream
                            $stream.CopyTo($ms)
                            $stream.Close()
                            $nativeBytes = $ms.ToArray()
                            $ms.Dispose()
                            $nativeContent = [System.Text.Encoding]::ASCII.GetString($nativeBytes)
                            $jniMatches = [regex]::Matches($nativeContent, $jniPattern)
                            foreach ($jni in $jniMatches) {
                                $findings.JniMethods += "$($entry.FullName): $($jni.Value)"
                            }
                        } catch {}
                    }
                    break
                }
            }
        }
        $zip.Dispose()
        # Scoring
        $criticalCount = ($findings.NativeFiles | Where-Object { $_.Severity -eq "CRITICAL" }).Count
        $highCount = ($findings.NativeFiles | Where-Object { $_.Severity -eq "HIGH" }).Count
        if ($criticalCount -gt 0) { $findings.Score += 30 + [Math]::Min(20, $criticalCount * 15) }
        if ($highCount -gt 3) { $findings.Score += 20 }
        elseif ($highCount -gt 0) { $findings.Score += 10 }
        if ($findings.JniMethods.Count -gt 5) { $findings.Score += 15 }
        elseif ($findings.JniMethods.Count -gt 0) { $findings.Score += 8 }
    } catch {}
    return $findings
}
function Test-AdvancedBytecodePatterns {
    param([string]$FilePath)
    $findings = @{
        InvokedynamicAbuse = 0
        ExceptionFlood = 0
        SyntheticMethods = 0
        TotalMethods = 0
        DeadCodeClasses = 0
        Score = 0
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $classEntries = $zip.Entries | Where-Object { $_.Name -match '\.class$' -and $_.Length -gt 100 -and $_.Length -lt 500000 }
        $scanned = 0
        foreach ($entry in $classEntries) {
            if ($scanned -ge 200) { break }
            try {
                $stream = $entry.Open()
                $ms = New-Object System.IO.MemoryStream
                $stream.CopyTo($ms)
                $stream.Close()
                $bytes = $ms.ToArray()
                $ms.Dispose()
                if ($bytes.Length -lt 20) { $scanned++; continue }
                # Check Java magic number (0xCAFEBABE)
                if ($bytes[0] -ne 0xCA -or $bytes[1] -ne 0xFE -or $bytes[2] -ne 0xBA -or $bytes[3] -ne 0xBE) {
                    $scanned++; continue
                }
                $content = [System.Text.Encoding]::ASCII.GetString($bytes)
                # invokedynamic abuse: CONSTANT_InvokeDynamic (tag 18) in constant pool
                # In bytecode, tag 18 = InvokeDynamic. Cheats use this for string encryption.
                # Count occurrences of bootstrap method patterns
                $invokeDynCount = 0
                $bootstrapPattern = "makeConcatWithConstants|metafactory|StringConcatFactory|LambdaMetafactory|CallSite"
                $bootMatches = [regex]::Matches($content, $bootstrapPattern)
                $invokeDynCount = $bootMatches.Count
                # Heavy invokedynamic use in non-lambda context = string decryption
                if ($invokeDynCount -gt 30) { $findings.InvokedynamicAbuse++ }
                # Exception handler flooding: many exception table entries = flow obfuscation
                # Look for exception class references in unusual density
                $exceptionRefs = ([regex]::Matches($content, "(?:java/lang/(?:Exception|Throwable|RuntimeException|Error|NullPointerException|ClassCastException|ArrayIndexOutOfBoundsException))")).Count
                if ($exceptionRefs -gt 15) { $findings.ExceptionFlood++ }
                # Synthetic/bridge method markers in bytecode
                # ACC_SYNTHETIC = 0x1000, ACC_BRIDGE = 0x0040
                # These show up as string patterns in class file metadata
                if ($content -match "synthetic" -or $content -match "bridge") {
                    $syntheticCount = ([regex]::Matches($content, "(?i)synthetic")).Count
                    if ($syntheticCount -gt 5) { $findings.SyntheticMethods += $syntheticCount }
                }
                # Dead code: classes with very minimal constant pool but many bytecode instructions
                # Indicated by high byte-to-string ratio (mostly non-printable = mostly opcodes)
                $printableCount = 0
                $checkLen = [Math]::Min($bytes.Length, 2000)
                for ($i = 0; $i -lt $checkLen; $i++) {
                    if ($bytes[$i] -ge 0x20 -and $bytes[$i] -le 0x7E) { $printableCount++ }
                }
                $printableRatio = $printableCount / $checkLen
                # Very low printable ratio = heavily obfuscated bytecode (mostly opcodes, no readable strings)
                if ($printableRatio -lt 0.15 -and $bytes.Length -gt 500) {
                    $findings.DeadCodeClasses++
                }
                $findings.TotalMethods++
                $scanned++
            } catch {}
        }
        $zip.Dispose()
        # Scoring
        $total = [Math]::Max(1, $scanned)
        if ($findings.InvokedynamicAbuse -gt 10) { $findings.Score += 20 }
        elseif ($findings.InvokedynamicAbuse -gt 3) { $findings.Score += 10 }
        if ($findings.ExceptionFlood -gt 15) { $findings.Score += 25 }
        elseif ($findings.ExceptionFlood -gt 5) { $findings.Score += 12 }
        $deadCodePct = ($findings.DeadCodeClasses / $total) * 100
        if ($deadCodePct -gt 40) { $findings.Score += 20 }
        elseif ($deadCodePct -gt 20) { $findings.Score += 10 }
        if ($findings.SyntheticMethods -gt 50) { $findings.Score += 15 }
        elseif ($findings.SyntheticMethods -gt 20) { $findings.Score += 8 }
        # Combo: exception flood + invokedynamic = classic flow obfuscation + string encryption
        if ($findings.ExceptionFlood -gt 5 -and $findings.InvokedynamicAbuse -gt 3) {
            $findings.Score += 15
        }
    } catch {}
    return $findings
}
function Test-ManifestSuspicious {
    param([string]$FilePath)
    $findings = @{
        Suspicious = @()
        Score = 0
    }
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        $manifest = $zip.Entries | Where-Object { $_.FullName -eq "META-INF/MANIFEST.MF" } | Select-Object -First 1
        if ($manifest) {
            $reader = New-Object System.IO.StreamReader($manifest.Open(), [System.Text.Encoding]::UTF8)
            $content = $reader.ReadToEnd()
            $reader.Close()
            if ($content -match "(?i)Premain-Class:") {
                $findings.Suspicious += "Premain-Class detected (Java Agent injection)"
                $findings.Score += 25
            }
            if ($content -match "(?i)Agent-Class:") {
                $findings.Suspicious += "Agent-Class detected (Java Agent injection)"
                $findings.Score += 25
            }
            if ($content -match "(?i)Can-Redefine-Classes:\s*true") {
                $findings.Suspicious += "Can-Redefine-Classes: true (runtime class modification)"
                $findings.Score += 15
            }
            if ($content -match "(?i)Can-Retransform-Classes:\s*true") {
                $findings.Suspicious += "Can-Retransform-Classes: true (runtime class modification)"
                $findings.Score += 15
            }
            if ($content -match "(?i)Boot-Class-Path:") {
                $findings.Suspicious += "Boot-Class-Path detected (bootclasspath injection)"
                $findings.Score += 20
            }
        }
        $zip.Dispose()
    } catch {}
    return $findings
}
function Test-SelfDestructPatterns {
    param([string]$FilePath)
    # Tightened detector: requires Argon-specific signatures to avoid false positives.
    # Generic patterns ("panic", lone "Argon", "onEnable", setName/clear etc.) are NOT used as triggers.
    $classes = [System.Collections.Generic.HashSet[string]]::new()
    $flags = @{
        ArgonNamespace      = $false  # dev/lvstrng/argon (full path)
        SelfDestructClass   = $false  # SelfDestruct class file or "Self Destruct" literal
        ImmediatelyFastUrl  = $false  # Modrinth project id 5ZwdcRci
        ReplaceModFile      = $false  # Argon Utils.replaceModFile
        GetCurrentJarPath   = $false  # Argon Utils.getCurrentJarPath
        ResetModifiedDate   = $false  # Argon-specific method
        ReplaceModSettings  = $false  # both "Replace Mod" and "Replace URL" literal settings
        MemoryPurgeDispose  = $false  # Memory.purge AND Memory.disposeAll combo (rare)
        SaveLastModSetting  = $false  # "Save Last Modified" literal setting
    }
            function Get-YumikoPrintableText {
                param([byte[]]$Bytes)
                $chars = New-Object char[] $Bytes.Length
                for ($i = 0; $i -lt $Bytes.Length; $i++) {
                    $b = $Bytes[$i]
                    if (($b -ge 32 -and $b -le 126) -or $b -eq 9 -or $b -eq 10 -or $b -eq 13) {
                        $chars[$i] = [char]$b
                    } else {
                        $chars[$i] = ' '
                    }
                }
                return -join $chars
            }
            function Test-YumikoSelfDestructContent {
                param([string]$EntryName, [byte[]]$Bytes)
                $content = Get-YumikoPrintableText -Bytes $Bytes
                $haystack = "$EntryName`n$content"
                # Argon namespace: REQUIRE the full path, not just "Argon" (avoids argon2, etc.)
                if ($haystack -match 'dev[/\\.]lvstrng[/\\.]argon') {
                    $flags.ArgonNamespace = $true
                }
                # SelfDestruct class file or exact "Self Destruct" module name literal
                if ($EntryName -match '(?i)SelfDestruct\.class$' -or $haystack -cmatch 'SelfDestruct' -or $haystack -match 'Self\s*Destruct') {
                    $flags.SelfDestructClass = $true
                    $classes.Add(($EntryName -replace '\.class$', '')) | Out-Null
                }
                # Modrinth ImmediatelyFast project ID (uniquely Argon's hardcoded URL)
                if ($haystack -match '5ZwdcRci' -or $haystack -match 'cdn\.modrinth\.com/data/5ZwdcRci') {
                    $flags.ImmediatelyFastUrl = $true
                }
                if ($haystack -cmatch 'replaceModFile') { $flags.ReplaceModFile = $true }
                if ($haystack -cmatch 'getCurrentJarPath') { $flags.GetCurrentJarPath = $true }
                if ($haystack -cmatch 'resetModifiedDate') { $flags.ResetModifiedDate = $true }
                # Both setting names together (Argon-specific UI strings)
                if (($haystack -match 'Replace Mod') -and ($haystack -match 'Replace URL')) {
                    $flags.ReplaceModSettings = $true
                }
                if ($haystack -match 'Save Last Modified') { $flags.SaveLastModSetting = $true }
                # Memory.purge + Memory.disposeAll combo (extremely rare outside Argon SelfDestruct)
                if (($haystack -match '(?i)Memory\.purge|Memory/purge') -and ($haystack -match '(?i)disposeAll')) {
                    $flags.MemoryPurgeDispose = $true
                }
            }
            function Scan-YumikoJarArchive {
                param([System.IO.Compression.ZipArchive]$Archive, [int]$Depth, [string]$Prefix)
                foreach ($entry in $Archive.Entries) {
                    $entryName = if ($Prefix) { "$Prefix!$($entry.FullName)" } else { $entry.FullName }
                    if ($entry.Name -match '\.jar$' -and $Depth -lt 3 -and $entry.Length -gt 0 -and $entry.Length -lt 50000000) {
                        try {
                            $nestedStream = New-Object System.IO.MemoryStream
                            $entryStream = $entry.Open()
                            $entryStream.CopyTo($nestedStream)
                            $entryStream.Close()
                            $nestedStream.Position = 0
                            $nestedArchive = New-Object System.IO.Compression.ZipArchive($nestedStream, [System.IO.Compression.ZipArchiveMode]::Read)
                            Scan-YumikoJarArchive -Archive $nestedArchive -Depth ($Depth + 1) -Prefix $entryName
                            $nestedArchive.Dispose()
                            $nestedStream.Dispose()
                        } catch {}
                        continue
                    }
                    if ($entry.Name -match '\.(class|java|json|toml|properties|cfg|txt|xml|mf)$' -and $entry.Length -gt 0 -and $entry.Length -lt 5000000) {
                        try {
                            $stream = $entry.Open()
                            $ms = New-Object System.IO.MemoryStream
                            $stream.CopyTo($ms)
                            $stream.Close()
                            $bytes = $ms.ToArray()
                            $ms.Dispose()
                            Test-YumikoSelfDestructContent -EntryName $entryName -Bytes $bytes
                        } catch {}
                    }
                }
            }
            try {
                Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
                Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
                $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
                Scan-YumikoJarArchive -Archive $zip -Depth 0 -Prefix ""
                $zip.Dispose()
                $rawBytes = [System.IO.File]::ReadAllBytes($FilePath)
                Test-YumikoSelfDestructContent -EntryName ([System.IO.Path]::GetFileName($FilePath)) -Bytes $rawBytes
            } catch {}
            $indicators = @()
            $score = 0
            if ($flags.ArgonNamespace)     { $indicators += 'Argon namespace (dev/lvstrng/argon)'; $score += 4 }
            if ($flags.SelfDestructClass)  { $indicators += 'SelfDestruct class/module name';      $score += 3 }
            if ($flags.ImmediatelyFastUrl) { $indicators += 'ImmediatelyFast Modrinth ID 5ZwdcRci'; $score += 5 }
            if ($flags.ReplaceModFile)     { $indicators += 'Utils.replaceModFile';                $score += 4 }
            if ($flags.GetCurrentJarPath)  { $indicators += 'Utils.getCurrentJarPath';             $score += 4 }
            if ($flags.ResetModifiedDate)  { $indicators += 'resetModifiedDate';                   $score += 3 }
            if ($flags.ReplaceModSettings) { $indicators += '"Replace Mod" + "Replace URL" settings'; $score += 4 }
            if ($flags.SaveLastModSetting) { $indicators += '"Save Last Modified" setting';        $score += 3 }
            if ($flags.MemoryPurgeDispose) { $indicators += 'Memory.purge + Memory.disposeAll';    $score += 4 }
            # Count of strong unique markers (any one is suspicious; multiple = certain Argon SelfDestruct)
            $uniqueHits = 0
            foreach ($k in 'ImmediatelyFastUrl','ReplaceModFile','GetCurrentJarPath','ResetModifiedDate','ReplaceModSettings','SaveLastModSetting','MemoryPurgeDispose') {
                if ($flags[$k]) { $uniqueHits++ }
            }
            # Detection rules - all require strong Argon evidence:
            #  A) Argon namespace + at least one unique behavior marker (ImmediatelyFast, replaceModFile, etc.)
            #  B) SelfDestruct class/literal + at least one unique behavior marker
            #  C) Two or more independent unique markers (covers heavily-obfuscated jars without namespace)
            $detected = $false
            if ($flags.ArgonNamespace -and $uniqueHits -ge 1) { $detected = $true }
            elseif ($flags.SelfDestructClass -and $uniqueHits -ge 1) { $detected = $true }
            elseif ($uniqueHits -ge 2) { $detected = $true }
            return @{
                Detected   = $detected
                Score      = $score
                Indicators = $indicators
                Classes    = @($classes)
            }
}
function Test-CheatStrings {
    param([string]$FilePath)
    $findings = [System.Collections.Generic.HashSet[string]]::new()
    $fullwidthPattern = "[\uFF21-\uFF3A\uFF41-\uFF5A\uFF10-\uFF19]{2,}"
    $categoryHits = @{
        Combat = [System.Collections.Generic.HashSet[string]]::new()
        Movement = [System.Collections.Generic.HashSet[string]]::new()
        Automation = [System.Collections.Generic.HashSet[string]]::new()
        ClientUI = [System.Collections.Generic.HashSet[string]]::new()
        Injection = [System.Collections.Generic.HashSet[string]]::new()
    }
    $state = @{
        Fullwidth = $false
        AgentManifest = $false
        ImGui = $false
        NativeHook = $false
    }
    $exactPatterns = @(
        @{ Label = 'Known cheat domain: api.novaclient.lol'; Pattern = 'api\.novaclient\.lol' },
        @{ Label = 'Known cheat domain: novaclient.lol'; Pattern = 'novaclient\.lol' },
        @{ Label = 'Known cheat domain: rise.today'; Pattern = 'rise\.today' },
        @{ Label = 'Known cheat domain: riseclient.com'; Pattern = 'riseclient\.com' },
        @{ Label = 'Known cheat domain: vape.gg'; Pattern = 'vape\.gg' },
        @{ Label = 'Known cheat domain: intent.store'; Pattern = 'intent\.store' },
        @{ Label = 'Known cheat domain: novoline.wtf'; Pattern = 'novoline\.wtf' },
        @{ Label = 'Known cheat domain: doomsdayclient.com'; Pattern = 'doomsdayclient\.com' },
        @{ Label = 'Known cheat domain: prestigeclient.vip'; Pattern = 'prestigeclient\.vip' },
        @{ Label = 'Known cheat domain: 198macros.com'; Pattern = '198macros\.com' },
        @{ Label = 'Known cheat domain: dqrkis.xyz'; Pattern = 'dqrkis\.xyz' },
        @{ Label = 'Known cheat domain: pandaware.wtf'; Pattern = 'pandaware\.wtf' },
        @{ Label = 'Known cheat domain: astolfo.lgbt'; Pattern = 'astolfo\.lgbt' },
        @{ Label = 'Known cheat domain: drip.ac'; Pattern = 'drip\.ac' },
        @{ Label = 'Known cheat package: net/wurstclient'; Pattern = 'net[/\\.]wurstclient' },
        @{ Label = 'Known cheat package: meteordevelopment/meteorclient'; Pattern = 'meteordevelopment[/\\.]meteorclient' },
        @{ Label = 'Known cheat package: meteordevelopment/orbit'; Pattern = 'meteordevelopment[/\\.]orbit' },
        @{ Label = 'Known cheat package: net/ccbluex'; Pattern = 'net[/\\.]ccbluex' },
        @{ Label = 'Known cheat package: cc/novoline'; Pattern = 'cc[/\\.]novoline' },
        @{ Label = 'Known cheat package: org/chainlibs/module/impl/modules'; Pattern = 'org[/\\.]chainlibs[/\\.]module[/\\.]impl[/\\.]modules' },
        @{ Label = 'Known cheat package: club/maxstats'; Pattern = 'club[/\\.]maxstats' },
        @{ Label = 'Known cheat package: wtf/moonlight'; Pattern = 'wtf[/\\.]moonlight' },
        @{ Label = 'Known cheat package: me/zeroeightsix/kami'; Pattern = 'me[/\\.]zeroeightsix[/\\.]kami' },
        @{ Label = 'Known cheat package: today/opai'; Pattern = 'today[/\\.]opai' },
        @{ Label = 'Known cheat package: xyz/greaj'; Pattern = 'xyz[/\\.]greaj' },
        @{ Label = 'Suspicious refmap: phantom-refmap.json'; Pattern = 'phantom-refmap\.json' },
        @{ Label = 'Suspicious refmap: client-refmap.json'; Pattern = 'client-refmap\.json' },
        @{ Label = 'Suspicious refmap: cheat-refmap.json'; Pattern = 'cheat-refmap\.json' },
        @{ Label = 'Nova webhook marker'; Pattern = 'aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==' },
        @{ Label = 'Discord webhook endpoint'; Pattern = 'discord\.com/api/webhooks' }
    )
    $categoryPatterns = @{
        Combat = @('KillAura', 'TriggerBot', 'AimAssist', 'AimBot', 'CrystalAura', 'AutoCrystal', 'AnchorAura', 'AutoAnchor', 'BedAura', 'AutoBed', 'ReachHack', 'AntiKB', 'NoKnockback', 'AutoTotem', 'ShieldBreaker')
        Movement = @('PacketFly', 'NoFall', 'FlyHack', 'SpeedHack', 'BHop', 'Scaffold', 'XRayHack', 'Freecam', 'VelocitySpoof')
        Automation = @('AutoClicker', 'ChestStealer', 'InventoryManager', 'AutoEat', 'FastPlace', 'AutoMine', 'Baritone', 'MacroSystem')
        ClientUI = @('ClickGUI', 'HUDEditor', 'ModuleManager', 'ConfigManager', 'KeybindManager', 'SelfDestruct', 'HideClient', 'Panic')
        Injection = @('-javaagent:', 'premain', 'agentmain', 'ClassFileTransformer', 'redefineClasses', 'retransformClasses')
    }
    function Get-YumikoPrintableText {
        param([byte[]]$Bytes)
        $chars = New-Object char[] $Bytes.Length
        for ($i = 0; $i -lt $Bytes.Length; $i++) {
            $b = $Bytes[$i]
            if (($b -ge 32 -and $b -le 126) -or $b -eq 9 -or $b -eq 10 -or $b -eq 13) {
                $chars[$i] = [char]$b
            } else {
                $chars[$i] = ' '
            }
        }
        return -join $chars
    }
    function Scan-ContentForCheats {
        param([string]$EntryName, [byte[]]$Bytes)
        $content = Get-YumikoPrintableText -Bytes $Bytes
        $searchContent = "$EntryName`n$content"
        foreach ($pattern in $exactPatterns) {
            if ($searchContent -match $pattern.Pattern) {
                $findings.Add($pattern.Label) | Out-Null
            }
        }
        if ($searchContent -match '(?i)Premain-Class:' -or $searchContent -match '(?i)Agent-Class:') {
            $state.AgentManifest = $true
        }
        if ($searchContent -match '(?i)imgui\.gl3|imgui\.glfw|imgui-java|imgui\.binding|\bimgui\b') {
            $state.ImGui = $true
        }
        if ($searchContent -match '(?i)jnativehook|GlobalScreen|NativeKeyListener|NativeMouseListener') {
            $state.NativeHook = $true
        }
        if ($searchContent -match $fullwidthPattern) {
            $state.Fullwidth = $true
        }
        foreach ($category in $categoryPatterns.Keys) {
            foreach ($marker in $categoryPatterns[$category]) {
                if ($searchContent -match [regex]::Escape($marker)) {
                    $categoryHits[$category].Add($marker) | Out-Null
                }
            }
        }
    }
    function Scan-NestedJar {
        param([System.IO.Stream]$JarStream, [int]$Depth = 0, [int]$MaxDepth = 3, [string]$Prefix = '')
        if ($Depth -gt $MaxDepth) { return }
        try {
            $archive = New-Object System.IO.Compression.ZipArchive($JarStream, [System.IO.Compression.ZipArchiveMode]::Read)
            foreach ($entry in $archive.Entries) {
                $entryName = if ($Prefix) { "$Prefix!$($entry.FullName)" } else { $entry.FullName }
                if ($entry.Name -like '*.jar' -and $Depth -lt $MaxDepth -and $entry.Length -gt 0 -and $entry.Length -lt 50000000) {
                    try {
                        $ms = New-Object System.IO.MemoryStream
                        $entryStream = $entry.Open()
                        $entryStream.CopyTo($ms)
                        $entryStream.Close()
                        $ms.Position = 0
                        Scan-NestedJar -JarStream $ms -Depth ($Depth + 1) -MaxDepth $MaxDepth -Prefix $entryName
                        $ms.Dispose()
                    } catch {}
                    continue
                }
                if ($entry.Name -match '\.(class|json|toml|properties|cfg|txt|xml|mf)$' -and $entry.Length -gt 0 -and $entry.Length -lt 5000000) {
                    try {
                        $stream = $entry.Open()
                        $ms = New-Object System.IO.MemoryStream
                        $stream.CopyTo($ms)
                        $stream.Close()
                        Scan-ContentForCheats -EntryName $entryName -Bytes $ms.ToArray()
                        $ms.Dispose()
                    } catch {}
                }
            }
            $archive.Dispose()
        } catch {}
    }
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $rawBytes = [System.IO.File]::ReadAllBytes($FilePath)
        Scan-ContentForCheats -EntryName ([System.IO.Path]::GetFileName($FilePath)) -Bytes $rawBytes
        $zip = [System.IO.Compression.ZipFile]::OpenRead($FilePath)
        Scan-NestedJar -JarStream ([System.IO.File]::OpenRead($FilePath)) -Depth 0 -MaxDepth 3 -Prefix ''
        $zip.Dispose()
    } catch {}
    if ($state.AgentManifest) {
        $findings.Add('Java agent manifest in mod JAR') | Out-Null
    }
    if ($state.ImGui -and $state.NativeHook) {
        $findings.Add('Overlay hook combo (imgui + jnativehook)') | Out-Null
    }
    $strongCategories = @()
    foreach ($category in $categoryHits.Keys) {
        if ($categoryHits[$category].Count -ge 2) {
            $strongCategories += "$category=$($categoryHits[$category].Count)"
        }
    }
    $genericDetected = $false
    if ($categoryHits.Injection.Count -ge 2) {
        $findings.Add("Injection combo: $(@($categoryHits.Injection) -join ', ')") | Out-Null
        $genericDetected = $true
    }
    if ($categoryHits.Combat.Count -ge 2 -and ($categoryHits.Movement.Count -ge 1 -or $categoryHits.ClientUI.Count -ge 1 -or $categoryHits.Automation.Count -ge 1)) {
        $findings.Add("Cheat module combo: Combat=$($categoryHits.Combat.Count), Movement=$($categoryHits.Movement.Count), ClientUI=$($categoryHits.ClientUI.Count), Automation=$($categoryHits.Automation.Count)") | Out-Null
        $genericDetected = $true
    }
    if ($categoryHits.ClientUI.Count -ge 2 -and ($categoryHits.Combat.Count -ge 1 -or $categoryHits.Movement.Count -ge 2)) {
        $findings.Add("Client UI combo: ClientUI=$($categoryHits.ClientUI.Count), Combat=$($categoryHits.Combat.Count), Movement=$($categoryHits.Movement.Count)") | Out-Null
        $genericDetected = $true
    }
    if ($state.Fullwidth -and (($categoryHits.Combat.Count + $categoryHits.Movement.Count + $categoryHits.ClientUI.Count) -ge 3)) {
        $findings.Add('Fullwidth obfuscation with cheat module markers') | Out-Null
        $genericDetected = $true
    }
    if ($findings.Count -gt 0 -or $genericDetected) {
        return $findings
    }
    return [System.Collections.Generic.HashSet[string]]::new()
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
function Get-ModJarFiles {
    param([string]$ModsPath)
    $jarFiles = @(Get-ChildItem -LiteralPath $ModsPath -Filter "*.jar" -Force -File -ErrorAction SilentlyContinue)
    foreach ($jarFile in $jarFiles) {
        $hasHiddenFlag = (([int]$jarFile.Attributes) -band [int][System.IO.FileAttributes]::Hidden) -ne 0
        $hasSystemFlag = (([int]$jarFile.Attributes) -band [int][System.IO.FileAttributes]::System) -ne 0
        $wasHidden = $hasHiddenFlag -or $hasSystemFlag
        $visibilityRestored = $false
        if ($wasHidden) {
            try {
                $visibilityMask = [int]([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System)
                $visibleAttributes = [System.IO.FileAttributes](([int]$jarFile.Attributes) -band (-bnot $visibilityMask))
                [System.IO.File]::SetAttributes($jarFile.FullName, $visibleAttributes)
                $jarFile = Get-Item -LiteralPath $jarFile.FullName -Force -ErrorAction SilentlyContinue
                $visibilityRestored = $true
            } catch {}
        }
        $displayName = if ($wasHidden) { "$($jarFile.Name) (hidden)" } else { $jarFile.Name }
        $jarFile | Add-Member -NotePropertyName DisplayName -NotePropertyValue $displayName -Force
        $jarFile | Add-Member -NotePropertyName WasHidden -NotePropertyValue $wasHidden -Force
        $jarFile | Add-Member -NotePropertyName VisibilityRestored -NotePropertyValue $visibilityRestored -Force
        $jarFile
    }
}
function Get-ModDisplayName {
    param([object]$ModFile)
    if ($ModFile -and $ModFile.PSObject.Properties['DisplayName']) {
        return $ModFile.DisplayName
    }
    return $ModFile.Name
}
function Check-DisallowedMods {
    param([object[]]$JarFiles)
    foreach ($file in $jarFiles) {
        $displayName = Get-ModDisplayName -ModFile $file
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
                    FileName = $displayName
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
    $jarFiles = @(Get-ModJarFiles -ModsPath $ModsPath)
    if ($jarFiles.Count -eq 0) {
        Write-Result "INFO" "No JAR files found in mods folder"
        return
    }
    $hiddenJarFiles = @($jarFiles | Where-Object { $_.WasHidden })
    if ($hiddenJarFiles.Count -gt 0) {
        Write-Result "WARN" "Hidden/system mods detected" "$($hiddenJarFiles.Count) file(s) made visible"
        foreach ($hiddenFile in $hiddenJarFiles) {
            $detail = if ($hiddenFile.VisibilityRestored) { "made visible" } else { "detected but could not clear attributes" }
            Write-Result "INFO" "Hidden mod" "$($hiddenFile.DisplayName) - $detail"
        }
    }
    Write-Result "INFO" "Found $($jarFiles.Count) mod(s) to analyze"
    Write-Host ""
    Check-DisallowedMods -JarFiles $jarFiles
    $counter = 0
    $total = $jarFiles.Count
    foreach ($file in $jarFiles) {
        $displayName = Get-ModDisplayName -ModFile $file
        $counter++
        Write-ProgressBar -Current $counter -Total $total -Activity $displayName
        $hash = Get-SHA1Hash -FilePath $file.FullName
        $obfResult = Test-Obfuscator -FilePath $file.FullName
        $hasCriticalObfuscator = ($obfResult.Detected | Where-Object { $_.Severity -eq "CRITICAL" }).Count -gt 0
        $isObfuscated = ($obfResult.Score -gt 60) -or $hasCriticalObfuscator
        if ($isObfuscated) {
            $script:ObfuscatedModsList += @{
                FileName = $displayName
                FilePath = $file.FullName
                Score = $obfResult.Score
                Detected = $obfResult.Detected
            }
        }
        # Scan for URLs, domains, and IPs
        $urlFindings = Test-JarURLsAndDomains -FilePath $file.FullName
        if ($urlFindings.URLs.Count -gt 0 -or $urlFindings.IPs.Count -gt 0 -or $urlFindings.SuspiciousTLDs.Count -gt 0) {
            $script:ModURLFindings += @{
                FileName = $displayName
                FilePath = $file.FullName
                URLs = @($urlFindings.URLs)
                Domains = @($urlFindings.Domains)
                IPs = @($urlFindings.IPs)
                SuspiciousTLDs = @($urlFindings.SuspiciousTLDs)
            }
        }
        $selfDestructResult = Test-SelfDestructPatterns -FilePath $file.FullName
        if ($selfDestructResult.Detected) {
            $script:SelfDestructFindings += @{
                FileName = $displayName
                FilePath = $file.FullName
                Score = $selfDestructResult.Score
                Indicators = $selfDestructResult.Indicators
                Classes = $selfDestructResult.Classes
            }
            Write-Host "`r$(' ' * 80)`r" -NoNewline
            Write-Result "FOUND" "Self Destruct Detected" $displayName
            $script:CheatMods += @{
                FileName = $displayName
                FilePath = $file.FullName
                StringsFound = @("Self Destruct Detected")
                InDependency = $false
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
                SelfDestructInfo = $selfDestructResult
            }
            continue
        }
        $modrinthResult = Test-ModrinthHash -Hash $hash
        if ($modrinthResult) {
            $script:VerifiedMods += @{
                FileName = $displayName
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
                FileName = $displayName
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
                FileName = $displayName
                FilePath = $file.FullName
                StringsFound = @($cheatStringsFound)
                InDependency = $false
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
            }
            continue
        }
        # Advanced detection: Bytecode, Entropy, Mixin, Manifest, String Encoding, Refmap, Native, Advanced Bytecode
        $bytecodeResult = Test-BytecodePatterns -FilePath $file.FullName
        $entropyResult = Test-ClassEntropy -FilePath $file.FullName
        $mixinResult = Test-MixinConfigs -FilePath $file.FullName
        $manifestResult = Test-ManifestSuspicious -FilePath $file.FullName
        $stringEncResult = Test-StringEncoding -FilePath $file.FullName
        $refmapResult = Test-RefmapAnalysis -FilePath $file.FullName
        $nativeResult = Test-NativeLibraries -FilePath $file.FullName
        $advBytecodeResult = Test-AdvancedBytecodePatterns -FilePath $file.FullName
        $advancedScore = $bytecodeResult.Score + $entropyResult.Score + $mixinResult.Score + $manifestResult.Score + $stringEncResult.Score + $refmapResult.Score + $nativeResult.Score + $advBytecodeResult.Score
        # Track findings for reporting
        if ($advancedScore -gt 0) {
            $script:BytecodeFindings += @{
                FileName = $displayName
                BytecodeScore = $bytecodeResult.Score
                EntropyScore = $entropyResult.Score
                MixinScore = $mixinResult.Score
                ManifestScore = $manifestResult.Score
                StringEncScore = $stringEncResult.Score
                RefmapScore = $refmapResult.Score
                NativeScore = $nativeResult.Score
                AdvBytecodeScore = $advBytecodeResult.Score
                TotalAdvancedScore = $advancedScore
                Bytecode = $bytecodeResult
                Entropy = $entropyResult
                Mixin = $mixinResult
                Manifest = $manifestResult
                StringEnc = $stringEncResult
                Refmap = $refmapResult
                Native = $nativeResult
                AdvBytecode = $advBytecodeResult
            }
        }
        # If advanced analysis flags this mod as highly suspicious, mark as cheat
        if ($advancedScore -ge 50) {
            $advancedReasons = @()
            if ($bytecodeResult.Score -gt 0) {
                $details = @()
                if ($bytecodeResult.Reflection.Count -gt 0) { $details += "Reflection($($bytecodeResult.Reflection.Count))" }
                if ($bytecodeResult.DynamicLoading.Count -gt 0) { $details += "DynLoad($($bytecodeResult.DynamicLoading.Count))" }
                if ($bytecodeResult.Networking.Count -gt 0) { $details += "Network($($bytecodeResult.Networking.Count))" }
                if ($bytecodeResult.NativeAccess.Count -gt 0) { $details += "Native($($bytecodeResult.NativeAccess.Count))" }
                if ($bytecodeResult.AgentAttachment.Count -gt 0) { $details += "Agent/JVMTI($($bytecodeResult.AgentAttachment.Count))" }
                $advancedReasons += "BYTECODE ANALYSIS (Score: $($bytecodeResult.Score)): $($details -join ', ')"
            }
            if ($entropyResult.Score -gt 0) {
                $advancedReasons += "HIGH ENTROPY (Score: $($entropyResult.Score)): $($entropyResult.HighEntropyClasses.Count) encrypted classes, Avg: $($entropyResult.AverageEntropy), Max: $($entropyResult.MaxEntropy)"
            }
            if ($mixinResult.Score -gt 0) {
                $advancedReasons += "SUSPICIOUS MIXINS (Score: $($mixinResult.Score)): $($mixinResult.SuspiciousTargets.Count) combat/movement/render targets"
            }
            if ($manifestResult.Score -gt 0) {
                $advancedReasons += "MANIFEST FLAGS (Score: $($manifestResult.Score)): $($manifestResult.Suspicious -join ', ')"
            }
            if ($stringEncResult.Score -gt 0) {
                $encDetails = @()
                if ($stringEncResult.DecodedCheatHits.Count -gt 0) { $encDetails += "DecodedCheats:$($stringEncResult.DecodedCheatHits.Count)" }
                if ($stringEncResult.Base64Strings.Count -gt 0) { $encDetails += "Base64:$($stringEncResult.Base64Strings.Count)" }
                if ($stringEncResult.CharArrayPatterns.Count -gt 0) { $encDetails += "CharArray:$($stringEncResult.CharArrayPatterns.Count)" }
                if ($stringEncResult.XorPatterns -gt 0) { $encDetails += "XOR:$($stringEncResult.XorPatterns)" }
                $advancedReasons += "STRING ENCODING (Score: $($stringEncResult.Score)): $($encDetails -join ', ')"
            }
            if ($refmapResult.Score -gt 0) {
                $advancedReasons += "REFMAP TARGETS (Score: $($refmapResult.Score)): $($refmapResult.RefmapTargets.Count) suspicious Minecraft class mappings"
            }
            if ($nativeResult.Score -gt 0) {
                $nativeDetails = @()
                foreach ($nf in $nativeResult.NativeFiles) { $nativeDetails += $nf.Path }
                $advancedReasons += "NATIVE LIBRARIES (Score: $($nativeResult.Score)): $($nativeDetails -join ', ')"
            }
            if ($advBytecodeResult.Score -gt 0) {
                $abcDetails = @()
                if ($advBytecodeResult.InvokedynamicAbuse -gt 0) { $abcDetails += "InvokeDyn:$($advBytecodeResult.InvokedynamicAbuse)" }
                if ($advBytecodeResult.ExceptionFlood -gt 0) { $abcDetails += "ExcFlood:$($advBytecodeResult.ExceptionFlood)" }
                if ($advBytecodeResult.SyntheticMethods -gt 0) { $abcDetails += "Synthetic:$($advBytecodeResult.SyntheticMethods)" }
                if ($advBytecodeResult.DeadCodeClasses -gt 0) { $abcDetails += "DeadCode:$($advBytecodeResult.DeadCodeClasses)" }
                $advancedReasons += "ADV BYTECODE (Score: $($advBytecodeResult.Score)): $($abcDetails -join ', ')"
            }
            $script:CheatMods += @{
                FileName = $displayName
                FilePath = $file.FullName
                StringsFound = $advancedReasons
                InDependency = $false
                IsObfuscated = $isObfuscated
                ObfuscatorInfo = $obfResult
            }
            continue
        }
        $downloadSource = Get-ZoneIdentifier -FilePath $file.FullName
        $script:UnknownMods += @{
            FileName = $displayName
            FilePath = $file.FullName
            ZoneId = $downloadSource
            Hash = $hash
            IsObfuscated = $isObfuscated
            ObfuscatorInfo = $obfResult
            AdvancedScore = $advancedScore
            BytecodeInfo = $bytecodeResult
            EntropyInfo = $entropyResult
            MixinInfo = $mixinResult
            ManifestInfo = $manifestResult
            StringEncInfo = $stringEncResult
            RefmapInfo = $refmapResult
            NativeInfo = $nativeResult
            AdvBytecodeInfo = $advBytecodeResult
        }
    }
    $toMoveToCheat = @()
    foreach ($mod in $script:UnknownMods) {
        $hasCritical = ($mod.ObfuscatorInfo.Detected | Where-Object { $_.Severity -eq "CRITICAL" }).Count -gt 0
        $advScore = if ($mod.AdvancedScore) { $mod.AdvancedScore } else { 0 }
        # Move to cheat if: heavy obfuscation OR critical obfuscator OR obfuscated + high advanced score
        if (($mod.IsObfuscated -and $mod.ObfuscatorInfo.Score -gt 80) -or $hasCritical -or ($mod.IsObfuscated -and $advScore -ge 30)) {
            $reasons = @("HEAVY OBFUSCATION (Score: $($mod.ObfuscatorInfo.Score)%)")
            if ($hasCritical) {
                $critObf = ($mod.ObfuscatorInfo.Detected | Where-Object { $_.Severity -eq "CRITICAL" } | Select-Object -First 1).Name
                $reasons += "Cheat Obfuscator: $critObf"
            }
            if ($mod.ObfuscatorInfo.Indicators.Count -gt 0) {
                $reasons += $mod.ObfuscatorInfo.Indicators | Select-Object -First 3
            }
            if ($advScore -gt 0) {
                $advDetails = @()
                if ($mod.BytecodeInfo -and $mod.BytecodeInfo.Score -gt 0) { $advDetails += "Bytecode:$($mod.BytecodeInfo.Score)" }
                if ($mod.EntropyInfo -and $mod.EntropyInfo.Score -gt 0) { $advDetails += "Entropy:$($mod.EntropyInfo.Score)" }
                if ($mod.MixinInfo -and $mod.MixinInfo.Score -gt 0) { $advDetails += "Mixin:$($mod.MixinInfo.Score)" }
                if ($mod.ManifestInfo -and $mod.ManifestInfo.Score -gt 0) { $advDetails += "Manifest:$($mod.ManifestInfo.Score)" }
                if ($mod.StringEncInfo -and $mod.StringEncInfo.Score -gt 0) { $advDetails += "StringEnc:$($mod.StringEncInfo.Score)" }
                if ($mod.RefmapInfo -and $mod.RefmapInfo.Score -gt 0) { $advDetails += "Refmap:$($mod.RefmapInfo.Score)" }
                if ($mod.NativeInfo -and $mod.NativeInfo.Score -gt 0) { $advDetails += "Native:$($mod.NativeInfo.Score)" }
                if ($mod.AdvBytecodeInfo -and $mod.AdvBytecodeInfo.Score -gt 0) { $advDetails += "AdvBC:$($mod.AdvBytecodeInfo.Score)" }
                $reasons += "ADVANCED ANALYSIS (Score: $advScore): $($advDetails -join ', ')"
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
            # Show advanced analysis results for unknown mods
            $advScore = if ($mod.AdvancedScore) { $mod.AdvancedScore } else { 0 }
            if ($advScore -gt 0) {
                Write-Host "        Advanced Analysis (Score: $advScore):" -ForegroundColor $script:Colors.Secondary
                if ($mod.BytecodeInfo -and $mod.BytecodeInfo.Score -gt 0) {
                    $bcDetails = @()
                    if ($mod.BytecodeInfo.Reflection.Count -gt 0) { $bcDetails += "Reflection:$($mod.BytecodeInfo.Reflection.Count)" }
                    if ($mod.BytecodeInfo.DynamicLoading.Count -gt 0) { $bcDetails += "DynLoad:$($mod.BytecodeInfo.DynamicLoading.Count)" }
                    if ($mod.BytecodeInfo.Networking.Count -gt 0) { $bcDetails += "Network:$($mod.BytecodeInfo.Networking.Count)" }
                    if ($mod.BytecodeInfo.NativeAccess.Count -gt 0) { $bcDetails += "Native:$($mod.BytecodeInfo.NativeAccess.Count)" }
                    if ($mod.BytecodeInfo.AgentAttachment.Count -gt 0) { $bcDetails += "Agent/JVMTI:$($mod.BytecodeInfo.AgentAttachment.Count)" }
                    Write-Host "          [BC] Bytecode: $($bcDetails -join ', ')" -ForegroundColor $script:Colors.Warning
                }
                if ($mod.EntropyInfo -and $mod.EntropyInfo.Score -gt 0) {
                    Write-Host "          [EN] Entropy: $($mod.EntropyInfo.HighEntropyClasses.Count) high-entropy classes (Avg: $($mod.EntropyInfo.AverageEntropy), Max: $($mod.EntropyInfo.MaxEntropy))" -ForegroundColor $script:Colors.Warning
                }
                if ($mod.MixinInfo -and $mod.MixinInfo.Score -gt 0) {
                    Write-Host "          [MX] Mixins: $($mod.MixinInfo.SuspiciousTargets.Count) suspicious targets" -ForegroundColor $script:Colors.Warning
                }
                if ($mod.ManifestInfo -and $mod.ManifestInfo.Score -gt 0) {
                    foreach ($s in $mod.ManifestInfo.Suspicious) {
                        Write-Host "          [MF] $s" -ForegroundColor $script:Colors.Warning
                    }
                }
                if ($mod.StringEncInfo -and $mod.StringEncInfo.Score -gt 0) {
                    $seDetails = @()
                    if ($mod.StringEncInfo.DecodedCheatHits.Count -gt 0) { $seDetails += "DecodedCheats:$($mod.StringEncInfo.DecodedCheatHits.Count)" }
                    if ($mod.StringEncInfo.Base64Strings.Count -gt 0) { $seDetails += "Base64:$($mod.StringEncInfo.Base64Strings.Count)" }
                    if ($mod.StringEncInfo.CharArrayPatterns.Count -gt 0) { $seDetails += "CharArrays:$($mod.StringEncInfo.CharArrayPatterns.Count)" }
                    if ($mod.StringEncInfo.XorPatterns -gt 0) { $seDetails += "XOR:$($mod.StringEncInfo.XorPatterns)" }
                    Write-Host "          [SE] String Encoding: $($seDetails -join ', ')" -ForegroundColor $script:Colors.Warning
                }
                if ($mod.RefmapInfo -and $mod.RefmapInfo.Score -gt 0) {
                    Write-Host "          [RM] Refmap: $($mod.RefmapInfo.RefmapTargets.Count) suspicious class mappings" -ForegroundColor $script:Colors.Warning
                }
                if ($mod.NativeInfo -and $mod.NativeInfo.Score -gt 0) {
                    $nfList = @()
                    foreach ($nf in $mod.NativeInfo.NativeFiles) { $nfList += $nf.Path }
                    Write-Host "          [NL] Native Libs: $($nfList -join ', ')" -ForegroundColor $script:Colors.Error
                }
                if ($mod.AdvBytecodeInfo -and $mod.AdvBytecodeInfo.Score -gt 0) {
                    $abDetails = @()
                    if ($mod.AdvBytecodeInfo.InvokedynamicAbuse -gt 0) { $abDetails += "InvokeDyn:$($mod.AdvBytecodeInfo.InvokedynamicAbuse)" }
                    if ($mod.AdvBytecodeInfo.ExceptionFlood -gt 0) { $abDetails += "ExcFlood:$($mod.AdvBytecodeInfo.ExceptionFlood)" }
                    if ($mod.AdvBytecodeInfo.SyntheticMethods -gt 0) { $abDetails += "Synthetic:$($mod.AdvBytecodeInfo.SyntheticMethods)" }
                    if ($mod.AdvBytecodeInfo.DeadCodeClasses -gt 0) { $abDetails += "DeadCode:$($mod.AdvBytecodeInfo.DeadCodeClasses)" }
                    Write-Host "          [AB] Adv Bytecode: $($abDetails -join ', ')" -ForegroundColor $script:Colors.Warning
                }
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
    if ($script:ModURLFindings.Count -gt 0) {
        Write-Host ""
        Write-Host "  [NET] " -NoNewline -ForegroundColor $script:Colors.Secondary
        Write-Host "URL / DOMAIN / IP FINDINGS" -ForegroundColor $script:Colors.Secondary
        Write-Host "  ====================================================" -ForegroundColor $script:Colors.Dim
        foreach ($mod in $script:ModURLFindings) {
            Write-Host ""
            Write-Host "    [>] " -NoNewline -ForegroundColor $script:Colors.Secondary
            Write-Host $mod.FileName -ForegroundColor $script:Colors.Info
            if ($mod.URLs.Count -gt 0) {
                Write-Host "        URLs found:" -ForegroundColor $script:Colors.Warning
                foreach ($url in $mod.URLs) {
                    # Highlight suspicious cheat-related URLs in red
                    $isSuspicious = $false
                    $suspiciousKeywords = @("vape", "intent", "novoline", "rise", "astolfo", "exhibition", "sigma", "nova", "doomsday", "prestige", "cheat", "hack", "inject", "exploit", "bypass", "hwid", "auth", "license", "loader", "panel", "webhook", "discord.com/api/webhooks", "pastebin", "hastebin", "paste.ee", "rentry", "anonfiles")
                    foreach ($kw in $suspiciousKeywords) {
                        if ($url -match [regex]::Escape($kw)) { $isSuspicious = $true; break }
                    }
                    if ($isSuspicious) {
                        Write-Host "          [!] " -NoNewline -ForegroundColor $script:Colors.Error
                        Write-Host $url -ForegroundColor $script:Colors.Error
                    } else {
                        Write-Host "          ->  " -NoNewline -ForegroundColor $script:Colors.Dim
                        Write-Host $url -ForegroundColor $script:Colors.Accent
                    }
                }
            }
            if ($mod.IPs.Count -gt 0) {
                Write-Host "        IP addresses found:" -ForegroundColor $script:Colors.Warning
                foreach ($ip in $mod.IPs) {
                    Write-Host "          [!] " -NoNewline -ForegroundColor $script:Colors.Warning
                    Write-Host $ip -ForegroundColor $script:Colors.Warning
                }
            }
            if ($mod.SuspiciousTLDs -and $mod.SuspiciousTLDs.Count -gt 0) {
                Write-Host "        Suspicious TLDs:" -ForegroundColor $script:Colors.Error
                foreach ($tld in $mod.SuspiciousTLDs) {
                    Write-Host "          [!] " -NoNewline -ForegroundColor $script:Colors.Error
                    Write-Host $tld -ForegroundColor $script:Colors.Error
                }
            }
        }
    }
    # Advanced Analysis Summary
    if ($script:BytecodeFindings.Count -gt 0) {
        Write-Host ""
        Write-Host "  [ADV] " -NoNewline -ForegroundColor $script:Colors.Primary
        Write-Host "ADVANCED ANALYSIS FINDINGS" -ForegroundColor $script:Colors.Primary
        Write-Host "  ====================================================" -ForegroundColor $script:Colors.Dim
        foreach ($finding in $script:BytecodeFindings) {
            Write-Host ""
            Write-Host "    [>] " -NoNewline -ForegroundColor $script:Colors.Primary
            Write-Host "$($finding.FileName)" -NoNewline -ForegroundColor $script:Colors.Info
            Write-Host " (Advanced Score: $($finding.TotalAdvancedScore))" -ForegroundColor $(if ($finding.TotalAdvancedScore -ge 50) { $script:Colors.Error } elseif ($finding.TotalAdvancedScore -ge 25) { $script:Colors.Warning } else { $script:Colors.Dim })
            if ($finding.BytecodeScore -gt 0) {
                $bc = $finding.Bytecode
                Write-Host "        [BC] Bytecode Analysis (Score: $($finding.BytecodeScore)):" -ForegroundColor $script:Colors.Secondary
                if ($bc.Reflection.Count -gt 0) { Write-Host "          Reflection calls: $($bc.Reflection.Count)" -ForegroundColor $script:Colors.Warning }
                if ($bc.DynamicLoading.Count -gt 0) { Write-Host "          Dynamic classloading: $($bc.DynamicLoading.Count)" -ForegroundColor $script:Colors.Error }
                if ($bc.Networking.Count -gt 0) { Write-Host "          Network operations: $($bc.Networking.Count)" -ForegroundColor $script:Colors.Warning }
                if ($bc.NativeAccess.Count -gt 0) { Write-Host "          Native/Unsafe access: $($bc.NativeAccess.Count)" -ForegroundColor $script:Colors.Error }
                if ($bc.AgentAttachment.Count -gt 0) { Write-Host "          Agent/JVMTI attachment: $($bc.AgentAttachment.Count)" -ForegroundColor $script:Colors.Error }
            }
            if ($finding.EntropyScore -gt 0) {
                $en = $finding.Entropy
                Write-Host "        [EN] Entropy Analysis (Score: $($finding.EntropyScore)):" -ForegroundColor $script:Colors.Secondary
                Write-Host "          High-entropy classes: $($en.HighEntropyClasses.Count) | Avg: $($en.AverageEntropy) | Max: $($en.MaxEntropy)" -ForegroundColor $script:Colors.Warning
            }
            if ($finding.MixinScore -gt 0) {
                $mx = $finding.Mixin
                Write-Host "        [MX] Mixin Config Analysis (Score: $($finding.MixinScore)):" -ForegroundColor $script:Colors.Secondary
                Write-Host "          Suspicious targets: $($mx.SuspiciousTargets.Count)" -ForegroundColor $script:Colors.Warning
                foreach ($target in ($mx.SuspiciousTargets | Select-Object -First 5)) {
                    Write-Host "            -> $target" -ForegroundColor $script:Colors.Dim
                }
            }
            if ($finding.ManifestScore -gt 0) {
                Write-Host "        [MF] Manifest Analysis (Score: $($finding.ManifestScore)):" -ForegroundColor $script:Colors.Secondary
                foreach ($s in $finding.Manifest.Suspicious) {
                    Write-Host "            -> $s" -ForegroundColor $script:Colors.Error
                }
            }
            if ($finding.StringEncScore -gt 0) {
                $se = $finding.StringEnc
                Write-Host "        [SE] String Encoding (Score: $($finding.StringEncScore)):" -ForegroundColor $script:Colors.Secondary
                if ($se.DecodedCheatHits.Count -gt 0) { Write-Host "          Decoded cheat keywords: $($se.DecodedCheatHits.Count)" -ForegroundColor $script:Colors.Error }
                if ($se.Base64Strings.Count -gt 0) { Write-Host "          Suspicious Base64 strings: $($se.Base64Strings.Count)" -ForegroundColor $script:Colors.Warning }
                if ($se.CharArrayPatterns.Count -gt 0) { Write-Host "          Char array constructions: $($se.CharArrayPatterns.Count)" -ForegroundColor $script:Colors.Warning }
                if ($se.XorPatterns -gt 0) { Write-Host "          XOR byte patterns: $($se.XorPatterns)" -ForegroundColor $script:Colors.Error }
            }
            if ($finding.RefmapScore -gt 0) {
                $rm = $finding.Refmap
                Write-Host "        [RM] Refmap Analysis (Score: $($finding.RefmapScore)):" -ForegroundColor $script:Colors.Secondary
                Write-Host "          Suspicious class mappings: $($rm.RefmapTargets.Count)" -ForegroundColor $script:Colors.Warning
                foreach ($target in ($rm.RefmapTargets | Select-Object -First 5)) {
                    Write-Host "            -> $target" -ForegroundColor $script:Colors.Dim
                }
            }
            if ($finding.NativeScore -gt 0) {
                $nl = $finding.Native
                Write-Host "        [NL] Native Library Detection (Score: $($finding.NativeScore)):" -ForegroundColor $script:Colors.Secondary
                foreach ($nf in $nl.NativeFiles) {
                    $jniLabel = if ($nf.HasJNI) { " [JNI]" } else { "" }
                    Write-Host "          $($nf.Path)$jniLabel" -ForegroundColor $script:Colors.Error
                }
            }
            if ($finding.AdvBytecodeScore -gt 0) {
                $ab = $finding.AdvBytecode
                Write-Host "        [AB] Advanced Bytecode (Score: $($finding.AdvBytecodeScore)):" -ForegroundColor $script:Colors.Secondary
                if ($ab.InvokedynamicAbuse -gt 0) { Write-Host "          Invokedynamic abuse (string encrypt): $($ab.InvokedynamicAbuse)" -ForegroundColor $script:Colors.Error }
                if ($ab.ExceptionFlood -gt 0) { Write-Host "          Exception handler flooding: $($ab.ExceptionFlood)" -ForegroundColor $script:Colors.Warning }
                if ($ab.SyntheticMethods -gt 0) { Write-Host "          Synthetic method anomalies: $($ab.SyntheticMethods)" -ForegroundColor $script:Colors.Warning }
                if ($ab.DeadCodeClasses -gt 0) { Write-Host "          Dead code / junk classes: $($ab.DeadCodeClasses)" -ForegroundColor $script:Colors.Warning }
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
    Check-CustomFonts
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
