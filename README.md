# YumikoModAnalyzer.ps1

Dedicated documentation for the Windows command-line analyzer `YumikoModAnalyzer.ps1`.

This README covers only this script.
It does not document the GUI build, the macOS build, or the paid variants.

## What This Script Is

`YumikoModAnalyzer.ps1` is the main Windows PowerShell analyzer in the Yumiko project.
It is designed to inspect Minecraft mods, verify known files by hash, detect suspicious or hidden JAR files, and run a large set of Windows-based forensic and bypass checks.

## What It Does

The script combines two major workflows:

- Mod analysis.
- Windows system analysis.

Depending on the mode you choose, it can:

- Scan a mods folder for JAR files.
- Detect hidden or system-marked mods and make them visible before analysis.
- Verify mod hashes against Modrinth and Megabase.
- Flag unknown, obfuscated, disallowed, or suspicious mods.
- Inspect nested JARs and dependency payloads.
- Analyze strings, bytecode, entropy, mixins, manifests, refmaps, native libraries, and advanced bytecode patterns.
- Check Windows forensic indicators such as registry restrictions, Prefetch, BAM/DAM, Shimcache, Amcache, DNS cache, scheduled tasks, startup items, and more.
- Inspect Java processes and launcher arguments for injection or cheat-related patterns.

## Requirements

- Windows 10 or newer.
- Windows PowerShell 5.1 or PowerShell 7.
- Administrator privileges recommended for full system visibility.
- Internet access recommended for Modrinth and Megabase hash lookups.

## Script Parameters

The script supports the following parameters:

| Parameter | Description |
|---|---|
| `-SkipSystemCheck` | Skip Windows system analysis and run mod analysis only |
| `-SkipModCheck` | Skip mod analysis and run system analysis only |
| `-ModPath <path>` | Use a custom mods folder path |
| `-AutoFix` | Reserved for remediation workflows where supported |
| `-Silent` | Reserved for quiet or scripted execution flows |

## How To Run It


```
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/veridondevvv/YumikoModAnalyzer/refs/heads/main/YumikoModAnalyzer.ps1')"
```

### Option 3: Common Examples

```powershell
# Mod analysis only
powershell -ExecutionPolicy Bypass -File .\YumikoModAnalyzer.ps1 -SkipSystemCheck

# System analysis only
powershell -ExecutionPolicy Bypass -File .\YumikoModAnalyzer.ps1 -SkipModCheck

# Custom mods folder
powershell -ExecutionPolicy Bypass -File .\YumikoModAnalyzer.ps1 -ModPath "D:\Minecraft\mods"
```

## Interactive Modes

When started normally, the script presents these modes:

- Full System + Mod Analysis.
- Mod Analysis Only.
- System Bypass Detection Only.
- Exit.

## Default Mods Folder

If no custom path is entered, the script uses:

```text
%APPDATA%\.minecraft\mods
```

## Mod Analysis Coverage

The mod-analysis part of `YumikoModAnalyzer.ps1` includes:

- Modrinth hash verification.
- Megabase hash verification.
- Detection of disallowed mods.
- Detection of hidden or system-flagged JAR files.
- Cheat-string detection.
- Obfuscator detection.
- URL, domain, and IP extraction.
- Self-destruct pattern detection.
- Bytecode pattern analysis.
- Class entropy analysis.
- Mixin config analysis.
- Manifest inspection.
- String-encoding inspection.
- Refmap analysis.
- Native library detection.
- Advanced bytecode heuristics.

## Hidden Mod Handling

This script now specifically detects mod JARs that were hidden with Windows file attributes such as Hidden or System.

If such files are found:

- They are still included in the scan.
- The script attempts to make them visible before analysis.
- They are marked with `(hidden)` in analysis output.

This prevents a simple attribute-based bypass where a JAR is hidden to avoid normal folder enumeration.

## System Analysis Coverage

The Windows system-analysis part includes checks such as:

- Hosts file manipulation.
- Registry restrictions.
- IFEO hijacking.
- DisallowRun policies.
- Firewall restrictions.
- Autorun abuse.
- Browser URL blocklists.
- CMD color bypass tricks.
- Prefetch manipulation.
- Event log clearing.
- Defender exclusions.
- Scheduled tasks.
- PowerShell logging status.
- Startup folder inspection.
- Suspicious processes.
- DNS cache review.
- BAM/DAM inspection.
- Shimcache inspection.
- Amcache inspection.
- Jump List analysis.
- Recent JAR tracking.
- JVM argument checks.
- Advanced JVM configuration checks.
- Java process memory analysis.
- Localhost web server detection.
- Custom font abuse checks.
- Prefetch-based trace detection.
- Doomsday trace detection.
- Fabric and Forge injection analysis.

## Result Categories

During or after a scan, the script commonly groups findings into these result types:

- Verified mods.
- Unknown mods.
- Cheat or suspicious mods.
- Disallowed mods.
- Obfuscated mods.
- URL and domain findings.
- Bytecode and advanced-analysis findings.
- Self-destruct findings.
- System findings.

## Typical Workflow

1. Start the script using the batch launcher or PowerShell.
2. Choose the analysis mode.
3. Enter a custom mods path or accept the default path.
4. Let the script inspect the mods and optionally the system.
5. Review verified, unknown, obfuscated, hidden, disallowed, and suspicious results.

## Notes About Findings

- A verified mod matched a known source by hash.
- An unknown mod did not match the verification APIs.
- An obfuscated mod is not automatically malicious, but it requires closer inspection.
- A hidden mod is a strong investigation signal because it may indicate bypass intent.
- A suspicious result is an investigation lead and should be reviewed in context.

## Limitations

- Some Windows forensic checks require Administrator privileges.
- API-based verification depends on external services being reachable.
- The script is Windows-focused and is not the correct entrypoint for macOS.
- Some reserved parameters exist for compatibility or future flows and may not always change behavior directly.

## Troubleshooting

### The script cannot see all findings

Run the script as Administrator so Windows-restricted checks can return complete results.

### The default mods path is wrong

Use `-ModPath` and point directly to the correct Minecraft instance or launcher-specific mods folder.

### Verification does not work

Check internet connectivity and verify that the Modrinth and Megabase APIs are reachable.

### A hidden JAR was found

Treat that as suspicious, even if the mod is not automatically classified as a cheat.
Hidden or system attributes are a common attempt to bypass simple folder scans.

## Credits

`YumikoModAnalyzer.ps1` is part of Yumiko Mod Analyzer by Veridon.

If you reuse this script or parts of it, give visible credit.
Recommended credit line:

```text
Based on Yumiko Mod Analyzer by Veridon.
```
