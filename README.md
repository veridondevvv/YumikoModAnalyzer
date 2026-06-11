# YumikoModAnalyzer.ps1

Dedicated documentation for the Windows command-line analyzer `YumikoModAnalyzer.ps1`.

This README covers only this script.
It does not document the GUI build, the macOS build, or the paid variants.

**Current version: 5.1.0**

## What This Script Is

`YumikoModAnalyzer.ps1` is the main Windows PowerShell analyzer in the Yumiko project.
It is designed to inspect Minecraft mods, verify known files by hash, detect suspicious or hidden JAR files, and run a large set of Windows-based forensic and bypass checks.

## What It Does

The script combines two major workflows:

- **Mod analysis** — deep static inspection of JAR files with 13+ specialized analyzers.
- **Windows system analysis** — forensic checks for bypass techniques, active cheat processes, and system tampering.

Depending on the mode you choose, it can:

- Scan a mods folder for JAR files (including hidden / system-flagged ones).
- Recursively unpack nested JARs (Jar-in-Jar up to depth 4) to find hidden payloads.
- Verify mod hashes against Modrinth and Megabase.
- Flag unknown, obfuscated, disallowed, or suspicious mods.
- Inspect nested JARs and dependency payloads.
- Analyze strings, bytecode, entropy, mixins, manifests, refmaps, native libraries, and advanced bytecode patterns.
- Detect modern obfuscated cheat clients via **class-file heuristics**, **mixin combo profiles**, **string-decryptor bytecode**, and **bytecode sequence patterns**.
- Scan active Java process memory for generic cheat signatures (GUI strings, injection hooks, webhooks, auth panels).
- Check Windows forensic indicators such as registry restrictions, Prefetch, BAM/DAM, Shimcache, Amcache, DNS cache, scheduled tasks, startup items, and more.
- Inspect Java processes and launcher arguments for injection or cheat-related patterns.

## Requirements

- Windows 10 or newer.
- Windows PowerShell 5.1 or PowerShell 7.
- **Administrator privileges strongly recommended** for full system visibility and Java memory forensics.
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

### Option 1: Direct execution (latest version from GitHub)

```powershell
powershell -ExecutionPolicy Bypass -Command "iex (irm 'https://raw.githubusercontent.com/veridondevvv/YumikoModAnalyzer/refs/heads/main/YumikoModAnalyzer.ps1')"
```

### Option 2: Local file

```powershell
powershell -ExecutionPolicy Bypass -File .\YumikoModAnalyzer.ps1
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

- **Full System + Mod Analysis** (recommended).
- **Mod Analysis Only**.
- **System Bypass Detection Only**.
- **Exit**.

## Default Mods Folder

If no custom path is entered, the script uses:

```text
%APPDATA%\.minecraft\mods
```

## Mod Analysis Coverage

The mod-analysis engine runs **13 independent analyzers** on every JAR:

| Analyzer | Tag | What it detects |
|---|---|---|
| **Cheat String Detection** | — | Direct keyword matches (KillAura, AutoCrystal, etc.) in JAR contents |
| **Obfuscator Detection** | — | Naming-pattern analysis for Skidfuscator, Radon, Paramorphism, Stringer, Zelix, and custom obfuscators |
| **Bytecode Pattern Analysis** | `[BC]` | Reflection calls, dynamic classloading, network operations, native access, agent/JVMTI attachment |
| **Class Entropy Analysis** | `[EN]` | High-entropy classes indicating encrypted strings or packed payloads |
| **Mixin Config Analysis** | `[MX]` | Suspicious mixin targets in combat, movement, render, and packet categories |
| **Manifest Inspection** | `[MF]` | Java-Agent injection flags (`Premain-Class`, `Can-Redefine-Classes`, `Boot-Class-Path`) |
| **String-Encoding Inspection** | `[SE]` | Base64, char-array construction, XOR patterns, and char-array string decoders |
| **Refmap Analysis** | `[RM]` | Mixin refmaps pointing at sensitive Minecraft classes |
| **Native Library Detection** | `[NL]` | Embedded `.dll`, `.so`, `.dylib`, JNI methods, and bundled executables |
| **Archive Structure Analysis** | `[AS]` | Anomalies in JAR layout (embedded Minecraft classes, missing nested JARs, obfuscated entrypoints) |
| **Advanced Bytecode Heuristics** | `[AB]` | Invokedynamic abuse, exception-handler flooding, synthetic methods, dead-code classes |
| **Class-File Heuristics** | `[CF]` | Constant-pool parsing: InvokeDynamic/MethodHandle counts, `reflect`/`invoke`/`Unsafe`/`instrument` refs *(v5.1.0)* |
| **Mixin Combo Profiles** | `[MC]` | Cheat profiles from category combinations: `UniversalCheat`, `FullCombatClient`, `MovementCheat` *(v5.1.0)* |
| **String Decryptor Bytecode** | `[SD]` | Obfuscator infrastructure: decrypt methods in `<clinit>`, heavy String[] init, XOR byte arrays *(v5.1.0)* |
| **Bytecode Sequence Patterns** | `[BS]` | Reflective chains, Unsafe usage, Instrumentation hooks, JNI loading *(v5.1.0)* |

### How the new v5.1.0 analyzers work

#### Class-File Heuristics (`[CF]`)
Instead of scanning raw ASCII strings, this analyzer parses the **Java Class File Format** binary constant pool of every `.class` file. It counts:
- `InvokeDynamic` entries (tag 18) — heavy counts indicate string encryption (Skidfuscator, Stringer).
- `MethodHandle` entries (tag 15) — reflection obfuscation.
- References to `java/lang/reflect`, `java/lang/invoke`, `sun/misc/Unsafe`, `java/lang/instrument`.
- `JNI_OnLoad` / `registerNatives` markers.

A combination of **>10 InvokeDynamic + >5 MethodHandle + >5 Reflection refs** triggers a **CRITICAL** heavy-obfuscation flag that no legitimate mod produces.

#### Mixin Combo Profiles (`[MC]`)
Refmap analysis now categorizes every target into **7 domains**: Combat, Movement, Render, Packet, Inventory, World, Input. A mod that patches **4+ categories simultaneously** (e.g. Combat + Movement + Render + Packet) matches the `UniversalCheat` profile and scores up to 50 points. Legitimate performance mods like Sodium or Iris rarely patch more than 2 categories.

#### String Decryptor Bytecode (`[SD]`)
Modern obfuscators encrypt all cheat strings. This analyzer detects the **decryption infrastructure** instead:
- Method descriptors containing `decrypt` or `decode` inside `<clinit>` (static initializer).
- Heavy `aastore` density (massive `String[]` initialization in static blocks).
- `newarray byte` patterns (XOR key arrays).

Finding a dedicated string-decryptor class is a near-certain cheat indicator even when no readable cheat strings exist.

#### Bytecode Sequence Patterns (`[BS]`)
Detects dangerous capability chains in raw bytecode:
- **Reflection chains**: `Class.forName` → `Method.invoke`
- **Unsafe sequences**: `sun/misc/Unsafe` + `getUnsafe`/`putInt`/`copyMemory`
- **Instrumentation hooks**: `java/lang/instrument/Instrumentation` + `redefineClasses`
- **JNI loading**: `System.loadLibrary` / `JNI_OnLoad`

This catches runtime-modification capabilities even when class names are fully encrypted.

#### Extended Memory Signatures (`Check-JavaProcessMemory`)
The Java RAM scanner now includes **generic cheat runtime signatures** beyond Doomsday/Argon:
- GUI system strings: `clickgui`, `ClickGUI`, `Watermark`, `TargetHUD`, `ModuleList`
- Category labels: `Category.COMBAT`, `Category.MOVEMENT`, `Category.RENDER`
- Injection hooks: `javaagent`, `premain`, `instrument`, `redefineClasses`
- Network indicators: `discord.com/api/webhooks`, `hwid`, `auth`, `panel`, `checkAuth`
- Process manipulation: `SetWindowsHookEx`, `GetAsyncKeyState`, `RegisterHotKey`

## Hidden Mod Handling

This script detects mod JARs hidden with Windows file attributes (Hidden or System).

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
- Prefetch manipulation and trace detection.
- Event log clearing.
- Defender exclusions.
- Scheduled tasks.
- PowerShell logging status.
- Startup folder inspection.
- Suspicious processes.
- DNS cache review.
- BAM/DAM inspection.
- Shimcache inspection.
- Amcache / Uninstall program inspection.
- Jump List analysis.
- Recent JAR tracking.
- JVM argument checks.
- Advanced JVM configuration checks.
- **Java process memory analysis** (Doomsday, Argon Self-Destruct, and **generic cheat signatures**).
- Localhost web server detection (cheat GUI detection).
- Custom font abuse checks.
- Doomsday trace detection.
- Fabric and Forge injection analysis.

## Result Categories

During or after a scan, the script groups findings into these result types:

- **Verified mods** — hash matches Modrinth or Megabase, and all deep checks passed.
- **Unknown mods** — no hash match; shown with obfuscation % and all 13 analyzer tags.
- **Obfuscated mods** — heavy obfuscation detected; may be promoted to Cheat.
- **Cheat / Suspicious mods** — failed string checks, deep analysis, or memory signatures.
- **Disallowed mods** — on the explicit blocklist (e.g. Freecam, Xero's Minimap).
- **Hidden mods** — JARs with Hidden/System attributes.
- **URL / Domain / IP findings** — extracted network endpoints from JAR contents.
- **System findings** — Windows forensic bypass indicators.

## Scoring and Escalation

Each mod receives an **Advanced Score** from all 13 analyzers (max ~220 raw points). The escalation threshold is **50 points**.

- **< 50 points**: Mod stays in Unknown (unless direct cheat strings are found).
- **>= 50 points**: Mod is escalated to **Cheat** with detailed reason strings.
- **Obfuscation-only path**: Unknown mods with >80% obfuscation score or a CRITICAL obfuscator are also promoted to Cheat.

All findings are exported to a timestamped `YumikoReport-<datetime>.json`.

## Typical Workflow

1. Start the script using the batch launcher or PowerShell.
2. Choose the analysis mode (Full recommended).
3. Enter a custom mods path or accept the default path.
4. Let the script inspect the mods and optionally the system.
5. Review verified, unknown, obfuscated, hidden, disallowed, and suspicious results.
6. Check the JSON report for machine-readable output.

## Notes About Findings

- A **verified** mod matched a known source by hash and passed all deep checks.
- An **unknown** mod did not match the verification APIs. It may be legitimate but unlisted, or custom / private.
- An **obfuscated** mod is not automatically malicious, but it requires closer inspection — especially if `[CF]` or `[SD]` tags are present.
- A **hidden** mod is a strong investigation signal because it may indicate bypass intent.
- A **suspicious** result is an investigation lead and should be reviewed in context. Multiple independent analyzer hits (`[CF]` + `[MC]` + `[SD]`) dramatically increase confidence.

## Limitations

- Some Windows forensic checks (BAM/DAM, memory scanning, Prefetch parsing) require **Administrator privileges**.
- API-based verification depends on external services (Modrinth, Megabase) being reachable.
- The script is Windows-focused and is not the correct entrypoint for macOS.
- Memory scanning requires a running Java process (Minecraft must be active). If no Java process is running, only JAR-based analysis is possible.
- Some reserved parameters exist for compatibility or future flows and may not always change behavior directly.

## Troubleshooting

### The script cannot see all findings

Run the script as **Administrator** so Windows-restricted checks and Java memory forensics can return complete results.

### The default mods path is wrong

Use `-ModPath` and point directly to the correct Minecraft instance or launcher-specific mods folder.

### Verification does not work

Check internet connectivity and verify that the Modrinth and Megabase APIs are reachable.

### A hidden JAR was found

Treat that as suspicious, even if the mod is not automatically classified as a cheat.
Hidden or system attributes are a common attempt to bypass simple folder scans.

### High scores on legitimate performance mods

Some large performance mods (Sodium, Iris, Lithium) may trigger low-level `[CF]` or `[MX]` tags due to legitimate mixin usage. These mods will **not** reach the 50-point escalation threshold unless they also show obfuscation, string encryption, or suspicious category combinations. Always review the **reason strings** before concluding a mod is a cheat.

## Credits

`YumikoModAnalyzer.ps1` is part of **Yumiko Mod Analyzer** by Veridon.

If you reuse this script or parts of it, give visible credit.
Recommended credit line:

```text
Based on Yumiko Mod Analyzer by Veridon.
```
