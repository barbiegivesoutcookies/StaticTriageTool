# StaticTriageTool

> **Copyright (c) 2026 barbiegivesoutcookies**

A high-performance, cross-platform command-line utility engineered in C# and .NET 10.0 for the automated static analysis and triage of suspicious binaries and archives. The engine performs a heuristic string/byte scan across raw data streams and archive contents — it is **not** a PE-import-table-aware parser.

---

## Core Architectural Features

- **Buffered Hashing Pipeline:** Securely computes SHA-256 fingerprints using a streaming 1 MB sequential buffer to handle files > 1 GB without exhausting system RAM.
- **Multi-Encoding Scanning:** Simultaneously inspects data streams for both standard ASCII and Windows native UTF-16LE (Wide-Char) string layouts.
- **Boundary Overlap Protection:** Retains a rolling 32-byte safety overlap buffer between data chunk boundaries to prevent target keywords from being split and missed across chunk thresholds.
- **Unified Regex Performance:** Utilizes a single, precompiled alternation Regular Expression engine (`RegexOptions.Compiled | RegexOptions.IgnoreCase`) for optimized throughput on massive inputs.

---

## Zip-Bomb Sandbox Defenses & Archive Scope

### Supported Containers

Native ZIP-family structures only:

| Container Family | Examples |
|---|---|
| Standard ZIP archives | `.zip` |
| Open XML office documents | `.docx`, `.xlsx`, `.pptx` |
| Java / Android packages | `.jar`, `.apk` |

ZIP-family membership is verified by structural file headers (magic bytes `PK\x03\x04`, `PK\x05\x06`, `PK\x07\x08`) — never by file extension alone.

### In-Memory Streaming

Unpacks allowed archive entries entirely within volatile RAM memory streams; zero data is written to the physical hard drive during scanning.

### Hard Constraints Matrix

Built-in thresholds used to block resource exhaustion:

- **Max Decompressed Size:** 2 GB total allocation window per archive.
- **Max Entry Expansion Ratio:** 100x max compression-to-decompression ratio per file element.
- **Max Entry Count Limit:** 10,000 files per container.
- **Max Recursive Nested Depth:** 2 levels deep (blocks nested archive loops).

Runtime decompressed byte volume is additionally counted against declared header sizes; entries whose actual expansion exceeds their declared/budgeted size are rejected as hostile-header anomalies.

---

## Strict Operational Constraints

- **No External Dependencies:** Built entirely on native .NET Base Class Library (BCL) footprints; relies on no third-party libraries or NuGet packages.
- **Proprietary Archive Restriction:** Out-of-scope formats such as `.7z`, `.rar`, or `.tar` are blocked by structural file header (magic byte) validation. The tool flags these as unsupported and exits cleanly rather than crashing.
- **Evasion Defenses Disclaimer:** Because it relies strictly on heuristic string patterns, it may suffer from false negatives if a binary is heavily obfuscated, packed (e.g., UPX), or completely encrypted.

---

## Rule Classification Reference

All indicators are matched case-insensitively as exact substrings across both encoding layers.

| Category | Indicators |
|---|---|
| Memory Allocation / Injection | `VirtualAlloc`, `VirtualAllocEx`, `VirtualQuery`, `WriteProcessMemory` |
| Process Hijacking | `OpenProcess`, `DuplicateHandle`, `Process32First`, `Process32Next` |
| Registry Persistence Hooks | `RegOpenKeyExW`, `RegSetValueExW`, `RegDeleteKeyW`, `RegCreateKeyExW` |
| Network & C2 Foundations | `WSASocketW`, `connect` *(context noise warning)*, `DnsQuery_W`, `GetAddrInfoW`, `InternetOpenW` |
| File & Share Manipulation | `CreateFileW`, `WriteFileW`, `DeleteFileW`, `MoveFileExW`, `NetShareAdd`, `NetShareDel` |
| Anti-Analysis / Anti-Sandbox | `rdtsc`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` |

> **Note:** The `connect` indicator carries high natural-text noise in ordinary documents and binaries. It is logged with placement details but is explicitly annotated with a context warning in output and reports.

---

## Usage & Exit Code Specification

```text
StaticTriageTool <path_to_file_or_archive>
```

| Exit Code | Meaning |
|---|---|
| `0` | Clean — no indicators matched |
| `1` | Hit Detected — threat indicators successfully flagged |
| `2` | Input/System Error — file missing, access denied, invalid path, or safety-limit abort |
| `3` | Unsupported Format — proprietary archive signature matched |

Every run prints a structured ASCII triage block to the console (target metadata, SHA-256, container classification, entry counts, skipped anomalies, categorized matches with hex offsets and internal archive paths) and mirrors that exact output into `triage_report.txt` in the execution directory.

---

## Cross-Compilation Guide

Build a standalone, self-contained single-file binary (.NET 10 SDK required):

**Windows 10/11 x64:**

```bash
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o publish/win-x64
```

Output: `publish/win-x64/StaticTriageTool.exe`

**Linux / Kali Linux x64:**

```bash
dotnet publish -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -o publish/linux-x64
```

Output: `publish/linux-x64/StaticTriageTool`