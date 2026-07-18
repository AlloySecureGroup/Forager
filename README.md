# LOL-Forager

# WDAC / AppLocker Bypass Capability Scanner

`Scan-WdacBypassCapabilities.ps1` inventories the trusted binaries present on a Windows host that can be abused to run unapproved code under a WDAC or AppLocker policy. It is a discovery and audit aid for defenders, detection engineers and policy authors. It does not exploit anything, it reports what is present so you can decide what to block, allow with rules, or monitor.

Every technique it looks for is publicly documented (see the LOLBAS project). Running this tells you which of those vectors actually exist on the box you are assessing.

> Run this only on systems you are authorised to assess. A match means the binary **contains or is a known vector for** the capability, not that it is exploitable in your specific policy. Confirm against your WDAC configuration before drawing conclusions.

## How it detects things

The scan runs two independent layers and reports a file if either fires.

### Layer A: known-LOLBAS catalog (matched by name)

A curated list of binaries whose bypass behaviour is documented. These are matched by file name, because the capability is a property of what the binary does, not of a string you can grep for. This layer surfaces the thin launcher EXEs whose real capability code lives in a companion DLL, and the native hosts that are not managed assemblies at all.

Current catalog:

| Binary | Tier | Technique |
|---|---|---|
| InstallUtil.exe | Trusted loader | Installer-class execution via `[RunInstaller(true)]` Install/Uninstall, plus the HelpText override path |
| RegAsm.exe | Trusted loader | `[ComRegisterFunction]` / `[ComUnregisterFunction]` execution |
| RegSvcs.exe | Trusted loader | EnterpriseServices registration hooks |
| AddInProcess.exe, AddInProcess32.exe | Trusted loader | System.AddIn out-of-process add-in host |
| dotnet.exe | Trusted loader | Native host that runs any managed DLL, `dotnet exec`, `dotnet fsi` |
| MSBuild.exe | In-memory compile | Inline `<Code>` task compilation (CodeTaskFactory / RoslynCodeTaskFactory) |
| MSBuild.dll | In-memory compile | SDK / dotnet-hosted MSBuild engine, invoked via `dotnet msbuild` / `dotnet build` |
| MSBuildTaskHost.exe | In-memory compile | MSBuild out-of-process task host |
| Microsoft.Build.Tasks.Core.dll | In-memory compile | Hosts the inline-task factories behind MSBuild |
| csc.exe, vbc.exe, jsc.exe | In-memory compile | Roslyn / JScript compilers |
| ilasm.exe | In-memory compile | IL assembler (text to PE) |
| csi.exe | In-memory compile | C# interactive / Roslyn scripting |
| fsi.exe, fsiAnyCpu.exe | In-memory compile | F# interactive scripting |
| aspnet_compiler.exe | In-memory compile | ASP.NET precompilation code execution |
| Microsoft.Workflow.Compiler.exe | In-memory compile | Workflow (XOML) compilation to arbitrary code |
| System.Configuration.Install.dll | Trusted loader | Hosts the InstallUtil installer machinery |

The catalog is matched by name and runs before the managed-assembly check, so native hosts such as `dotnet.exe` are reported even though they are not .NET assemblies. Catalog matches are authoritative and are always reported as top priority.

### Layer B: capability fingerprints (managed binaries only)

For every managed (.NET) binary, the raw bytes are scanned for API and type-name fingerprints in two tiers:

- **Tier1 (in-memory compile)**: CodeDom and Roslyn compilation, `System.Reflection.Emit`, embedded scripting engines (DLR, IronPython, F# interactive), T4 templating, XSLT scripting, PowerShell hosting.
- **Tier2 (trusted loader)**: installer-class execution, COM registration hooks, reflection-based assembly loading, .NET Core plugin loading (`AssemblyLoadContext`), MEF catalogs.

This layer catches unknown or third-party binaries that carry the same capability but are not in the catalog.

Optionally, matched managed binaries are decompiled with `ilspycmd` and each pattern is re-checked against the decompiled source, so a real call site can be told apart from a namespace that merely appears in a `using` line. Bare imports, bare namespace declarations, comment-only lines and Roslyn's synthesised compiler-generated markers are stripped before this check, and a pattern that survives is reported as a confirmed call site.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- Read access to the paths you scan (run elevated for full `System32` and framework coverage).
- Optional: `ilspycmd` for call-site verification. The script can install it (via the .NET SDK through winget, then as a dotnet global tool) unless you pass `-SkipIlSpyAutoInstall`. Not used in `-CatalogOnly` mode.

## Usage

Fast inventory of known bypass binaries present on the host:

```powershell
.\Scan-WdacBypassCapabilities.ps1 -CatalogOnly
```

Targeted run against a single framework directory:

```powershell
.\Scan-WdacBypassCapabilities.ps1 -ScanPaths "C:\Windows\Microsoft.NET\FrameworkArm64\v4.0.30319"
```

Full catalog plus fingerprint scan with ILSpy call-site verification:

```powershell
.\Scan-WdacBypassCapabilities.ps1 -OutputCsv C:\reports\scan.csv
```

Fingerprint scan without the decompiler:

```powershell
.\Scan-WdacBypassCapabilities.ps1 -SkipIlSpy
```

### Parameters

| Parameter | Default | Purpose |
|---|---|---|
| `-ScanPaths` | Framework trees, GACs, System32, SysWOW64, Program Files (both), dotnet, ProgramData | Roots to search recursively |
| `-IncludeWinSxS` | off | Also scan WinSxS (slow, low extra signal) |
| `-OutputCsv` | `.\WdacBypassScan.csv` | Report path |
| `-MaxFileSizeMB` | 64 | Skip larger files for the byte-scan (catalog matches still report) |
| `-ExeOnly` | off | Only scan `.exe` (misses capability DLLs; MSBuild.exe still caught by catalog) |
| `-CatalogOnly` | off | Name-match only, no byte-scan or ILSpy (fastest) |
| `-SkipIlSpy` | off | No decompiler verification |
| `-SkipIlSpyAutoInstall` | off | Use ilspycmd if present, but do not install it |

### Where MSBuild lives

MSBuild is not always in the .NET Framework directory, and on trimmed ARM64 framework trees it is often absent there. On modern systems it ships in two other places, both covered by the default scan:

- Visual Studio or Build Tools, as `MSBuild.exe` under `...\MSBuild\Current\Bin\` (with `arm64\` or `amd64\` subfolders) inside Program Files.
- The .NET SDK, as `MSBuild.dll` under `C:\Program Files\dotnet\sdk\<version>\`, invoked via `dotnet msbuild` or `dotnet build`.

To locate every MSBuild binary on a host directly:

```powershell
Get-ChildItem "C:\Program Files","C:\Program Files (x86)","C:\Windows\Microsoft.NET" -Recurse -Include MSBuild.exe,MSBuild.dll -File -ErrorAction SilentlyContinue | Select-Object FullName, Length
```

## Output columns

| Column | Meaning |
|---|---|
| `Path`, `FileName` | Location and name |
| `DetectionSource` | `Catalog`, `Fingerprint`, or `Both` |
| `KnownLolbasTechnique` | Documented technique, for catalog hits |
| `Tiers` | Capability tiers hit (compile and/or trusted loader) |
| `SignatureStatus`, `Signer` | Authenticode / catalog signature result |
| `MatchedPatterns` | Fingerprints found in the bytes |
| `IlSpyVerification` | `KnownLolbas`, `CallSiteFound`, `ReferenceOnlyLikelyFalsePositive`, `UnconfirmedByDecompile`, or `NotChecked` |
| `CallSitePatterns` / `ReferenceOnlyPatterns` | ILSpy classification detail |
| `Notes` | Technique detail for catalog hits |
| `SizeKB` | File size |

The console summary prints catalog hits first (top priority), then signed non-catalog binaries with a confirmed call site, then likely false positives to deprioritise.

## Interpreting results, and limitations

- **Signature status matters.** A validly signed, Microsoft-signed catalog binary is the highest-interest case for bypass review, because the whole point of a LOLBAS is that it is already trusted. On modern Windows these binaries are catalog-signed rather than embedded-signed, which `Get-AuthenticodeSignature` reports as `Valid`.
- **The ILSpy call-site pass is a heuristic, not a call graph.** It can miss a genuine reference buried in a structural line and can pass a dead-code or string-literal match. Treat it as a triage sort, not proof.
- **A catalog match is authoritative for presence, not for exploitability.** Whether a given vector actually bypasses your policy depends on your WDAC rules (signer rules, path rules, managed-code enforcement, blocklist coverage). Microsoft publishes a recommended blocklist that covers most of these binaries; cross-check your policy against it.
- **The catalog is not exhaustive.** It covers the well-known .NET vectors. Layer B is there to catch the rest, but no signature list is complete. Keep the catalog and fingerprint lists updated as new techniques are published.
- **This finds capability, not intent or activity.** It is an attack-surface inventory, not an incident detector.
