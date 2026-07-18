# LOL-Forager

# WDAC / AppLocker Bypass Capability Scanner

`Scan-WdacBypassCapabilities.ps1` inventories the trusted binaries present on a Windows host that can be abused to run unapproved code under a WDAC or AppLocker policy. It is a discovery and audit aid for defenders, detection engineers and policy authors. It does not exploit anything, it reports what is present so you can decide what to block, allow with rules, or monitor.

Every technique it looks for is publicly documented (see the LOLBAS project). Running this tells you which of those vectors actually exist on the box you are assessing.

> Run this only on systems you are authorised to assess. A match means the binary **contains or is a known vector for** the capability, not that it is exploitable in your specific policy. Confirm against your WDAC configuration before drawing conclusions.

## How it detects things

The scan runs two independent layers and reports a file if either fires.

### Layer A: known-LOLBAS catalog (matched by name)

A curated list of binaries whose bypass behaviour is documented. These are matched by file name, because the capability is a property of what the binary does, not of a string you can grep for. This layer is what reliably surfaces the thin launcher EXEs whose real capability code lives in a companion DLL.

Current catalog:

| Binary | Tier | Technique |
|---|---|---|
| InstallUtil.exe | Trusted loader | Installer-class execution via `[RunInstaller(true)]` Install/Uninstall, plus the HelpText override path |
| RegAsm.exe | Trusted loader | `[ComRegisterFunction]` / `[ComUnregisterFunction]` execution |
| RegSvcs.exe | Trusted loader | EnterpriseServices registration hooks |
| AddInProcess.exe, AddInProcess32.exe | Trusted loader | System.AddIn out-of-process add-in host |
| dotnet.exe | Trusted loader | Native host that runs any managed DLL, `dotnet exec`, `dotnet fsi` |
| MSBuild.exe | In-memory compile | Inline `<Code>` task compilation (CodeTaskFactory / RoslynCodeTaskFactory) |
| Microsoft.Build.Tasks.Core.dll | In-memory compile | Hosts the inline-task factories behind MSBuild |
| csc.exe, vbc.exe, jsc.exe | In-memory compile | Roslyn / JScript compilers |
| ilasm.exe | In-memory compile | IL assembler (text to PE) |
| csi.exe | In-memory compile | C# interactive / Roslyn scripting |
| fsi.exe, fsiAnyCpu.exe | In-memory compile | F# interactive scripting |
| aspnet_compiler.exe | In-memory compile | ASP.NET precompilation code execution |
| Microsoft.Workflow.Compiler.exe | In-memory compile | Workflow (XOML) compilation to arbitrary code |
| System.Configuration.Install.dll | Trusted loader | Hosts the InstallUtil installer machinery |

### Layer B: capability fingerprints (managed binaries only)

For every managed (.NET) binary, the raw bytes are scanned for API and type-name fingerprints in two tiers:

- **Tier1 (in-memory compile)**: CodeDom and Roslyn compilation, `System.Reflection.Emit`, embedded scripting engines (DLR, IronPython, F# interactive), T4 templating, XSLT scripting, PowerShell hosting.
- **Tier2 (trusted loader)**: installer-class execution, COM registration hooks, reflection-based assembly loading, .NET Core plugin loading (`AssemblyLoadContext`), MEF catalogs.

This layer catches unknown or third-party binaries that carry the same capability but are not in the catalog.

Optionally, matched managed binaries are decompiled with `ilspycmd` and each pattern is re-checked against the decompiled source, so a real call site can be told apart from a namespace that merely appears in a `using` line.

## What changed from the previous version, and why your three expected hits were missing

You expected a scan of `C:\Windows\Microsoft.NET\FrameworkArm64\v4.0.30319\` to surface InstallUtil (install and HelpText paths), RegAsm and MSBuild. Here is why the earlier script fell short and how this version fixes it.

1. **Path was not the problem, matching was.** The old default included `C:\Windows\Microsoft.NET` and scanned recursively, so `FrameworkArm64\v4.0.30319` was already covered, and the PE parser already handled PE32+ (ARM64) headers. The framework architecture directories are now listed explicitly (Framework, Framework64, FrameworkArm64) so ARM64 coverage is intentional and obvious rather than incidental.

2. **MSBuild.exe carries no fingerprint of its own.** The inline-task factories (`CodeTaskFactory`, `RoslynCodeTaskFactory`) live in `Microsoft.Build.Tasks.Core.dll`, not in `MSBuild.exe`. A pure byte-scan of the EXE never matched. The catalog now flags `MSBuild.exe` by name as the execution vector and `Microsoft.Build.Tasks.Core.dll` by name as the capability DLL.

3. **InstallUtil.exe was being actively demoted.** The old fingerprint list matched the namespace `System.Configuration.Install`, which in decompiled output appears only as a `using` line. The ILSpy call-site filter strips `using` lines, so the genuine hit was labelled `ReferenceOnlyLikelyFalsePositive` and pushed into the deprioritise bucket. This version adds the actual invoked type and method names (`ManagedInstallerClass`, `InstallHelper`, plus `RunInstaller`), and also flags `InstallUtil.exe` directly via the catalog with both the install-method and HelpText-override techniques noted.

4. **RegAsm / RegSvcs made robust.** Added call-site names (`RegisterAssembly`, `UnregisterAssembly`, `RegistrationHelper`, `RegistrationConfig`) and catalog entries for `RegAsm.exe` and `RegSvcs.exe`.

5. **Native hosts now reported.** `dotnet.exe` is a native apphost, so the old managed-only gate skipped it. The catalog layer now runs before that gate, so native LOLBAS hosts are reported.

6. **New `-CatalogOnly` fast mode**, a broader default path set including `C:\Program Files\dotnet`, and a few extra CodeDom fingerprints (`CompilerParameters`, `CodeSnippetCompileUnit`).

## Requirements

- Windows PowerShell 5.1 or PowerShell 7+.
- Read access to the paths you scan (run elevated for full `System32` / framework coverage).
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

## Interpreting results, and honest limitations

- **Signature status matters.** A validly signed, Microsoft-signed catalog binary is the highest-interest case for bypass review, because the whole point of a LOLBAS is that it is already trusted. On modern Windows these binaries are catalog-signed rather than embedded-signed; `Get-AuthenticodeSignature` reports that as `Valid`.
- **The ILSpy call-site pass is a heuristic, not a call graph.** It can miss a genuine reference buried in a structural line and can pass a dead-code or string-literal match. Treat it as a triage sort, not proof.
- **A catalog match is authoritative for presence, not for exploitability.** Whether a given vector actually bypasses your policy depends on your WDAC rules (signer rules, path rules, managed-code enforcement, blocklist coverage). Microsoft publishes a recommended blocklist that covers most of these binaries; cross-check your policy against it.
- **The catalog is not exhaustive.** It covers the well-known .NET vectors. Layer B is there to catch the rest, but no signature list is complete. Keep the catalog and fingerprint lists updated as new techniques are published.
- **This finds capability, not intent or activity.** It is an attack-surface inventory, not an incident detector.
