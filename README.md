# Forager

A local Windows scanner for finding signed .NET binaries that can either compile and run code in memory, or load and execute a caller-supplied assembly. Both are the underlying mechanism behind known LOLBAS entries like `MSBuild.exe`, `InstallUtil.exe`, `RegAsm.exe`, and `TextTransform.exe`, and this script is a way to find other binaries with the same capability that may not be catalogued yet.

## What it does

1. Walks a set of directories (System32, SysWOW64, Program Files, Program Files (x86), ProgramData, the .NET Framework tree, and the .NET Framework GAC by default) looking for `.exe` and `.dll` files.
2. Checks each file's PE header to confirm it is a managed .NET assembly before doing anything more expensive.
3. Checks Authenticode signature status and signer.
4. Scans the raw bytes for a list of known API and type-name fingerprints (see below).
5. For anything that matches, optionally decompiles the assembly with `ilspycmd` and checks whether the matched pattern shows up in real code, not just a `using` import statement. This is the main false-positive filter.
6. Writes every match to a CSV as it's found, so an interrupted scan still leaves a usable partial result on disk.

This is a discovery aid, not a verdict. A match means the binary **contains** the capability. It does not mean that capability is reachable by anything you control, or exploitable. See "What a match does and doesn't tell you" below.

## What it finds

Matches are grouped into two capability tiers.

**Tier 1: In-memory compile / dynamic code generation.** The binary can turn source code, or IL instructions, into a running assembly without ever writing that assembly to disk. Covers CodeDom compilation, Roslyn compilation and scripting, raw IL emission (`Reflection.Emit`), embedded scripting engines (IronPython, F# Interactive), T4 templating, inline XSLT scripting, and PowerShell's `Add-Type` hosting path.

**Tier 2: Trusted loader of caller-supplied code.** The binary loads and executes a DLL that someone else built, without compiling anything itself. Covers InstallUtil-style installer classes, RegAsm/RegSvcs COM registration hooks, generic reflection-based assembly loading (`LoadFrom`, `ExecuteAssembly`, etc.), .NET Core's `AssemblyLoadContext`, and MEF-style plugin catalogs.

Full pattern lists live in the `$fingerprints` variable near the top of the script if you want to see or extend exactly what's being matched.

## Reading the CSV

| Column | Meaning |
|---|---|
| `Path` | Full path to the matched binary |
| `SignatureStatus` | Authenticode status (`Valid` is the interesting case: signed and trusted) |
| `Signer` | Certificate subject |
| `Tiers` | JSON array, which tier(s) matched |
| `MatchedPatterns` | JSON array, every fingerprint string found in the raw bytes |
| `IlSpyVerification` | `CallSiteFound`, `ReferenceOnlyLikelyFalsePositive`, `UnconfirmedByDecompile`, or `NotChecked` |
| `CallSitePatterns` | JSON array, patterns confirmed in real decompiled code, not just an import |
| `ReferenceOnlyPatterns` | JSON array, patterns that only ever appeared as a `using` statement, likely a shared dependency rather than a real capability |
| `SizeKB` | File size |

Start with rows where `SignatureStatus = Valid` and `IlSpyVerification = CallSiteFound`. That's the shortest, highest-confidence list. The console output at the end of a run also prints this subset directly, separated from the likely-false-positive rows.

## What a match does and doesn't tell you

A `CallSiteFound` match confirms the capability exists and is actually invoked somewhere in the binary, not just referenced. It does **not** confirm that:
- the input to that call is attacker-controllable (command-line arg, config file, environment variable),
- the code path is reachable from how the binary is normally launched,
- the binary is exploitable in your environment.

Those require manual follow-up: decompiling the specific method to trace where its input comes from, checking the binary's supported CLI arguments and config formats, and ideally confirming dynamically with a debugger breakpoint on the matched API while exercising the binary normally.

## Usage

```powershell
# Full default scan, with ILSpy auto-installed if missing
.\Scan-InMemoryCompilePatterns.ps1

# Narrow to a specific directory
.\Scan-InMemoryCompilePatterns.ps1 -ScanPaths "C:\Program Files\dotnet"

# Fast pass, byte-scan only, no decompiler
.\Scan-InMemoryCompilePatterns.ps1 -SkipIlSpy

# Only .exe files, skip .dll entirely (faster, but misses capabilities
# implemented in a companion DLL, e.g. RoslynCodeTaskFactory lives in
# Microsoft.Build.Tasks.Core.dll, not MSBuild.exe itself)
.\Scan-InMemoryCompilePatterns.ps1 -ExeOnly

# Use ilspycmd if already installed, don't attempt to install it
.\Scan-InMemoryCompilePatterns.ps1 -SkipIlSpyAutoInstall

# Include WinSxS (large, slow, off by default)
.\Scan-InMemoryCompilePatterns.ps1 -IncludeWinSxS
```

## Notes and known limitations

- The raw byte scan only finds strings that are stored contiguously in the assembly's metadata. Namespace strings and standalone type/method names work well. A pattern combining a type name and method name with a dot (e.g. `Assembly.LoadFrom`) generally does not, since .NET metadata stores those as separate entries. The fingerprint list uses standalone tokens for this reason; see the comments in `$fingerprints` for details.
- `ilspycmd` verification is a heuristic, not a real call graph. It filters out the "imported but never called" false positive, but a dead code path (called from nowhere reachable) will still show as `CallSiteFound`.
- ILSpy auto-install uses winget to install the .NET SDK if `dotnet` isn't already present, since `ilspycmd` itself only ships as a `dotnet tool`, not a winget package.
