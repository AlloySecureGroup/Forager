<#
.SYNOPSIS
    Scans local binaries for two things at once:

      A. Known LOLBAS catalog match. A curated list of trusted binaries that
         are publicly documented WDAC / AppLocker bypass execution vectors
         (InstallUtil, RegAsm, RegSvcs, MSBuild, the Roslyn compilers, the
         workflow compiler, dotnet host, and so on). These are matched by
         file name and reported with high confidence regardless of the byte
         scan below, because the capability is a property of the binary's
         documented behaviour, not of a string you can grep for.

      B. Capability fingerprint match. For managed (.NET) binaries, the raw
         bytes are scanned for API / type-name fingerprints tied to two
         capability classes:

         Tier1  - Self-contained compile-and-run (CodeDom or Roslyn compiling
                  to memory and executing without writing a payload assembly
                  to disk, IL emission, embedded scripting engines).
         Tier2  - Trusted loader of pre-built code (loads and invokes a
                  caller supplied DLL or plugin, for example InstallUtil-style
                  installer-class execution or COM registration hooks).

    Layer A reliably surfaces the thin launcher EXEs whose capability lives
    in a companion DLL (MSBuild.exe, InstallUtil.exe, RegAsm.exe). Layer B
    surfaces unknown or third-party binaries that carry the same capability
    but are not in the catalog.

.DESCRIPTION
    For every candidate .exe / .dll under the given search roots, the script:
      1. Checks the file name against the known-LOLBAS catalog (Layer A).
      2. Confirms whether it is a managed (.NET) assembly (native binaries
         that are not catalog entries are skipped).
      3. For managed binaries, scans the raw bytes for the Tier1 / Tier2
         fingerprints (Layer B).
      4. Checks Authenticode signature status and signer (catalog-signed
         system binaries report as Valid / Microsoft).
      5. For fingerprint matches, optionally decompiles the assembly with
         ilspycmd and re-checks each pattern against the decompiled source
         to separate a real call site from an unrelated metadata string.
         Catalog matches are authoritative and are never demoted by this
         pass.
      6. Emits a CSV report, and prints a prioritised summary.

    This is a discovery aid, not a verdict. A match, even an ILSpy-confirmed
    one, means the binary CONTAINS or IS a known vector for the capability,
    not that it is exploitable in your specific WDAC policy. Confirm against
    your policy before drawing conclusions. Run it only on systems you are
    authorised to assess.

.PARAMETER ScanPaths
    Root directories to search. Defaults to the three .NET Framework
    architecture trees (Framework, Framework64, FrameworkArm64), the
    Framework GAC, the legacy GAC, System32, SysWOW64, Program Files,
    Program Files (x86), the dotnet host directory, and ProgramData.

    The FrameworkArm64 tree is listed explicitly so that ARM64 devices get
    first-class coverage. The managed-assembly check handles PE32+ (ARM64
    and x64) headers, so ARM64 binaries are parsed correctly.

.PARAMETER IncludeWinSxS
    Also scan C:\Windows\WinSxS. Off by default because it holds thousands
    of side-by-side assembly copies and adds significant scan time for
    little signal beyond what is already found elsewhere.

.PARAMETER OutputCsv
    Path to write the CSV report. Defaults to .\WdacBypassScan.csv

.PARAMETER MaxFileSizeMB
    Skip files larger than this to keep the byte-scan fast. Default 64.
    Note: catalog matches are by name, so a catalog binary above this size
    is still reported, it just is not fingerprint-scanned.

.PARAMETER ExeOnly
    Only scan .exe files, skip .dll entirely. Cuts the candidate set, useful
    for a fast first pass focused on directly launchable binaries, at the
    cost of missing capability DLLs (for example Microsoft.Build.Tasks.Core.dll,
    where the MSBuild inline-task factories actually live). MSBuild.exe itself
    is still caught by the catalog even in this mode.

.PARAMETER CatalogOnly
    Skip the managed-assembly parse, the byte-scan, and ILSpy entirely.
    Report only known-LOLBAS catalog matches with their signature status.
    This is the fastest mode and the right one for a quick WDAC vector
    inventory.

.PARAMETER SkipIlSpy
    Skip the ILSpy decompile-and-confirm pass. The CSV still contains the
    raw byte-scan matches, just without call-site verification.

.PARAMETER SkipIlSpyAutoInstall
    Use ilspycmd if it is already on PATH, but do not attempt to install it
    when it is missing.

.EXAMPLE
    .\Scan-WdacBypassCapabilities.ps1 -CatalogOnly
    Fast inventory of known WDAC / AppLocker bypass binaries present on the box.

.EXAMPLE
    .\Scan-WdacBypassCapabilities.ps1 -ScanPaths "C:\Windows\Microsoft.NET\FrameworkArm64\v4.0.30319"
    Targeted run against a single framework directory. Surfaces InstallUtil
    (install method and HelpText override), RegAsm, RegSvcs and MSBuild.

.EXAMPLE
    .\Scan-WdacBypassCapabilities.ps1 -OutputCsv C:\reports\scan.csv
    Full catalog plus fingerprint scan with ILSpy verification.
#>

[CmdletBinding()]
param(
    [string[]]$ScanPaths = @(
        "C:\Windows\Microsoft.NET\Framework",
        "C:\Windows\Microsoft.NET\Framework64",
        "C:\Windows\Microsoft.NET\FrameworkArm64",
        "C:\Windows\Microsoft.NET\assembly",
        "C:\Windows\assembly",
        "C:\Windows\System32",
        "C:\Windows\SysWOW64",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\Program Files\dotnet",
        "C:\ProgramData"
    ),
    [switch]$IncludeWinSxS,
    [string]$OutputCsv = ".\WdacBypassScan.csv",
    [int]$MaxFileSizeMB = 64,
    [switch]$ExeOnly,
    [switch]$CatalogOnly,
    [switch]$SkipIlSpy,
    [switch]$SkipIlSpyAutoInstall
)

if ($IncludeWinSxS) {
    $ScanPaths += "C:\Windows\WinSxS"
    Write-Warning "IncludeWinSxS is set. This directory holds thousands of assemblies and will substantially increase scan time."
}

# ---------------------------------------------------------------------------
# LAYER A: Known-LOLBAS catalog.
#
# Keyed by file name (case-insensitive lookup). Every entry here is a binary
# whose WDAC / AppLocker bypass behaviour is publicly documented. These are
# matched by name, not by byte content, because the capability is a property
# of what the binary DOES, not of a string that happens to sit in its
# metadata. This is the layer that surfaces the thin launcher EXEs whose
# actual capability code lives in a companion DLL (MSBuild.exe, InstallUtil.exe,
# RegAsm.exe), which the fingerprint scan alone misses.
# ---------------------------------------------------------------------------
$knownLolbas = @{
    # ---- Tier2: trusted loaders / registration-hook execution ----
    "installutil.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "InstallUtil installer-class execution"
        Notes = "Executes code in a class marked [RunInstaller(true)] through its Install or Uninstall override, typically 'InstallUtil /logfile= /LogToConsole=false /U payload.dll'. A second, quieter path is the HelpText override: when InstallUtil instantiates installer objects to render help, their constructor, static initialiser and HelpText getter run, giving code execution without a full install transaction. Calls into System.Configuration.Install.ManagedInstallerClass.InstallHelper."
    }
    "regasm.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "RegAsm COM register / unregister function execution"
        Notes = "Runs methods marked [ComRegisterFunction] or [ComUnregisterFunction] when (un)registering a supplied assembly. Uses System.Runtime.InteropServices.RegistrationServices."
    }
    "regsvcs.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "RegSvcs EnterpriseServices registration execution"
        Notes = "Registers a serviced component and runs its register / unregister hooks. Uses System.EnterpriseServices.Internal.RegistrationHelper."
    }
    "addinprocess.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "System.AddIn out-of-process add-in host"
        Notes = "Loads and runs a managed add-in in a separate process, invoked with a GUID and pipe name. Documented AppLocker bypass host."
    }
    "addinprocess32.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "System.AddIn out-of-process add-in host (32-bit)"
        Notes = "32-bit variant of AddInProcess.exe."
    }
    "dotnet.exe" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "dotnet host executes arbitrary managed code"
        Notes = "Native apphost, not a managed assembly, so it is caught only by this catalog and not the fingerprint scan. Runs any managed DLL via 'dotnet app.dll', 'dotnet exec', and can drive scripting via 'dotnet fsi'."
    }

    # ---- Tier1: compile / dynamic-code execution ----
    "msbuild.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "MSBuild inline-task compilation"
        Notes = "Compiles and runs arbitrary code from an inline <Code> task in a project, targets or XML file (CodeTaskFactory on .NET Framework, RoslynCodeTaskFactory on newer toolsets). The factory classes live in Microsoft.Build.Tasks.Core.dll, so MSBuild.exe carries no fingerprint of its own and is surfaced here by name."
    }
    "microsoft.build.tasks.core.dll" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "Hosts the MSBuild inline-task factories"
        Notes = "Contains CodeTaskFactory and RoslynCodeTaskFactory, the types that actually compile MSBuild inline tasks. This is the capability DLL behind MSBuild.exe."
    }
    "csc.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "C# compiler (Roslyn)"
        Notes = "Compiles supplied C# source to an assembly. A trusted compiler present on the box is itself a bypass primitive."
    }
    "vbc.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "VB compiler (Roslyn)"
        Notes = "Compiles supplied VB source to an assembly."
    }
    "jsc.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "JScript.NET compiler"
        Notes = "Compiles JScript.NET to an assembly, and can produce a runnable EXE."
    }
    "ilasm.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "IL assembler"
        Notes = "Assembles supplied IL into a PE (EXE or DLL), a well known AppLocker bypass path since the input is text."
    }
    "csi.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "C# interactive / Roslyn scripting host"
        Notes = "Runs C# script files or stdin (Visual Studio component). Executes arbitrary C# without a compile-to-disk step."
    }
    "fsi.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "F# interactive scripting host"
        Notes = "Runs F# scripts, evaluating arbitrary code."
    }
    "fsianycpu.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "F# interactive scripting host (AnyCPU)"
        Notes = "AnyCPU variant of fsi.exe."
    }
    "aspnet_compiler.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "ASP.NET precompilation code execution"
        Notes = "Precompiles an ASP.NET site, which compiles and can execute code-behind supplied by the attacker."
    }
    "microsoft.workflow.compiler.exe" = [PSCustomObject]@{
        Tier = "Tier1_InMemoryCompile"
        Technique = "Workflow (XOML) compilation to arbitrary code"
        Notes = "Compiles a serialised workflow described in an XML input file, which permits arbitrary code execution. Classic AppLocker bypass."
    }
    "system.configuration.install.dll" = [PSCustomObject]@{
        Tier = "Tier2_TrustedLoader"
        Technique = "Hosts the InstallUtil installer machinery"
        Notes = "Contains ManagedInstallerClass.InstallHelper and the Installer base class whose Install / Uninstall / HelpText members InstallUtil invokes. Capability DLL behind InstallUtil.exe."
    }
}

# ---------------------------------------------------------------------------
# LAYER B: capability fingerprints for managed binaries.
#
# Tier1: presence suggests the binary can compile or dynamically generate
#        code and run it without writing a payload assembly to disk.
# Tier2: presence suggests the binary loads and executes caller supplied
#        assemblies or plugins.
#
# New in this version: the actual call-site type and method names for the
# InstallUtil / RegAsm / RegSvcs paths (ManagedInstallerClass, InstallHelper,
# RegisterAssembly, RegistrationHelper, and so on). The previous list only
# had the NAMESPACE strings for these (for example System.Configuration.Install),
# which show up in decompiled output only as a 'using' line and were therefore
# stripped by the ILSpy false-positive filter, causing genuine InstallUtil
# hits to be demoted to 'ReferenceOnlyLikelyFalsePositive'. Matching on the
# invoked type and method names lets the call-site pass promote them correctly.
# ---------------------------------------------------------------------------
$fingerprints = @{
    Tier1_InMemoryCompile = @(
        # CodeDom compilation (classic .NET Framework path)
        "GenerateInMemory",
        "CSharpCodeProvider",
        "VBCodeProvider",
        "JScriptCodeProvider",
        "CodeDomProvider",
        "ICodeCompiler",
        "CompilerParameters",
        "CompileAssemblyFromSource",
        "CompileAssemblyFromFile",
        "CompileAssemblyFromDom",
        "CodeSnippetCompileUnit",
        # Roslyn compilation and scripting
        "RoslynCodeTaskFactory",
        "CodeTaskFactory",
        "Microsoft.CodeAnalysis",
        "Microsoft.CodeAnalysis.CSharp",
        "Microsoft.CodeAnalysis.VisualBasic",
        "CSharpCompilation",
        "VisualBasicCompilation",
        "CSharpScript",
        "ScriptOptions",
        "InteractiveAssemblyLoader",
        "EmitToStream",
        # IL emission / reflection-based dynamic code generation
        "System.Reflection.Emit",
        "AssemblyBuilder",
        "ModuleBuilder",
        "TypeBuilder",
        "DynamicMethod",
        "ILGenerator",
        # Dynamic Language Runtime / embedded scripting engines
        "Microsoft.Scripting",
        "IronPython",
        "IronRuby",
        "FSharp.Compiler.Interactive",
        "FsiEvaluationSession",
        # T4 text templating (TextTransform.exe)
        "Microsoft.VisualStudio.TextTemplating",
        "ITextTemplatingEngineHost",
        "DirectiveProcessor",
        # XSLT inline scripting
        "System.Xml.Xsl.XslCompiledTransform",
        # PowerShell hosting (Add-Type / runspace execution)
        "System.Management.Automation.PowerShell",
        "RunspaceFactory",
        # Windows Script Host engines
        "IActiveScript",
        "ScriptControl"
    )
    Tier2_TrustedLoader = @(
        # InstallUtil-style installer class execution.
        # Both the attribute forms and the actual invoked type / method are
        # listed so the ILSpy call-site pass can confirm a real invocation.
        "RunInstallerAttribute",
        "RunInstaller",
        "ManagedInstallerClass",
        "InstallHelper",
        "System.Configuration.Install",
        "TransactedInstaller",
        "AssemblyInstaller",
        # RegAsm / RegSvcs COM registration hooks
        "ComRegisterFunctionAttribute",
        "ComUnregisterFunctionAttribute",
        "RegistrationServices",
        "RegisterAssembly",
        "UnregisterAssembly",
        "RegistrationHelper",
        "RegistrationConfig",
        "System.EnterpriseServices",
        # Generic reflection-based assembly loading and execution.
        # These are standalone method names, not "Assembly.LoadFrom" style
        # dotted strings. .NET metadata stores the type name and the method
        # name as separate string-heap entries, never concatenated with a
        # dot, so a dotted pattern almost never appears in raw IL bytes.
        # "LoadFrom" and "LoadFile" are generic and can false-positive; the
        # ILSpy call-site pass is what separates a real Assembly.LoadFrom
        # call from noise.
        "LoadFrom",
        "LoadFile",
        "UnsafeLoadFrom",
        "ReflectionOnlyLoadFrom",
        "CreateInstanceFromAndUnwrap",
        "ExecuteAssembly",
        # .NET Core plugin loading
        "System.Runtime.Loader",
        "AssemblyLoadContext",
        "AssemblyDependencyResolver",
        # MEF-style plugin catalogs
        "System.ComponentModel.Composition",
        "CompositionContainer",
        "DirectoryCatalog"
    )
}

function Test-IsManagedAssembly {
    <#
        Fast managed-assembly check via PE header inspection instead of
        AssemblyName.GetAssemblyName's exception-driven path. At System32 /
        Program Files scale, most files are native, and the exception-based
        check is expensive per miss, so this reads only the handful of
        header bytes needed to confirm a CLR (COM descriptor) data
        directory is present. Handles both PE32 and PE32+ (x64 / ARM64).
    #>
    param([string]$Path)

    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        $reader = [System.IO.BinaryReader]::new($stream)

        if ($stream.Length -lt 0x40) { return $false }

        $mzSig = $reader.ReadUInt16()
        if ($mzSig -ne 0x5A4D) { return $false }   # 'MZ'

        $stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -eq 0 -or $peOffset -ge $stream.Length) { return $false }

        $stream.Seek($peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $peSig = $reader.ReadUInt32()
        if ($peSig -ne 0x00004550) { return $false }   # 'PE\0\0'

        # Optional header starts right after the 20 byte COFF file header.
        $optionalHeaderStart = $peOffset + 4 + 20
        $stream.Seek($optionalHeaderStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $magic = $reader.ReadUInt16()
        $isPE32Plus = ($magic -eq 0x20B)

        # Data directory array offset within the optional header:
        # 96 bytes in for PE32, 112 bytes in for PE32+.
        $dataDirOffset = if ($isPE32Plus) { $optionalHeaderStart + 112 } else { $optionalHeaderStart + 96 }

        # CLR (COM descriptor) header is data directory index 14 (0-based),
        # each directory entry is 8 bytes (4 byte RVA + 4 byte size).
        $clrEntryOffset = $dataDirOffset + (14 * 8)
        if ($clrEntryOffset + 8 -gt $stream.Length) { return $false }

        $stream.Seek($clrEntryOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
        $clrRva = $reader.ReadUInt32()
        $clrSize = $reader.ReadUInt32()

        return ($clrRva -ne 0 -and $clrSize -ne 0)
    }
    catch {
        return $false
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Get-Fingerprints {
    param([string]$Path)

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)

    $matches = [System.Collections.Generic.List[string]]::new()
    $tiersHit = [System.Collections.Generic.List[string]]::new()

    foreach ($tier in $fingerprints.Keys) {
        foreach ($pattern in $fingerprints[$tier]) {
            if ($text.Contains($pattern)) {
                $matches.Add($pattern)
                if (-not $tiersHit.Contains($tier)) {
                    $tiersHit.Add($tier)
                }
            }
        }
    }

    return [PSCustomObject]@{
        Matches = $matches
        Tiers   = $tiersHit
    }
}

function Get-SignatureInfo {
    param([string]$Path)
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { "" }
        return [PSCustomObject]@{
            Status = $sig.Status
            Signer = $signer
        }
    }
    catch {
        return [PSCustomObject]@{
            Status = "Unknown"
            Signer = ""
        }
    }
}

function Resolve-IlSpyCmd {
    <#
        Locates ilspycmd on PATH. If missing and auto-install is allowed,
        installs the .NET SDK via winget (ilspycmd itself ships only as a
        dotnet global tool, not a winget package), then installs ilspycmd
        with "dotnet tool install --global ilspycmd".
        Returns the resolved path to ilspycmd.exe, or $null if unavailable.
    #>
    param([bool]$AutoInstall = $true)

    $existing = Get-Command ilspycmd -ErrorAction SilentlyContinue
    if ($existing) {
        return $existing.Source
    }

    Write-Warning "ilspycmd not found on PATH."

    if (-not $AutoInstall) {
        Write-Host "Auto-install disabled. Continuing without decompiler verification." -ForegroundColor Yellow
        return $null
    }

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Host "dotnet SDK not found. Attempting install via winget..." -ForegroundColor Cyan
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget install --id Microsoft.DotNet.SDK.8 -e --accept-package-agreements --accept-source-agreements
        }
        else {
            Write-Warning "winget is not available on this system. Install the .NET SDK manually, then re-run this script."
            return $null
        }
    }

    if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
        Write-Warning "dotnet SDK still not detected after the winget install. Continuing without decompiler verification."
        return $null
    }

    Write-Host "Installing ilspycmd as a dotnet global tool..." -ForegroundColor Cyan
    dotnet tool install --global ilspycmd | Out-Null

    $toolsPath = Join-Path $env:USERPROFILE ".dotnet\tools"
    if ((Test-Path $toolsPath) -and ($env:Path -notlike "*$toolsPath*")) {
        $env:Path += ";$toolsPath"
    }

    $confirmed = Get-Command ilspycmd -ErrorAction SilentlyContinue
    if ($confirmed) {
        return $confirmed.Source
    }

    Write-Warning "ilspycmd installation could not be verified. Continuing without decompiler verification."
    return $null
}

function Get-IlSpyAnalysis {
    <#
        Decompiles the assembly once and evaluates each candidate pattern in
        two passes:

          1. Confirmed  - the pattern appears anywhere in the decompiled
                          source.
          2. CallSite   - the pattern appears outside the known non-call-site
                          contexts: bare 'using Namespace;' imports, bare
                          'namespace Namespace' declarations, and the
                          [CompilerGenerated] / [Embedded] markers Roslyn uses
                          for its own synthesised attribute polyfills. This is
                          the false-positive filter: a binary that merely
                          references or declares a namespace, without ever
                          calling into it, drops out here.

        This filter is a heuristic, not a real call graph. A pattern surviving
        it means the string shows up somewhere other than a known non-functional
        context, which is still worth a manual look, just a much shorter list
        of manual looks than the raw scan.
    #>
    param(
        [string]$IlspyPath,
        [string]$AssemblyPath,
        [string[]]$CandidatePatterns
    )

    $emptyResult = [PSCustomObject]@{
        Confirmed     = [System.Collections.Generic.List[string]]::new()
        CallSite      = [System.Collections.Generic.List[string]]::new()
        ReferenceOnly = [System.Collections.Generic.List[string]]::new()
    }

    if (-not $IlspyPath -or $CandidatePatterns.Count -eq 0) {
        return $emptyResult
    }

    try {
        $rawLines = & $IlspyPath $AssemblyPath 2>$null
    }
    catch {
        return $emptyResult
    }

    if (-not $rawLines) {
        return $emptyResult
    }

    $fullText = $rawLines -join "`n"

    # Drop lines that are structurally never a real call site: bare imports,
    # bare namespace declarations, comment-only lines, and the compiler
    # generated / embedded attribute markers. See the block comment above.
    $codeOnlyLines = $rawLines | Where-Object {
        ($_ -notmatch '^\s*using\s+[\w\.]+\s*;\s*$') -and
        ($_ -notmatch '^\s*namespace\s+[\w\.]+\s*$') -and
        ($_ -notmatch '^\s*\[\s*CompilerGenerated\s*\]\s*$') -and
        ($_ -notmatch '^\s*\[\s*Embedded\s*\]\s*$') -and
        ($_ -notmatch '^\s*//')
    }
    $codeOnlyText = $codeOnlyLines -join "`n"

    $confirmed = [System.Collections.Generic.List[string]]::new()
    $callSite = [System.Collections.Generic.List[string]]::new()
    $referenceOnly = [System.Collections.Generic.List[string]]::new()

    foreach ($pattern in $CandidatePatterns) {
        $escaped = [regex]::Escape($pattern)

        if ($fullText -notmatch $escaped) {
            continue
        }
        $confirmed.Add($pattern)

        if ($codeOnlyText -match $escaped) {
            $callSite.Add($pattern)
        }
        else {
            $referenceOnly.Add($pattern)
        }
    }

    return [PSCustomObject]@{
        Confirmed     = $confirmed
        CallSite      = $callSite
        ReferenceOnly = $referenceOnly
    }
}

# ---------------------------------------------------------------------------
# ILSpy setup (skipped entirely in CatalogOnly mode)
# ---------------------------------------------------------------------------
$ilspyPath = $null
if (-not $SkipIlSpy -and -not $CatalogOnly) {
    $ilspyPath = Resolve-IlSpyCmd -AutoInstall:(-not $SkipIlSpyAutoInstall)
    if ($ilspyPath) {
        Write-Host ("Using ilspycmd at: {0}" -f $ilspyPath) -ForegroundColor Green
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$maxBytes = $MaxFileSizeMB * 1MB

# Start with a clean output file. Every match is appended the moment it is
# found, so if the scan is interrupted, everything found up to that point is
# already on disk.
if (Test-Path $OutputCsv) {
    Remove-Item $OutputCsv -Force
}

Write-Host "Enumerating candidate files under:" -ForegroundColor Cyan
$ScanPaths | ForEach-Object { Write-Host ("  {0}" -f $_) }
if ($CatalogOnly) {
    Write-Host "CatalogOnly is set. Reporting known-LOLBAS name matches only, no byte-scan or ILSpy." -ForegroundColor Yellow
}

$candidateExtensions = if ($ExeOnly) { @("*.exe") } else { @("*.exe", "*.dll") }
if ($ExeOnly) {
    Write-Host "ExeOnly is set. Skipping .dll files (capability DLLs like Microsoft.Build.Tasks.Core.dll will be missed; MSBuild.exe is still caught by the catalog)." -ForegroundColor Yellow
}

$candidates = foreach ($root in $ScanPaths) {
    if (Test-Path $root) {
        Get-ChildItem -Path $root -Recurse -Include $candidateExtensions -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -le $maxBytes }
    }
    else {
        Write-Warning ("Path not found, skipping: {0}" -f $root)
    }
}

$total = ($candidates | Measure-Object).Count
Write-Host ("Found {0} candidate files. Scanning..." -f $total) -ForegroundColor Cyan

$i = 0
foreach ($file in $candidates) {
    $i++
    if ($i % 250 -eq 0) {
        Write-Progress -Activity "Scanning binaries" -Status $file.FullName -PercentComplete (($i / [math]::Max($total, 1)) * 100)
    }

    # LAYER A: catalog match by name. Done first and independent of the
    # managed-assembly gate so that native hosts like dotnet.exe still report.
    $catalog = $knownLolbas[$file.Name]

    $isManaged = Test-IsManagedAssembly -Path $file.FullName

    # A native binary that is not a catalog entry is not our concern.
    if (-not $catalog -and -not $isManaged) {
        continue
    }

    # LAYER B: fingerprint scan (managed binaries only, and not in CatalogOnly).
    $fp = if ($isManaged -and -not $CatalogOnly) {
        Get-Fingerprints -Path $file.FullName
    }
    else {
        [PSCustomObject]@{
            Matches = [System.Collections.Generic.List[string]]::new()
            Tiers   = [System.Collections.Generic.List[string]]::new()
        }
    }

    # Report if it is a catalog hit OR has at least one fingerprint match.
    if (-not $catalog -and $fp.Matches.Count -eq 0) {
        continue
    }

    $sig = Get-SignatureInfo -Path $file.FullName

    # ILSpy call-site verification, only when there are fingerprint matches
    # to verify and a decompiler is available. Catalog hits are authoritative
    # and never need this.
    $analysis = [PSCustomObject]@{
        Confirmed     = [System.Collections.Generic.List[string]]::new()
        CallSite      = [System.Collections.Generic.List[string]]::new()
        ReferenceOnly = [System.Collections.Generic.List[string]]::new()
    }
    if ($ilspyPath -and $fp.Matches.Count -gt 0) {
        $analysis = Get-IlSpyAnalysis -IlspyPath $ilspyPath -AssemblyPath $file.FullName -CandidatePatterns $fp.Matches
    }

    # Combine tiers from both layers.
    $allTiers = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $fp.Tiers) {
        if (-not $allTiers.Contains($t)) { $allTiers.Add($t) }
    }
    if ($catalog -and -not $allTiers.Contains($catalog.Tier)) {
        $allTiers.Add($catalog.Tier)
    }

    $detectionSource =
        if ($catalog -and $fp.Matches.Count -gt 0) { "Both" }
        elseif ($catalog) { "Catalog" }
        else { "Fingerprint" }

    $verificationStatus =
        if ($catalog) { "KnownLolbas" }
        elseif (-not $ilspyPath) { "NotChecked" }
        elseif ($analysis.CallSite.Count -gt 0) { "CallSiteFound" }
        elseif ($analysis.ReferenceOnly.Count -gt 0) { "ReferenceOnlyLikelyFalsePositive" }
        else { "UnconfirmedByDecompile" }

    $resultRow = [PSCustomObject]@{
        Path                  = $file.FullName
        FileName              = $file.Name
        DetectionSource       = $detectionSource
        KnownLolbasTechnique  = if ($catalog) { $catalog.Technique } else { "" }
        Tiers                 = (ConvertTo-Json -InputObject @($allTiers) -Compress)
        SignatureStatus       = $sig.Status
        Signer                = $sig.Signer
        MatchedPatterns       = (ConvertTo-Json -InputObject @($fp.Matches) -Compress)
        IlSpyVerification     = $verificationStatus
        CallSitePatterns      = (ConvertTo-Json -InputObject @($analysis.CallSite) -Compress)
        ReferenceOnlyPatterns = (ConvertTo-Json -InputObject @($analysis.ReferenceOnly) -Compress)
        Notes                 = if ($catalog) { $catalog.Notes } else { "" }
        SizeKB                = [math]::Round($file.Length / 1KB, 1)
    }

    $results.Add($resultRow)

    # Write immediately for crash / interrupt durability.
    try {
        $resultRow | Export-Csv -Path $OutputCsv -NoTypeInformation -Append -Encoding UTF8
    }
    catch {
        Write-Warning ("Failed to write row for {0}: {1}" -f $file.FullName, $_.Exception.Message)
    }
}

Write-Progress -Activity "Scanning binaries" -Completed

# Final pass: rewrite the same file sorted for readability. If the scan was
# interrupted before here, the unsorted incremental file is what is on disk,
# and nothing is lost.
try {
    $results |
        Sort-Object DetectionSource, Tiers, SignatureStatus, Path |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Final report sorted for readability." -ForegroundColor Green
}
catch {
    Write-Warning "Could not write the sorted final pass. The unsorted incremental data on disk is still intact."
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ("`nScan complete. {0} binaries reported." -f $results.Count) -ForegroundColor Green
Write-Host ("Report written to: {0}" -f (Resolve-Path $OutputCsv))

$catalogHits = $results | Where-Object { $_.DetectionSource -in @("Catalog", "Both") }
$signedCatalog = $catalogHits | Where-Object { $_.SignatureStatus -eq "Valid" }

if ($catalogHits.Count -gt 0) {
    Write-Host ("`n{0} known-LOLBAS binaries found ({1} validly signed). These are documented WDAC / AppLocker bypass vectors and are the top priority:" -f $catalogHits.Count, $signedCatalog.Count) -ForegroundColor Red
    $catalogHits |
        Sort-Object SignatureStatus, FileName |
        Select-Object FileName, KnownLolbasTechnique, SignatureStatus, Path |
        Format-Table -AutoSize -Wrap
}

$fingerprintOnly = $results | Where-Object { $_.DetectionSource -eq "Fingerprint" }
$signedCallSite = $fingerprintOnly | Where-Object { $_.SignatureStatus -eq "Valid" -and $_.IlSpyVerification -eq "CallSiteFound" }
$signedRefOnly = $fingerprintOnly | Where-Object { $_.SignatureStatus -eq "Valid" -and $_.IlSpyVerification -eq "ReferenceOnlyLikelyFalsePositive" }

if ($signedCallSite.Count -gt 0) {
    Write-Host ("`n{0} signed non-catalog binaries have a real call site, not just an import. Review these next:" -f $signedCallSite.Count) -ForegroundColor Yellow
    $signedCallSite | Select-Object FileName, Tiers, CallSitePatterns, Path | Format-Table -AutoSize -Wrap
}

if ($signedRefOnly.Count -gt 0) {
    Write-Host ("`n{0} signed non-catalog binaries only reference the pattern as an import, likely a shared dependency rather than a real capability. Deprioritise these:" -f $signedRefOnly.Count) -ForegroundColor DarkGray
    $signedRefOnly | Select-Object FileName, Tiers, ReferenceOnlyPatterns, Path | Format-Table -AutoSize -Wrap
}
