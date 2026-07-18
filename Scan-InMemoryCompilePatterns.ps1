<#
.SYNOPSIS
    Scans local .NET binaries for signatures matching two known LOLBAS-relevant
    capability classes:

    Tier1  - Self-contained compile-and-run (CodeDom or Roslyn compiling to
             memory and executing without writing a payload assembly to disk).
    Tier2  - Trusted loader of pre-built code (loads and invokes a caller
             supplied DLL, e.g. InstallUtil-style installer class execution).

.DESCRIPTION
    For every candidate .exe/.dll under the given search roots, the script:
      1. Confirms it is a managed (.NET) assembly.
      2. Checks Authenticode signature status and signer.
      3. Scans the raw bytes for known API/type-name fingerprints tied to
         each tier.
      4. For anything that matched, optionally decompiles the assembly with
         ilspycmd and re-checks the same fingerprints against the actual
         decompiled source. This filters out matches that are just an
         unrelated string in the metadata heap rather than a real call site.
      5. Emits a CSV report of everything that matched, sorted by tier and
         signature status.

    This is a discovery aid, not a verdict. A match, even an ILSpy-confirmed
    one, means the binary CONTAINS the capability, not that it is
    exploitable in your environment. Confirm manually before drawing
    conclusions.

.PARAMETER ScanPaths
    Root directories to search. Defaults to System32, SysWOW64, Program
    Files, Program Files (x86), ProgramData, the .NET Framework tree, and
    the .NET Framework GAC. This is a broad, slow scan by design; narrow it
    with -ScanPaths for a faster targeted run.

.PARAMETER IncludeWinSxS
    Also scan C:\Windows\WinSxS. Off by default because it holds thousands
    of side-by-side assembly copies and adds significant scan time for
    little additional signal beyond what's already found elsewhere.

.PARAMETER OutputCsv
    Path to write the CSV report. Defaults to .\InMemoryCompileScan.csv

.PARAMETER MaxFileSizeMB
    Skip files larger than this to keep the byte-scan fast. Default 64.

.PARAMETER ExeOnly
    Only scan .exe files, skip .dll entirely. Cuts the candidate set
    substantially, useful for a fast first pass focused on directly
    launchable binaries, at the cost of missing capability implementations
    that live in a companion DLL (e.g. RoslynCodeTaskFactory, which lives
    in Microsoft.Build.Tasks.Core.dll, not MSBuild.exe itself).

.PARAMETER SkipIlSpy
    Skip the ILSpy decompile-and-confirm pass entirely. The CSV will still
    contain the raw byte-scan matches, just without verification.

.PARAMETER SkipIlSpyAutoInstall
    Use ilspycmd if it is already on PATH, but do not attempt to install it
    (via winget for the .NET SDK, then as a dotnet global tool) when it is
    missing.

.EXAMPLE
    .\Scan-InMemoryCompilePatterns.ps1 -OutputCsv C:\reports\scan.csv

.EXAMPLE
    .\Scan-InMemoryCompilePatterns.ps1 -SkipIlSpy
    Fast run, byte-scan only, no decompiler involved.

.EXAMPLE
    .\Scan-InMemoryCompilePatterns.ps1 -ExeOnly
    Only scan .exe files. Much smaller candidate set, but will miss
    capabilities that live in a companion DLL rather than the exe itself.
#>

[CmdletBinding()]
param(
    [string[]]$ScanPaths = @(
        "C:\Windows\Microsoft.NET",
        "C:\Windows\assembly",
        "C:\Windows\System32",
        "C:\Windows\SysWOW64",
        "C:\Program Files",
        "C:\Program Files (x86)",
        "C:\ProgramData"
    ),
    [switch]$IncludeWinSxS,
    [string]$OutputCsv = ".\InMemoryCompileScan.csv",
    [int]$MaxFileSizeMB = 64,
    [switch]$ExeOnly,
    [switch]$SkipIlSpy,
    [switch]$SkipIlSpyAutoInstall
)

if ($IncludeWinSxS) {
    $ScanPaths += "C:\Windows\WinSxS"
    Write-Warning "IncludeWinSxS is set. This directory holds thousands of assemblies and will substantially increase scan time."
}

# Fingerprint patterns per capability tier.
# Tier1: presence strongly suggests the binary can compile or dynamically
#        generate code and run it without writing a payload assembly to
#        disk (CodeDom, Roslyn, the DLR, T4, XSLT scripting, IL emission).
# Tier2: presence suggests the binary loads and executes caller supplied
#        assemblies or plugins (installer classes, COM registration hooks,
#        MEF/plugin catalogs, reflection-based assembly loading).
$fingerprints = @{
    Tier1_InMemoryCompile = @(
        # CodeDom compilation (classic .NET Framework path)
        "GenerateInMemory",
        "CSharpCodeProvider",
        "VBCodeProvider",
        "JScriptCodeProvider",
        "CodeDomProvider",
        "ICodeCompiler",
        "CompileAssemblyFromSource",
        "CompileAssemblyFromFile",
        "CompileAssemblyFromDom",
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
        # InstallUtil-style installer class execution
        "RunInstallerAttribute",
        "System.Configuration.Install",
        "TransactedInstaller",
        "AssemblyInstaller",
        # RegAsm / RegSvcs COM registration hooks
        "ComRegisterFunctionAttribute",
        "ComUnregisterFunctionAttribute",
        "RegistrationServices",
        "System.EnterpriseServices",
        # Generic reflection-based assembly loading and execution.
        # NOTE: these are the standalone method names, not "Assembly.LoadFrom"
        # style dotted strings. .NET metadata stores the type name and the
        # method name as separate string-heap entries (TypeRef.Name and
        # MemberRef.Name), never concatenated with a dot, so a dotted
        # pattern almost never appears in raw IL bytes and would silently
        # never match. "LoadFrom" and "LoadFile" are somewhat generic and
        # can false-positive on unrelated APIs; the ILSpy call-site pass
        # is what separates a real Assembly.LoadFrom call from noise.
        "LoadFrom",
        "LoadFile",
        "UnsafeLoadFrom",
        "ReflectionOnlyLoadFrom",
        "CreateInstanceFromAndUnwrap",
        "ExecuteAssembly",
        # .NET Core plugin loading. AssemblyLoadContext is a standalone type
        # name; its namespace (System.Runtime.Loader) is listed separately
        # since namespace and type name are also stored as distinct strings.
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
        directory is present.
    #>
    param([string]$Path)

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

function Ensure-IlSpyCmd {
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
        Decompiles the assembly once and evaluates each candidate pattern
        in two passes:

          1. Confirmed  - the pattern appears anywhere in the decompiled
                           source (same check as before).
          2. CallSite    - the pattern appears outside of a bare "using
                            Namespace;" import line. This is the Step 1
                            false-positive filter: a binary that merely
                            references Microsoft.CodeAnalysis as a shared
                            dependency, without ever calling into it, will
                            show the pattern only inside its using-block
                            and nowhere else, so it drops out here.

        The using-line filter is a heuristic, not a real call graph. A
        pattern surviving this filter means "the string shows up somewhere
        other than an import statement," which is still worth a manual
        look, just a much shorter list of manual looks than the raw scan.
    #>
    param(
        [string]$IlspyPath,
        [string]$AssemblyPath,
        [string[]]$CandidatePatterns
    )

    $emptyResult = [PSCustomObject]@{
        Confirmed      = [System.Collections.Generic.List[string]]::new()
        CallSite       = [System.Collections.Generic.List[string]]::new()
        ReferenceOnly  = [System.Collections.Generic.List[string]]::new()
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

    # Drop bare "using X.Y.Z;" import lines and comment-only lines before
    # the call-site check, so a namespace that is only ever imported and
    # never referenced again does not count as a call site.
    $codeOnlyLines = $rawLines | Where-Object {
        ($_ -notmatch '^\s*using\s+[\w\.]+\s*;\s*$') -and
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

$ilspyPath = $null
if (-not $SkipIlSpy) {
    $ilspyPath = Ensure-IlSpyCmd -AutoInstall:(-not $SkipIlSpyAutoInstall)
    if ($ilspyPath) {
        Write-Host ("Using ilspycmd at: {0}" -f $ilspyPath) -ForegroundColor Green
    }
}

$results = [System.Collections.Generic.List[object]]::new()
$maxBytes = $MaxFileSizeMB * 1MB

# Start with a clean output file. Every match is appended to this file the
# moment it's found, not held in memory until the end, so if the scan is
# interrupted (Ctrl+C, crash, remote session drop), everything found up to
# that point is already on disk.
if (Test-Path $OutputCsv) {
    Remove-Item $OutputCsv -Force
}

Write-Host "Enumerating candidate files under:" -ForegroundColor Cyan
$ScanPaths | ForEach-Object { Write-Host "  $_" }

$candidateExtensions = if ($ExeOnly) { @("*.exe") } else { @("*.exe", "*.dll") }
if ($ExeOnly) {
    Write-Host "ExeOnly is set. Skipping .dll files entirely." -ForegroundColor Yellow
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

$total = $candidates.Count
Write-Host ("Found {0} candidate files. Scanning..." -f $total) -ForegroundColor Cyan

$i = 0
foreach ($file in $candidates) {
    $i++
    if ($i % 250 -eq 0) {
        Write-Progress -Activity "Scanning binaries" -Status $file.FullName -PercentComplete (($i / $total) * 100)
    }

    if (-not (Test-IsManagedAssembly -Path $file.FullName)) {
        continue
    }

    $fp = Get-Fingerprints -Path $file.FullName
    if ($fp.Matches.Count -eq 0) {
        continue
    }

    $sig = Get-SignatureInfo -Path $file.FullName

    $analysis = [PSCustomObject]@{
        Confirmed     = [System.Collections.Generic.List[string]]::new()
        CallSite      = [System.Collections.Generic.List[string]]::new()
        ReferenceOnly = [System.Collections.Generic.List[string]]::new()
    }
    if ($ilspyPath) {
        $analysis = Get-IlSpyAnalysis -IlspyPath $ilspyPath -AssemblyPath $file.FullName -CandidatePatterns $fp.Matches
    }

    $verificationStatus =
        if (-not $ilspyPath) { "NotChecked" }
        elseif ($analysis.CallSite.Count -gt 0) { "CallSiteFound" }
        elseif ($analysis.ReferenceOnly.Count -gt 0) { "ReferenceOnlyLikelyFalsePositive" }
        else { "UnconfirmedByDecompile" }

    $resultRow = [PSCustomObject]@{
        Path                    = $file.FullName
        SignatureStatus         = $sig.Status
        Signer                  = $sig.Signer
        Tiers                   = (ConvertTo-Json -InputObject $fp.Tiers -Compress)
        MatchedPatterns         = (ConvertTo-Json -InputObject $fp.Matches -Compress)
        IlSpyVerification       = $verificationStatus
        CallSitePatterns        = (ConvertTo-Json -InputObject $analysis.CallSite -Compress)
        ReferenceOnlyPatterns   = (ConvertTo-Json -InputObject $analysis.ReferenceOnly -Compress)
        SizeKB                  = [math]::Round($file.Length / 1KB, 1)
    }

    $results.Add($resultRow)

    # Write immediately. Export-Csv -Append opens, writes, and closes the
    # file on every call, so this row is durable on disk before moving on
    # to the next candidate, not buffered in a stream that could be lost.
    try {
        $resultRow | Export-Csv -Path $OutputCsv -NoTypeInformation -Append -Encoding UTF8
    }
    catch {
        Write-Warning ("Failed to write row for {0}: {1}" -f $file.FullName, $_.Exception.Message)
    }
}

Write-Progress -Activity "Scanning binaries" -Completed

# Everything found is already on disk from the incremental writes above.
# This final pass just rewrites the same file sorted for readability; if
# the scan was interrupted before reaching here, the unsorted incremental
# file from the loop is what's on disk, and that's fine, nothing is lost.
try {
    $results |
        Sort-Object Tiers, SignatureStatus, Path |
        Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8
    Write-Host "Final report sorted for readability." -ForegroundColor Green
}
catch {
    Write-Warning "Could not write the sorted final pass. The unsorted incremental data on disk is still intact."
}

Write-Host ("`nScan complete. {0} binaries matched at least one fingerprint." -f $results.Count) -ForegroundColor Green
Write-Host ("Report written to: {0}" -f (Resolve-Path $OutputCsv))

$signedHits = $results | Where-Object { $_.SignatureStatus -eq "Valid" }
Write-Host ("Of those, {0} are validly signed (highest interest for AppLocker/WDAC bypass review)." -f $signedHits.Count) -ForegroundColor Yellow

$signedCallSite = $signedHits | Where-Object { $_.IlSpyVerification -eq "CallSiteFound" }
$signedRefOnly = $signedHits | Where-Object { $_.IlSpyVerification -eq "ReferenceOnlyLikelyFalsePositive" }

if ($signedCallSite.Count -gt 0) {
    Write-Host ("`n{0} signed binaries have a real call site, not just an import. Review these first:" -f $signedCallSite.Count) -ForegroundColor Red
    $signedCallSite | Select-Object Path, Tiers, CallSitePatterns | Format-Table -AutoSize
}

if ($signedRefOnly.Count -gt 0) {
    Write-Host ("`n{0} signed binaries only reference the pattern as an import, likely a shared dependency, not a real capability. Deprioritize these:" -f $signedRefOnly.Count) -ForegroundColor DarkGray
    $signedRefOnly | Select-Object Path, Tiers, ReferenceOnlyPatterns | Format-Table -AutoSize
}
