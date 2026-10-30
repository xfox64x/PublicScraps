#Requires -Version 5.1
<#
.SYNOPSIS
    Enumerates running processes and identifies DLLs that could be candidates for DLL hijacking.
.DESCRIPTION
    Uses only native PowerShell / .NET capabilities (no ProcMon or external tools).
    Focuses on:
      1. Imported DLLs (from the PE import table) that are not in the KnownDLLs list
         when the process executable directory is writable.
      2. Currently loaded modules that reside in writable non-system directories.
    Notes:
      - Run elevated for best coverage (many processes deny module access otherwise).
      - Application directory is searched before System32 for DLLs loaded by name.
      - KnownDLLs are protected against this form of hijacking.
      - This highlights potential risk; it does not prove exploitability.
#>

function Get-KnownDlls {
    try {
        $props = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs' -ErrorAction Stop
        $props.PSObject.Properties |
            Where-Object { $_.Name -notlike 'PS*' -and $_.Value -is [string] } |
            ForEach-Object { $_.Value.ToLowerInvariant() }
    }
    catch {
        @()
    }
}

function Test-DirectoryWritable {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $testFile = Join-Path $Path ("_dllcheck_" + [guid]::NewGuid().ToString() + ".tmp")
    try {
        $fs = [System.IO.File]::Create($testFile)
        $fs.Close()
        Remove-Item -LiteralPath $testFile -Force -ErrorAction SilentlyContinue
        return $true
    }
    catch {
        return $false
    }
}

function Get-PEImportedDlls {
    param([string]$FilePath)
    $dlls = [System.Collections.Generic.List[string]]::new()
    try {
        $fs = New-Object System.IO.FileStream(
            $FilePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite
        )
        $bytes = New-Object byte[] $fs.Length
        [void]$fs.Read($bytes, 0, $bytes.Length)
        $fs.Dispose()

        if ($bytes.Length -lt 64) { return $dlls }

        $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($e_lfanew -le 0 -or ($e_lfanew + 24) -ge $bytes.Length) { return $dlls }

        $peSig = [BitConverter]::ToUInt32($bytes, $e_lfanew)
        if ($peSig -ne 0x00004550) { return $dlls }   # PE\0\0

        $coffOffset      = $e_lfanew + 4
        $numberOfSections = [BitConverter]::ToUInt16($bytes, $coffOffset + 2)
        $optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $coffOffset + 16)
        $optionalOffset  = $coffOffset + 20

        $magic = [BitConverter]::ToUInt16($bytes, $optionalOffset)
        $is64  = ($magic -eq 0x20B)

        # DataDirectory[1] = Import table (each entry is 8 bytes: RVA + Size)
        $dataDirOffset = if ($is64) { $optionalOffset + 112 } else { $optionalOffset + 96 }
        if (($dataDirOffset + 16) -gt $bytes.Length) { return $dlls }

        $importRVA = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
        if ($importRVA -eq 0) { return $dlls }

        # Section headers
        $sectionOffset = $optionalOffset + $optionalHeaderSize
        $sections = [System.Collections.Generic.List[pscustomobject]]::new()
        for ($i = 0; $i -lt $numberOfSections; $i++) {
            $secOff = $sectionOffset + ($i * 40)
            if (($secOff + 40) -gt $bytes.Length) { break }
            $sections.Add([pscustomobject]@{
                VA     = [BitConverter]::ToUInt32($bytes, $secOff + 12)
                RawSize = [BitConverter]::ToUInt32($bytes, $secOff + 16)
                RawPtr  = [BitConverter]::ToUInt32($bytes, $secOff + 20)
            })
        }

        function Convert-RVAToOffset {
            param($rva)
            foreach ($sec in $sections) {
                if ($rva -ge $sec.VA -and $rva -lt ($sec.VA + $sec.RawSize)) {
                    return $sec.RawPtr + ($rva - $sec.VA)
                }
            }
            return $null
        }

        $importOffset = Convert-RVAToOffset $importRVA
        if (-not $importOffset) { return $dlls }

        $index = 0
        while ($true) {
            $descOff = $importOffset + ($index * 20)   # IMAGE_IMPORT_DESCRIPTOR = 20 bytes
            if (($descOff + 20) -gt $bytes.Length) { break }

            $nameRVA = [BitConverter]::ToUInt32($bytes, $descOff + 12)
            if ($nameRVA -eq 0) { break }

            $nameOff = Convert-RVAToOffset $nameRVA
            if ($nameOff -and $nameOff -lt $bytes.Length) {
                $nameBytes = [System.Collections.Generic.List[byte]]::new()
                $p = $nameOff
                while ($p -lt $bytes.Length -and $bytes[$p] -ne 0) {
                    $nameBytes.Add($bytes[$p])
                    $p++
                }
                if ($nameBytes.Count -gt 0) {
                    $dllName = [System.Text.Encoding]::ASCII.GetString($nameBytes.ToArray())
                    if ($dllName) { $dlls.Add($dllName) }
                }
            }
            $index++
            if ($index -gt 500) { break }
        }
    }
    catch {
        # Ignore unreadable files / access issues
    }
    return $dlls | Select-Object -Unique
}

# ---------- Main ----------
$knownDlls = Get-KnownDlls
$results   = [System.Collections.Generic.List[pscustomobject]]::new()
$systemRoots = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    $env:SystemRoot
)

Write-Host "Enumerating processes (run elevated for full coverage)..." -ForegroundColor Cyan

Get-Process | ForEach-Object {
    $proc = $_
    try {
        $exePath = $null
        try { $exePath = $proc.MainModule.FileName } catch { }

        if ([string]::IsNullOrWhiteSpace($exePath) -or -not (Test-Path -LiteralPath $exePath)) {
            return
        }

        $exeDir   = Split-Path -Parent $exePath
        $writable = Test-DirectoryWritable $exeDir

        # 1. Static imports that are not KnownDLLs + writable app directory
        if ($writable) {
            $imports = Get-PEImportedDlls -FilePath $exePath
            foreach ($dll in $imports) {
                if ($knownDlls -notcontains $dll.ToLowerInvariant()) {
                    $results.Add([pscustomobject]@{
                        ProcessName     = $proc.ProcessName
                        PID             = $proc.Id
                        Executable      = $exePath
                        DLL             = $dll
                        LoadedPath      = $null
                        Reason          = 'Imported (not KnownDLL) and process directory is writable'
                        AppDirWritable  = $true
                    })
                }
            }
        }

        # 2. Currently loaded modules from writable non-system locations
        $modules = $null
        try { $modules = $proc.Modules } catch { }
        if ($modules) {
            foreach ($mod in $modules) {
                $modPath = $mod.FileName
                if ([string]::IsNullOrWhiteSpace($modPath)) { continue }
                $modDir  = Split-Path -Parent $modPath
                $modName = Split-Path -Leaf $modPath

                $isSystem = $false
                foreach ($root in $systemRoots) {
                    if ($modDir.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $isSystem = $true
                        break
                    }
                }

                if (-not $isSystem -and (Test-DirectoryWritable $modDir)) {
                    $results.Add([pscustomobject]@{
                        ProcessName     = $proc.ProcessName
                        PID             = $proc.Id
                        Executable      = $exePath
                        DLL             = $modName
                        LoadedPath      = $modPath
                        Reason          = 'Loaded from writable non-system directory'
                        AppDirWritable  = $writable
                    })
                }
            }
        }
    }
    catch {
        # Skip processes we cannot inspect
    }
}

# Output
if ($results.Count -eq 0) {
    Write-Host "No obvious DLL hijack candidates found." -ForegroundColor Green
}
else {
    $results |
        Sort-Object ProcessName, DLL |
        Format-Table -AutoSize ProcessName, PID, DLL, Reason, AppDirWritable, LoadedPath, Executable

    # Optional: export
    # $results | Export-Csv -Path "$env:TEMP\DllHijackCandidates.csv" -NoTypeInformation
    Write-Host "`nFound $($results.Count) potential candidate(s). Review writable directories and KnownDLL status." -ForegroundColor Yellow
}
