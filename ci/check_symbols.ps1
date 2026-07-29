# ci/check_symbols.ps1
# Enumera los simbolos exportados del cdylib sak_abi y los compara con SYMBOLS.lock.
# Bloqueante (L-01 / INV-01). No requiere dumpbin: lee la tabla PE Export.

param(
    [string]$DllPath = "",
    [string]$LockPath = ""
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if (-not $LockPath) { $LockPath = Join-Path $Root "SYMBOLS.lock" }
if (-not $DllPath) {
    $candidates = @()
    if ($env:CARGO_TARGET_DIR) {
        $candidates += (Join-Path $env:CARGO_TARGET_DIR "debug\sak_abi.dll")
        $candidates += (Join-Path $env:CARGO_TARGET_DIR "release\sak_abi.dll")
    }
    $candidates += (Join-Path $Root "target\debug\sak_abi.dll")
    $candidates += (Join-Path $Root "target\release\sak_abi.dll")
    $DllPath = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $DllPath) {
        Write-Error "No se encontro sak_abi.dll. Ejecute primero: cargo build -p sak-abi"
        exit 2
    }
}

function Get-ExpectedSymbols([string]$path) {
    Get-Content -LiteralPath $path |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") }
}

function Get-PeExportNames([string]$path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    if ($bytes.Length -lt 0x40) { throw "PE demasiado corto" }
    $peOff = [BitConverter]::ToInt32($bytes, 0x3C)
    $peSig = [System.Text.Encoding]::ASCII.GetString($bytes, $peOff, 4)
    if ($peSig -ne "PE`0`0") { throw "Firma PE invalida" }
    $coff = $peOff + 4
    $opt = $coff + 20
    $magic = [BitConverter]::ToUInt16($bytes, $opt)
    if ($magic -eq 0x20B) {
        $exportDirRva = [BitConverter]::ToUInt32($bytes, $opt + 112)
        $numSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
        $sizeOpt = [BitConverter]::ToUInt16($bytes, $coff + 16)
        $sectionStart = $opt + $sizeOpt
    } elseif ($magic -eq 0x10B) {
        $exportDirRva = [BitConverter]::ToUInt32($bytes, $opt + 96)
        $numSections = [BitConverter]::ToUInt16($bytes, $coff + 2)
        $sizeOpt = [BitConverter]::ToUInt16($bytes, $coff + 16)
        $sectionStart = $opt + $sizeOpt
    } else {
        throw "Optional header magic desconocido: $magic"
    }
    if ($exportDirRva -eq 0) { return @() }

    function RvaToOff([uint32]$rva) {
        for ($i = 0; $i -lt $numSections; $i++) {
            $s = $sectionStart + ($i * 40)
            $virt = [BitConverter]::ToUInt32($bytes, $s + 12)
            $rawSize = [BitConverter]::ToUInt32($bytes, $s + 16)
            $rawPtr = [BitConverter]::ToUInt32($bytes, $s + 20)
            $virtSize = [BitConverter]::ToUInt32($bytes, $s + 8)
            $span = [Math]::Max($rawSize, $virtSize)
            if ($rva -ge $virt -and $rva -lt ($virt + $span)) {
                return [int]($rawPtr + ($rva - $virt))
            }
        }
        throw "RVA no mapeada: $rva"
    }

    $expOff = RvaToOff $exportDirRva
    $numNames = [BitConverter]::ToUInt32($bytes, $expOff + 24)
    $namesRva = [BitConverter]::ToUInt32($bytes, $expOff + 32)
    $namesOff = RvaToOff $namesRva
    $names = New-Object System.Collections.Generic.List[string]
    for ($i = 0; $i -lt $numNames; $i++) {
        $nameRva = [BitConverter]::ToUInt32($bytes, $namesOff + ($i * 4))
        $nameOff = RvaToOff $nameRva
        $end = $nameOff
        while ($bytes[$end] -ne 0) { $end++ }
        $name = [System.Text.Encoding]::ASCII.GetString($bytes, $nameOff, $end - $nameOff)
        # Ignorar simbolas de runtime del CRT / compilador
        if ($name -like "_*" -or $name -like "Dll*" -or $name -eq "TlsCallback") { continue }
        $names.Add($name) | Out-Null
    }
    return ($names | Sort-Object -Unique)
}

$expected = @(Get-ExpectedSymbols $LockPath | Sort-Object)
$actual = @(Get-PeExportNames $DllPath | Sort-Object)

Write-Host "DLL:      $DllPath"
Write-Host "LOCK:     $LockPath"
Write-Host "Esperados ($($expected.Count)): $($expected -join ', ')"
Write-Host "Exportados filtrados ($($actual.Count)): $($actual -join ', ')"

$missing = @($expected | Where-Object { $_ -notin $actual })
$extra = @($actual | Where-Object { $_ -notin $expected })

if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
    if ($missing.Count -gt 0) { Write-Host "FALTAN: $($missing -join ', ')" }
    if ($extra.Count -gt 0) { Write-Host "SOBRAN: $($extra -join ', ')" }
    Write-Error "Enumeracion de simbolos NO coincide con SYMBOLS.lock"
    exit 1
}

Write-Host "OK: enumeracion de simbolos coincide con SYMBOLS.lock"
exit 0
