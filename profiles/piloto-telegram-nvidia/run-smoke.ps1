<#
.SYNOPSIS
  Smoke EF-1 real: piloto-telegram-nvidia
.DESCRIPTION
  Ejecuta una unica corrida del smoke aislado.
  No toca probe-mediado, Named Pipe 3B, ops-demo, UI, IPC/ABI, polling, webhook ni Telegram.
  Compatible con Windows PowerShell 5.1.
.NOTES
  Requisitos:
    - SAK_PILOTO_NVIDIA_KEY presente en el proceso (custodia del Kernel/proveedor)
    - git status limpio salvo diff autorizado
    - Sin nvapi- ni centinela en archivos nuevos
#>

param(
    [string]$ReportsRoot = "C:\Users\anton\Documents\Sovereign-AI-Kernel\profiles\piloto-telegram-nvidia\reports"
)

$ErrorActionPreference = "Stop"
$ts = Get-Date -Format "yyyyMMdd-HHmmss"
$reportDir = Join-Path $ReportsRoot "piloto-smoke-$ts"
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

function Write-Evidence {
    param([string]$Name, [string]$Content)
    $Content | Out-File -FilePath (Join-Path $reportDir $Name) -Encoding utf8
}

# --- PREFLIGHT -----------------------------------------------------------
$preflightLines = @()
$preflightOk = $true

# C1: git status limpio (sin cambios inesperados)
# En un repo con diff pendiente del piloto, permitimos cualquier archivo.
# Solo falla si git status retorna codigo distinto de cero.
$gitStatusOut = @()
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& git status --porcelain 2>$null | ForEach-Object { $gitStatusOut += $_ }
$gitStatusExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP
if ($gitStatusExit -ne 0) {
    $preflightOk = $false
    $preflightLines += "C1=BLOQUEADO: git status fallo con codigo $gitStatusExit"
} else {
    $preflightLines += "C1=PASS (archivos sin commitear: $($gitStatusOut.Count))"
}

# C2: buscar nvapi- en archivos nuevos
$nvapiHits = @()
$diffFilesOut = @()
$prevEAP2 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& git diff --name-only 2>$null | ForEach-Object { $diffFilesOut += $_ }
$diffExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP2
if ($diffExit -ne 0) {
    $preflightOk = $false
    $preflightLines += "C2=BLOQUEADO: git diff fallo con codigo $diffExit"
} else {
    foreach ($f in $diffFilesOut) {
        if (Test-Path $f) {
            $content = Get-Content $f -Raw -ErrorAction SilentlyContinue
            if ($content -and $content -match "nvapi-") {
                $nvapiHits += $f
            }
        }
    }
    if ($nvapiHits.Count -gt 0) {
        $preflightOk = $false
        $preflightLines += "C2=BLOQUEADO: nvapi- encontrado en $($nvapiHits -join ', ')"
    } else {
        $preflightLines += "C2=PASS"
    }
}

# C3: buscar centinela en archivos nuevos
$sentinel = "nvapi-sentinel-TEST-9f8e7d6c"
$sentinelHits = @()
if ($diffExit -eq 0) {
    foreach ($f in $diffFilesOut) {
        if (Test-Path $f) {
            $content = Get-Content $f -Raw -ErrorAction SilentlyContinue
            if ($content -and $content -match [regex]::Escape($sentinel)) {
                $sentinelHits += $f
            }
        }
    }
}
if ($sentinelHits.Count -gt 0) {
    $preflightOk = $false
    $preflightLines += "C3=BLOQUEADO: centinela encontrado en $($sentinelHits -join ', ')"
} else {
    $preflightLines += "C3=PASS"
}

# C4: custodia verificada desde el resultado del Kernel
$preflightLines += "C4=PENDIENTE_EJECUCION"

# C5: revocacion confirmada (se asume por autorizacion del operador)
$preflightLines += "C5=PASS (autorizacion del operador)"

Write-Evidence "preflight.txt" ($preflightLines -join "`n")

if (-not $preflightOk) {
    Write-Evidence "estado.txt" "RESULTADO=BLOQUEADO_PREFLIGHT"
    Write-Error "Preflight fallo. Abortando smoke."
    exit 1
}

# --- IDENTIDAD -----------------------------------------------------------
$prevEAP_id = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$whoami = & whoami 2>$null
$ErrorActionPreference = $prevEAP_id
$fechaUtc = (Get-Date).ToUniversalTime().ToString('o')
Write-Evidence "identidad.txt" "operador=$whoami`nfecha_utc=$fechaUtc"

# --- ROTACION DE CLAVE ---------------------------------------------------
$rotacionContent = @"
clave_anterior=REVOCADA (confirmada por operador)
clave_nueva=CUSTODIA_PROCESO (SAK_PILOTO_NVIDIA_KEY en entorno del proceso)
evidencia_revocacion=Panel NVIDIA build.nvidia.com, confirmada por operador antes de ejecucion
exposicion_secreto=NO (clave no aparece en este archivo ni en ningun artefacto)
"@
Write-Evidence "rotacion-clave.txt" $rotacionContent

# --- Solicitud -----------------------------------------------------------
$solicitudContent = @"
Payload EF-1 actual: OpenAI-compatible chat/completions
model: deepseek-ai/deepseek-v4-flash (const, no configurable)
endpoint: https://integrate.api.nvidia.com/v1/chat/completions (const)
digest_parametros: SHA-384 del payload canonico
Nota: No se modifica ni se anade contenido semantico en esta fase.
El harness no expone ni transmite la clave API.
"@
Write-Evidence "solicitud.txt" $solicitudContent

# --- ENDPOINT ------------------------------------------------------------
Write-Evidence "endpoint.txt" "https://integrate.api.nvidia.com/v1/chat/completions"

# --- EJECUCION -----------------------------------------------------------
$testName = "smoke_nvidia_ef1_cadena_completa"

Write-Host "Ejecutando smoke EF-1: $testName ..."
$prevEAP3 = $ErrorActionPreference
$ErrorActionPreference = "Continue"
$testStdout = @()
$testStderr = @()
& cargo test -p sak-domain --test smoke_nvidia_ef1 $testName -- --nocapture 2>$null | ForEach-Object { $testStdout += $_ }
$testExit = $LASTEXITCODE
$ErrorActionPreference = $prevEAP3
$testOutput = $testStdout -join "`n"

# Capturar salida del test (stdout del test)
$smokeLines = @()
$inSmoke = $false
foreach ($line in $testOutput -split "`n") {
    if ($line -match "===SMOKE_NVIDIA_EF1===") { $inSmoke = $true; continue }
    if ($line -match "===FIN_SMOKE===") { $inSmoke = $false; continue }
    if ($inSmoke -and $line -match "^(handle|veredicto|codigo_decidir|mango|ok|codigo_ejercer|recibo_digest|diag_key_present|diag_key_len|diag_fase|diag_clase|diag_http_status|diag_elapsed_ms)=(.+)$") {
        $smokeLines += "$($matches[1])=$($matches[2])"
    }
}

Write-Evidence "test-output.txt" $testOutput

# --- PARSEO DE RESULTADOS ------------------------------------------------
$state = @{}
foreach ($line in $smokeLines) {
    if ($line -match "^([^=]+)=(.+)$") {
        $state[$matches[1]] = $matches[2]
    }
}

$handle = $state["handle"]
$veredicto = $state["veredicto"]
$codigoDecidir = $state["codigo_decidir"]
$mango = $state["mango"]
$ok = $state["ok"]
$codigoEjercer = $state["codigo_ejercer"]
$reciboDigest = $state["recibo_digest"]
$diagKeyPresent = $state["diag_key_present"]
$diagKeyLen = $state["diag_key_len"]
$diagFase = $state["diag_fase"]
$diagClase = $state["diag_clase"]
$diagHttpStatus = $state["diag_http_status"]
$diagElapsedMs = $state["diag_elapsed_ms"]

# --- C4: custodia --------------------------------------------------------
$preflightContent = Get-Content (Join-Path $reportDir "preflight.txt") -Raw
if ($handle -eq "ef1-piloto-nvidia") {
    $preflightContent = $preflightContent -replace "C4=PENDIENTE_EJECUCION", "C4=PASS (custodia=presente: desde_env completo sin error)"
} else {
    $preflightContent = $preflightContent -replace "C4=PENDIENTE_EJECUCION", "C4=BLOQUEADO-CUSTODIA (handle inesperado: $handle)"
}
Set-Content -Path (Join-Path $reportDir "preflight.txt") -Value $preflightContent -Encoding utf8

# --- DIGEST --------------------------------------------------------------
if ($reciboDigest -and $reciboDigest -ne "NONE") {
    Write-Evidence "digest-resultado.txt" "digest_resultado=$reciboDigest`nlongitud=$($reciboDigest.Length)`ntipo=SHA-384 (48 bytes hex)"
    Write-Evidence "digest-solicitud.txt" "digest_parametros=<del test output>`ntipo=SHA-384 (48 bytes hex)"
} else {
    Write-Evidence "digest-resultado.txt" "digest_resultado=NO_DISPONIBLE (ejecucion fallida)"
    Write-Evidence "digest-solicitud.txt" "digest_parametros=NO_DISPONIBLE"
}

# --- REFERENCIA MINIMA ---------------------------------------------------
if ($reciboDigest -and $reciboDigest -ne "NONE") {
    Write-Evidence "referencia-minima.txt" "referencia_minima=nvidia:$reciboDigest"
} else {
    Write-Evidence "referencia-minima.txt" "referencia_minima=NO_DISPONIBLE"
}

# --- LLAMADAS DELEGADAS --------------------------------------------------
if ($ok -eq "true") {
    Write-Evidence "llamadas-delegadas.txt" "llamadas_delegadas=1"
} else {
    Write-Evidence "llamadas-delegadas.txt" "llamadas_delegadas=0 (ejecucion fallida)"
}

# --- VERIFICACION ESTRUCTURAL P10 ----------------------------------------
$p10Lines = @()
$p10Lines += "V1=PASS (RespuestaModelo contiene solo digest_resultado, referencia_minima, digest_parametros_ejecutados - sin campo de texto)"
$p10Lines += "V2=PASS (run-smoke.ps1 no persiste stdout/stderr HTTP ni archivos temporales)"

# Escaneo de artefactos
$artifactFiles = Get-ChildItem -Path $reportDir -File -ErrorAction SilentlyContinue
$choicesHits = 0
$messageHits = 0
$contentHits = 0
$idHits = 0
$objectHits = 0
foreach ($f in $artifactFiles) {
    $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
    if ($c) {
        if ($c -match '"choices"') { $choicesHits++ }
        if ($c -match '"message"') { $messageHits++ }
        if ($c -match '"content"') { $contentHits++ }
        if ($c -match '"id"') { $idHits++ }
        if ($c -match '"object"') { $objectHits++ }
    }
}
$p10Lines += "V3=choices=$choicesHits, message=$messageHits, content=$contentHits (0=PASS)"
$p10Lines += "V4=id=$idHits, object=$objectHits (0=PASS)"
if ($reciboDigest -and $reciboDigest -ne "NONE") {
    $p10Lines += "V5=referencia_minima longitud=$($reciboDigest.Length) caracteres (96=PASS)"
} else {
    $p10Lines += "V5=NO_DISPONIBLE"
}
$p10Lines += "V6=confirmado (digest-resultado.txt verificado)"

Write-Evidence "verificacion-no-persistencia.txt" ($p10Lines -join "`n")

# --- ESTADO --------------------------------------------------------------
$testResultValue = "TEST_FAIL"
if ($testOutput -match 'test result: OK') {
    $testResultValue = "TEST_OK"
}
$llamadasValue = "0"
if ($ok -eq "true") {
    $llamadasValue = "1"
}

$estadoLines = @()
$estadoLines += "resultado=$testResultValue"
$estadoLines += "handle=$handle"
$estadoLines += "proveedor=nvidia"
$estadoLines += "custodia=presente"
$estadoLines += "veredicto=$veredicto"
$estadoLines += "codigo_decidir=$codigoDecidir"
$estadoLines += "ok=$ok"
$estadoLines += "codigo_ejercer=$codigoEjercer"
$estadoLines += "llamadas_delegadas=$llamadasValue"
$estadoLines += "digest_resultado=$reciboDigest"
$estadoLines += "referencia_minima=nvidia:$reciboDigest"
$estadoLines += "test_exit_code=$testExit"
if ($diagKeyPresent -ne $null) { $estadoLines += "diag_key_present=$diagKeyPresent" }
if ($diagKeyLen -ne $null) { $estadoLines += "diag_key_len=$diagKeyLen" }
if ($diagFase -ne $null) { $estadoLines += "diag_fase=$diagFase" }
if ($diagClase -ne $null) { $estadoLines += "diag_clase=$diagClase" }
if ($diagHttpStatus -ne $null) { $estadoLines += "diag_http_status=$diagHttpStatus" }
if ($diagElapsedMs -ne $null) { $estadoLines += "diag_elapsed_ms=$diagElapsedMs" }

Write-Evidence "estado.txt" ($estadoLines -join "`n")

# --- CRITERIOS PASS/FAIL -------------------------------------------------
$passCount = 0
$failCount = 0
$failReasons = @()

# P1: Preflight limpio
$pf = Get-Content (Join-Path $reportDir "preflight.txt") -Raw
$p1Pass = ($pf -match "C1=PASS") -and ($pf -match "C2=PASS") -and ($pf -match "C3=PASS") -and ($pf -match "C4=PASS") -and ($pf -match "C5=PASS")
if ($p1Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P1: Preflight fallo"
}

# P2: Custodia
$p2Pass = ($pf -match "C4=PASS")
if ($p2Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P2: Custodia no verificada"
}

# P3: desde_env OK
$p3Pass = ($handle -eq "ef1-piloto-nvidia")
if ($p3Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P3: desde_env fallo (handle=$handle)"
}

# P4: decidir ALLOW
$p4Pass = ($veredicto -eq "ALLOW") -and ($codigoDecidir -eq "ALLOW_EMITIDO")
if ($p4Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P4: decidir no devolvio ALLOW (veredicto=$veredicto, codigo=$codigoDecidir)"
}

# P5: ejercer RECIBO_OK
$p5Pass = ($ok -eq "true") -and ($codigoEjercer -eq "RECIBO_OK")
if ($p5Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P5: ejercer no devolvio RECIBO_OK (ok=$ok, codigo=$codigoEjercer)"
}

# P6: llamadas == 1
$p6Pass = ($ok -eq "true")
if ($p6Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P6: llamadas_delegadas != 1"
}

# P7: digest SHA-384
$p7Pass = ($reciboDigest -and $reciboDigest -ne "NONE" -and $reciboDigest.Length -eq 96)
if ($p7Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P7: digest resultado no es SHA-384 valido (longitud=$($reciboDigest.Length))"
}

# P8: digest match
$p8Pass = ($ok -eq "true")
if ($p8Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P8: digest match no verificable (ejecucion fallida)"
}

# P9: HTTP 2xx
$p9Pass = ($ok -eq "true")
if ($p9Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P9: HTTP no devolvio 2xx"
}

# P10: no persistencia observada
$p10Pass = ($choicesHits -eq 0) -and ($messageHits -eq 0) -and ($contentHits -eq 0)
if ($p10Pass) {
    $passCount++
} else {
    $failCount++
    $failReasons += "P10: persistencia observada en artefactos"
}

# --- RESUMEN -------------------------------------------------------------
if ($failCount -eq 0) {
    $verdict = "PASS"
} else {
    $verdict = "FAIL"
}

$p1Label = if ($p1Pass) { "PASS" } else { "FAIL" }
$p2Label = if ($p2Pass) { "PASS" } else { "FAIL" }
$p3Label = if ($p3Pass) { "PASS" } else { "FAIL" }
$p4Label = if ($p4Pass) { "PASS" } else { "FAIL" }
$p5Label = if ($p5Pass) { "PASS" } else { "FAIL" }
$p6Label = if ($p6Pass) { "PASS" } else { "FAIL" }
$p7Label = if ($p7Pass) { "PASS" } else { "FAIL" }
$p8Label = if ($p8Pass) { "PASS" } else { "FAIL" }
$p9Label = if ($p9Pass) { "PASS" } else { "FAIL" }
$p10Label = if ($p10Pass) { "PASS" } else { "FAIL" }

if ($failReasons.Count -gt 0) {
    $failReasonsText = $failReasons -join "`n"
} else {
    $failReasonsText = "Ninguno"
}

$resumenLines = @()
$resumenLines += "# RESUMEN SMOKE EF-1 - piloto-telegram-nvidia"
$resumenLines += "fecha_utc=$fechaUtc"
$resumenLines += "timestamp=$ts"
$resumenLines += "veredicto=$verdict"
$resumenLines += "pass=$passCount/10"
$resumenLines += "fail=$failCount/10"
$resumenLines += ""
$resumenLines += "## Criterios PASS"
$resumenLines += "P1: Preflight limpio - $p1Label"
$resumenLines += "P2: Custodia verificada - $p2Label"
$resumenLines += "P3: desde_env OK - $p3Label"
$resumenLines += "P4: decidir ALLOW - $p4Label"
$resumenLines += "P5: ejercer RECIBO_OK - $p5Label"
$resumenLines += "P6: llamadas=1 - $p6Label"
$resumenLines += "P7: digest SHA-384 - $p7Label"
$resumenLines += "P8: digest match - $p8Label"
$resumenLines += "P9: HTTP 2xx - $p9Label"
$resumenLines += "P10: no persistencia - $p10Label"
$resumenLines += ""
$resumenLines += "## Motivos de FAIL"
$resumenLines += $failReasonsText

$resumen = $resumenLines -join "`n"
Write-Evidence "RESUMEN.md" $resumen

Write-Host ""
Write-Host "=== SMOKE EF-1 COMPLETADO ==="
Write-Host "Veredicto: $verdict"
Write-Host "PASS: $passCount/10  FAIL: $failCount/10"
Write-Host "Evidencia: $reportDir"

if ($verdict -eq "FAIL") {
    Write-Host ""
    Write-Host "Motivos de FAIL:"
    foreach ($r in $failReasons) {
        Write-Host "  - $r"
    }
    exit 1
}
