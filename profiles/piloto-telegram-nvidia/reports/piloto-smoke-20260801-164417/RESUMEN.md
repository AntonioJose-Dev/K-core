# RESUMEN SMOKE EF-1 - piloto-telegram-nvidia
fecha_utc=2026-08-01T14:44:18.1178051Z
timestamp=20260801-164417
veredicto=FAIL
pass=5/10
fail=5/10

## Criterios PASS
P1: Preflight limpio - PASS
P2: Custodia verificada - PASS
P3: desde_env OK - PASS
P4: decidir ALLOW - PASS
P5: ejercer RECIBO_OK - FAIL
P6: llamadas=1 - FAIL
P7: digest SHA-384 - FAIL
P8: digest match - FAIL
P9: HTTP 2xx - FAIL
P10: no persistencia - PASS

## Motivos de FAIL
P5: ejercer no devolvio RECIBO_OK (ok=false, codigo=Evidencia("fallo interno del proveedor"))
P6: llamadas_delegadas != 1
P7: digest resultado no es SHA-384 valido (longitud=4)
P8: digest match no verificable (ejecucion fallida)
P9: HTTP no devolvio 2xx
