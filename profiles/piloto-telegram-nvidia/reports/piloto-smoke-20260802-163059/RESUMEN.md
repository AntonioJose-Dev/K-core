# RESUMEN SMOKE EF-1 - piloto-telegram-nvidia
fecha_utc=2026-08-02T14:31:00.1169333Z
timestamp=20260802-163059
veredicto=FAIL
pass=1/10
fail=9/10

## Criterios PASS
P1: Preflight limpio - FAIL
P2: Custodia verificada - FAIL
P3: desde_env OK - FAIL
P4: decidir ALLOW - FAIL
P5: ejercer RECIBO_OK - FAIL
P6: llamadas=1 - FAIL
P7: digest SHA-384 - FAIL
P8: digest match - FAIL
P9: HTTP 2xx - FAIL
P10: no persistencia - PASS

## Motivos de FAIL
P1: Preflight fallo
P2: Custodia no verificada
P3: desde_env fallo (handle=)
P4: decidir no devolvio ALLOW (veredicto=, codigo=)
P5: ejercer no devolvio RECIBO_OK (ok=, codigo=)
P6: llamadas_delegadas != 1
P7: digest resultado no es SHA-384 valido (longitud=0)
P8: digest match no verificable (ejecucion fallida)
P9: HTTP no devolvio 2xx
