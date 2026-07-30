# Registro de cierre — §M 12

**Estado:** CERRADO EN CÓDIGO Y PRUEBAS  
**Fecha:** 2026-07-29 (Europe/Madrid)  
**Repositorio:** `Sovereign-AI-Kernel`  
**Contrato:** `docs/CONTRATO-M12-PERFILES-AVANZADOS.md`

## Correcciones del mapa aplicadas

| Corrección | Cumplimiento |
|---|---|
| Sonda EF-1…EF-12 por puerta canónica (no stub DENY); EF-12 DENY incondicional | `recorrer_puerta_sin_capacidad` → `comprobar_puerta_control` + emisión por ausencia; EF-12 `EF12_NUNCA` |
| C5 solo `C5_CALCULADO_SOBRE_HECHOS_APORTADOS`; nunca `C5_HOST_REAL` | `NivelControl::denominacion_c5_calculado` + P3 |

## Pruebas de cierre (verdes)

| Comando | Resultado |
|---|---|
| `cargo test -p sak-core --test m12_perfiles_avanzados` | **13** passed, **0** failed |
| `cargo test -p sak-core --test bloque18_ef9` | **11** passed (gancho `ConfinadoAtestado`) |
| `cargo test -p sak-core --tests` | **221** passed, **0** failed (208 previos §M 11 + 13 §M 12) |

## Auditoría fila-a-fila (§M 12 vs Matriz / contrato)

| Ítem | Veredicto |
|---|---|
| Entregable perfiles avanzados (I.10 + multiparte) | **VERDE** |
| Ocho predicados I.10 → `CONFINADO` ≤300 s | **VERDE** |
| Predicado 6 = 10/10 distinto de sonda §M 12 clases | **VERDE** |
| Sonda EF-1…EF-12 sin capacidad → 12 DENY firmados | **VERDE** |
| Sonda por puerta canónica (no stub) | **VERDE** |
| EF-12 siempre DENY / no emitible | **VERDE** |
| C5 = hechos aportados; etiqueta `C5_CALCULADO_SOBRE_HECHOS_APORTADOS` | **VERDE** |
| H-2: CONFINADO ∧ ¬CUSTODIA/EXCLUSIVIDAD ≠ C5 | **VERDE** |
| Multiparte `q=⌊2N/3⌋+1`; certificado inválido rojo→verde test | **VERDE** |
| Integración mínima B18 / EF-9 | **VERDE** |
| P1–P5 / N1–N6 | **VERDE** |
| Límites DESP/VAL-EXT/GOB / `no_comprobado` declarados | **VERDE** (abiertos a propósito) |
| Sin etapas posteriores a §M 12; B12–B20 intactos salvo gancho | **VERDE** |
| `C5_HOST_REAL` / TCB real / HSM / TSA / ALCANZABLES completo | **NO** (declarado abierto; no cierra §M 12) |

## Fuera de la afirmación de cierre (límites abiertos)

| Ítem | Etiqueta |
|---|---|
| HSM y titularidad real de claves | `no_comprobado` / **[DESP]** |
| TSA | `no_comprobado` / **[VAL-EXT]** |
| TCB / atestación real de plataforma | `no_comprobado` / **[VAL-EXT]** / **[DESP]** |
| `C5_HOST_REAL` | prohibido afirmar; solo cálculo sobre hechos |
| Completitud `ALCANZABLES` / rutas no sondadas | **[DESP]** |
| Exclusividad real de red | **[DESP]** |
| Conformidad legal | **[GOB]** |

## Construcción §M 1–12

Con este cierre, las **doce** filas de construcción §M tienen criterio demostrable en código/pruebas del repositorio de implementación. Los límites declarados arriba **no** quedan cerrados y **no** invalidan el cierre de construcción.

## Fuera de alcance

Cualquier requisito o etapa **posterior** a la fila 12 de §M; reescritura de B12–B20 salvo el gancho B18 documentado.
