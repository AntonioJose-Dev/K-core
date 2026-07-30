# Contrato literal — §M 12 (implementado)

Fuente: Matriz Maestra Canónica v1.1, §M fila **12**, I.10 (atestación de confinamiento), D.1/D.3 (`CONFINADO` / C5), C (EF-1…EF-12), K (consistencia distribuida / multiparte), INV-09, INV-11, L-19, L-23, H-2.  
Este documento **no añade** requisitos. **No** incluye etapas posteriores a §M 12. **No** modifica B12–B20 salvo el gancho mínimo B18/EF-9 (`PerfilEf9::ConfinadoAtestado`).

**Estado:** implementación en código y pruebas **verde** (mapa corregido: sonda por puerta canónica; C5 solo como `C5_CALCULADO_SOBRE_HECHOS_APORTADOS`).

## Entregable (§M 12)

> **Perfiles avanzados.** Confinamiento sin autoridad ambiental con sus ocho predicados de atestación; y perfil de autoridad multiparte con quórum de dos tercios más uno también en el certificado de cambio de vista.

## Invariantes afectados (§M 12)

- **INV-09** — El Kernel no autoriza una clase de efecto cuyo nivel de control medido esté por debajo del mínimo exigido para esa clase.
- **INV-11** — Si un sistema puede ejecutar código con autoridad ambiental, el nivel de toda clase cuyo efector sea alcanzable desde ese código se limita al nivel cooperativo.

## Criterio de aceptación demostrable (§M 12)

> En confinamiento, la sonda intenta las **doce clases** sin capacidad y obtiene **doce denegaciones**, con resultado firmado. En multiparte, el invariante de seguridad se comprueba y el test de certificado inválido está en verde.

## Correcciones obligatorias del mapa (aplicadas)

1. **Sonda EF-1…EF-12:** no stub DENY. Cada clase (salvo EF-12) aporta `capacidad=None` a `comprobar_puerta_control` y, si Continuar, deniega por emisión/capacidad ausente. EF-12 = DENY incondicional (`EF12_NUNCA`), sin ruta permisiva; emisión tipada también rechaza alcance EF-12.
2. **C5:** P3 solo prueba `NivelControl::C5` como `C5_CALCULADO_SOBRE_HECHOS_APORTADOS` sobre hechos aportados (incl. `CONFINADO`). Prohibido `C5_HOST_REAL`. Host/TCB/plataforma/atestación real/red/completitud inventario = `no_comprobado` / [DESP] / [VAL-EXT].

## Artefactos de código

| Artefacto | Ruta |
|---|---|
| I.10 / CONFINADO | `crates/sak-core/src/libro/confinamiento.rs` |
| Sonda 12 EF | `crates/sak-core/src/libro/sonda_ef.rs` |
| Multiparte vista | `crates/sak-core/src/libro/multiparte.rs` (`q = ⌊2N/3⌋+1`) |
| Denominación C5 | `crates/sak-core/src/libro/nivel.rs` |
| Gancho B18 | `PerfilEf9::ConfinadoAtestado` en `evaluador_ef9.rs` |
| Emisión EF-12 | `ErrorEmision::EfectoEf12Nunca` |
| Harness P1–P5 / N1–N6 | `crates/sak-core/tests/m12_perfiles_avanzados.rs` |

## Pruebas

| # | Observable |
|---|---|
| P1 | Ocho predicados I.10 ⇒ atestación `CONFINADO` |
| P2 | Sonda 12× DENY por puerta canónica + firma |
| P3 | C5 solo como `C5_CALCULADO_SOBRE_HECHOS_APORTADOS` |
| P4 | Certificado vista con quórum 2/3+1 |
| P5 | B18: `ConfinadoAtestado` cierra canal ambiental EF-9 |
| N1–N6 | Predicado fallo; CONFINADO sin CUSTODIA; ALLOW en sonda; quórum inválido; EF-12; límites `no_comprobado` |

## Límites que permanecen abiertos

Igual que §G del contrato original: HSM, TSA, TCB/plataforma, `C5_HOST_REAL`, ALCANZABLES completo, red real, [GOB]. **No** se afirman etapas posteriores a §M 12.
