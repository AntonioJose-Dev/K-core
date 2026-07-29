# Sovereign AI Kernel

Implementación del Sovereign AI Kernel conforme a la **Matriz Maestra Canónica v1.1**
(`K-CORE/KERNEL/MATRIZ MAESTRA CANONICA - Sovereign AI Kernel v1.1.md`).
K-CORE es fuente documental canónica y de **solo lectura**: este repositorio no la modifica nunca.

## Estado actual

**Bloque 1 — esqueleto.** Solo existe la estructura del workspace. No hay motor,
ABI, tipos de decisión, `Capability` ni tests funcionales. Véase
`docs/TRAZABILIDAD-BLOQUE-1.md` para el registro completo de estado y decisiones.

## Bloque 1 — alcance (Matriz, sección M, fila 1)

> «Motor de decisión determinista con frontera externa cerrada. Función pura con
> presupuesto de pasos; tipos de decisión y capacidad con constructor privado;
> lista cerrada de ocho símbolos.»

Invariantes que habilita: **INV-01, INV-02, INV-06, INV-14**.

Criterio de aceptación demostrable:

1. La enumeración de símbolos del binario compilado coincide con la lista
   cerrada (`SYMBOLS.lock`).
2. Recomputación bit a bit de un conjunto de decisiones por un proceso
   independiente (`sak-recompute` sobre `conformance/bloque1/`).

## Estructura

| Ruta | Papel |
|---|---|
| `crates/sak-core/` | Núcleo autoritativo: tipos de decisión, contexto, perfil, presupuesto, motor puro y `Capability`. `#![forbid(unsafe_code)]`, sin dependencias, sin reloj/entropía/red/disco (INV-14). |
| `crates/sak-abi/` | Frontera externa cerrada: `cdylib` que exportará exactamente los 8 símbolos de `SYMBOLS.lock`. Único crate donde se permitirá `unsafe` mínimo y auditado (lectura de buffers FFI). |
| `crates/sak-recompute/` | Proceso independiente de recomputación bit a bit del conjunto de conformidad. |
| `conformance/bloque1/` | Conjunto de decisiones: entradas y salidas esperadas con serialización canónica. |
| `SYMBOLS.lock` | Lista cerrada de 8 símbolos, fuente que la CI compara contra el binario (L-01, bloqueante). |
| `docs/TRAZABILIDAD-BLOQUE-1.md` | Registro de trazabilidad: decisiones vinculantes, mapa entregable → archivo → test, pendientes. |

## Frontera de lenguajes (E.1 de la Matriz)

Tres familias, sin tercera vía con autoridad:

- **Pedir decisión:** `sak_decidir`
- **Ejercer capacidad:** `sak_ejercer`
- **Observar:** `sak_estado`, `sak_salud`, `sak_exportar_evidencia`,
  `sak_verificar`, `sak_version`, `sak_describir_abi`

No existe, y no existirá, ninguna función que conceda, emita, amplíe, prorrogue,
anule o eluda. No hay símbolo público de gestión de memoria: el FFI usa buffers
proporcionados por el llamador o salida de tamaño fijo y documentada.

## Mapa criterio → test (se implementará en este bloque)

| Propiedad | Invariante | Test |
|---|---|---|
| Símbolos del binario = lista cerrada | INV-01, INV-06 | `ci/check_symbols.ps1` contra `SYMBOLS.lock` (pendiente) |
| Recomputación bit a bit | INV-14 | `sak-recompute` sobre `conformance/bloque1/`, dos procesos, comparación byte a byte (pendiente) |
| Pureza de la decisión | INV-14 | Harness `pureza_de_decision` (pendiente) |
| `Capability` inconstruible sin decisión | INV-01 | Compile-fail `capacidad_exige_decision` (pendiente) |
| Cierre conservador | INV-02 | Test `DENY(SIN_NORMA_APLICABLE)` sin norma aplicable (pendiente) |
| Presupuesto de pasos | INV-14 | Test `DENY(NORMA_NO_EVALUABLE)` determinista al agotar presupuesto (pendiente) |

## Límites declarados del Bloque 1

- `PerfilNormativo` será un dato mínimo de prueba: el objeto de norma completo,
  el lenguaje de predicados y las ocho reglas de precedencia son del **Bloque 2**.
- `CompromisoEvidencia` existirá solo como tipo opaco exigido por `emitir`:
  la cadena de evidencia real y su verificador son del **Bloque 3**.
- `HechoFirmado` llevará la firma como dato; la verificación criptográfica de
  productores llega con los **Bloques 3–4**.
- No hay servidor ni red: el Bloque 1 es biblioteca + ABI + binario de recomputación.
