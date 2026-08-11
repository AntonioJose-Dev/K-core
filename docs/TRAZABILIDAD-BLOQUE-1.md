# Registro de trazabilidad — Bloque 1

Fuente canónica: `K-CORE/KERNEL/MATRIZ MAESTRA CANONICA - Sovereign AI Kernel v1.1.md`
(solo lectura; este repositorio no la modifica).

## Decisiones vinculantes del operador

| Fecha | Decisión |
|---|---|
| 2026-07-28 | Plan del Bloque 1 aprobado: estructura, invariantes, tests, límites declarados y orden de ejecución. |
| 2026-07-28 | Lista cerrada de 8 símbolos aprobada: `sak_decidir`, `sak_ejercer`, `sak_estado`, `sak_salud`, `sak_exportar_evidencia`, `sak_verificar`, `sak_version`, `sak_describir_abi`. |
| 2026-07-28 | `sak_describir_abi` sustituye a `sak_liberar` (familia observar; devuelve versión, esquema, capacidades públicas y hash de `SYMBOLS.lock`, sin autoridad). |
| 2026-07-28 | Sin símbolo público de gestión de memoria: el FFI usa buffers proporcionados por el llamador o salida de tamaño fijo y documentada. No se añade novena vía pública. |
| 2026-07-29 | **Nomenclatura:** queda prohibido llamar «bloque de Matriz» / «bloque §M» a rebanadas `bloque12`…`bloque20`. Son implementaciones EF-3…EF-11 (C/E/F). Ver `docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md`. |
| 2026-07-29 | **§M 11 CERRADO EN CÓDIGO Y PRUEBAS** — commit `1ddd1b33dcca67f32defbbb902f8cb1c770c894b`; `cargo test -p sak-core --tests` 208/0; `sak-verify --self-test` `m11_expediente_ok=true`. Registro: `docs/CERRADO-M11.md` + Matriz §M. Límites DESP/VAL-EXT/GOB abiertos. Siguiente: **§M 12** (`docs/CONTRATO-M12-PERFILES-AVANZADOS.md`). |

## Mapa entregable → invariante → archivo → criterio/test

| Parte del entregable (M, fila 1) | Invariante | Archivo | Criterio / test | Estado |
|---|---|---|---|---|
| Tipos de decisión (códigos G.3, orden R2, traza) | INV-02, INV-14 | `crates/sak-core/src/decision.rs` | Usados por cierre conservador y recomputación | Esqueleto |
| Contexto tipado y hechos firmados | INV-14 | `crates/sak-core/src/contexto.rs` | Harness `pureza_de_decision` | Esqueleto |
| Perfil normativo como dato (costura Bloque 2) | INV-02 | `crates/sak-core/src/perfil.rs` | Test `DENY(SIN_NORMA_APLICABLE)` | Esqueleto |
| Presupuesto de pasos con corte determinista | INV-14 | `crates/sak-core/src/presupuesto.rs` | Test `DENY(NORMA_NO_EVALUABLE)` al agotar, mismo paso siempre | Esqueleto |
| Función pura `decidir()` con ínfimo R2 | INV-02, INV-14 | `crates/sak-core/src/motor.rs` | `pureza_de_decision`; recomputación bit a bit | Esqueleto |
| `Capability` con constructor privado; `emitir(...)` | INV-01 | `crates/sak-core/src/capacidad.rs` | Compile-fail `capacidad_exige_decision` | Esqueleto |
| Lista cerrada de ocho símbolos | INV-01, INV-06 | `SYMBOLS.lock` | Enumeración del binario contra la lista, bloqueante (L-01) | **Creado** |
| Frontera externa `cdylib` (8 símbolos) | INV-01, INV-06 | `crates/sak-abi/src/lib.rs` | `ci/check_symbols.ps1` contra `SYMBOLS.lock` | Esqueleto |
| Proceso independiente de recomputación | INV-14 | `crates/sak-recompute/src/main.rs` | Comparación byte a byte del conjunto de conformidad | Esqueleto (sale con código 2) |
| Conjunto de conformidad | INV-14 | `conformance/bloque1/` | Entradas y salidas canónicas para recomputación | Esqueleto (solo README) |

## Pendientes del Bloque 1 (orden de ejecución aprobado)

1. ~~Esqueleto del workspace, toolchain, `SYMBOLS.lock`, `git init`~~ — esqueleto **hecho**; `git init` **pendiente** (terminal sin respuesta en la sesión actual).
2. Tipos de `sak-core` (decisión, códigos, contexto, hechos).
3. Motor puro con presupuesto, cierre conservador e ínfimo R2.
4. `capacidad.rs` con constructor privado y `emitir`.
5. `sak-abi` con los 8 símbolos.
6. Conjunto de conformidad y `sak-recompute`.
7. Tests (`pureza_de_decision`, `capacidad_exige_decision`, cierre conservador, presupuesto) y puerta de símbolos en CI (`ci/check_symbols.ps1`).
8. Ejecución de los dos criterios de aceptación y reporte con evidencia.

## Pendientes técnicos registrados

| Pendiente | Motivo | Dónde se resuelve |
|---|---|---|
| `git init` del repositorio | Terminal sin respuesta en la sesión actual | Paso 1, al recuperar el terminal |
| Pin de versión exacta en `rust-toolchain.toml` | No se pudo verificar la toolchain instalada (`rustc --version` sin respuesta) | Paso 1, al recuperar el terminal |
| Compilación de verificación del esqueleto (`cargo check`) | Igual que lo anterior | Antes del paso 2 |

## Deuda técnica preexistente (descubierta en Fase 3)

Los siguientes problemas existen en el repositorio antes de cualquier cambio de Fase 3 y no están relacionados con `id_peticion` ni con el atado a petición. Se registran aquí para que no se pierdan.

### DT-1: Errores de compilación en `gate1_crypto_default_v1.rs`

**Archivo:** `crates/sak-core/tests/gate1_crypto_default_v1.rs`  
**Líneas:** 15, 34, 107

- **Línea 15:** Array `salt` declarado como `[u8; 22]` pero inicializado con 33 elementos.
- **Línea 34:** Array `ikm` declarado como `[u8; 64]` pero inicializado con 105 elementos.
- **Línea 107:** `sha2::Sha256::new()` falla porque el trait `sha2::Digest` no está importado.

**Impacto:** Impide compilar el conjunto completo de tests de `sak-core` con `cargo test -p sak-core`.  
**Sugerencia:** Revisar si estos tests son necesarios para la entrega actual o si pueden desactivarse temporalmente. Si son necesarios, corregir los tamaños de array y añadir `use sha2::Digest;`.

### DT-2: Crash del compilador en `bloque6_pep_ef1` (STATUS_STACK_BUFFER_OVERRUN)

**Archivo:** `crates/sak-core/tests/bloque6_pep_ef1.rs`  
**Entorno:** rustc 1.96.0-x86_64-pc-windows-msvc

**Síntoma:** Al compilar el test `bloque6_pep_ef1`, el compilador Rust se cierra con `STATUS_STACK_BUFFER_OVERRUN` (0xc0000409). Esto ocurre incluso sin ejecutar el test, durante la compilación.

** Hipótesis:**  
1. Bug del compilador (rustc 1.96.0) desencadenado por código complejo en el test.  
2. Código inseguro en el test (macros complejas, recursión profunda, `unsafe` implícito) que causa stack overflow durante la compilación.

**Impacto:** Impide compilar el conjunto completo de tests de `sak-core` con `cargo test -p sak-core`.  
**Sugerencia:** Revisar el contenido de `bloque6_pep_ef1.rs` para identificar macros recursivas, traits complejos o patrones que puedan desbordar la pila del compilador. Considerar:  
- Simplificar el test.  
- Dividirlo en tests más pequeños.  
- Reportar el bug a Rust si se reproduce con un caso mínimo ajeno al proyecto.

**Nota:** Estos dos problemas son preexistentes y no están relacionados con los cambios de Fase 3 (atado a petición).

## Límites declarados del Bloque 1

- `PerfilNormativo` es dato mínimo de prueba; objeto de norma, lenguaje de predicados y precedencia completa: **Bloque 2**.
- `CompromisoEvidencia` es tipo opaco; cadena de evidencia y verificador independiente: **Bloque 3**.
- `HechoFirmado` lleva la firma como dato; verificación criptográfica de productores: **Bloques 3–4**.
- Sin servidor ni red: biblioteca + ABI + binario de recomputación.
- `unsafe` mínimo y auditado solo en `sak-abi` (lectura de buffers FFI); `sak-core` con `#![forbid(unsafe_code)]` (mitigación de INV-06).
