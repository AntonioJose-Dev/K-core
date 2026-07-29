# Registro de cierre — §M 11

**Estado:** CERRADO EN CÓDIGO Y PRUEBAS  
**Fecha:** 2026-07-29 (Europe/Madrid)  
**Repositorio:** `Sovereign-AI-Kernel`  
**Commit de cierre:** `1ddd1b33dcca67f32defbbb902f8cb1c770c894b`  
**Mensaje:** `§M 11 CERRADO EN CODIGO Y PRUEBAS`

## Pruebas de cierre (verdes)

| Comando | Resultado |
|---|---|
| `cargo test -p sak-core --tests` | **208** passed, **0** failed (incl. 18× `m11_expediente`) |
| `sak-verify --self-test` | exit **0**; `m11_expediente_ok=true`; `m11_inclusiones_ok=true`; J.2_1…13 impresos |

## Registro en Matriz

Anotación no normativa en `KERNEL/MATRIZ MAESTRA CANONICA - Sovereign AI Kernel v1.1.md` (§M — Registro de cierre de construcción): fila **11** = CERRADO EN CÓDIGO Y PRUEBAS con el commit anterior.

## Fuera de la afirmación de cierre (límites abiertos)

Estos **no** quedan cerrados por el código §M 11 y **no invalidan** el cierre del bloque:

| Ítem | Etiqueta |
|---|---|
| HSM y titularidad real de claves | `no_comprobado` / **[DESP]** |
| Testigo honesto | **[DESP]** |
| TSA / sello de tiempo de autoridad externa | `no_comprobado` / **[VAL-EXT]** |
| TCB / atestación real de plataforma | `no_comprobado` / **[VAL-EXT]** / **[DESP]** |
| C5 como propiedad de host/HW | fuera §M 11; D.1 |
| Suelo legal aplicable de retención 12 meses | **[VAL-EXT]** |
| Conformidad legal | **[GOB]** |
| Competencia humana (p. ej. autor de interpretación jurídica) | **[GOB]** |

## Siguiente etapa canónica

**§M 12** — contrato: `docs/CONTRATO-M12-PERFILES-AVANZADOS.md`. Sin implementación en este registro.
