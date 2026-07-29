# Conjunto de conformidad — Bloque 1

Vectores de decisión para la recomputación bit a bit exigida por el criterio
de aceptación del Bloque 1 (Matriz, sección M, fila 1).

## Uso

```powershell
cargo run -p sak-recompute -- --write-expected   # regenerar .expected.hex
cargo run -p sak-recompute                       # verificar bit a bit
```

## Casos

| Id | Qué demuestra |
|---|---|
| `01_sin_norma` | INV-02: `DENY(SIN_NORMA_APLICABLE)` |
| `02_allow_constante` | `ALLOW` con norma citada |
| `03_deny_constante` | `DENY` explícito |
| `04_presupuesto_agotado` | INV-14: `DENY(NORMA_NO_EVALUABLE)` |
| `05_ambigua_escala` | G.3 / R8: `ESCALATE(AMBIGUEDAD_DECLARADA)` |
| `06_infimo_deny_gana` | R2: una sola denegación decide |

Cada `.expected.hex` es la serialización canónica (esquema v1) producida por
`sak-recompute`. Dos ejecuciones independientes deben coincidir byte a byte.
