# Aceptación Bloque A — checklist operador

**Fase:** A2  
**Estado:** artefacto de aceptación humana (complementa harness CI A1/A3/A4)  
**UI:** sin autoridad; no certifica conformidad.

## Afirmación permitida al cerrar Bloque A

> El dominio custodia identidad declarada, referencias de custodia (sin material), inventario ALCANZABLES incompleto y deniega atajos de autoridad en el canal operador IPC.

## Afirmación todavía NO permitida

> Las llamadas del agente a modelo / herramientas / datos pasan por el Kernel como única frontera (Bloque B; requiere cierre B5).

## Checklist (recorrer tras `e2e_bloque_a` / Auditoría)

| # | Comprobación | Ops / señal | OK |
|---|---|---|---|
| 1 | Latido del dominio | `obs.salud`, `obs.estado` | ☐ |
| 2 | Sistema + pasaporte | `con.sistemas.listar`, `con.pasaporte.get` → `firma_valida` | ☐ |
| 3 | PEP declarativo sin secretos | `con.pep.vista` — sin API keys | ☐ |
| 4 | ALCANZABLES incompleto | `incompleto_declarado:true`, `afirma_completitud:false` | ☐ |
| 5 | Custodia sin material | `cus.estado` → `material:null`, huella/handle | ☐ |
| 6 | Control / Libro | `obs.libro.matriz`, `obs.hechos.listar` — sin `libro.elevar` | ☐ |
| 7 | Evidencia | `obs.evidencia.exportar` + `.verificar` + `no_comprobado[]` | ☐ |
| 8 | DENY de autoridad | `cap.emitir`, `libro.elevar`, `cus.reveal`, `obs.diagnostico.*`, secretos | ☐ |
| 9 | Disclaimer A4 visible | banner «No afirma frontera única de efectos del agente» | ☐ |

## Artefactos CI esperados

Tras `cargo test -p sak-domain --test e2e_bloque_a`:

- `target*/artefactos/bloque_a/a1_flujo.json`
- `target*/artefactos/bloque_a/a1_evidencia_export.json`
- `target*/artefactos/bloque_a/a3_matriz_deny.json`

## Criterio de cierre Fase A

CI A1+A3 verde · checklist A2 recorrida · disclaimer A4 presente en Auditoría · **ninguna** afirmación de mediación E2E.

**Cerrado en repo:** harness `e2e_bloque_a` + `ops_ui_bloque_a` + `docs/ACEPTACION-BLOQUE-A.md`.  
Siguiente: `docs/ACTA-FRONTERA-ABI-BLOQUE-B.md` y `e2e_bloque_b` (B0–B5).
