# Acta — Frontera Bloque B (B0)

**Estado:** CONGELADA tras cierre Bloque A (A1–A4 verdes).  
**Fecha:** 2026-07-30  
**Norma:** Matriz Maestra v1.1 E.1 · `docs/CONTRATO-IPC-OPERADOR-LOCAL.md` §2, §5.1, §6.

## Frontera permitida

| Capa | Superficie | Rol |
|---|---|---|
| Sujeto / agente | ABI E.1 + módulo dominio `sujeto` (misma cadena) | `decidir` → emisión interna → `ejercer` |
| Operador | `obs.diagnostico.decidir` / `.ejercer` | Espejo de la misma cadena; UI **no** emite |
| PEP | Un gateway `sak-core` por clase (MVP: EF-1 `GatewayModelos` + `ProveedorSimulado`) | Único egreso al proveedor en harness |

## No-hacer (explícito)

- No HTTP/`/v1/chat` ni APIs REST nuevas de proveedor.
- No convertir `con.pep.configurar` en proxy.
- No `cap.emitir` / `libro.elevar` desde UI o IPC operador.
- No devolver material de clave / API key al agente.
- No afirmar mediación multi-clase ni “única frontera en host no confinado” hasta pruebas por clase + B5.

## Afirmación B0

**Permitida:** frontera de diseño fijada sin APIs inventadas.  
**No permitida:** mediación E2E implementada (requiere B1–B5).

## Criterio de avance

Solo después de este acta: B1 (decidir con pasaporte/Libro) → B2 (emisión interna) → B3 (ejercer EF-1) → B4 (espejo obs) → B5 (harness agente sin key).

**Implementado en repo:** `sak-domain::sujeto` + `e2e_bloque_b` (B1–B5).  
`sak_ejercer` ABI permanece `SAK_ERR_NO_DISPONIBLE` (host sin registro); la cadena E.1 validada es in-process vía dominio. UI sigue denegando `obs.diagnostico.*` (espejo solo por IPC/estado, no autoridad UI).
