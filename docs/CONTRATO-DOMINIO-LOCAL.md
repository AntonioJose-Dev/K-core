# Contrato — Proceso autoritativo por dominio (estado durable)

**Estado:** D0/D1 acotados a la Matriz literal; resto diferido.  
**Fecha:** 2026-07-30  
**Regla de corte:** Si un elemento de D0/D1 **no** sale directamente de §E, INV-03, INV-07, G.5, H o J, **se elimina y no se implementa**.

---

## 1. Mandato normativo (solo citas que autorizan D0/D1)

| Fuente | Exigencia literal | Implica en D0/D1 |
|---|---|---|
| **§E** | «**Un proceso autoritativo por dominio, en Rust.**» Núcleo con «motor, emisor, verificador, **estado** y custodia **en un solo proceso**.» | Binario de dominio Rust que posee el estado del dominio. |
| **INV-07** | Evidencia «de forma **durable**» antes de capacidad; «El almacenamiento **no miente** sobre la durabilidad»; no escribible ⇒ no emisión ⇒ `SUSPENDED`. | `AlmacenEvidencia` en disco; fallo de escritura ⇒ no emitir. |
| **H / J** | Cadena de evidencia, escritura de registros/checkpoints vía ledger existente. | El almacén disco es el backend del ledger ya construido; **no** se reescribe H/J. |

**Fuera de D0/D1** (aunque la Matriz los exija más adelante): persistencia de registro/pasaporte, corpus G.5 completo, Libro, expedientes indexados, refs custodia, config PEP, canal IPC, UI, etiquetas DEMO/REAL de producto, telemetría. Eso es **D2+** cuando se implemente solo con cita normativa propia.

**INV-03 / G.5** («paquetes se conservan indefinidamente», historial G.5): **no** entran en D0/D1 salvo que el ledger ya escriba blobs con cita en el almacén durable; no se añade árbol `corpus/` ni activación en esta franja.

---

## 2. D0 — Persistencia durable de evidencia (INV-07)

| Incluye | Excluye |
|---|---|
| `AlmacenDiscoLocal: AlmacenEvidencia` (clave→archivo bajo directorio del dominio) | SQLite, red, API HTTP |
| Prueba: escribir → nuevo proceso/handle → `leer` igual | Seed DEMO como evidencia operativa |
| Prueba: fallo de escritura ⇒ ledger no emite / suspende (comportamiento existente) | Reinventar motor, emisor o esquemas J |
| Uso por `EpocaMonotonica` vía mismas claves `sak/epoca/*` | Árbol registro/libro/pep/custodia |

---

## 3. D1 — Proceso autoritativo vacío (§E)

| Incluye | Excluye |
|---|---|
| Binario `sak-domain`: `init`, `status`, `run` | Consola UI, named pipe, `obs.*` |
| Un `dominio_id` → un directorio local → un proceso | Bind público, egress, telemetría |
| Al arrancar: abre `AlmacenDisco` + `LedgerEvidencia` + época desde almacén | Alta de sistemas, gobernanza G.5, emitir capacidades por CLI de conveniencia |
| `status`: path, época/suelo si existen, estado del ledger | Presentar datos sintéticos como REAL |

**Vacío:** dominio sin sujetos/pasaportes/corpus/Libro cargados — solo el proceso y el almacén durable listos. Eso es §E (proceso+estado) + INV-07 (almacén que no miente), no un producto de demos.

---

## 4. Ubicación en Windows (operativa, no normativa)

```text
%LOCALAPPDATA%\SovereignAIKernel\domains\<dominio_id>\evidencia\
```

Solo el subárbol **evidencia** en D0/D1. Sin `meta.json` de producto ni carpetas extras.

---

## 5. Criterio de aceptación D0/D1

1. `AlmacenDiscoLocal` persiste y recupera bytes tras reabrir el path (INV-07).  
2. Con almacén que falla al escribir, `emitir_tras_evidencia` no concede capacidad (INV-07).  
3. `sak-domain init <id>` crea el directorio de evidencia del dominio.  
4. `sak-domain run <id>` mantiene un proceso Rust con ledger sobre ese almacén (§E).  
5. `sak-domain status <id>` reporta path y época sin inventar Libro/expediente.  
6. Nada de red, telemetría ni UI en este binario.

---

## 6. Fases posteriores (no implementar ahora)

- **D2+:** snapshots registro, corpus G.5, Libro, expedientes (INV-03, G.5, J, D) con cita explícita cada uno.  
- **D3:** canal `obs.*` RO.  
- **D4:** UI dueño.
