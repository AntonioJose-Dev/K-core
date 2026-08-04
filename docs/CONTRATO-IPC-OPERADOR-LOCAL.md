# Contrato IPC — Operador local (UI ↔ Kernel)

**Estado:** CONGELADO (contrato tipado; sin implementación de UI ni de canal en este documento).  
**Fecha de congelación:** 2026-07-30  
**Clasificación:** capa operativa local del dueño sobre el Kernel ya construido (§M 1–§M 12). **No** es etapa §M 13. **No** añade requisitos a la Matriz Maestra v1.1.  
**Fuente normativa:** Matriz Maestra Canónica v1.1 — E, E.1, G.5, D, J, INV-01/06/08/09/10/15/16; diseño funcional de consola local aprobado; correcciones vinculantes de congelación.

---

## 1. Naturaleza y límites de autoridad

- La UI **no posee autoridad técnica** para emitir capacidades o secretos.
- Un único emisor de autoridad por dominio sigue siendo el **núcleo Rust** (INV-01). La UI no crea, amplía, prorroga, transfiere ni reactiva capacidades.
- **Corrección vinculante — engaño de interfaz:** sin embargo, toda **acción humana irreversible** debe protegerse contra engaño de interfaz mediante, como mínimo:
  1. **visualización canónica** del objeto sobre el que se actúa;
  2. **digest firmado** de ese objeto (o de la petición canónica);
  3. **identidad y rol** del firmante;
  4. **consecuencias** explícitas (qué cambia / qué se revoca / qué no se puede deshacer);
  5. **época** (y suelo de época cuando aplique);
  6. **confirmación independiente** cuando exista clave o hardware de firma (segundo factor / dispositivo / canal de firma distinto de la sola pulsación en pantalla).
- Comprometer solo el *look* de la UI no debe bastar para producir una acción irreversible válida: el Kernel valida digest, identidad, rol, prerrequisitos y firmas; no un clic opaco.

---

## 2. Transporte y prohibiciones globales de canal

| Regla | Valor |
|---|---|
| Transporte | IPC local únicamente (pipe / socket loopback / memoria compartida / in-process). |
| Bind público | **DENY** de arranque del canal operador. |
| Egress | **Off por defecto.** Ningún mensaje implica salida de red. |
| Telemetría | **Prohibida.** Cualquier `telemetry.*` o equivalente → **DENY**. |
| Relación con ABI C de 8 símbolos | La ABI (`sak_decidir` … `sak_describir_abi`) es frontera de **sujeto/integración** (E.1). Este contrato es el **canal operador local**. No añade un noveno símbolo que conceda autoridad. |

### Envelope común — petición

`op`, `req_id`, `schema_v`, `operador_id`, `artefacto_auth_humano`, `digest_peticion`, `firma_operador?`, `epoca_vista`, `ts_local_mono`

### Envelope común — respuesta

`req_id`, `resultado` (`OK` \| `DENY` \| `ERROR`), `codigo`, `digest_respuesta`, `recibo_id?`, `limites[]` (`no_comprobado` / **[DESP]** / **[VAL-EXT]** / **[GOB]**)

### Prohibido en todo mensaje IPC

| Prohibido | Notas |
|---|---|
| **Secretos raíz o material de clave exportable** | **Corrección vinculante.** No se incluyen PEM/raw/seed/wrapping exportable de raíz. |
| Elevación del Libro (`elevar_nivel` o equivalente) | INV-10 / D.3: no existe interfaz para elevar. |
| Emisión, ampliación, prórroga o reactivación de capacidades **desde la UI** | Solo el emisor del Kernel tras decisión + compromiso. |
| Cualquier vía que conceda **EF-12** a un sistema de IA | Siempre DENY a IA; gobierno solo por G.5 humana. |
| Bind público, telemetría, egress por defecto | Ver arriba. |

### Permitido observar / exportar (no confundir con secretos)

**Sí** pueden observarse y exportarse: hashes de **raíz Merkle**, pruebas de inclusión, huellas públicas, digests de evidencia, handles/referencias opacas de custodia, hashes de paquete normativo, digests de contexto de supervisión.

---

## 3. Tipos de acción

| Tipo | Significado |
|---|---|
| `LECTURA` | No muta autoridad ni corpus; no requiere confirmación irreversible. |
| `PROPUESTA_HUMANA` | Introduce borrador, firma o reconocimiento; el Kernel valida; puede o no ser reversible. |
| `IRREVERSIBLE` | Cambia suelo de época, revoca capacidades vivas, rota material de custodia, etc. Exige protecciones anti-engaño de la §1. |

---

## 4. Familias E.1 (cuando el flujo toca sujeto)

1. **Pedir decisión** — nunca material de credencial en perfil confinado.  
2. **Ejercer capacidad** — vía PEP; la UI no posee credencial de efector.  
3. **Observar** — estado, salud, exportación de evidencia, verificación; no influye en ninguna decisión.

Prohibición E.1: ninguna función que conceda, emita, amplíe, prorrogue, anule o eluda.

Flujos Gobernar / Custodiar / Conectar / Supervisión usan además el **canal humano** hacia componentes E (gobernanza, custodia, registro, supervisión): la UI transporta firmas y referencias; no es emisor.

---

## 5. Operaciones por pilar (especificación)

### 5.1 Observar

| op | Petición (mín.) | Respuesta (mín.) | Identidad / firma | Validador | DENY | Evidencia | Tipo |
|---|---|---|---|---|---|---|---|
| `obs.estado` | `dominio_id?` | estado, época/suelo?, límites | operador auth; firma opcional | Monitor / núcleo | canal no local; schema | — / audit acceso | LECTURA |
| `obs.salud` | — | salud, latido/autotest si hay | idem | Monitor | idem | — | LECTURA |
| `obs.version` / `obs.describir_canal` | — | versión, schema IPC, nota canal≠ABI sujeto | idem | Núcleo | — | — | LECTURA |
| `obs.libro.matriz` | `sistema?`, `clase?` | nivel C0–C5, hechos, caducidades, bypass, `C5_CALCULADO_…` si aplica, límites | idem | Libro | N/A; **elevar** | — | LECTURA |
| `obs.hechos.listar` | filtros | tipo, productor, digest, TTL, vigente | idem | Libro | inyectar hecho sin productor | — | LECTURA |
| `obs.decisiones.listar` / `.get` | `sujeto?`, `seq?`, `id?` | veredicto, código, hash_paquete, traza, nivel_en_instante | idem | Ledger | id inexistente | — | LECTURA |
| `obs.evidencia.exportar` | alcance, `confirmacion_explicita` | paquete; digests; **raíces Merkle / inclusiones permitidas** | firma sobre digest(alcance‖época) | Evidencia | sin confirmación; **secreto raíz / material exportable** | registro export | PROPUESTA_HUMANA |
| `obs.evidencia.verificar` | paquete o path local | informe J.5 + `no_comprobado[]` | auth | Verificador (p. ej. hermano `sak-verify`) | exigir veredicto conformidad | informe | LECTURA |
| `obs.expediente.get` | `expediente_id` | 12 partes; etiquetas J.3; sin veredicto conformidad | auth | Evidencia | ocultar `NO_AFIRMADO`; mezcla etiquetas | — | LECTURA |
| `obs.limites` / `obs.incidentes` | — | DESP/VAL-EXT/GOB; incidentes | auth | Libro/Monitor/Evid. | ocultación de límites | — | LECTURA |
| `obs.diagnostico.decidir` | efecto tipado + sistema | decisión | auth (+ cadena H) | Motor + puertas | sin pasaporte; control insuficiente; **EF-12→IA** | decisión encadenada | PROPUESTA_HUMANA |
| `obs.diagnostico.ejercer` | mango/cap id | recibo PEP | auth | Emisor+PEP+Custodia | material exportable; ampliar cap | recibo | PROPUESTA_HUMANA |

**DENY fijo de esquema:** `libro.elevar`, `cap.emitir` desde UI, `cus.reveal` / export de material de clave, `conceder_ef12` a IA, `net.bind_public`, `telemetry.*`.

### 5.2 Gobernar (G.5)

| op | Petición | Respuesta | Identidad / firma / anti-engaño | Validador | DENY | Evidencia | Tipo |
|---|---|---|---|---|---|---|---|
| `gob.proponer` | borrador normas/citas/L* | `hash_paquete` | firma sobre hash borrador; vista canónica del borrador | Gobernanza | L1 materias reservadas; EF-12 emitible a IA | propuesta | PROPUESTA_HUMANA |
| `gob.revision_juridica` | hash, interpretación, L*, ambigüedad | ack | revisor + competencia; digest | Gobernanza | sin competencia | `INTERPRETACION_JURIDICA` | PROPUESTA_HUMANA |
| `gob.diff_conformidad` | hash | diff decisiones | — | Conformidad | — | — | LECTURA |
| `gob.reconocer_diff` | hash, cambios[], firmas | ack | firma por cambio; vista canónica diff | Gobernanza | pendiente sin reconocer | diff firmado | PROPUESTA_HUMANA |
| `gob.doble_firma` | hash, firmas jurídico+técnico | ack | ids distintas; digest paquete; confirmación indep. si HSM firma | Gobernanza | 1 firma; firma IA; mismo rol | firmas | PROPUESTA_HUMANA |
| `gob.entrar_sombra` / `gob.estado_sombra` | hash | estado sombra 7d | anti-engaño si muta | Activación | aplicar sombra como vivo | evento sombra | PROPUESTA_HUMANA / LECTURA |
| `gob.activar_epoca` | hash, época | ack | **IRREVERSIBLE:** objeto canónico, digest, rol, consecuencias, época, confirmación indep. | Gobernanza+época | sin etapas 4–5; diff no reconocido | evento activación | IRREVERSIBLE |
| `gob.revocar` / `gob.revertir` | hash, firmas 2-de-N | ack | idem anti-engaño; consecuencias=revocar caps vivas | Gobernanza | borrar historia; umbral | revocación | IRREVERSIBLE |

### 5.3 Custodiar

| op | Petición | Respuesta | Identidad / firma | Validador | DENY | Evidencia | Tipo |
|---|---|---|---|---|---|---|---|
| `cus.alta_referencia` | alias, clase EF, handle/ref KMS|PKCS#11 | `secreto_id`, huella/handle | firma operador; vista canónica de metadatos (sin material) | Custodia | **cualquier** `material` / PEM / raw / seed exportable | alta sin clave | PROPUESTA_HUMANA |
| `cus.estado` | `secreto_id` / alias | presente/rotado, huella, TTL derivadas | auth | Custodia | pedir raw | — | LECTURA |
| `cus.rotar` | `secreto_id`, nuevo handle | ack | **IRREVERSIBLE:** anti-engaño §1 | Custodia | exportar material antiguo/nuevo | rotación sin bytes | IRREVERSIBLE |

**DENY fijo:** `cus.export_raiz`, `cus.reveal`, entrega de material a IA/SDK/MCP.

### 5.4 Conectar

| op | Petición | Respuesta | Identidad / firma | Validador | DENY | Evidencia | Tipo |
|---|---|---|---|---|---|---|---|
| `con.sistema.alta` | declaración (finalidad, modelo, herramientas, efectores, riesgo…) | `sistema_id` | firma responsable; vista canónica declaración | Registro | sin firma; UI “autoriza efectos” | declaración | PROPUESTA_HUMANA |
| `con.pasaporte.emitir` / `.get` | sistema / id | pasaporte versionado | auth (+ firma emisión) | Registro+Identidad | identidad solo autodeclarada como autoridad | pasaporte firmado | PROPUESTA_HUMANA / LECTURA |
| `con.pep.configurar` / vista | mapa clase→PEP, egreso | ack / vista | auth | PEPs/Registro | API key proveedor en claro al agente; PEP decide en silencio | config | PROPUESTA_HUMANA / LECTURA |
| `con.inventario.alcanzables` | inventario firmado+caducidad | ack | productor | Libro | afirmar completitud | hecho inventario | PROPUESTA_HUMANA |

### 5.5 Supervisión

| op | Petición | Respuesta | Identidad / firma / anti-engaño | Validador | DENY | Evidencia | Tipo |
|---|---|---|---|---|---|---|---|
| `sup.listar_escalados` | filtros | cola, plazo, digest anclado | auth | Supervisión | — | — | LECTURA |
| `sup.aprobar` / `sup.rechazar` | `escalado_id`, digest_contexto exacto, competencia, rol, firmas quórum | ack | digest canónico visible; solicitante≠aprobador; confirmación indep. si hardware firma | Supervisión | genérica; mismo solicitante; plazo→ALLOW; digest≠ancla | hecho firmado | PROPUESTA_HUMANA |

---

## 6. Tabla única consolidada

| Flujo UI | Mensaje IPC | Datos permitidos | Datos prohibidos | Validador Kernel | DENY | Evidencia | Soporte ABI actual (8 símbolos) | Cambio mínimo |
|---|---|---|---|---|---|---|---|---|
| Estado dominio | `obs.estado` | estado, época/suelo, límites | secretos raíz / material exportable; caps | Monitor/núcleo | IPC no local; schema | — / audit | **Parcial** `sak_estado` (stub) | Estado real del monitor |
| Salud | `obs.salud` | salud, latidos | idem | Monitor | idem | — | **Parcial** `sak_salud` | Autotest/latido reales |
| Versión / describir canal | `obs.version` / `obs.describir_canal` | versión, schema IPC | símbolos de concesión | Núcleo | — | — | **Sí** `sak_version`, `sak_describir_abi` | Declarar canal operador ≠ SYMBOLS sujeto |
| Matriz Libro | `obs.libro.matriz` | C0–C5, hechos, bypass, C5 calculado, límites | elevar; `C5_HOST_REAL` | Libro | elevación | — | **No** ABI | IPC lectura Libro |
| Rebajar nivel | `libro.rebajar` | sistema, clase, causa, firma | cualquier alza | Libro | elevar | declaración/incidente | **No** | Solo rebaja |
| Hechos | `obs.hechos.listar` | hechos+TTL+digest | hecho sin productor | Libro | firma inválida | — | **No** | Exponer hechos |
| Decisiones | `obs.decisiones.*` | veredicto, código, traza, nivel instante | reescritura | Ledger | id N/A | — | **No** | Lectura ledger |
| Exportar evidencia | `obs.evidencia.exportar` | paquete; **Merkle root / inclusiones / digests** | **secreto raíz o material de clave exportable**; egress auto | Evidencia | sin confirmación/firma | registro export | `sak_exportar_evidencia` = N/D | Implementar export |
| Verificar | `obs.evidencia.verificar` | informe + `no_comprobado` | veredicto conformidad | Verificador | conformidad autocert. | informe | `sak_verificar` = N/D; CLI sí | IPC→verify / spawn |
| Expediente | `obs.expediente.get` | 12 partes, J.3 | veredicto; ocultar NO_AFIRMADO | Evidencia | mezcla etiquetas | — | **No** ABI | Serializar por IPC |
| Límites / incidentes | `obs.limites` / `obs.incidentes` | DESP/VAL-EXT/GOB | ocultar límites | varios | — | — | **No** | Vistas |
| Diagnóstico decidir | `obs.diagnostico.decidir` | efecto tipado | credencial; EF-12 ALLOW IA | Motor+H | pasaporte/control/EF-12 IA | decisión | **Parcial** `sak_decidir` | Cadena H real |
| Diagnóstico ejercer | `obs.diagnostico.ejercer` | mango/cap id | material exportable; ampliar | Emisor+PEP | N/D hoy | recibo | `sak_ejercer` = N/D | Implementar ejercer |
| Proponer corpus | `gob.proponer` | borrador, hash | activar ya | Gobernanza | L1 reservado; EF-12→IA | propuesta | **No** ABI; lib sí | IPC `proponer` |
| Revisión jurídica | `gob.revision_juridica` | interpretación, L* | auto-jurídico | Gobernanza | sin competencia | etiqueta J.3 | lib parcial | IPC |
| Diff | `gob.diff_conformidad` | diff | — | Conformidad | — | — | lib sí | IPC |
| Reconocer diff | `gob.reconocer_diff` | firmas por cambio | activar sin reconocer | Gobernanza | pendiente | diff firmado | lib sí | IPC |
| Doble firma | `gob.doble_firma` | 2 firmas roles | 1 firma; firma IA | Gobernanza | umbral/roles | firmas | lib sí | IPC + anti-engaño |
| Sombra | `gob.entrar_sombra` / `estado_sombra` | ventana 7d | vivo prematuro | Activación | skip | evento | lib sí | IPC |
| Activar época | `gob.activar_epoca` | hash, época | sin 4–5 | Gob.+época | prerrequisitos | activación | lib sí | IPC + anti-engaño |
| Revocar | `gob.revocar` | firmas 2-de-N | borrar historia | Gobernanza | umbral | revocación | lib sí | IPC + anti-engaño |
| Alta ref. secreto | `cus.alta_referencia` | handle/ref, alias | **material raíz / exportable** | Custodia | reveal/export | alta | lib broker | IPC handles only |
| Estado custodia | `cus.estado` | huella, estado | bytes clave | Custodia | raw | — | **No** ABI | IPC |
| Rotar | `cus.rotar` | handles | material | Custodia | export | rotación | lib | IPC + anti-engaño |
| Alta sistema | `con.sistema.alta` | declaración+firma | autorizar efectos | Registro | sin firma | declaración | lib | IPC |
| Pasaporte | `con.pasaporte.*` | pasaporte | mentir identidad | Registro+Id | sin vigente | pasaporte | lib | IPC |
| PEP config/vista | `con.pep.*` | mapa PEP, egreso | API key a agente | PEPs | PEP decide | config | lib/tests | IPC |
| ALCANZABLES | `con.inventario.alcanzables` | inventario+caducidad | completitud afirmada | Libro | firma | hecho | lib | IPC |
| Escalados | `sup.listar_escalados` | cola, digest | — | Supervisión | — | — | lib | IPC |
| Aprobar/rechazar | `sup.aprobar` / `.rechazar` | digest exacto, quórum | genérica; plazo ALLOW | Supervisión | QUORUM/plazo/digest | hecho | lib | IPC + anti-engaño |
| EF-12→IA | — | — | **toda vía** | Motor/Gob. | **siempre DENY** | DENY | endurecer decidir | DENY schema+motor |
| Bind / telemetría / egress default | — | — | **todo** | Arranque | **DENY fijo** | — | **Capa UI (+flag)** | Política proceso |
| Elevar Libro / emitir cap UI | — | — | **todo** | Libro/Emisor | **DENY fijo** | intento | N/A | Rechazo schema |

---

## 7. Correcciones vinculantes (registro)

1. **Autoridad UI:** la UI no posee autoridad técnica para emitir capacidades o secretos; toda acción humana irreversible exige visualización canónica, digest firmado, identidad/rol, consecuencias, época y confirmación independiente cuando exista clave/hardware de firma.  
2. **Material vs Merkle:** prohibido incluir **secretos raíz o material de clave exportable**. Hashes de raíz Merkle, pruebas de inclusión, huellas públicas y digests de evidencia **sí** se observan y exportan.

---

## 8. Fuera de alcance de este contrato congelado

- Implementación de UI, framework o código del canal IPC.  
- Activación/revocación/rotación en la primera entrega MVP (ver §9).  
- Cierre de límites `no_comprobado` / **[DESP]** / **[VAL-EXT]** / **[GOB]**.  
- Nueva etapa §M 13.

---

## 9. Priorización de implementación mínima (primera consola usable)

**Objetivo de la primera entrega:** abrir una consola local y **ver** el Kernel (estado, decisiones, Libro, evidencia, límites). No controlar todo de golpe.  
**No** es diseño de UI completa: solo flujos, dependencias, cambios mínimos, mensajes IPC, pruebas y pantalla local indicativa.

### 9.1 MVP-OBSERVAR — prioridad 1 (primera entrega)

| Flujo | Dependencias ya disponibles | Cambio mínimo Kernel / canal | Mensajes IPC | Pruebas | Pantalla local (indicativa) |
|---|---|---|---|---|---|
| Estado / salud | `sak_estado` / `sak_salud` stubs; monitor en `sak-core` | Exponer estado/salud reales vía IPC operador (o ampliar stubs con datos del monitor de prueba) | `obs.estado`, `obs.salud`, `obs.version`, `obs.describir_canal` | Harness: respuesta OK en IPC local; DENY si schema malo | **Panel Estado** |
| Libro C0–C5 + hechos | `LibroControl`, `calcular_nivel_base`, hechos firmados, tests bloque8 / m12 | Serializar matriz+hechos+caducidades+bypass+límites C5 calculado; **rechazar elevar** | `obs.libro.matriz`, `obs.hechos.listar` | Test: lectura coincide con evaluación Libro; DENY `libro.elevar` | **Panel Libro** |
| Límites / incidentes | etiquetas en atestaciones/sonda/verify; incidentes en monitor/Libro según código | Agregar `obs.limites`, `obs.incidentes` (agregar desde fuentes existentes; no inventar métricas) | `obs.limites`, `obs.incidentes` | Límites no vacíos en demo; incluyen DESP/VAL-EXT/GOB donde consten | **Panel Límites** (o sección del Estado) |
| Decisiones | ledger / registros de decisión en evidencia | Listado/get por IPC desde almacén local del proceso | `obs.decisiones.listar`, `obs.decisiones.get` | Tras seed de demo: ≥1 ALLOW y ≥1 DENY visibles | **Panel Decisiones** |
| Evidencia export + verify | ledger; `sak-verify --self-test`; export ABI aún N/D | `obs.evidencia.exportar` (paquete local) + `obs.evidencia.verificar` (in-process o spawn `sak-verify`); permitir Merkle/digests; **prohibir material de clave** | `obs.evidencia.exportar`, `obs.evidencia.verificar` | Export sin material clave; verify `ok` + `no_comprobado` listado | **Panel Evidencia** |
| Expediente | `m11_expediente`, constructor expediente, verify M11 | `obs.expediente.get` sobre expediente de demo seed | `obs.expediente.get` | 12 partes; sin veredicto; `NO_AFIRMADO` visible si aplica | **Panel Expediente** |

**Fuera de MVP-OBSERVAR:** `obs.diagnostico.decidir` / `ejercer` (pueden esperar a una entrega siguiente).

**Seed de demostración (requerido para “ver algo”):** fixture local en proceso Kernel de demo (pasaporte mínimo, hechos Libro, 2–3 decisiones, paquete evidencia/expediente) — **sin** red, **sin** secretos exportables.

### 9.2 MVP-CONECTAR — prioridad 2

| Flujo | Dependencias disponibles | Cambio mínimo | Mensajes IPC | Pruebas | Pantalla |
|---|---|---|---|---|---|
| Alta sistema | registro / pasaporte en `sak-core` (bloque4) | IPC `con.sistema.alta` con firma responsable | `con.sistema.alta` | Alta → id; sin firma → DENY | **Alta de sistema** |
| Pasaporte | emisión/consulta pasaporte | `con.pasaporte.emitir` / `.get` | idem | Get tras alta muestra versión firmada | **Pasaporte** |
| Vista PEPs | PEPs en lib + tests bloque6+ | Solo **lectura/config declarativa** mínima: listar mapa clase→PEP del seed; configurar sin credenciales | `con.pep.configurar` (declarativo) + vista lectura | DENY si petición incluye API key en claro | **PEPs (vista)** |

### 9.3 MVP-CUSTODIAR — prioridad 3

| Flujo | Dependencias | Cambio mínimo | Mensajes IPC | Pruebas | Pantalla |
|---|---|---|---|---|---|
| Alta referencia | `BrokerCredenciales` / handles conceptuales | Alta **solo** por handle/ref; API que rechace campos de material | `cus.alta_referencia` | DENY si body trae PEM/raw | **Custodia — referencias** |
| Estado | `tiene_raiz_encapsulada` / metadatos | `cus.estado` sin bytes | `cus.estado` | Respuesta sin material | misma |
| **Excluido 1ª entrega** | rotación | — | `cus.rotar` | — | — |

### 9.4 MVP-GOBERNAR — prioridad 4 (recorte explícito)

| Flujo | Dependencias | Cambio mínimo | Mensajes IPC | Pruebas | Pantalla |
|---|---|---|---|---|---|
| Propuesta | `GobernanzaCorpus::proponer` | IPC propuesta + hash | `gob.proponer` | Hash estable; vista canónica del borrador | **Gobernanza — propuesta** |
| Diff | `DiffDecisiones` / conformidad | IPC diff | `gob.diff_conformidad` | Diff visible tras propuesta vs activo de demo | **Gobernanza — diff** |
| Firma humana | firmas paquete / reconocimiento | IPC firma sobre digest **con** UI canónica digest+objeto (anti-engaño, aunque aún no active) | `gob.doble_firma` *o* reconocimiento parcial acordado solo como **registro de firma**, sin transición a activo | Firma verifica; **no** cambia paquete activo | **Gobernanza — firmar** |
| **Excluido 1ª entrega** | sombra, activación época, revocación, rotación custodia | — | `gob.activar_epoca`, `gob.revocar`, `cus.rotar`, … | — | — |

---

## 10. Orden de entrega recomendado

1. **MVP-OBSERVAR** + seed demo + consola mínima de solo lectura (Estado, Libro, Decisiones, Evidencia, Expediente, Límites).  
2. **MVP-CONECTAR** (alta + pasaporte + vista PEPs).  
3. **MVP-CUSTODIAR** (referencias/handles).  
4. **MVP-GOBERNAR** recortado (propuesta + diff + firma sin activar).

Criterio de éxito de la primera entrega: el dueño abre la consola local, ve estado/salud, matriz del Libro, decisiones ALLOW/DENY, exporta/verifica evidencia con límites `no_comprobado` visibles, y abre un expediente — **sin** red, **sin** material de clave exportable, **sin** elevar Libro ni emitir capacidades desde la UI.
