# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1r4

**Estado:** BORRADOR para revisión humana adversarial · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** · **D6 BLOQUEADO**  
**Precede:** `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r3.md` (borrador de revisión; no vigente).  
**Destino propuesto:** Anexo EfectoTipado de la Matriz Maestra Canónica v1.1 + enmienda fundacional que crea G.ET.  
**Objetivo:** cerrar H.1↔H.5 **sin circularidad** entre esquema de parámetros, `clase_solicitada` y `clase_aplicada`.  
**Fecha de redacción:** 2026-07-30.  
**Nota:** No iniciar enmienda fundacional ni implementación a partir de este texto.

### Convención tipográfica

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación. **No** afirma que G.5 cubra este artefacto. |

---

## Cambios respecto de v1r3

| # | Tema | Cambio en v1r4 |
|---|---|---|
| 1 | Circularidad esquema↔clase | `clase_solicitada` selecciona el esquema de **ese** objeto; no autoriza reclasificar a otra EF sin evidencia tipada completa de esa otra. Motor no inventa parámetros ni interpreta opacos para completar reclasificación. |
| 2 | Efecto vs consecuencia | EF-1 no se convierte retrospectivamente en EF-8. Consumo decisional exige **EfectoTipado EF-8 separado** con sus obligatorios; enlace opcional por digest de procedencia. |
| 3 | Múltiples consecuencias | Un EfectoTipado = una clase material (salvo EF-4). Objetos separados para efectos distintos. EF-4 solo agrega hijos completos. Consecuencia conocida sin objeto tipado ⇒ DENY. META/HECHO contradictorio sin objetos ⇒ DENY. |
| 4 | Cierre EF-4 | Anti-anidamiento por clase solicitada **y** aplicada/candidata (incl. META/HECHO); si aparece EF-4 en hijo ⇒ DENY. |
| 5 | Terminología `clase_aplicada` | No es reclasificación libre; es validación de evidencia tipada ya presente por cada clase material aplicable. |
| 6 | Vectores | EF-1 solo; EF-1 sin EF-8 al consumir; EF-1+EF-8 ligados; hijo “EF-1” que es/contiene EF-4 por META/HECHO; consecuencia META/HECHO sin objeto tipado. |

---

## 0. Motivación y alcance

**[LITERAL]** H.1: efecto tipado con clase y parámetros; no lenguaje natural; bien formado; clase ∈ doce; `DENY(EFECTO_NO_TIPIFICADO)`.  
**[LITERAL]** H.5: deriva clase y atributos; ambigüedad ⇒ más restrictiva; Motor de decisión.  
**[LITERAL]** §C precisión EF-8: mediación en el **consumo**, no en la inferencia.  
**[LITERAL]** §E Motor: no completar huecos por inferencia; sin reloj/red/disco. INV-14.  
**[LITERAL]** H.2 identidad por artefacto; H.6 hechos firmados; §C EF-12 DENY / gobernanza humana.

**[PROPUESTA]** v1r4 corrige la circularidad de v1r3: no se tipifica un objeto con esquema de la clase A para que H.5 lo «convierta» en clase B sin los parámetros obligatorios de B.

**[PROPUESTA]** **D6 bloqueado.** No fundacional ni implementación desde v1r4.

---

## 1. Objeto canónico y anti-circularidad

### 1.1 Definición de EfectoTipado

**[LITERAL]** «Efecto tipado con clase y parámetros» (H.1).

**[PROPUESTA]** Cada **EfectoTipado** representa **exactamente una clase de efecto material**, salvo el caso compuesto **EF-4** (§3, §6.1). Consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` / `esquema_version` | id + u32 | sí | Contrato EfectoTipado |
| `clase_solicitada` | enum EF-1…EF-12 | sí | Selecciona el **esquema de parámetros de esa clase** para **este** objeto (§1.2) |
| `parametros` | objeto del esquema de `clase_solicitada` | sí | Obligatorios/opcionales/prohibidos de **esa** fila §3 |
| `digest_parametros` | SHA-384 dominio | sí | Inmoviliza `parametros` |
| `ref_procedencia` | BytesDigest opc. | no | Enlace a otro EfectoTipado (p. ej. EF-1→EF-8); no sustituye parámetros |

**[PROPUESTA]** Identidad del solicitante fuera del objeto (H.2). `clase_declarada` retirada.

### 1.2 `clase_solicitada` selecciona esquema — no reclasifica sola

**[PROPUESTA]**

1. `clase_solicitada` **elige el esquema cerrado** con el que se valida `parametros` de **este** objeto.  
2. **No** permite, por sí sola, que H.5 declare `clase_aplicada` = otra EF **careciendo** de la evidencia tipada (parámetros obligatorios + META/HECHO aplicables) de esa otra clase.  
3. El Motor **no inventa** parámetros de la otra clase, **no interpreta** payloads/digests opacos para completarlos, y **no acepta** campos no previstos en el esquema de `clase_solicitada` «solo para reclasificar».  
4. Si META/HECHO o la realidad operativa exigen **otra** clase material, debe existir un **EfectoTipado separado** (u hijo EF-4 completo) ya tipado bajo el esquema de esa clase (§1.6, §2).

### 1.3 `clase_aplicada` — terminología corregida

**[LITERAL]** H.5 evidencia «Clase y atributos aplicados».

**[PROPUESTA]** `clase_aplicada` **no** es una «reclasificación libre» de una solicitud cuyos parámetros son ajenos a la clase destino.

Es el resultado de **validar un objeto que ya contiene evidencia tipada suficiente** para la clase material que ese objeto representa:

- Para un objeto simple: tras V1–V5, si los parámetros del esquema de `clase_solicitada` son válidos y no hay META/HECHO que exija **otra** clase material sin objeto tipado adicional, entonces `clase_aplicada = clase_solicitada` (más atributos H.5 derivados).  
- La **ausencia** de evidencia tipada de otra clase **nunca** se rellena desde texto, payload, digest solo, ni inferencia del Motor.  
- Si hay conflicto (META/HECHO indica otra consecuencia) **sin** el objeto tipado completo de esa consecuencia ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (§2).

### 1.4 Digest y no lenguaje natural

**[LITERAL]** H.1 no NL; digests en cadena.  
**[PROPUESTA]** Digest vincula e inmoviliza; no aporta semántica H.5 solo. Payloads solo opacos. Cambiar clasificación/política ⇒ campo tipado, META o HECHO tipificados — nunca relleno por inferencia.

### 1.5 Tiempo determinista

**[LITERAL]** INV-14 / §E sin reloj.  
**[PROPUESTA]** Vigencia META/HECHO vs `epoca_contexto` inyectada y citada en evidencia.

### 1.6 Efecto y consecuencia adicional (separación)

**[LITERAL]** §C: EF-8 se media en el **consumo**, no donde se calcula; EF-1 es inferencia.

**[PROPUESTA]**

1. Una inferencia tipificada como **EF-1** **no** se convierte retrospectivamente en **EF-8** usando solo la solicitud EF-1.  
2. Si el resultado puede/debe **consumirse** para una decisión sobre personas, se exige un **EfectoTipado EF-8 separado** en el punto de consumo, con obligatorios propios: `tipo_decision`, `canal_consumo`, `artefacto_autoridad_consumo`, `sujeto_afectado_clase`, `decide_sobre_personas=SI` (y demás de la fila EF-8).  
3. Ambos objetos pueden ligarse por `ref_procedencia` / digest del EF-1 (o del resultado), pero **conservan** parámetros, evaluación H.5, mínimos de garantía y evidencia **propios**.  
4. Presentar solo EF-1 cuando el PEP **conoce** que habrá consumo decisional tipificable como EF-8, **sin** presentar el objeto EF-8 ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

---

## 2. Mecanismo de múltiples consecuencias (v1r4)

**[PROPUESTA — opción preferida]**

| Regla | Contenido |
|---|---|
| R-MC1 | Un EfectoTipado = **exactamente una** clase material, **salvo** EF-4 compuesto. |
| R-MC2 | Efectos materialmente distintos ⇒ **objetos EfectoTipado separados**, cada uno tipado bajo su esquema. |
| R-MC3 | EF-4 **solo agrega** hijos **completos**; no sustituye ni inventa parámetros de los hijos. |
| R-MC4 | Si el PEP conoce una consecuencia adicional y **no** presenta su objeto tipado completo ⇒ `DENY(EFECTO_NO_TIPIFICADO)`. |
| R-MC5 | Si META/HECHO válido **contradice** una única `clase_solicitada` (señala otra clase material): se **conserva el conflicto** en evidencia; se aplica composición **solo** si existen **todos** los objetos tipados necesarios para cada clase material; si falta alguno ⇒ `DENY(EFECTO_NO_TIPIFICADO)`. |
| R-MC6 | Cada EF que figure como `clase_aplicada` de un objeto (o como clase de un hijo) dispone de **todos** sus parámetros obligatorios **en ese objeto**, sin inferencia del Motor. |

**[PROPUESTA]** No se adopta en v1r4 un modelo de «una solicitud, varias clases aplicadas» sobre un solo blob de parámetros de otra clase.

---

## 3. Validación (orden)

**[LITERAL]** H.1 bien formado; H.5 atributos; Motor sin inferir huecos.

**[PROPUESTA]**

| # | Comprobación | Fallo |
|---|---|---|
| V1 | Versión de esquema usable | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_solicitada` ∈ doce | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | `parametros` conforme al esquema de **`clase_solicitada`** (no de otra) | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | Digest + objeto canónico; sin campos ajenos al esquema | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | Regla no-NL §1.4 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | Si EF-4: hijos completos + cierre anti-EF-4 §6.1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V7 | META/HECHO / `epoca_contexto`; conflicto ⇒ §2 R-MC5 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V8 | H.5: `clase_aplicada` = clase material de **este** objeto (o DENY); atributos | según §1.3 |
| V9 | EF-12 ⇒ registro + DENY autorización; sin capacidad (§6.4) | DENY |

**[PROPUESTA]** «Bien formado» = V1–V5 para el objeto; no autoriza otras clases sin objetos tipados adicionales.

---

## 4. Parámetros por clase (resumen contractual)

**[LITERAL]** §C ejemplos/mínimos.  
**[PROPUESTA]** Filas como en v1r3 (EF-1…EF-12), con estas precisiones v1r4:

- El esquema validado es **siempre** el de `clase_solicitada` del objeto.  
- EF-8: obligatorios de consumo en el **objeto EF-8**, no inherentes a un EF-1.  
- EF-4: `efectos_hijos` = lista de EfectoTipado completos (o refs recuperables); cada hijo con su propia `clase_solicitada` y parámetros.  
- Digests opacos (`entrada_digest`, `cuerpo_digest`, etc.) no tipifican otra EF.  
- EF-12: solo taxonomía de intento (§6.4).  
- META de catálogo y HECHO: contrato mínimo v1r3 («como mínimo» + campos de catálogo); vigencia vs `epoca_contexto`.

*(Detalle campo-a-campo de EF-1…EF-11: el de v1r3, incorporado por referencia de borrador; v1r4 no lo reedita salvo lo anterior.)*

---

## 5. Atributos H.5 y composición

**[LITERAL]** H.5 cinco atributos; más restrictiva sin orden total EF en Matriz.

**[PROPUESTA]**

1. Por cada **objeto** tipificado: derivar los cinco atributos desde **sus** parámetros + META/HECHO aplicables a **ese** objeto (`HECHO` > `META` > `PEP` > `REGLA`).  
2. Composición de **mínimos/obligaciones** entre varios objetos de una misma solicitud compuesta (p. ej. padre EF-4 + hijos, o EF-1 + EF-8 ligados): conjunción sobre los objetos presentados; no fusionar parámetros.  
3. «Más restrictiva» = conjunción / tratamientos conservadores de `DESCONOCIDO` / DENY si falta objeto tipado — **no** reclasificar un esquema ajeno.

---

## 6. Reglas específicas

### 6.1 EF-4 — cierre de anidamiento (corregido)

**[LITERAL]** §C herramientas / producen otras clases.

**[PROPUESTA]**

1. Hijos completos; parámetros propios; no sustituibles por nombres de clase.  
2. La prohibición de anidamiento **no** mira solo `clase_solicitada=EF-4` del hijo.  
3. Se valida que **ningún hijo**:  
   - tenga `clase_solicitada=EF-4`, **ni**  
   - tenga `clase_aplicada` o candidata material **EF-4**, **ni**  
   - **contenga** (tras META/HECHO válidos) una clase aplicada/candidata EF-4.  
4. Si META/HECHO introduce EF-4 sobre un hijo (o lo reclasificaría a EF-4) ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (no se «promueve» el hijo a EF-4 anidado).  
5. Digests visitados; ciclo ⇒ DENY; profundidad de herramientas = 1.

### 6.2 EF-8

**[LITERAL]** Consumo, no inferencia.  
**[PROPUESTA]** Solo sobre objeto EF-8 con obligatorios de §1.6; nunca como reclasificación de EF-1.

### 6.3 EF-9

**[LITERAL]** Eliminar/confinar; INV-11.  
**[PROPUESTA]** No reclasificar desde otro esquema por inferencia.

### 6.4 EF-12

**[LITERAL]** DENY; gobernanza humana doble firma.  
**[PROPUESTA]** Taxonomía de intento; no interfaz H.1–H.16; ninguna capacidad EF-12; petición H.1 ⇒ registro + DENY (IA o humano); gobierno humano fuera de H.

---

## 7. Historia y citas

**[LITERAL]** INV-14.  
**[PROPUESTA]** Citar por cada objeto: esquema, digests, `clase_solicitada`, `clase_aplicada`, `ref_procedencia` si existe, META (catálogo ids/digests), HECHO, `epoca_contexto`. Recomputación bit a bit con los mismos objetos.

---

## 8. Gobernanza

**[LITERAL]** G.5 ≠ este artefacto.  
**[PROPUESTA]** Fundacional 8.A crea G.ET; D6 bloqueado. **No iniciar desde v1r4.**

---

## 9. No automatizable

**[LITERAL]** INV-16.  
**[PROPUESTA]** Aprobar esquemas; decidir cuándo una consecuencia «conocida» obliga objeto tipado adicional en política operativa de PEPs; catálogos; fundacional; gobierno; composición no escrita.

---

## 10. Vectores de conformidad (v1r4 + heredados)

**[PROPUESTA]**

| Caso | Esperado |
|---|---|
| **EF-1 válido sin EF-8 adicional** | Tipificable **solo** como EF-1; `clase_aplicada=EF-1` |
| **EF-1** cuyo resultado se quiere consumir para decidir, **sin** objeto EF-8 | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-1 + EF-8** separados, ambos completos, ligados por digest | Ambos tipificables; H.5/mínimos/evidencia **por separado** |
| Intento de reclasificar EF-1→EF-8 inventando campos EF-8 en el blob EF-1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| Hijo con `clase_solicitada=EF-1` pero META/HECHO lo hace candidato/`clase_aplicada` **EF-4** | `DENY(EFECTO_NO_TIPIFICADO)` |
| META/HECHO indica consecuencia adicional **sin** objeto tipado completo | `DENY(EFECTO_NO_TIPIFICADO)`; conflicto conservado en evidencia |
| EF-4 con hijo EF-4 (solicitada o aplicada/candidata) | `DENY(EFECTO_NO_TIPIFICADO)` |
| Ciclo / profundidad >1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-12 por H.1 (IA o humano) | Registro + DENY; sin capacidad |
| META catálogo no aprobado / digest o vigencia vs `epoca_contexto` | `DENY(EFECTO_NO_TIPIFICADO)` si tipificación dependía |
| Payload opaco interpretado para reclasificar | `DENY(EFECTO_NO_TIPIFICADO)` |
| Recomputación misma época + mismos objetos | Igual bit a bit |

---

## 11. Criterio de cierre

**[PROPUESTA]** Solo tras fundacional, tabla operativa, vectores verdes, y no-D6 previo. **v1r4 no autoriza el inicio.**

---

## Apéndice A — Circularidad cerrada

| Antipatron (v1r3 riesgoso) | Cierre v1r4 |
|---|---|
| Esquema de A + H.5 ⇒ clase B | Prohibido sin objeto tipado B |
| EF-1 «es» EF-8 por intención | EF-8 separado en consumo |
| Una solicitud, N clases sin N esquemas | N objetos (o hijos EF-4 completos) |
| Anti-EF-4 solo por solicitada | También aplicada/candidata/META/HECHO |

---

NO VIGENTE · NO APROBADO · NO IMPLEMENTABLE · D6 BLOQUEADO
