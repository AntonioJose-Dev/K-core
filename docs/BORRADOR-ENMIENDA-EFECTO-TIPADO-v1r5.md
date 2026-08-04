# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1r5

**Estado:** BORRADOR · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** · **D6 BLOQUEADO**  
**Precede:** `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r4.md`  
**Corrige únicamente:** hallazgos bloqueantes **B1, B2, B3** de la revisión adversarial de v1r4.  
**Destino propuesto:** Anexo EfectoTipado de la Matriz Maestra Canónica v1.1 + enmienda fundacional que crea G.ET.  
**Fecha de redacción:** 2026-07-30.  
**Nota:** No iniciar enmienda fundacional ni implementación a partir de este texto.

### Convención tipográfica

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación. **No** afirma que G.5 cubra este artefacto. |

---

## Diff por sección (v1r4 → v1r5) — solo B1/B2/B3

| Sección | Cambio | Hallazgo |
|---|---|---|
| §1.3 | El DENY por «otra clase» exige señal tipada **S-MC5** (§2.1), no interpretación | B2 |
| §1.6.4 | Eliminado DENY Motor por «PEP conoce»; deber operativo externo (§9) | B1 |
| §2 R-MC4 | Ya no produce DENY en el Motor; obligación externa | B1 |
| §2 R-MC5 + **§2.1 nuevo** | Señal **S-MC5** cerrada, tipada, determinista | B2 |
| §3 V7 | Remite a S-MC5 / R-MC5 reformulado | B2 |
| §4 | Tablas de parámetros **autocontenidas**; exclusión expresa de reglas de clasificación de v1r3 | B3 |
| §6.1.4 | «Introduce EF-4» = S-MC5 con `valor=EF-4` (u homólogo tipado) sobre el hijo | B2 (alineación) |
| §9 | Aclara deber PEP externo vs Motor | B1 |
| §10 | Vectores B1–B3 nuevos/modificados | B1–B3 |
| Apéndice B | Tabla de no-regresión EF-4 / EF-12 / D6 | — |

**Sin cambio de sustancia** respecto de v1r4 en: §0 (salvo mención v1r5), §1.1–§1.2, §1.4–§1.5, §1.6.1–§1.6.3, R-MC1–R-MC3, R-MC6, §5, §6.2–§6.4, §7–§8, §11, Apéndice A (circularidad).

---

## Cambios respecto de v1r4 (resumen)

| # | Tema |
|---|---|
| B1 | Motor sin condición «PEP conoce»; DENY solo por señal tipada de entrada |
| B2 | **S-MC5** define de forma cerrada cuándo R-MC5 dispara DENY |
| B3 | Filas de parámetros en este documento; v1r3 no aporta reglas de clasificación |

---

## 0. Motivación y alcance

**[LITERAL]** H.1: efecto tipado con clase y parámetros; no lenguaje natural; bien formado; clase ∈ doce; `DENY(EFECTO_NO_TIPIFICADO)`.  
**[LITERAL]** H.5: deriva clase y atributos; ambigüedad ⇒ más restrictiva; Motor de decisión.  
**[LITERAL]** §C precisión EF-8: mediación en el **consumo**, no en la inferencia.  
**[LITERAL]** §E Motor: no completar huecos por inferencia; sin reloj/red/disco. INV-14.  
**[LITERAL]** H.2 identidad por artefacto; H.6 hechos firmados; §C EF-12 DENY / gobernanza humana.

**[PROPUESTA]** v1r5 mantiene el cierre de circularidad de v1r4 y corrige B1–B3.

**[PROPUESTA]** **D6 bloqueado.** No fundacional ni implementación desde v1r5.

---

## 1. Objeto canónico y anti-circularidad

### 1.1 Definición de EfectoTipado

**[LITERAL]** «Efecto tipado con clase y parámetros» (H.1).

**[PROPUESTA]** Cada **EfectoTipado** representa **exactamente una clase de efecto material**, salvo el caso compuesto **EF-4** (§4, §6.1). Consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` / `esquema_version` | id + u32 | sí | Contrato EfectoTipado |
| `clase_solicitada` | enum EF-1…EF-12 | sí | Selecciona el **esquema de parámetros de esa clase** para **este** objeto (§1.2) |
| `parametros` | objeto del esquema de `clase_solicitada` | sí | Obligatorios/opcionales/prohibidos de **esa** fila §4 |
| `digest_parametros` | SHA-384 dominio | sí | Inmoviliza `parametros` |
| `ref_procedencia` | BytesDigest opc. | no | Enlace a otro EfectoTipado (p. ej. EF-1→EF-8); no sustituye parámetros |

**[PROPUESTA]** Identidad del solicitante fuera del objeto (H.2). `clase_declarada` retirada.

### 1.2 `clase_solicitada` selecciona esquema — no reclasifica sola

**[PROPUESTA]**

1. `clase_solicitada` **elige el esquema cerrado** con el que se valida `parametros` de **este** objeto.  
2. **No** permite, por sí sola, que H.5 declare `clase_aplicada` = otra EF **careciendo** de un objeto tipado completo bajo el esquema de esa otra clase.  
3. El Motor **no inventa** parámetros de la otra clase, **no interpreta** payloads/digests opacos para completarlos, y **no acepta** campos no previstos en el esquema de `clase_solicitada` «solo para reclasificar».  
4. Si una señal tipada **S-MC5** (§2.1) exige otra clase material, debe existir un **EfectoTipado separado** (u hijo EF-4 completo) ya tipado bajo el esquema de esa clase; si no ⇒ R-MC5.

### 1.3 `clase_aplicada` — terminología corregida

**[LITERAL]** H.5 evidencia «Clase y atributos aplicados».

**[PROPUESTA]** `clase_aplicada` **no** es una «reclasificación libre» de una solicitud cuyos parámetros son ajenos a la clase destino.

Es el resultado de **validar un objeto que ya contiene evidencia tipada suficiente** para la clase material que ese objeto representa:

- Para un objeto simple: tras V1–V5, si los parámetros del esquema de `clase_solicitada` son válidos y **no** se cumple S-MC5 sin objeto tipado adicional (§2.1), entonces `clase_aplicada = clase_solicitada` (más atributos H.5 derivados).  
- La **ausencia** de evidencia tipada de otra clase **nunca** se rellena desde texto, payload, digest solo, ni inferencia del Motor.  
- Si se cumple **S-MC5** y falta el objeto tipado completo de la clase señalada ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (R-MC5).

### 1.4 Digest y no lenguaje natural

**[LITERAL]** H.1 no NL; digests en cadena.  
**[PROPUESTA]** Digest vincula e inmoviliza; no aporta semántica H.5 solo. Payloads solo opacos. Cambiar clasificación/política ⇒ campo tipado, META o HECHO **con atributos tipificados del contrato** — nunca relleno por inferencia. META/HECHO/digest/payload/extensión **no tipificada** no activa S-MC5 ni completa parámetros (§2.1).

### 1.5 Tiempo determinista

**[LITERAL]** INV-14 / §E sin reloj.  
**[PROPUESTA]** Vigencia META/HECHO vs `epoca_contexto` inyectada y citada en evidencia.

### 1.6 Efecto y consecuencia adicional (separación)

**[LITERAL]** §C: EF-8 se media en el **consumo**, no donde se calcula; EF-1 es inferencia.

**[PROPUESTA]**

1. Una inferencia tipificada como **EF-1** **no** se convierte retrospectivamente en **EF-8** usando solo la solicitud EF-1.  
2. Si el resultado puede/debe **consumirse** para una decisión sobre personas, se exige un **EfectoTipado EF-8 separado** en el punto de consumo, con obligatorios propios: `tipo_decision`, `canal_consumo`, `artefacto_autoridad_consumo`, `sujeto_afectado_clase`, `decide_sobre_personas=SI` (y demás de la fila EF-8 §4).  
3. Ambos objetos pueden ligarse por `ref_procedencia` / digest del EF-1 (o del resultado), pero **conservan** parámetros, evaluación H.5, mínimos de garantía y evidencia **propios**.  
4. **(B1)** El Motor **no** deniega por el hecho de que el PEP «conozca» o «quiera» un consumo EF-8 no presentado. Si subsiste un deber de presentar el objeto EF-8 en ciertos despliegues, es **obligación operativa externa** del PEP (§9), **fuera** de H.5. El DENY del Motor por consecuencia adicional **solo** procede ante **S-MC5** (§2.1) sin objeto tipado completo.

---

## 2. Mecanismo de múltiples consecuencias

**[PROPUESTA — opción preferida, con B1/B2]**

| Regla | Contenido |
|---|---|
| R-MC1 | Un EfectoTipado = **exactamente una** clase material, **salvo** EF-4 compuesto. |
| R-MC2 | Efectos materialmente distintos ⇒ **objetos EfectoTipado separados**, cada uno tipado bajo su esquema. |
| R-MC3 | EF-4 **solo agrega** hijos **completos**; no sustituye ni inventa parámetros de los hijos. |
| R-MC4 | **(B1)** Obligación operativa **externa** (PEP/despliegue): presentar objetos tipados de consecuencias materiales adicionales cuando la política operativa del punto de aplicación lo exija. **No** es condición del Motor. **No** produce por sí sola `DENY(EFECTO_NO_TIPIFICADO)`. |
| R-MC5 | **(B2)** Si y solo si se cumple la señal tipada **S-MC5** (§2.1) y **falta** el objeto tipado completo de cada `ClaseEfecto` señalada: se **conserva el conflicto** en evidencia y el Motor produce `DENY(EFECTO_NO_TIPIFICADO)`. Si S-MC5 se cumple y **existen** todos los objetos tipados necesarios, se evalúa cada objeto por separado (conjunción de mínimos entre objetos presentados, sin fusionar parámetros). |
| R-MC6 | Cada EF que figure como `clase_aplicada` de un objeto (o como clase de un hijo) dispone de **todos** sus parámetros obligatorios **en ese objeto**, sin inferencia del Motor. |

**[PROPUESTA]** No se adopta un modelo de «una solicitud, varias clases aplicadas» sobre un solo blob de parámetros de otra clase.

### 2.1 Señal tipada S-MC5 (cerrada, determinista) — B2

**[PROPUESTA]** **S-MC5** se cumple **si y solo si** existe al menos un registro **META** o **HECHO** que, **conjuntamente**, satisfaga **todas** las condiciones siguientes (evaluación pura sobre entradas tipadas + `epoca_contexto`):

| # | Condición |
|---|---|
| S1 | El registro es usable en H.5: firma válida, `productor_id` registrado, no caducado vs `epoca_contexto`, `ambito_recurso` aplicable al objeto bajo evaluación, `digest_objeto` vinculado a ese objeto (contrato §4.M). |
| S2 | Si es META: procede de catálogo aprobado (`catalogo_id`, `catalogo_version`, `autoridad_emisora`, `digest_catalogo` vigentes vs `epoca_contexto`). |
| S3 | `atributo` es **exactamente** el token cerrado `clase_material_adicional_requerida` (único token admitido para S-MC5 en v1r5). |
| S4 | `valor` es **exactamente** un literal de `ClaseEfecto` ∈ {`EF-1`,…,`EF-12`} (codificación canónica del esquema). |
| S5 | Ese `valor` es **≠** `clase_solicitada` del objeto bajo evaluación. |
| S6 | En el **conjunto de objetos tipados presentados** a esta evaluación (padre, hermanos, hijos EF-4 recuperables, objetos ligados por `ref_procedencia` incluidos en el lote) **no** existe ningún EfectoTipado con `clase_solicitada = valor` (S4) que haya pasado V1–V5 bajo el esquema de esa clase. |

**[PROPUESTA]** **No** activan S-MC5 ni completan parámetros:

- digest o payload opaco;  
- extensión META/HECHO no tipificada;  
- cualquier `atributo` distinto de `clase_material_adicional_requerida`;  
- `valor` no parseable como `ClaseEfecto` canónico;  
- interpretación de texto, intención o conocimiento del PEP;  
- inferencia del Motor.

**[PROPUESTA]** Ampliar el conjunto de tokens `atributo` que disparan S-MC5 exige **nueva versión** del esquema (G.ET / fundacional), no interpretación en ejecución.

---

## 3. Validación (orden)

**[LITERAL]** H.1 bien formado; H.5 atributos; Motor sin inferir huecos.

**[PROPUESTA]**

| # | Comprobación | Fallo |
|---|---|---|
| V1 | Versión de esquema usable | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_solicitada` ∈ doce | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | `parametros` conforme al esquema de **`clase_solicitada`** (§4) | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | Digest + objeto canónico; sin campos ajenos al esquema | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | Regla no-NL §1.4 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | Si EF-4: hijos completos + cierre anti-EF-4 §6.1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V7 | META/HECHO / `epoca_contexto`; **S-MC5** ⇒ R-MC5 | `DENY(EFECTO_NO_TIPIFICADO)` si S-MC5 ∧ falta objeto |
| V8 | H.5: `clase_aplicada` = clase material de **este** objeto; atributos | según §1.3 |
| V9 | EF-12 ⇒ registro + DENY autorización; sin capacidad (§6.4) | DENY |

**[PROPUESTA]** «Bien formado» = V1–V5 para el objeto; no autoriza otras clases sin objetos tipados adicionales.

---

## 4. Parámetros por clase (autocontenidos) — B3

**[LITERAL]** §C ejemplos/mínimos.  

**[PROPUESTA — B3]** Las tablas de **campos** de este §4 son **autocontenidas**.  

**Exclusión expresa:** cualquier referencia a `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r3.md` (u otra revisión) **no** incorpora reglas de **clasificación**, **composición**, **candidatas**, **reclasificación**, `clase_aplicada` ≠ `clase_solicitada` sobre un solo blob, ni §1.5/§5 de v1r3. Solo este v1r5 (§1–§2, §5–§6) gobierna esas materias.

**Precisiones (heredadas v1r4, inalteradas en sustancia):** esquema validado = el de `clase_solicitada`; EF-8 solo en objeto EF-8; EF-4 = hijos completos; digests opacos no tipifican otra EF; EF-12 = taxonomía de intento.

### Tipos compartidos

| Tipo | Semántica **[PROPUESTA]** |
|---|---|
| `Tri` | SI \| NO \| DESCONOCIDO — DESCONOCIDO nunca como NO permisivo |
| `Reversibilidad` | REVERSIBLE \| IRREVERSIBLE \| DESCONOCIDO |
| `DestinatarioClase` | NINGUNO \| SISTEMA \| PERSONA_IDENTIFICADA \| PERSONA_NO_IDENTIFICADA \| PUBLICO \| DESCONOCIDO |
| `ClaseEfecto` | EF-1…EF-12 |
| `RefEfectoHijo` | EfectoTipado embebido o `{ digest_efecto, esquema_version }` recuperable |
| `BytesDigest` | Contenido de negocio opaco |
| `Epoca` | Entero de época |

Leyenda: **Obl** / **Opc** / **Proh**. `[NINGUNO]` solo donde la fila lo permita.

### EF-1 — Inferencia

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `modo` | Obl | Enum |
| `destino_modelo` | Obl | Uri\|Id |
| `contiene_datos_personales` | Obl | Tri |
| `categoria_especial` | Opc | Tri |
| `destinatarios` | Obl | Lista (`[NINGUNO]` si aún no hay entrega) |
| `decide_sobre_personas` | Obl | Tri |
| `entrada_digest` | Opc | BytesDigest |
| `codigo_arbitrario` | Proh | — |
| `texto_intencion` | Proh | — |

### EF-2 — Acceso a datos

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `operacion` | Obl | Enum |
| `recurso` | Obl | Id |
| `contiene_datos_personales` | Obl | Tri |
| `categoria_especial` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `volumen_max` | Opc | u64 |
| `escritura` | Proh | — |
| `texto_intencion` | Proh | — |

### EF-3 — Escritura

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `operacion` | Obl | Enum |
| `objetivo` | Obl | Id |
| `reversibilidad` | Obl | Reversibilidad |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `payload_digest` | Opc | BytesDigest |
| `codigo_arbitrario` | Proh | — |
| `texto_intencion` | Proh | — |

### EF-4 — Herramientas

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `herramienta_id` | Obl | Id |
| `efectos_hijos` | Obl | Lista[`RefEfectoHijo`] no vacía |
| `argumentos_digest` | Obl | BytesDigest |
| `invocacion_directa_no_mediada` | Proh | — |
| `texto_intencion` | Proh | — |
| `clases_producidas` (solo nombres) | Proh | — |
| Hijo EF-4 | Proh | — §6.1 |

### EF-5 — Operación de negocio

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `tipo_operacion` | Obl | Enum |
| `contraparte` | Obl | Id |
| `importe_digest` | Opc | BytesDigest |
| `reversibilidad` | Obl | Reversibilidad |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `texto_intencion` | Proh | — |

### EF-6 — Comunicaciones

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `canal` | Obl | Enum |
| `destinatarios` | Obl | Lista (persona; no `[NINGUNO]`) |
| `contiene_datos_personales` | Obl | Tri |
| `decide_sobre_personas` | Obl | Tri (puede ser NO) |
| `reversibilidad` | Obl | Reversibilidad |
| `cuerpo_digest` | Opc | BytesDigest |
| `texto_intencion` | Proh | — |

### EF-7 — Publicación

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `canal_publicacion` | Obl | Id |
| `destinatarios` | Obl | Lista (PUBLICO y/o persona; no `[NINGUNO]`) |
| `contiene_datos_personales` | Obl | Tri |
| `decide_sobre_personas` | Obl | Tri |
| `reversibilidad` | Obl | Reversibilidad |
| `contenido_digest` | Opc | BytesDigest |
| `texto_intencion` | Proh | — |

### EF-8 — Decisión sobre personas

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `tipo_decision` | Obl | Enum |
| `canal_consumo` | Obl | Id |
| `artefacto_autoridad_consumo` | Obl | Id |
| `sujeto_afectado_clase` | Obl | Enum |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri (debe ser SI) |
| `resultado_digest` | Opc | BytesDigest |
| `mediacion_en_inferencia` | Proh | — |
| `texto_intencion` | Proh | — |

### EF-9 — Ejecución de código

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `modo` | Obl | Enum |
| `autoridad_ambiental` | Obl | Tri |
| `superficie_atestada` | Opc | BytesDigest |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `reversibilidad` | Obl | Reversibilidad |
| `artefacto_codigo_digest` | Opc | BytesDigest |
| `capacidad_efector_solicitada` | Proh | — |
| `texto_intencion` | Proh | — |

### EF-10 — Movimiento entre dominios

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `destino_dominio` | Obl | Id\|Uri |
| `jurisdiccion_destino` | Opc | código |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista (no `[NINGUNO]`) |
| `decide_sobre_personas` | Obl | Tri |
| `reversibilidad` | Obl | Reversibilidad |
| `texto_intencion` | Proh | — |

### EF-11 — Físico / ciberfísico

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `actuador_id` | Obl | Id |
| `orden_digest` | Obl | BytesDigest |
| `pep_fisico_presente` | Obl | Tri |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `reversibilidad` | Obl | Reversibilidad |
| `texto_intencion` | Proh | — |

### EF-12 — taxonomía de intento

| Parámetro | Obl/Opc/Proh | Tipo |
|---|---|---|
| `objeto_gobierno` | Obl | Enum |
| `contiene_datos_personales` | Obl | Tri |
| `destinatarios` | Obl | Lista |
| `decide_sobre_personas` | Obl | Tri |
| `reversibilidad` | Obl | Reversibilidad |
| `solicitante_es_ia` | Proh | — |
| Capacidad / ALLOW / ejecución vía H | Proh | — §6.4 |

### 4.M Contrato mínimo META / HECHO (para S-MC5 y atributos)

**[PROPUESTA]** Como mínimo: `productor_id`, `firma`, `emitido_en_epoca`, `expira_en_epoca`, `ambito_recurso`, `atributo`, `valor`, `digest_objeto`.  
META de catálogo, además: `catalogo_id`, `catalogo_version`, `autoridad_emisora`, `digest_catalogo`.  
Extensiones solo si versionadas, canonizadas y tipificadas; no interpretadas salvo tipificación aprobada. No activan S-MC5 salvo S3–S4 (§2.1).

---

## 5. Atributos H.5 y composición

**[LITERAL]** H.5 cinco atributos; más restrictiva sin orden total EF en Matriz.

**[PROPUESTA]**

1. Por cada **objeto** tipificado: derivar los cinco atributos desde **sus** parámetros + META/HECHO aplicables a **ese** objeto (`HECHO` > `META` > `PEP` > `REGLA`), sin usar S-MC5 para inventar campos.  
2. Composición de **mínimos/obligaciones** entre varios objetos presentados (p. ej. padre EF-4 + hijos, o EF-1 + EF-8 ligados): conjunción sobre los objetos presentados; no fusionar parámetros.  
3. «Más restrictiva» = conjunción / tratamientos conservadores de `DESCONOCIDO` / DENY por R-MC5 — **no** reclasificar un esquema ajeno.

---

## 6. Reglas específicas

### 6.1 EF-4 — cierre de anidamiento

**[LITERAL]** §C herramientas / producen otras clases.

**[PROPUESTA]** *(sin cambio de régimen respecto de v1r4; alineación B2)*

1. Hijos completos; parámetros propios; no sustituibles por nombres de clase.  
2. La prohibición de anidamiento **no** mira solo `clase_solicitada=EF-4` del hijo.  
3. Se valida que **ningún hijo**:  
   - tenga `clase_solicitada=EF-4`, **ni**  
   - tenga `clase_aplicada` **EF-4**, **ni**  
   - dispare **S-MC5** con `valor=EF-4` (u otra forma tipada equivalente bajo §2.1) aplicable a ese hijo.  
4. Si S-MC5 / META/HECHO tipado introduce EF-4 sobre un hijo ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (no se promociona a EF-4 anidado).  
5. Digests visitados; ciclo ⇒ DENY; profundidad de herramientas = 1.

### 6.2 EF-8

**[LITERAL]** Consumo, no inferencia.  
**[PROPUESTA]** Solo sobre objeto EF-8 con obligatorios de §1.6 / §4; nunca como reclasificación de EF-1.

### 6.3 EF-9

**[LITERAL]** Eliminar/confinar; INV-11.  
**[PROPUESTA]** No reclasificar desde otro esquema por inferencia.

### 6.4 EF-12

**[LITERAL]** DENY; gobernanza humana doble firma.  
**[PROPUESTA]** Taxonomía de intento; no interfaz H.1–H.16; ninguna capacidad EF-12; petición H.1 ⇒ registro + DENY (IA o humano); gobierno humano fuera de H. **Sin cambio respecto de v1r4.**

---

## 7. Historia y citas

**[LITERAL]** INV-14.  
**[PROPUESTA]** Citar por cada objeto: esquema, digests, `clase_solicitada`, `clase_aplicada`, `ref_procedencia` si existe, META (catálogo ids/digests), HECHO (incl. si hubo S-MC5), `epoca_contexto`. Recomputación bit a bit con los mismos objetos.

---

## 8. Gobernanza

**[LITERAL]** G.5 ≠ este artefacto.  
**[PROPUESTA]** Fundacional 8.A crea G.ET; D6 bloqueado. **No iniciar desde v1r5.** **Sin cambio de bloqueo respecto de v1r4.**

---

## 9. No automatizable

**[LITERAL]** INV-16.  

**[PROPUESTA]** Aprobar esquemas y tokens S-MC5 adicionales; catálogos; fundacional; gobierno; composición de mínimos no escrita.  

**[PROPUESTA — B1]** Si la política de un despliegue exige que el PEP presente un EF-8 (u otra clase) junto a un EF-1 en ciertos casos, esa exigencia es **operativa externa**: su incumplimiento se gestiona fuera del Motor (rechazo en frontera PEP, auditoría, etc.). El Motor **solo** aplica R-MC5 ante **S-MC5**.

---

## 10. Vectores de conformidad

### 10.1 Heredados (v1r4) — ajuste B1 en la fila de «consumo sin EF-8»

| Caso | Esperado |
|---|---|
| **EF-1 válido sin EF-8 y sin S-MC5** | Tipificable **solo** como EF-1; `clase_aplicada=EF-1` |
| **EF-1 + EF-8** separados, ambos completos, ligados por digest | Ambos tipificables; H.5/mínimos/evidencia **por separado** |
| Intento de reclasificar EF-1→EF-8 inventando campos EF-8 en el blob EF-1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-4 con hijo EF-4 (solicitada o aplicada) | `DENY(EFECTO_NO_TIPIFICADO)` |
| Ciclo / profundidad >1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-12 por H.1 (IA o humano) | Registro + DENY; sin capacidad |
| META catálogo no aprobado / digest o vigencia vs `epoca_contexto` | No usable; DENY si tipificación/S-MC5 dependía |
| Payload opaco interpretado para reclasificar | No activa S-MC5; no completa parámetros; tipificación según resto |
| Recomputación misma época + mismos objetos | Igual bit a bit |

### 10.2 Nuevos / modificados por B1–B3

| ID | Caso | Esperado |
|---|---|---|
| **B1-a** | EF-1 válido; operador/PEP «quiere» consumo decisional; **sin** S-MC5 y **sin** objeto EF-8 | Tipificable EF-1 (**no** DENY Motor por conocimiento) |
| **B1-b** | Igual que B1-a + obligación operativa externa incumplida | Fuera de alcance del Motor; no cambia B1-a |
| **B2-a** | EF-1 válido + META/HECHO usable con `atributo=clase_material_adicional_requerida`, `valor=EF-8`, sin objeto EF-8 en el lote | **S-MC5** ⇒ `DENY(EFECTO_NO_TIPIFICADO)`; conflicto en evidencia |
| **B2-b** | Igual B2-a + objeto EF-8 completo en el lote | Tipificables por separado; no DENY por R-MC5 |
| **B2-c** | META con `atributo` distinto / extensión no tipificada / payload que «sugiere» EF-8 | **No** S-MC5; EF-1 tipificable si V1–V5 ok |
| **B2-d** | HECHO con `valor` no canónico como `ClaseEfecto` | **No** S-MC5 |
| **B2-e** | S-MC5 con `valor=EF-4` aplicable a hijo `clase_solicitada=EF-1` | `DENY(EFECTO_NO_TIPIFICADO)` (§6.1) |
| **B3-a** | Lectura de reglas de clasificación solo desde v1r5 §1–§2 | Régimen único; v1r3 §1.5 **no** aplicable |

---

## 11. Criterio de cierre

**[PROPUESTA]** Solo tras fundacional, tabla operativa, vectores verdes, y no-D6 previo. **v1r5 no autoriza el inicio.**

---

## Apéndice A — Circularidad cerrada

| Antipatron | Cierre |
|---|---|
| Esquema de A + H.5 ⇒ clase B | Prohibido sin objeto tipado B |
| EF-1 «es» EF-8 por intención | EF-8 separado; DENY Motor solo vía S-MC5 |
| Una solicitud, N clases sin N esquemas | N objetos (o hijos EF-4 completos) |
| Anti-EF-4 solo por solicitada | También aplicada / S-MC5=`EF-4` |

---

## Apéndice B — No-regresión (EF-4, EF-12, D6)

| Tema | v1r4 | v1r5 | ¿Modificado? |
|---|---|---|---|
| EF-4: hijos completos; profundidad 1; ciclo DENY | §6.1 | §6.1 (misma sustancia; S-MC5 alinea detección META) | No en régimen |
| EF-4 anidado (solicitada/aplicada/META→EF-4) ⇒ DENY | Sí | Sí | No |
| EF-12: taxonomía; DENY H; sin capacidad; gobierno fuera de H | §6.4 | §6.4 | **No** |
| D6 bloqueado; no fundacional desde el borrador | §0, §8, §11 | §0, §8, §11 | **No** |

---

NO VIGENTE · NO APROBADO · NO IMPLEMENTABLE · D6 BLOQUEADO
