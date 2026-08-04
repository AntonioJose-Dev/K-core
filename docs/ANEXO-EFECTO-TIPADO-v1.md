# Anexo EfectoTipado v1

**Identificador:** `ANEXO-EFECTO-TIPADO-v1`  
**Versión:** `1`  
**Destino:** referencia externa canónica de la Matriz Maestra Canónica v1.1, cuando la enmienda fundacional que lo cite esté vigente.  
**Procedencia de sustancia:** contenido normativo del artefacto de redacción `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r5.md` (SHA-384 `752D10C48962153F744650A5CEB920801B4DA880C5F43959D6588F5EBED3647C1675B5A1F8344542A8703121A9D3B120`), aceptado como base por `ACTA-ACEPTACION-BORRADOR-EFECTO-TIPADO-v1r5.md`.  
**Nota de vigencia:** este Anexo **no** entra en vigor por su sola existencia; su vigencia depende de la enmienda fundacional que lo referencie por nombre, ruta, versión y digest. Este texto **no** activa G.ET, **no** habilita tabla operativa y **no** desbloquea D6.

---

## 0. Motivación y alcance

Remisión a la Matriz Maestra Canónica v1.1: H.1 (efecto tipado; no lenguaje natural; bien formado; clase ∈ doce; `DENY(EFECTO_NO_TIPIFICADO)`); H.5 (deriva clase y atributos; ambigüedad ⇒ más restrictiva); §C precisión EF-8 (mediación en el **consumo**, no en la inferencia); §E Motor (no completar huecos por inferencia; sin reloj/red/disco); INV-14; H.2 (identidad por artefacto); H.6 (hechos firmados); §C EF-12 (DENY / gobernanza humana).

Este Anexo define el contrato **EfectoTipado**, el cierre de circularidad de tipificación y las reglas deterministas asociadas.

**D6 permanece bloqueado** hasta cumplirse el criterio de cierre (§11).

---

## 1. Objeto canónico y anti-circularidad

### 1.1 Definición de EfectoTipado

«Efecto tipado con clase y parámetros» (H.1).

Cada **EfectoTipado** representa **exactamente una clase de efecto material**, salvo el caso compuesto **EF-4** (§4, §6.1). Consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` / `esquema_version` | id + u32 | sí | Contrato EfectoTipado |
| `clase_solicitada` | enum EF-1…EF-12 | sí | Selecciona el **esquema de parámetros de esa clase** para **este** objeto (§1.2) |
| `parametros` | objeto del esquema de `clase_solicitada` | sí | Obligatorios/opcionales/prohibidos de **esa** fila §4 |
| `digest_parametros` | SHA-384 dominio | sí | Inmoviliza `parametros` |
| `ref_procedencia` | BytesDigest opc. | no | Enlace a otro EfectoTipado (p. ej. EF-1→EF-8); no sustituye parámetros |

Identidad del solicitante fuera del objeto (H.2). `clase_declarada` retirada.

### 1.2 `clase_solicitada` selecciona esquema — no reclasifica sola

1. `clase_solicitada` **elige el esquema cerrado** con el que se valida `parametros` de **este** objeto.  
2. **No** permite, por sí sola, que H.5 declare `clase_aplicada` = otra EF **careciendo** de un objeto tipado completo bajo el esquema de esa otra clase.  
3. El Motor **no inventa** parámetros de la otra clase, **no interpreta** payloads/digests opacos para completarlos, y **no acepta** campos no previstos en el esquema de `clase_solicitada` «solo para reclasificar».  
4. Si una señal tipada **S-MC5** (§2.1) exige otra clase material, debe existir un **EfectoTipado separado** (u hijo EF-4 completo) ya tipado bajo el esquema de esa clase; si no ⇒ R-MC5.

### 1.3 `clase_aplicada`

H.5 evidencia «Clase y atributos aplicados».

`clase_aplicada` **no** es una «reclasificación libre» de una solicitud cuyos parámetros son ajenos a la clase destino.

Es el resultado de **validar un objeto que ya contiene evidencia tipada suficiente** para la clase material que ese objeto representa:

- Para un objeto simple: tras V1–V5, si los parámetros del esquema de `clase_solicitada` son válidos y **no** se cumple S-MC5 sin objeto tipado adicional (§2.1), entonces `clase_aplicada = clase_solicitada` (más atributos H.5 derivados).  
- La **ausencia** de evidencia tipada de otra clase **nunca** se rellena desde texto, payload, digest solo, ni inferencia del Motor.  
- Si se cumple **S-MC5** y falta el objeto tipado completo de la clase señalada ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (R-MC5).

### 1.4 Digest y no lenguaje natural

H.1: no lenguaje natural; digests en cadena.

Digest vincula e inmoviliza; no aporta semántica H.5 solo. Payloads solo opacos. Cambiar clasificación/política ⇒ campo tipado, META o HECHO **con atributos tipificados del contrato** — nunca relleno por inferencia. META/HECHO/digest/payload/extensión **no tipificada** no activa S-MC5 ni completa parámetros (§2.1).

### 1.5 Tiempo determinista

INV-14 / §E sin reloj. Vigencia META/HECHO vs `epoca_contexto` inyectada y citada en evidencia.

### 1.6 Efecto y consecuencia adicional (separación)

§C: EF-8 se media en el **consumo**, no donde se calcula; EF-1 es inferencia.

1. Una inferencia tipificada como **EF-1** **no** se convierte retrospectivamente en **EF-8** usando solo la solicitud EF-1.  
2. Si el resultado puede/debe **consumirse** para una decisión sobre personas, se exige un **EfectoTipado EF-8 separado** en el punto de consumo, con obligatorios propios: `tipo_decision`, `canal_consumo`, `artefacto_autoridad_consumo`, `sujeto_afectado_clase`, `decide_sobre_personas=SI` (y demás de la fila EF-8 §4).  
3. Ambos objetos pueden ligarse por `ref_procedencia` / digest del EF-1 (o del resultado), pero **conservan** parámetros, evaluación H.5, mínimos de garantía y evidencia **propios**.  
4. El Motor **no** deniega por el hecho de que el PEP «conozca» o «quiera» un consumo EF-8 no presentado. Si subsiste un deber de presentar el objeto EF-8 en ciertos despliegues, es **obligación operativa externa** del PEP (§9), **fuera** de H.5. El DENY del Motor por consecuencia adicional **solo** procede ante **S-MC5** (§2.1) sin objeto tipado completo.

---

## 2. Mecanismo de múltiples consecuencias

| Regla | Contenido |
|---|---|
| R-MC1 | Un EfectoTipado = **exactamente una** clase material, **salvo** EF-4 compuesto. |
| R-MC2 | Efectos materialmente distintos ⇒ **objetos EfectoTipado separados**, cada uno tipado bajo su esquema. |
| R-MC3 | EF-4 **solo agrega** hijos **completos**; no sustituye ni inventa parámetros de los hijos. |
| R-MC4 | Obligación operativa **externa** (PEP/despliegue): presentar objetos tipados de consecuencias materiales adicionales cuando la política operativa del punto de aplicación lo exija. **No** es condición del Motor. **No** produce por sí sola `DENY(EFECTO_NO_TIPIFICADO)`. |
| R-MC5 | Si y solo si se cumple la señal tipada **S-MC5** (§2.1) y **falta** el objeto tipado completo de cada `ClaseEfecto` señalada: se **conserva el conflicto** en evidencia y el Motor produce `DENY(EFECTO_NO_TIPIFICADO)`. Si S-MC5 se cumple y **existen** todos los objetos tipados necesarios, se evalúa cada objeto por separado (conjunción de mínimos entre objetos presentados, sin fusionar parámetros). |
| R-MC6 | Cada EF que figure como `clase_aplicada` de un objeto (o como clase de un hijo) dispone de **todos** sus parámetros obligatorios **en ese objeto**, sin inferencia del Motor. |

No se adopta un modelo de «una solicitud, varias clases aplicadas» sobre un solo blob de parámetros de otra clase.

### 2.1 Señal tipada S-MC5 (cerrada, determinista)

**S-MC5** se cumple **si y solo si** existe al menos un registro **META** o **HECHO** que, **conjuntamente**, satisfaga **todas** las condiciones siguientes (evaluación pura sobre entradas tipadas + `epoca_contexto`):

| # | Condición |
|---|---|
| S1 | El registro es usable en H.5: firma válida, `productor_id` registrado, no caducado vs `epoca_contexto`, `ambito_recurso` aplicable al objeto bajo evaluación, `digest_objeto` vinculado a ese objeto (contrato §4.M). |
| S2 | Si es META: procede de catálogo aprobado (`catalogo_id`, `catalogo_version`, `autoridad_emisora`, `digest_catalogo` vigentes vs `epoca_contexto`). |
| S3 | `atributo` es **exactamente** el token cerrado `clase_material_adicional_requerida` (único token admitido para S-MC5 en esta versión del Anexo). |
| S4 | `valor` es **exactamente** un literal de `ClaseEfecto` ∈ {`EF-1`,…,`EF-12`} (codificación canónica del esquema). |
| S5 | Ese `valor` es **≠** `clase_solicitada` del objeto bajo evaluación. |
| S6 | En el **conjunto de objetos tipados presentados** a esta evaluación (padre, hermanos, hijos EF-4 recuperables, objetos ligados por `ref_procedencia` incluidos en el lote) **no** existe ningún EfectoTipado con `clase_solicitada = valor` (S4) que haya pasado V1–V5 bajo el esquema de esa clase. |

**No** activan S-MC5 ni completan parámetros:

- digest o payload opaco;  
- extensión META/HECHO no tipificada;  
- cualquier `atributo` distinto de `clase_material_adicional_requerida`;  
- `valor` no parseable como `ClaseEfecto` canónico;  
- interpretación de texto, intención o conocimiento del PEP;  
- inferencia del Motor.

Ampliar el conjunto de tokens `atributo` que disparan S-MC5 exige **nueva versión** del esquema (vía G.ET tras enmienda fundacional vigente), no interpretación en ejecución.

---

## 3. Validación (orden)

H.1 bien formado; H.5 atributos; Motor sin inferir huecos.

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

«Bien formado» = V1–V5 para el objeto; no autoriza otras clases sin objetos tipados adicionales.

---

## 4. Parámetros por clase (autocontenidos)

§C: ejemplos/mínimos de clase.

Las tablas de **campos** de este §4 son **autocontenidas**.

**Exclusión expresa:** ninguna revisión previa de redacción del contrato EfectoTipado **incorpora** reglas de **clasificación**, **composición**, **candidatas**, **reclasificación**, `clase_aplicada` ≠ `clase_solicitada` sobre un solo blob, ni regímenes de clasificación ajenos a este Anexo. Solo este Anexo (§1–§2, §5–§6) gobierna esas materias.

**Precisiones:** esquema validado = el de `clase_solicitada`; EF-8 solo en objeto EF-8; EF-4 = hijos completos; digests opacos no tipifican otra EF; EF-12 = taxonomía de intento.

### Tipos compartidos

| Tipo | Semántica |
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

Como mínimo: `productor_id`, `firma`, `emitido_en_epoca`, `expira_en_epoca`, `ambito_recurso`, `atributo`, `valor`, `digest_objeto`.  
META de catálogo, además: `catalogo_id`, `catalogo_version`, `autoridad_emisora`, `digest_catalogo`.  
Extensiones solo si versionadas, canonizadas y tipificadas; no interpretadas salvo tipificación aprobada. No activan S-MC5 salvo S3–S4 (§2.1).

---

## 5. Atributos H.5 y composición

H.5: cinco atributos; más restrictiva sin orden total EF en Matriz.

1. Por cada **objeto** tipificado: derivar los cinco atributos desde **sus** parámetros + META/HECHO aplicables a **ese** objeto (`HECHO` > `META` > `PEP` > `REGLA`), sin usar S-MC5 para inventar campos.  
2. Composición de **mínimos/obligaciones** entre varios objetos presentados (p. ej. padre EF-4 + hijos, o EF-1 + EF-8 ligados): conjunción sobre los objetos presentados; no fusionar parámetros.  
3. «Más restrictiva» = conjunción / tratamientos conservadores de `DESCONOCIDO` / DENY por R-MC5 — **no** reclasificar un esquema ajeno.

---

## 6. Reglas específicas

### 6.1 EF-4 — cierre de anidamiento

§C: herramientas / producen otras clases.

1. Hijos completos; parámetros propios; no sustituibles por nombres de clase.  
2. La prohibición de anidamiento **no** mira solo `clase_solicitada=EF-4` del hijo.  
3. Se valida que **ningún hijo**:  
   - tenga `clase_solicitada=EF-4`, **ni**  
   - tenga `clase_aplicada` **EF-4**, **ni**  
   - dispare **S-MC5** con `valor=EF-4` (u otra forma tipada equivalente bajo §2.1) aplicable a ese hijo.  
4. Si S-MC5 / META/HECHO tipado introduce EF-4 sobre un hijo ⇒ `DENY(EFECTO_NO_TIPIFICADO)` (no se promociona a EF-4 anidado).  
5. Digests visitados; ciclo ⇒ DENY; profundidad de herramientas = 1.

### 6.2 EF-8

Consumo, no inferencia. Solo sobre objeto EF-8 con obligatorios de §1.6 / §4; nunca como reclasificación de EF-1.

### 6.3 EF-9

Eliminar/confinar; INV-11. No reclasificar desde otro esquema por inferencia.

### 6.4 EF-12

DENY; gobernanza humana doble firma. Taxonomía de intento; no interfaz H.1–H.16; ninguna capacidad EF-12; petición H.1 ⇒ registro + DENY (IA o humano); gobierno humano fuera de H.

---

## 7. Historia y citas

INV-14. Citar por cada objeto: esquema, digests, `clase_solicitada`, `clase_aplicada`, `ref_procedencia` si existe, META (catálogo ids/digests), HECHO (incl. si hubo S-MC5), `epoca_contexto`. Recomputación bit a bit con los mismos objetos.

---

## 8. Gobernanza

G.5 **no** cubre por omisión este contrato. La enmienda fundacional crea G.ET. **D6 permanece bloqueado** hasta el criterio de §11. G.ET no se autoactiva y no sustituye G.5 para paquetes normativos.

---

## 9. No automatizable

INV-16. El Motor no decide: aprobar esquemas y tokens S-MC5 adicionales; catálogos; fundacional; gobierno; composición de mínimos no escrita.

Si la política de un despliegue exige que el PEP presente un EF-8 (u otra clase) junto a un EF-1 en ciertos casos, esa exigencia es **operativa externa**: su incumplimiento se gestiona fuera del Motor (rechazo en frontera PEP, auditoría, etc.). El Motor **solo** aplica R-MC5 ante **S-MC5**.

---

## 10. Vectores de conformidad

### 10.1 Base

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

### 10.2 Adicionales (cierre de tipificación)

| ID | Caso | Esperado |
|---|---|---|
| **V-a** | EF-1 válido; operador/PEP «quiere» consumo decisional; **sin** S-MC5 y **sin** objeto EF-8 | Tipificable EF-1 (**no** DENY Motor por conocimiento) |
| **V-b** | Igual que V-a + obligación operativa externa incumplida | Fuera de alcance del Motor; no cambia V-a |
| **V-c** | EF-1 válido + META/HECHO usable con `atributo=clase_material_adicional_requerida`, `valor=EF-8`, sin objeto EF-8 en el lote | **S-MC5** ⇒ `DENY(EFECTO_NO_TIPIFICADO)`; conflicto en evidencia |
| **V-d** | Igual V-c + objeto EF-8 completo en el lote | Tipificables por separado; no DENY por R-MC5 |
| **V-e** | META con `atributo` distinto / extensión no tipificada / payload que «sugiere» EF-8 | **No** S-MC5; EF-1 tipificable si V1–V5 ok |
| **V-f** | HECHO con `valor` no canónico como `ClaseEfecto` | **No** S-MC5 |
| **V-g** | S-MC5 con `valor=EF-4` aplicable a hijo `clase_solicitada=EF-1` | `DENY(EFECTO_NO_TIPIFICADO)` (§6.1) |
| **V-h** | Lectura de reglas de clasificación solo desde este Anexo §1–§2 | Régimen único; revisiones previas de redacción **no** aplicables |

---

## 11. Criterio de cierre (D6)

D6 solo puede valorarse tras: enmienda fundacional vigente; tabla operativa habilitada; vectores §10 en verde; y constancia de no-implementación previa de D6. Cumplir estos criterios **no** desbloquea D6 automáticamente: exige acto humano ulterior expreso. Hasta entonces, **D6 bloqueado**.

---

## Apéndice A — Circularidad cerrada

| Antipatron | Cierre |
|---|---|
| Esquema de A + H.5 ⇒ clase B | Prohibido sin objeto tipado B |
| EF-1 «es» EF-8 por intención | EF-8 separado; DENY Motor solo vía S-MC5 |
| Una solicitud, N clases sin N esquemas | N objetos (o hijos EF-4 completos) |
| Anti-EF-4 solo por solicitada | También aplicada / S-MC5=`EF-4` |
