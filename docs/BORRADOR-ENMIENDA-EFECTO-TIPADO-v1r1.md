# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1r1

**Estado:** BORRADOR · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** · **D6 BLOQUEADO**  
**Precede:** `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1.md` (también no vigente).  
**Destino propuesto:** Anexo EfectoTipado de la Matriz Maestra Canónica v1.1 + enmienda fundacional que crea G.ET.  
**Objetivo:** cerrar la omisión entre **H.1** y **H.5**, corregido según revisión de 2026-07-30.  
**Fecha de redacción:** 2026-07-30.

### Convención tipográfica

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación. **No** afirma que G.5 cubra este artefacto. |

---

## Cambios respecto de v1

| # | Tema | Cambio en v1r1 |
|---|---|---|
| 1 | EF-8 / destinatarios | Eliminada la contradicción «persona en `destinatarios` ⇒ no puede ser `decide_sobre_personas=NO`». EF-8 exige consecuencia decisoria + `canal_consumo` + `artefacto_autoridad_consumo` + `decide_sobre_personas=SI`. |
| 2 | Restrictividad | Retirado el orden total EF-1…EF-12. Sustituido por composición de obligaciones/mínimos, precedencias solo si están explícitas, incompatibilidad ⇒ `DENY(EFECTO_NO_TIPIFICADO)`, EF-12 siempre denegado a IA. |
| 3 | EF-4 compuesto | `clases_producidas` deja de ser lista de nombres; pasa a **efectos hijos tipados** (o referencias digestadas a hijos tipados disponibles). |
| 4 | Procedencia H.5 | Fuentes: declaración PEP / metadato firmado / hecho firmado / regla determinista; precedencia y conflicto definidos. |
| 5 | Arranque G.ET | Separada **enmienda fundacional** (crea G.ET) de **gobierno posterior** G.ET (versiones futuras). Sin circularidad. |
| 6a | Digest | Digest vincula e inmoviliza; no sustituye el objeto canónico para derivar significado. |
| 6b | `destinatarios` | Revisado por clase; `NINGUNO` permitido donde tenga sentido; no se impone lista no vacía universal. |
| 6c | Gobierno humano | Cambios de gobierno fuera de EfectoTipado de sujetos IA; EF-12 siempre DENY a IA. |
| 6d | Vectores | Añadida sección de vectores de aceptación/rechazo por EF y casos críticos. |

---

## 0. Motivación y alcance

**[LITERAL]** H.1: «Efecto tipado con clase y parámetros. **No lenguaje natural**… bien formado y su clase es una de las doce… `DENY(EFECTO_NO_TIPIFICADO)`.»  
**[LITERAL]** H.5: deriva «Clase, reversibilidad, presencia de datos personales, destinatarios, si decide sobre personas»; «Clasificación ambigua ⇒ se toma la más restrictiva».  
**[LITERAL]** §C: doce clases; reabrir con decisión firmada si no encaja.  
**[LITERAL]** §E Motor: no «Completar huecos normativos por inferencia»; función pura.  
**[LITERAL]** INV-16; G.5 = paquetes normativos, **no** este contrato.

**[PROPUESTA]** Este borrador define EfectoTipado, parámetros por clase, derivación H.5, procedencia de atributos, G.ET **tras** enmienda fundacional, y vectores de conformidad.

**[PROPUESTA]** **D6 permanece bloqueado** hasta enmienda fundacional + primera versión operativa habilitada expresamente (§8).

---

## 1. Objeto canónico EfectoTipado, versión y serialización

### 1.1 Definición

**[LITERAL]** «Efecto tipado con clase y parámetros» (H.1); clases `EF-1`…`EF-12` (§C).

**[PROPUESTA]** **EfectoTipado** consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` | string fija | sí | p. ej. `efecto-tipado` |
| `esquema_version` | u32 | sí | Versión del contrato |
| `clase_declarada` | enum EF-1…EF-12 | sí | Afirmada por el PEP / punto de aplicación |
| `parametros` | objeto tipado §3 | sí | Parámetros de la clase |
| `digest_parametros` | SHA-384 dominio | sí | Digest de `canon(parametros)` |

**[PROPUESTA]** El Motor no inventa campos. Solo valida contra la versión citada y vigente del esquema.

### 1.2 Digest: vínculo, no semántica

**[LITERAL]** Recibos y capacidades ligan digests de parámetros (H.14, INV-08 espíritu).

**[PROPUESTA]** Un `digest_parametros` **vincula e inmoviliza** el contenido canónico de los parámetros: garantiza integridad y comparación bit a bit. **No** permite, por sí solo, derivar el significado de los campos ni los atributos H.5. La derivación exige el **objeto canónico** `parametros` (o su reconstrucción exacta desde almacén durable). Evaluar H.5 solo con el digest y sin el objeto ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.3 Serialización determinista

**[LITERAL]** G.1 / INV-14: serialización determinista; reproducibilidad.

**[PROPUESTA]** Canon publicado por versión; claves ordenadas; campos desconocidos ⇒ no tipificable; `digest_parametros = SHA-384(dominio ‖ canon(parametros))`.

### 1.4 Versiones

**[PROPUESTA]** Cada versión es artefacto firmado e inmutable. Activación posterior a la enmienda fundacional: por **G.ET** (§8.B), no por G.5 salvo unificación futura expresa.

---

## 2. Reglas comunes de validación y fallo seguro

**[LITERAL]** H.1; H.5 ambigüedad ⇒ más restrictiva; G.2 sin salida permisiva por defecto; Motor sin inferir huecos.

**[PROPUESTA]** Orden de validación:

| # | Comprobación | Fallo |
|---|---|---|
| V1 | Versión de esquema usable (activa o histórica citada) | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_declarada` ∈ doce | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | Parámetros conforme §3; hijos EF-4 disponibles si aplica | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | Digest coincide **y** objeto canónico presente para evaluar | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | Sin campos desconocidos ni lenguaje natural | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | Resolución de procedencia §4 y atributos H.5 | según §4–§5 |
| V7 | Composición de clases candidatas §5.2 | incompatibilidad ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |

**[PROPUESTA]** «Bien formado» (H.1) = V1–V5.

---

## 3. Tabla EF-1…EF-12 — parámetros

**[LITERAL]** §C: ejemplos y mínimos de garantía; no esquema de campos.  
**[PROPUESTA]** Contrato de campos siguiente. Ampliar enums ⇒ nueva versión del esquema.

### Tipos compartidos

| Tipo | Semántica **[PROPUESTA]** |
|---|---|
| `Tri` | `SI` \| `NO` \| `DESCONOCIDO` — nunca `DESCONOCIDO` como `NO` permisivo |
| `Reversibilidad` | `REVERSIBLE` \| `IRREVERSIBLE` \| `DESCONOCIDO` |
| `DestinatarioClase` | `NINGUNO` \| `SISTEMA` \| `PERSONA_IDENTIFICADA` \| `PERSONA_NO_IDENTIFICADA` \| `PUBLICO` \| `DESCONOCIDO` |
| `ClaseEfecto` | `EF-1`…`EF-12` |
| `RefEfectoHijo` | EfectoTipado embebido **o** `{ digest_efecto, esquema_version }` con objeto recuperable |

**[PROPUESTA]** Sobre `destinatarios`: no se exige lista no vacía en todas las clases. Donde el efecto no tiene destinatario material, se admite exactamente `[NINGUNO]`. `DESCONOCIDO` no equivale a `NINGUNO`.

Leyenda: **Obl** / **Opc** / **Proh**.

### EF-1 — Inferencia

**[LITERAL]** §C ejemplos; mínimo según datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | INFERENCIA / EMBEDDING / CLASIFICACION / TRANSCRIPCION / OTRO |
| `destino_modelo` | Obl | Uri\|Id | Punto de servicio |
| `contiene_datos_personales` | Obl | Tri | |
| `categoria_especial` | Opc | Tri | Solo con sentido si datos personales = SI |
| `destinatarios` | Obl | Lista | Puede ser `[NINGUNO]` si la salida no se entrega a nadie aún; no vacío genérico |
| `decide_sobre_personas` | Obl | Tri | Independiente de meros destinatarios |
| `codigo_arbitrario` | Proh | — | → EF-9 |
| `texto_intencion` | Proh | — | |

### EF-2 — Acceso a datos

**[LITERAL]** §C; categorías especiales ⇒ delegado.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum | LECTURA / CONSULTA / RAG / EXPEDIENTE / TRANSFORMACION |
| `recurso` | Obl | Id | |
| `contiene_datos_personales` | Obl | Tri | |
| `categoria_especial` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` si solo lee el propio sujeto sin reenvío |
| `decide_sobre_personas` | Obl | Tri | |
| `volumen_max` | Opc | u64 | |
| `escritura` | Proh | — | → EF-3 |
| `texto_intencion` | Proh | — | |

### EF-3 — Escritura

**[LITERAL]** §C INSERT/UPDATE/borrado/fichero/config.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum | |
| `objetivo` | Obl | Id | |
| `reversibilidad` | Obl | Reversibilidad | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Suele `[SISTEMA]` o `[NINGUNO]` (mutación de estado) |
| `decide_sobre_personas` | Obl | Tri | |
| `codigo_arbitrario` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-4 — Herramientas (compuesto)

**[LITERAL]** §C: herramienta/MCP/API; «delegado si la herramienta produce EF-3, EF-5, EF-6 o EF-7».

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `herramienta_id` | Obl | Id | Declarada en pasaporte / catálogo |
| `efectos_hijos` | Obl | Lista[`RefEfectoHijo`] **no vacía** | Cada hijo es un EfectoTipado completo (o ref digestada + objeto disponible) |
| `argumentos_digest` | Obl | BytesDigest | Digest de argumentos de la invocación de herramienta |
| `invocacion_directa_no_mediada` | Proh | — | |
| `texto_intencion` | Proh | — | |
| `clases_producidas` (solo nombres) | Proh | — | **Retirado:** no sustituye hijos tipados |

**[PROPUESTA]** Los atributos H.5 «de la herramienta» no reemplazan los de cada hijo. Atributos agregados del EF-4 padre: ver §6.1.

### EF-5 — Operación de negocio

**[LITERAL]** §C; delegado sin excepción.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_operacion` | Obl | Enum | |
| `contraparte` | Obl | Id | |
| `importe_digest` | Opc | BytesDigest | |
| `reversibilidad` | Obl | Reversibilidad | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Contraparte tipada; no forzar PUBLICO |
| `decide_sobre_personas` | Obl | Tri | |
| `texto_intencion` | Proh | — | |

### EF-6 — Comunicaciones

**[LITERAL]** §C correo/mensajería/llamada/notificación.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal` | Obl | Enum | |
| `destinatarios` | Obl | Lista | Al menos una clase de persona **o** SYSTEM+persona; **no** `[NINGUNO]` |
| `contiene_datos_personales` | Obl | Tri | |
| `decide_sobre_personas` | Obl | Tri | Puede ser NO: comunicar ≠ decidir (corrección v1r1) |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-7 — Publicación

**[LITERAL]** §C publicación / respuesta pública.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal_publicacion` | Obl | Id | |
| `destinatarios` | Obl | Lista | Incluye `PUBLICO` y/o persona; **no** `[NINGUNO]` |
| `contiene_datos_personales` | Obl | Tri | |
| `decide_sobre_personas` | Obl | Tri | Puede ser NO |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-8 — Decisión sobre personas

**[LITERAL]** Consecuencia; mediación en **consumo**; artefacto de autoridad del canal de consumo.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_decision` | Obl | Enum | |
| `canal_consumo` | Obl | Id | **Requisito específico EF-8** |
| `artefacto_autoridad_consumo` | Obl | Id | **Requisito específico EF-8** |
| `sujeto_afectado_clase` | Obl | Enum | PERSONA_IDENTIFICADA / NO_IDENTIFICADA |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Canal/consumidor; independiente de «decidir» en otras clases |
| `decide_sobre_personas` | Obl | Tri | **Debe ser SI** para EF-8; otro ⇒ no tipificable |
| `mediacion_en_inferencia` | Proh | — | No presentar como EF-1 |
| `texto_intencion` | Proh | — | |

**[PROPUESTA — corrección v1r1]** En clases que no son EF-8, `destinatarios` con persona **y** `decide_sobre_personas=NO` **no** es contradicción (p. ej. EF-6).

### EF-9 — Ejecución de código

**[LITERAL]** No se media; se elimina o confina; INV-11 si abierto.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | |
| `autoridad_ambiental` | Obl | Tri | |
| `superficie_atestada` | Opc | BytesDigest | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Puede ser `[NINGUNO]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `capacidad_efector_solicitada` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-10 — Movimiento entre dominios

**[LITERAL]** §C; delegado con datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `destino_dominio` | Obl | Id\|Uri | |
| `jurisdiccion_destino` | Opc | código | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Destino; no `[NINGUNO]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-11 — Físico / ciberfísico

**[LITERAL]** §C; PEP físico; aprobación humana previa.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `actuador_id` | Obl | Id | |
| `orden_digest` | Obl | BytesDigest | |
| `pep_fisico_presente` | Obl | Tri | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Puede ser `[NINGUNO]` o `[SISTEMA]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-12 — Cambio de gobierno

**[LITERAL]** Siempre DENY a IA; solo gobernanza humana con doble firma.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `objeto_gobierno` | Obl | Enum | |
| `solicitante_es_ia` | Obl | Bool | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | Puede ser `[NINGUNO]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `autorizacion_ia` | Proh | — | |

**[PROPUESTA]** Los **cambios humanos de gobierno** (corpus, pasaporte, config Kernel, etc.) **no** se modelan como EfectoTipado emitido por sujeto IA. EF-12 tipificado desde IA ⇒ siempre denegación de autorización (§6.4). La vía humana es G.5 / enmienda fundacional / G.ET, no H.1 de un agente.

---

## 4. Procedencia de atributos H.5

**[LITERAL]** H.5 deriva cinco atributos desde parámetros; hechos firmados en H.6; Motor no infiere huecos (§E).

**[PROPUESTA]** Cada valor usado en H.5 debe declarar **procedencia**:

| Código | Fuente | Quién lo aporta |
|---|---|---|
| `PEP` | Declaración tipada del punto de aplicación / PEP | Solicitud |
| `META` | Metadato firmado del recurso, herramienta o catálogo (p. ej. pasaporte, registro de herramienta) | Catálogo / registro |
| `HECHO` | Hecho firmado externo vigente (productor registrado) | Productores |
| `REGLA` | Regla determinista del esquema sobre datos ya tipados | Este contrato |

### 4.1 Precedencia (propuesta)

Orden de prevalencia ante el mismo atributo:

1. **`HECHO`** vigente y aplicable  
2. **`META`** firmado y vigente  
3. **`PEP`** (declaración del solicitante / PEP)  
4. **`REGLA`** solo sobre valores ya fijados por 1–3 (no inventa hechos)

**[PROPUESTA]** Una declaración `PEP` **no prevalece** sobre `META` o `HECHO` contradictorios.

### 4.2 Conflicto

| Conflicto | Conducta |
|---|---|
| `PEP` vs `META`/`HECHO` | Se descarta `PEP`; se usa la fuente superior; se registra en evidencia |
| `META` vs `HECHO` | `HECHO` prevalece; si incompatibles para tipificar ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |
| Dos `HECHO` incompatibles | `DENY(EFECTO_NO_TIPIFICADO)` |
| Sin base suficiente (obligatorio sin PEP/META/HECHO y sin REGLA aplicable) | `DENY(EFECTO_NO_TIPIFICADO)` **o**, solo si la enmienda fundacional aprueba expresamente un tratamiento conservador nombrado (p. ej. `DESCONOCIDO`→SI), ese tratamiento — **nunca ALLOW por omisión** |

### 4.3 Derivación de cada atributo H.5

**[LITERAL]** Los cinco atributos de H.5.

**[PROPUESTA]**

| Atributo | Cómo se obtiene |
|---|---|
| **Clase** | `clase_declarada` (PEP) + composición §5.2 / §6; no orden total entre EF |
| **Reversibilidad** | Preferir META/HECHO; si solo PEP; `DESCONOCIDO` ⇒ IRREVERSIBLE (**REGLA** conservadora propuesta) salvo tratamiento distinto aprobado |
| **Datos personales** | Preferir META/HECHO del recurso; `DESCONOCIDO` ⇒ SI (**REGLA**); `categoria_especial=SI` fuerza SI |
| **Destinatarios** | Preferir META/HECHO; PEP tipado; `[DESCONOCIDO]` solo ⇒ DENY o tratamiento conservador **aprobado**; `[NINGUNO]` solo donde §3 lo permite |
| **Decide sobre personas** | Preferir META/HECHO; PEP; para **EF-8** debe ser SI; `DESCONOCIDO` ⇒ SI (**REGLA**); **no** inferir SI solo por persona en destinatarios |

---

## 5. Ambigüedad, composición y «más restrictiva»

**[LITERAL]** H.5: «Clasificación ambigua ⇒ se toma la más restrictiva».  
**[LITERAL]** La Matriz **no** define un orden total EF-1…EF-12.  
**[LITERAL]** §C mínimos de garantía por clase; EF-12 siempre DENY a IA.  
**[LITERAL]** G.2 R2 ínfimo de decisiones (normas); espíritu: sin salida permisiva por defecto.

### 5.1 Retirada del orden total

**[PROPUESTA]** Se **retira** el orden `EF-1 < … < EF-12` de v1. No forma parte de este borrador.

### 5.2 Regla de composición (sustituto)

**[PROPUESTA]** Cuando hay **varias clases candidatas** (p. ej. EF-4 con hijos, o divergencia declaración/META):

1. **Compatibles:** se aplican **todas** las obligaciones y **todos** los mínimos de garantía de las clases candidatas (conjunción / ínfimo de admisibilidad: hay que satisfacer cada mínimo).  
2. **Precedencias explícitas únicamente:** solo las definidas en Matriz o en este contrato aprobado (p. ej. EF-4 «delegado si produce EF-3/5/6/7»; EF-8 en consumo; EF-9 abierto → degradación Libro INV-11; EF-12 no emitible).  
3. **Incompatibles** (no existe regla aprobada de composición que las reconcilie) ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.  
4. **EF-12** entre candidatas o como hijo ⇒ autorización a IA **siempre denegada** (§6.4), sin usar orden de clases.

**[PROPUESTA]** «Más restrictiva» (H.5) se interpreta, en este borrador, como: (a) conjunción de obligaciones/mínimos cuando es posible; (b) tratamientos conservadores de §4.3 sobre `DESCONOCIDO`; (c) DENY si no hay composición aprobada — **no** como ranking ordinal de IDs EF.

### 5.3 Tabla de fallos

| Situación | Conducta |
|---|---|
| Obligatorio ausente / prohibido presente / tipo malo | `DENY(EFECTO_NO_TIPIFICADO)` |
| Digest ok pero objeto canónico ausente | `DENY(EFECTO_NO_TIPIFICADO)` |
| `DESCONOCIDO` | §4.3 — nunca permisivo |
| Conflicto fuentes firmadas | §4.2 |
| Clases candidatas incompatibles | `DENY(EFECTO_NO_TIPIFICADO)` |
| No encaja en doce | **[LITERAL]** reabrir §C; en ejecución `DENY(EFECTO_NO_TIPIFICADO)` |

---

## 6. Reglas específicas EF-4, EF-8, EF-9, EF-12

### 6.1 EF-4 compuesto

**[LITERAL]** §C: produce EF-3/5/6/7 ⇒ exige delegado para esas consecuencias.

**[PROPUESTA]**

1. `efectos_hijos` no vacía; cada hijo es EfectoTipado válido (o ref digestada con objeto recuperable y tipificable).  
2. Se evalúa el **padre como EF-4** (herramienta) **y** cada hijo con **sus propios parámetros y atributos H.5**.  
3. Obligaciones/mínimos = composición §5.2 sobre {EF-4} ∪ clases de los hijos.  
4. Hijo EF-12 ⇒ §6.4. Hijo EF-8 ⇒ §6.2 sobre ese hijo.  
5. Prohibido sustituir hijos por una lista de meros nombres de clase.

### 6.2 EF-8

**[LITERAL]** Consumo, no inferencia; artefacto del canal de consumo.

**[PROPUESTA]**

1. Obligatorios: `canal_consumo`, `artefacto_autoridad_consumo`, `decide_sobre_personas=SI`.  
2. Sin esos requisitos ⇒ no es EF-8 tipificable.  
3. Comunicar a una persona (EF-6) con `decide_sobre_personas=NO` **no** es EF-8.

### 6.3 EF-9

**[LITERAL]** Eliminar o confinar; abierto degrada alcanzables.

**[PROPUESTA]** No reclasificar código arbitrario como EF-1…EF-8 «seguro». `autoridad_ambiental=SI` informa Libro (fuera de tipificación pura). `DESCONOCIDO` en reversibilidad ⇒ IRREVERSIBLE.

### 6.4 EF-12

**[LITERAL]** Nunca se concede a IA; DENY; gobernanza humana.

**[PROPUESTA]** Tipificar EF-12 desde sujeto IA produce atributos H.5 pero **autorización siempre denegada**. Gobierno humano fuera de EfectoTipado de IA (§3 EF-12).

---

## 7. Compatibilidad, migración y reproducción histórica

**[LITERAL]** INV-14; conservación de paquetes / reconstrucción (G.5 espíritu); INV-03 citas.

**[PROPUESTA]**

1. Toda decisión H.5 cita `esquema_id`, `esquema_version`, hash del contrato EfectoTipado, y digests de parámetros **más** disponibilidad del objeto canónico usado.  
2. Recomputación histórica: misma versión + mismos objetos canónicos ⇒ mismos atributos y mismo veredicto de tipificación.  
3. Migración N→N+1: tabla de mapeo publicada; Motor no rellena campos nuevos por inferencia.  
4. Sin mapeo: historia en N; solicitudes nuevas en N+1.

---

## 8. Gobernanza — enmienda fundacional y G.ET

**[LITERAL]** G.5 = paquetes normativos. §C reapertura con decisión firmada. G.5 **no** cubre por omisión el contrato EfectoTipado.

### 8.A Enmienda fundacional (rompe la circularidad)

**[PROPUESTA]** G.ET **no puede** aprobar su propia primera activación: aún no existe como procedimiento vigente.

**[PROPUESTA]** La **enmienda fundacional** es una **decisión humana canónica y firmada** (fuera de G.ET) que:

1. Incorpora el **Anexo EfectoTipado** (texto aprobado) a la Matriz o lo referencia como canónico.  
2. **Crea G.ET**: autoridad, registro de firmantes (al menos un jurídico y un técnico, identidades distintas), umbrales, y reglas de entrada en vigor.  
3. Declara expresamente si, en el mismo acto, habilita o no una **tabla operativa inicial** `efecto-tipado@v1` (o deja esa tabla al primer ciclo G.ET).  
4. Fija la fecha/época de entrada en vigor.  
5. Constata que **D6 permanece bloqueado** hasta que (3) esté vigente según esa misma decisión.

Firmas fundacionales **[PROPUESTA]:** umbral ≥ 2 de N, con al menos firmante jurídico y técnico distintos (espejo deliberado del espíritu G.5.4, **sin** afirmar cobertura G.5).

### 8.B Gobierno posterior (solo tras 8.A vigente)

**[PROPUESTA]** Una vez vigente la enmienda fundacional, **G.ET** gobierna:

- Versiones **futuras** del contrato EfectoTipado.  
- La tabla operativa inicial **solo si** 8.A lo habilitó expresamente vía G.ET (si 8.A ya la activó, G.ET empieza en v2+).

Etapas G.ET (espejo de G.5, **cobertura no alegada**):

| Etapa | Contenido |
|---|---|
| ET.1 Propuesta | Esquema + vectores §10 |
| ET.2 Revisión | Jurídica + técnica |
| ET.3 Conformidad | Harness + **diff** de tipificaciones reconocido y firmado |
| ET.4 Doble firma | 2 de N; jurídico + técnico |
| ET.5 Sombra | 7 días sin aplicar a ALLOW reales |
| ET.6 Activación | Límite de época; versión anterior conservada |
| ET.7 Reversión | Mismo umbral; no borrar historia |

**[PROPUESTA]** Mientras 8.A no esté firmada y vigente: **no hay G.ET operativo**; **D6 bloqueado**; G.5 no sustituye.

### 8.C Relación con §C

**[LITERAL]** Reabrir §C con decisión firmada si el efecto no encaja.  
**[PROPUESTA]** Nueva clase o redefinición de clase: §C (fundacional o decisión firmada) **más** actualización de esquema por G.ET (tras 8.A).

---

## 9. Decisiones humanas/normativas no automatizables

**[LITERAL]** INV-16; G.4; R8; interpretación G.1.

**[PROPUESTA]** El Motor no decide:

1. Aprobar la enmienda fundacional ni cualquier versión del anexo.  
2. El contenido de la tabla de parámetros (§3).  
3. Tratamientos conservadores concretos para `DESCONOCIDO` más allá de lo ya aprobado.  
4. Reglas de composición entre clases no escritas.  
5. Mapeos de migración.  
6. Reapertura de §C.  
7. Unificación G.ET ↔ G.5.  
8. Interpretación jurídica casuística de «datos personales» / «decisión sobre personas».  
9. Autorizar EF-12 o cambios de gobierno.  
10. Contenido de catálogos/pasaportes que aportan META.

---

## 10. Vectores de conformidad (propuestos)

**[LITERAL]** L-31 / bloque evidencia: esquemas con vectores de aceptación y rechazo (espíritu).  
**[PROPUESTA]** Toda versión EfectoTipado publica, como mínimo:

### 10.1 Por cada EF-1…EF-12

| Vector | Esperado |
|---|---|
| Aceptación mínima bien formada | Tipificable; atributos H.5 deterministas |
| Rechazo: obligatorio ausente | `DENY(EFECTO_NO_TIPIFICADO)` |
| Rechazo: campo prohibido / lenguaje natural | `DENY(EFECTO_NO_TIPIFICADO)` |
| Rechazo: digest ≠ canon(parametros) | `DENY(EFECTO_NO_TIPIFICADO)` |
| Rechazo: solo digest, sin objeto canónico | `DENY(EFECTO_NO_TIPIFICADO)` |

### 10.2 Casos específicos

| Caso | Esperado |
|---|---|
| **EF-4** con hijo EF-5 tipado completo | Padre EF-4 + hijo evaluado; mínimos EF-4∧EF-5 |
| **EF-4** solo con nombres de clase (sin hijos) | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-4** hijo no recuperable por digest | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-8** sin `canal_consumo` o sin artefacto | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-8** con `decide_sobre_personas≠SI` | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-6** persona en destinatarios + `decide_sobre_personas=NO` | Tipificable como EF-6 (**no** forzar EF-8) |
| **EF-9** con reclasificación a EF-1 | `DENY(EFECTO_NO_TIPIFICADO)` o rechazo de esa forma |
| **EF-12** solicitante IA | Tipificación posible; **autorización DENY** |
| Atributo **DESCONOCIDO** (datos personales / reversibilidad / decide) | Tratamiento §4.3; nunca ALLOW por omisión |
| Conflicto **PEP vs META/HECHO** | Prevalece META/HECHO; evidencia de descarte PEP |
| Conflicto **dos HECHO** | `DENY(EFECTO_NO_TIPIFICADO)` |
| **Recomputación histórica** misma versión+objetos | Bit a bit igual |
| Recomputación con versión activa distinta sin citar la histórica | Prohibido / distinto resultado no alegable como el histórico |

---

## 11. Criterio de cierre (cuando deje de ser borrador)

**[PROPUESTA]** Vigencia solo si:

1. Enmienda fundacional (§8.A) firmada e incorporada.  
2. Tabla operativa inicial habilitada según §8.A (directamente o primer G.ET).  
3. Vectores §10 en verde.  
4. Constancia de que D6 no se implementó antes.

---

## Apéndice A — LITERAL ↔ hueco

| Exigencia | ¿Cubierta hoy? | Este borrador |
|---|---|---|
| H.1 tipado | Parcial | §1–§3 |
| H.5 cinco atributos | No | §4–§5 |
| Orden total EF | No existe en Matriz | Retirado (v1 lo proponía) |
| G.5 = EfectoTipado | No | §8.A fundacional + §8.B G.ET |
| D6 | Bloqueado | Sigue bloqueado |

---

**NO VIGENTE · NO APROBADO · NO IMPLEMENTABLE · D6 BLOQUEADO**
