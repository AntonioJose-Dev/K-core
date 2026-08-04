# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1r2

**Estado:** BORRADOR para revisión humana adversarial · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** · **D6 BLOQUEADO**  
**Precede:** `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r1.md` (aceptado como borrador de revisión; no vigente).  
**Destino propuesto:** Anexo EfectoTipado de la Matriz Maestra Canónica v1.1 + enmienda fundacional que crea G.ET.  
**Objetivo:** cerrar la omisión entre **H.1** y **H.5**.  
**Fecha de redacción:** 2026-07-30.

### Convención tipográfica

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación. **No** afirma que G.5 cubra este artefacto. |

---

## Cambios respecto de v1r1

| # | Tema | Cambio en v1r2 |
|---|---|---|
| 1 | EF-12 / identidad | Eliminado `solicitante_es_ia` de parámetros. Identidad solo por artefacto de autoridad / pasaporte (fuera de parámetros). Identidad declarada en la petición ignorada. Solicitante autenticado IA + EF-12 ⇒ siempre DENY. Gobierno humano fuera de EfectoTipado de IA. |
| 2 | No lenguaje natural | Definición precisa: Motor solo interpreta campos tipados del contrato. Payloads/contenido de negocio solo por bytes/digest/objeto opaco; nunca como intención normativa. Para alterar clasificación/política ⇒ campo tipado, META o HECHO. |
| 3 | Contrato META/HECHO | Campos mínimos de procedencia; fallos de firma/productor/caducidad/ámbito/digest; distinción tipificación H.5 vs evidencia normativa H.6. |
| 4 | Recursión EF-4 | **Prohibido** EF-4 como hijo de EF-4 en v1r2 (profundidad de anidamiento de herramientas = 1). Vectores de rechazo: hijo EF-4, ciclo, profundidad excedida. |

*(Los cambios v1→v1r1 siguen asumidos; este documento es la línea base v1r2.)*

---

## 0. Motivación y alcance

**[LITERAL]** H.1: «Efecto tipado con clase y parámetros. **No lenguaje natural**… bien formado y su clase es una de las doce… `DENY(EFECTO_NO_TIPIFICADO)`.»  
**[LITERAL]** H.5: deriva «Clase, reversibilidad, presencia de datos personales, destinatarios, si decide sobre personas»; ambigüedad ⇒ más restrictiva.  
**[LITERAL]** H.2: «**El campo de identidad de la petición se ignora**»; identidad por artefacto emitido por el Kernel.  
**[LITERAL]** H.6: hechos firmados; ausente/caducado ⇒ `DENY(EVIDENCIA_AUSENTE)`; ningún hecho sin firma entra.  
**[LITERAL]** §C; §E Motor; INV-16; G.5 ≠ este contrato.

**[PROPUESTA]** Este borrador define EfectoTipado, parámetros, H.5, procedencia META/HECHO, anti-recursión EF-4, G.ET tras enmienda fundacional, y vectores.

**[PROPUESTA]** **D6 permanece bloqueado** hasta enmienda fundacional + tabla operativa habilitada (§8).

---

## 1. Objeto canónico EfectoTipado, versión y serialización

### 1.1 Definición

**[LITERAL]** «Efecto tipado con clase y parámetros» (H.1); clases `EF-1`…`EF-12` (§C).

**[PROPUESTA]** **EfectoTipado** consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` | string fija | sí | p. ej. `efecto-tipado` |
| `esquema_version` | u32 | sí | Versión del contrato |
| `clase_declarada` | enum EF-1…EF-12 | sí | Afirmada por el PEP (tipada; no es identidad del sujeto) |
| `parametros` | objeto tipado §3 | sí | Parámetros de la clase |
| `digest_parametros` | SHA-384 dominio | sí | Digest de `canon(parametros)` |

**[PROPUESTA]** El Motor no inventa campos. La **identidad del solicitante no forma parte** de `parametros` ni de EfectoTipado.

### 1.2 Digest: vínculo, no semántica

**[LITERAL]** Digests de parámetros en recibos/capacidades (H.14, INV-08 espíritu).

**[PROPUESTA]** Un digest **vincula e inmoviliza** el contenido canónico. **No** deriva por sí solo significado ni atributos H.5. H.5 exige el **objeto canónico** presente. Solo digest ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.3 «No lenguaje natural» (definición precisa)

**[LITERAL]** H.1: no lenguaje natural; el punto de aplicación no interpreta intenciones.

**[PROPUESTA]**

1. El Motor, en tipificación/clasificación (H.1/H.5), **solo interpreta campos tipados** del contrato EfectoTipado (enums, ids, `Tri`, digests, listas tipadas, refs de hijos).  
2. **Payloads o contenido de negocio** (cuerpo de correo, prompt, documento, JSON libre, bytes de fichero, etc.) pueden **referenciarse** como `BytesDigest`, blob opaco o id de objeto, **sin** que el Motor los lea para clasificar.  
3. Esos contenidos **nunca** se interpretan como intención normativa ni para elegir clase, mínimos, predicados o atributos H.5.  
4. Si un contenido **debe** cambiar clasificación o política, **debe entrar** como: (a) campo tipado del contrato, (b) **META** firmado, o (c) **HECHO** firmado — no como texto libre interpretado.  
5. Incluir texto libre en un campo tipado cerrado, o un campo `texto_intencion`, ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.4 Serialización y versiones

**[LITERAL]** G.1 / INV-14.

**[PROPUESTA]** Canon por versión; campos desconocidos ⇒ no tipificable; activación de versiones tras §8.

---

## 2. Reglas comunes de validación y fallo seguro

**[LITERAL]** H.1; H.5; G.2 sin salida permisiva por defecto; Motor sin inferir huecos; H.2 identidad por artefacto.

**[PROPUESTA]** Orden de validación:

| # | Comprobación | Fallo |
|---|---|---|
| V1 | Versión de esquema usable | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_declarada` ∈ doce | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | Parámetros §3; hijos EF-4; anti-recursión §6.1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | Digest + objeto canónico presentes | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | Solo campos tipados; regla §1.3 | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | Procedencia META/HECHO §4; atributos H.5 | §4–§5 |
| V7 | Composición de clases §5.2 | incompatibilidad ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |
| V8 | Si clase aplicada incluye EF-12 y sujeto autenticado es IA | tipificación puede cerrar; **autorización DENY** (§6.4) |

**[PROPUESTA]** «Bien formado» (H.1) = V1–V5.

---

## 3. Tabla EF-1…EF-12 — parámetros

**[LITERAL]** §C: ejemplos y mínimos; no esquema de campos.  
**[PROPUESTA]** Contrato siguiente. Ampliar enums ⇒ nueva versión.

### Tipos compartidos

| Tipo | Semántica **[PROPUESTA]** |
|---|---|
| `Tri` | `SI` \| `NO` \| `DESCONOCIDO` — nunca `DESCONOCIDO` como `NO` permisivo |
| `Reversibilidad` | `REVERSIBLE` \| `IRREVERSIBLE` \| `DESCONOCIDO` |
| `DestinatarioClase` | `NINGUNO` \| `SISTEMA` \| `PERSONA_IDENTIFICADA` \| `PERSONA_NO_IDENTIFICADA` \| `PUBLICO` \| `DESCONOCIDO` |
| `ClaseEfecto` | `EF-1`…`EF-12` |
| `RefEfectoHijo` | EfectoTipado embebido **o** `{ digest_efecto, esquema_version }` con objeto recuperable |
| `BytesDigest` / opaco | Referencia a contenido de negocio **sin** interpretación normativa (§1.3) |

**[PROPUESTA]** `destinatarios`: `[NINGUNO]` solo donde §3 lo permite. `DESCONOCIDO` ≠ `NINGUNO`.

Leyenda: **Obl** / **Opc** / **Proh**.

### EF-1 — Inferencia

**[LITERAL]** §C; mínimo según datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | |
| `destino_modelo` | Obl | Uri\|Id | |
| `contiene_datos_personales` | Obl | Tri | |
| `categoria_especial` | Opc | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` permitido si aún no hay entrega |
| `decide_sobre_personas` | Obl | Tri | |
| `entrada_digest` | Opc | BytesDigest | Prompt/entrada opaca; no interpretada (§1.3) |
| `codigo_arbitrario` | Proh | — | → EF-9 |
| `texto_intencion` | Proh | — | |

### EF-2 — Acceso a datos

**[LITERAL]** §C; categorías especiales ⇒ delegado.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum | |
| `recurso` | Obl | Id | |
| `contiene_datos_personales` | Obl | Tri | |
| `categoria_especial` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` si no hay reenvío |
| `decide_sobre_personas` | Obl | Tri | |
| `volumen_max` | Opc | u64 | |
| `escritura` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-3 — Escritura

**[LITERAL]** §C.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum | |
| `objetivo` | Obl | Id | |
| `reversibilidad` | Obl | Reversibilidad | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[SISTEMA]` o `[NINGUNO]` |
| `decide_sobre_personas` | Obl | Tri | |
| `payload_digest` | Opc | BytesDigest | Contenido opaco (§1.3) |
| `codigo_arbitrario` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-4 — Herramientas (compuesto, no recursivo)

**[LITERAL]** §C; delegado si produce EF-3/5/6/7.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `herramienta_id` | Obl | Id | |
| `efectos_hijos` | Obl | Lista[`RefEfectoHijo`] no vacía | Hijos tipados; **ningún hijo con `clase_declarada=EF-4`** (§6.1) |
| `argumentos_digest` | Obl | BytesDigest | Argumentos opacos (§1.3) |
| `invocacion_directa_no_mediada` | Proh | — | |
| `texto_intencion` | Proh | — | |
| `clases_producidas` (solo nombres) | Proh | — | |
| Hijo EF-4 | Proh | — | Recursión cerrada en v1r2 |

### EF-5 — Operación de negocio

**[LITERAL]** §C; delegado sin excepción.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_operacion` | Obl | Enum | |
| `contraparte` | Obl | Id | |
| `importe_digest` | Opc | BytesDigest | |
| `reversibilidad` | Obl | Reversibilidad | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | |
| `decide_sobre_personas` | Obl | Tri | |
| `texto_intencion` | Proh | — | |

### EF-6 — Comunicaciones

**[LITERAL]** §C.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal` | Obl | Enum | |
| `destinatarios` | Obl | Lista | Persona; **no** `[NINGUNO]` |
| `contiene_datos_personales` | Obl | Tri | |
| `decide_sobre_personas` | Obl | Tri | Puede ser NO |
| `reversibilidad` | Obl | Reversibilidad | |
| `cuerpo_digest` | Opc | BytesDigest | Cuerpo opaco (§1.3) |
| `texto_intencion` | Proh | — | |

### EF-7 — Publicación

**[LITERAL]** §C.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal_publicacion` | Obl | Id | |
| `destinatarios` | Obl | Lista | PUBLICO y/o persona; **no** `[NINGUNO]` |
| `contiene_datos_personales` | Obl | Tri | |
| `decide_sobre_personas` | Obl | Tri | Puede ser NO |
| `reversibilidad` | Obl | Reversibilidad | |
| `contenido_digest` | Opc | BytesDigest | Opaco (§1.3) |
| `texto_intencion` | Proh | — | |

### EF-8 — Decisión sobre personas

**[LITERAL]** Consumo; artefacto del canal de consumo.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_decision` | Obl | Enum | |
| `canal_consumo` | Obl | Id | |
| `artefacto_autoridad_consumo` | Obl | Id | |
| `sujeto_afectado_clase` | Obl | Enum | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | |
| `decide_sobre_personas` | Obl | Tri | Debe ser SI |
| `resultado_digest` | Opc | BytesDigest | Resultado opaco (§1.3) |
| `mediacion_en_inferencia` | Proh | — | |
| `texto_intencion` | Proh | — | |

**[PROPUESTA]** Persona en `destinatarios` + `decide_sobre_personas=NO` en EF-6/EF-7 **no** fuerza EF-8.

### EF-9 — Ejecución de código

**[LITERAL]** Eliminar o confinar; INV-11 si abierto.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | |
| `autoridad_ambiental` | Obl | Tri | |
| `superficie_atestada` | Opc | BytesDigest | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` permitido |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `artefacto_codigo_digest` | Opc | BytesDigest | Código como opaco; no interpretado como política (§1.3) |
| `capacidad_efector_solicitada` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-10 — Movimiento entre dominios

**[LITERAL]** §C; delegado con datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `destino_dominio` | Obl | Id\|Uri | |
| `jurisdiccion_destino` | Opc | código | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | No `[NINGUNO]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-11 — Físico / ciberfísico

**[LITERAL]** §C; PEP físico; aprobación humana previa.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `actuador_id` | Obl | Id | |
| `orden_digest` | Obl | BytesDigest | Orden opaca (§1.3) |
| `pep_fisico_presente` | Obl | Tri | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` o `[SISTEMA]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-12 — Cambio de gobierno

**[LITERAL]** Siempre DENY a IA; solo gobernanza humana con doble firma.  
**[LITERAL]** H.2: identidad por artefacto; campo de identidad de la petición ignorado.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `objeto_gobierno` | Obl | Enum | POLITICA / CORPUS / PERMISOS / PASAPORTE / IDENTIDAD / PROMPT_SISTEMA / MEMORIA_AGENTE / CONFIG_KERNEL |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` permitido |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `solicitante_es_ia` | Proh | — | **Eliminado en v1r2** — no declarar identidad en parámetros |
| `autorizacion_ia` | Proh | — | |

**[PROPUESTA]** Si el **solicitante autenticado** (artefacto → pasaporte) es un **sistema de IA**, toda solicitud cuya clase aplicada sea EF-12 ⇒ **autorización siempre DENY**. Gobierno humano **fuera** de EfectoTipado de sujetos IA (G.5 / fundacional / G.ET).

---

## 4. Procedencia de atributos H.5 y contrato META/HECHO

**[LITERAL]** H.5: tipificación/clasificación.  
**[LITERAL]** H.6: hechos firmados para contexto normativo; `DENY(EVIDENCIA_AUSENTE)` si exigidos ausentes/caducados.  
**[LITERAL]** Motor no completa huecos por inferencia.

### 4.0 Distinción de fases

**[PROPUESTA]**

| Fase | Función | Fallo típico |
|---|---|---|
| **H.5** | Tipificar y derivar los cinco atributos | `DENY(EFECTO_NO_TIPIFICADO)` |
| **H.6** | Admitir hechos firmados exigidos por normas / contexto posterior a la tipificación | `DENY(EVIDENCIA_AUSENTE)` |

**[PROPUESTA]** Un META/HECHO usado **para fijar un atributo H.5** que falle integridad/ámbito/caducidad ⇒ tipificación falla con `DENY(EFECTO_NO_TIPIFICADO)`.  
Un HECHO exigido solo como evidencia normativa **tras** tipificación válida (H.6 / requisitos L2) que falte o caduque ⇒ `DENY(EVIDENCIA_AUSENTE)` (**[LITERAL]** H.6), no se reinterpreta como «no tipificado» salvo que el esquema marque ese hecho como **precondición de tipificación**.

### 4.1 Códigos de fuente

**[PROPUESTA]**

| Código | Fuente |
|---|---|
| `PEP` | Declaración tipada del PEP en la solicitud |
| `META` | Metadato firmado de recurso/herramienta/catálogo |
| `HECHO` | Hecho firmado de productor registrado |
| `REGLA` | Regla determinista del esquema sobre datos ya tipados |

### 4.2 Contrato mínimo de procedencia (META y HECHO)

**[PROPUESTA]** Todo registro `META` o `HECHO` usable en H.5 (y, con el mismo esquema de campos, los HECHO de H.6) incluye **exactamente**:

| Campo | Semántica |
|---|---|
| `productor_id` | Productor registrado |
| `firma` | Firma verificable del productor |
| `emitido_en` | Instante de emisión (dato inyectado; el Motor no consulta reloj del sistema) |
| `expira_en` | Caducidad |
| `ambito_recurso` | Recurso/herramienta/efecto al que aplica |
| `atributo` | Nombre del atributo tipado (p. ej. `contiene_datos_personales`) |
| `valor` | Valor tipado |
| `digest_objeto` | Digest que vincula este registro al objeto canónico del efecto o recurso |

**[PROPUESTA]** Fallos de procedencia:

| Defecto | Si el registro alimenta **H.5** | Si el registro es solo evidencia **H.6** |
|---|---|---|
| Firma inválida | `DENY(EFECTO_NO_TIPIFICADO)` | `DENY(EVIDENCIA_AUSENTE)` / no entra (**[LITERAL]** ningún hecho sin firma) |
| Productor no registrado | `DENY(EFECTO_NO_TIPIFICADO)` | No entra / `DENY(EVIDENCIA_AUSENTE)` si exigido |
| Fuente caducada (`ahora` inyectado > `expira_en`) | `DENY(EFECTO_NO_TIPIFICADO)` si era necesaria para tipificar; si opcional, se ignora | Caducado ⇒ falso / `DENY(EVIDENCIA_AUSENTE)` si exigido (**[LITERAL]** H.6 espíritu) |
| `ambito_recurso` no aplicable al efecto | No usable; si no queda base ⇒ `DENY(EFECTO_NO_TIPIFICADO)` | No satisface el requisito |
| `digest_objeto` no vinculado al objeto del efecto | `DENY(EFECTO_NO_TIPIFICADO)` | No cuenta como evidencia de ese efecto |

### 4.3 Precedencia

**[PROPUESTA]** Orden: `HECHO` > `META` > `PEP` > `REGLA` (esta última no inventa hechos).  
`PEP` **no prevalece** sobre `META`/`HECHO` contradictorios.

### 4.4 Conflicto

| Conflicto | Conducta |
|---|---|
| PEP vs META/HECHO | Descartar PEP; registrar |
| META vs HECHO | HECHO; si incompatibles para tipificar ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |
| Dos HECHO incompatibles | `DENY(EFECTO_NO_TIPIFICADO)` |
| Sin base suficiente | `DENY(EFECTO_NO_TIPIFICADO)` o tratamiento conservador **aprobado** en fundacional — nunca ALLOW por omisión |

### 4.5 Derivación de atributos H.5

**[LITERAL]** Cinco atributos H.5.

**[PROPUESTA]**

| Atributo | Obtención |
|---|---|
| Clase | `clase_declarada` + composición §5.2 / §6 |
| Reversibilidad | META/HECHO > PEP; `DESCONOCIDO` ⇒ IRREVERSIBLE (REGLA) salvo otro tratamiento aprobado |
| Datos personales | META/HECHO > PEP; `DESCONOCIDO` ⇒ SI (REGLA) |
| Destinatarios | META/HECHO > PEP; reglas `[NINGUNO]` / `DESCONOCIDO` de §3–§5 |
| Decide sobre personas | META/HECHO > PEP; EF-8 ⇒ SI; `DESCONOCIDO` ⇒ SI (REGLA); **no** inferir por mero destinatario persona |

---

## 5. Ambigüedad y composición

**[LITERAL]** H.5 más restrictiva; Matriz sin orden total EF; §C mínimos; EF-12 DENY a IA.

**[PROPUESTA]** Sin orden total EF-1…EF-12. Composición:

1. Candidatas **compatibles** ⇒ conjunción de obligaciones y mínimos.  
2. Solo precedencias **explícitas** (Matriz o este contrato).  
3. **Incompatibles** sin regla de composición ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.  
4. EF-12 ⇒ autorización a IA siempre denegada (§6.4).

---

## 6. Reglas específicas EF-4, EF-8, EF-9, EF-12

### 6.1 EF-4 compuesto — cierre de recursión (v1r2)

**[LITERAL]** §C sobre herramientas que producen otras clases.

**[PROPUESTA — v1r2]**

1. `efectos_hijos` no vacía; cada hijo tipado y recuperable.  
2. Evaluar padre como EF-4 **y** cada hijo con sus parámetros/H.5.  
3. Composición §5.2 sobre {EF-4} ∪ clases de hijos.  
4. **Prohibido** que un hijo tenga `clase_declarada = EF-4` (no hay EF-4 anidado). Profundidad máxima de anidamiento de herramientas = **1** (padre EF-4 → solo hojas no-EF-4).  
5. Al expandir hijos: conjunto de `digest_efecto` visitados; si un digest se repite (ciclo por referencias) ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.  
6. Presupuesto determinista de expansión: acotado al cardinal de `efectos_hijos` del padre (sin recursión); exceder (p. ej. intento de anidar) ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.  
7. Prohibido sustituir hijos por nombres de clase sueltos.

*(Anidamiento EF-4 profundo queda fuera de v1r2; requeriría enmienda futura con profundidad máxima >1, DAG, digests visitados y presupuesto — no incluido aquí.)*

### 6.2 EF-8

**[LITERAL]** Consumo; artefacto del canal.

**[PROPUESTA]** Obligatorios: `canal_consumo`, `artefacto_autoridad_consumo`, `decide_sobre_personas=SI`.

### 6.3 EF-9

**[LITERAL]** Eliminar/confinar; INV-11.

**[PROPUESTA]** No reclasificar como EF-1…EF-8 «seguro». Código solo como digest opaco (§1.3).

### 6.4 EF-12

**[LITERAL]** Nunca a IA; DENY; gobernanza humana. H.2: identidad por artefacto.

**[PROPUESTA]** Identidad del solicitante **fuera** de parámetros. Autenticado como IA + clase aplicada EF-12 ⇒ **autorización DENY**. Gobierno humano no viaja como EfectoTipado de IA.

---

## 7. Compatibilidad, migración y reproducción histórica

**[LITERAL]** INV-14; citas; conservación histórica.

**[PROPUESTA]** Citar esquema + hash + objetos canónicos + META/HECHO usados (con sus digests). Recomputación bit a bit con la versión citada. Migración sin inferencia del Motor.

---

## 8. Gobernanza — enmienda fundacional y G.ET

**[LITERAL]** G.5 = paquetes; no cubre EfectoTipado por omisión. §C reapertura firmada.

### 8.A Enmienda fundacional

**[PROPUESTA]** G.ET no se auto-activa. Decisión humana firmada que: incorpora el Anexo; **crea G.ET**; opcionalmente habilita tabla inicial; fija entrada en vigor; mantiene D6 bloqueado hasta habilitación. Firmas ≥2 de N, jurídico + técnico distintos (espíritu G.5.4, sin cobertura G.5).

### 8.B G.ET posterior

**[PROPUESTA]** Tras 8.A: versiones futuras; tabla inicial solo si 8.A lo remite a G.ET. Etapas ET.1–ET.7 (propuesta/revisión/conformidad+diff/doble firma/sombra/activación/reversión).

### 8.C §C

**[LITERAL]** Reabrir §C si no encaja.  
**[PROPUESTA]** Nueva clase: §C + esquema vía G.ET (tras 8.A).

---

## 9. Decisiones humanas/normativas no automatizables

**[LITERAL]** INV-16; G.4; R8; G.1 interpretación.

**[PROPUESTA]** El Motor no decide: fundacional/versiones; tabla §3; tratamientos `DESCONOCIDO` no aprobados; composición no escrita; migraciones; reapertura §C; unificación G.ET/G.5; interpretación jurídica casuística; autorizar EF-12/gobierno; contenido de catálogos META; habilitar anidamiento EF-4 futuro.

---

## 10. Vectores de conformidad (propuestos)

**[LITERAL]** Espíritu L-31 / vectores de esquema.  
**[PROPUESTA]** Mínimos:

### 10.1 Por cada EF-1…EF-12

| Vector | Esperado |
|---|---|
| Aceptación mínima | Tipificable; H.5 determinista |
| Obligatorio ausente / prohibido / NL | `DENY(EFECTO_NO_TIPIFICADO)` |
| Digest ≠ canon / solo digest | `DENY(EFECTO_NO_TIPIFICADO)` |
| Payload solo como digest (sin interpretar) | Tipificable si resto ok |

### 10.2 Casos específicos

| Caso | Esperado |
|---|---|
| EF-4 + hijo EF-5 tipado | Padre+hijo; mínimos conjugados |
| EF-4 solo nombres de clase | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-4 hijo no recuperable | `DENY(EFECTO_NO_TIPIFICADO)` |
| **EF-4 hijo EF-4** | `DENY(EFECTO_NO_TIPIFICADO)` |
| **Ciclo** de digests en refs de hijos | `DENY(EFECTO_NO_TIPIFICADO)` |
| **Profundidad excedida** (>1 anidamiento herramienta) | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-8 sin canal/artefacto o decide≠SI | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-6 persona + decide=NO | Tipificable EF-6 |
| EF-9 reclasificado a EF-1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| EF-12 + sujeto autenticado IA | Autorización **DENY** (identidad fuera de parámetros) |
| Parámetro `solicitante_es_ia` presente | `DENY(EFECTO_NO_TIPIFICADO)` (campo prohibido) |
| DESCONOCIDO en atributos | §4.5; nunca ALLOW por omisión |
| META/HECHO firma inválida / productor no registrado / caducado / ámbito / digest no vinculado (H.5) | `DENY(EFECTO_NO_TIPIFICADO)` |
| HECHO H.6 exigido ausente/caducado tras tipificación ok | `DENY(EVIDENCIA_AUSENTE)` |
| PEP vs META/HECHO | Prevalece META/HECHO |
| Dos HECHO conflictivos | `DENY(EFECTO_NO_TIPIFICADO)` |
| Recomputación histórica misma versión+objetos | Igual bit a bit |
| Texto libre interpretado como política | `DENY(EFECTO_NO_TIPIFICADO)` |

---

## 11. Criterio de cierre

**[PROPUESTA]** Vigencia solo con: fundacional 8.A; tabla operativa habilitada; vectores §10 verdes; D6 no implementado antes.

---

## Apéndice A — LITERAL ↔ hueco

| Exigencia | Hoy | v1r2 |
|---|---|---|
| H.1 tipado / no NL | Parcial | §1.3, §3 |
| H.5 | No | §4–§5 |
| H.2 identidad | Sí en Matriz | EF-12 sin `solicitante_es_ia` |
| H.6 vs H.5 | Confundible | §4.0 |
| EF-4 recursión | Abierta en v1r1 | Cerrada §6.1 |
| D6 | Bloqueado | Bloqueado |

---

NO VIGENTE · NO APROBADO · NO IMPLEMENTABLE · D6 BLOQUEADO
