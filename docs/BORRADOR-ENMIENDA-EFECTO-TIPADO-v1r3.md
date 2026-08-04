# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1r3

**Estado:** BORRADOR para revisión humana adversarial · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** · **D6 BLOQUEADO**  
**Precede:** `BORRADOR-ENMIENDA-EFECTO-TIPADO-v1r2.md` (borrador de revisión; no vigente).  
**Destino propuesto:** Anexo EfectoTipado de la Matriz Maestra Canónica v1.1 + enmienda fundacional que crea G.ET.  
**Objetivo:** cerrar la omisión entre **H.1** y **H.5**.  
**Fecha de redacción:** 2026-07-30.  
**Nota:** No iniciar enmienda fundacional ni implementación a partir de este texto.

### Convención tipográfica

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación. **No** afirma que G.5 cubra este artefacto. |

---

## Cambios respecto de v1r2

| # | Tema | Cambio en v1r3 |
|---|---|---|
| 1 | Clase solicitada vs aplicada | Campo renombrado a `clase_solicitada` (candidata tipada del PEP, no clasificación cerrada ni autoridad). `clase_aplicada` es salida determinista de H.5. Discrepancia: ambas en evidencia; composición de candidatas o `DENY(EFECTO_NO_TIPIFICADO)`. La solicitada no oculta una clase más restrictiva. |
| 2 | META de catálogo | Campos mínimos adicionales: `catalogo_id`, `catalogo_version`, `autoridad_emisora`, `digest_catalogo`, vigencia. META solo de catálogo aprobado/firmado/vigente/versionado/inmovilizado. Decisión cita ids y digests. «Incluye como mínimo» (extensiones versionadas y tipificadas). |
| 3 | EF-12 | Taxonomía descriptiva para clasificar/registrar/detectar intentos; **no** interfaz H.1–H.16 de solicitud/autorización/capacidad/ejecución. Ningún solicitante (IA o humano) recibe capacidad EF-12 por esa cadena. Gobierno humano solo fuera de H, con doble firma. Petición H.1 de EF-12 ⇒ registro + **DENY** siempre. |
| 4 | Tiempo determinista | Vigencia contra `epoca_contexto` / hecho de tiempo firmado inyectado y comprometido en evidencia. Motor sin reloj/red/estado externo. Vectores nuevos (§10). |

---

## 0. Motivación y alcance

**[LITERAL]** H.1: efecto tipado con clase y parámetros; no lenguaje natural; bien formado; clase ∈ doce; `DENY(EFECTO_NO_TIPIFICADO)`.  
**[LITERAL]** H.5: deriva clase, reversibilidad, datos personales, destinatarios, si decide sobre personas; ambigüedad ⇒ más restrictiva.  
**[LITERAL]** H.2: campo de identidad de la petición ignorado; identidad por artefacto.  
**[LITERAL]** H.6: hechos firmados; `DENY(EVIDENCIA_AUSENTE)`; ningún hecho sin firma.  
**[LITERAL]** §E Motor: sin reloj, entropía, red ni disco; no completar huecos por inferencia. INV-14.  
**[LITERAL]** §C EF-12: siempre DENY; cambio solo por gobernanza con doble firma humana; no emitible a IA.  
**[LITERAL]** G.5 ≠ contrato EfectoTipado.

**[PROPUESTA]** Este borrador define EfectoTipado, `clase_solicitada`/`clase_aplicada`, parámetros, H.5, META de catálogo, anti-recursión EF-4, EF-12 no-vía-H, tiempo por época inyectada, G.ET tras fundacional, y vectores.

**[PROPUESTA]** **D6 bloqueado.** No enmienda fundacional ni implementación desde v1r3.

---

## 1. Objeto canónico EfectoTipado

### 1.1 Definición

**[LITERAL]** «Efecto tipado con clase y parámetros» (H.1); clases `EF-1`…`EF-12` (§C).

**[PROPUESTA]** **EfectoTipado** (entrada de solicitud) consta de:

| Campo | Tipo | Obl. | Semántica |
|---|---|---|---|
| `esquema_id` | string fija | sí | p. ej. `efecto-tipado` |
| `esquema_version` | u32 | sí | Versión del contrato |
| `clase_solicitada` | enum EF-1…EF-12 | sí | **Candidata tipada** aportada por el PEP; **no** es clasificación cerrada ni autoridad (§1.5) |
| `parametros` | objeto tipado §3 | sí | Parámetros asociados a la solicitud |
| `digest_parametros` | SHA-384 dominio | sí | Digest de `canon(parametros)` |

**[PROPUESTA]** Alias: el nombre `clase_declarada` de borradores previos queda **retirado**; si aparece en un mensaje ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

**[PROPUESTA]** Identidad del solicitante **fuera** de EfectoTipado (H.2).

### 1.5 `clase_solicitada` frente a `clase_aplicada`

**[LITERAL]** H.5 produce «Clase … aplicados» como evidencia del Motor. H.1 valida que la clase (de la solicitud tipada) sea una de las doce.

**[PROPUESTA]**

| Término | Rol |
|---|---|
| `clase_solicitada` | Entrada: candidata tipada del PEP. Forma parte del efecto tipado. **No** cierra la clasificación. **No** otorga autoridad ni elude mínimos. |
| `clase_aplicada` | Salida determinista de **H.5**: de parámetros tipados, META/HECHO válidos y composición aprobada (§5). |
| `clases_candidatas` | Conjunto usado en composición: incluye `clase_solicitada`, clases de hijos EF-4, y clases impuestas por META/HECHO/reglas §6. |

**[PROPUESTA]** Si `clase_solicitada` ≠ `clase_aplicada` (o el conjunto de candidatas no se reduce a una sola clase sin composición):

1. La evidencia de H.5 **conserva ambas** (solicitada y aplicada) y el conjunto de candidatas.  
2. Se aplican **todas** las obligaciones y mínimos de las candidatas **compatibles** (§5), o `DENY(EFECTO_NO_TIPIFICADO)` si no hay composición aprobada.  
3. `clase_solicitada` **no puede ocultar** una clase más restrictiva exigida por parámetros, hijos, META o HECHO (p. ej. solicitar EF-1 cuando los datos tipificados imponen EF-8).

### 1.2 Digest

**[LITERAL]** Digests en recibos/capacidades.

**[PROPUESTA]** Digest vincula e inmoviliza; no sustituye el objeto canónico para H.5. Solo digest ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.3 «No lenguaje natural»

**[LITERAL]** H.1: no NL; no interpretar intenciones.

**[PROPUESTA]** Motor solo interpreta campos tipados del contrato. Payloads/contenido de negocio solo por bytes/digest/objeto opaco; nunca como intención normativa. Para cambiar clasificación/política ⇒ campo tipado, META o HECHO. Texto libre / `texto_intencion` ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.4 Tiempo determinista (vigencia)

**[LITERAL]** INV-14 / §E Motor: sin reloj, red, entropía ni disco; tiempo como hecho inyectado.

**[PROPUESTA]**

1. Se retira la evaluación de vigencia contra un reloj del proceso.  
2. Todo juicio `emitido`/`expira` de META/HECHO se evalúa contra una **`epoca_contexto`** (o hecho de tiempo firmado equivalente) **inyectada** al Motor como dato del contexto tipado y **comprometida** en la evidencia de la decisión.  
3. Campos de procedencia pueden llamarse `emitido_en_epoca` / `expira_en_epoca` (enteros de época) o instantes relativos a la época; lo normativo es: comparación solo con `epoca_contexto` inyectada.  
4. El Motor **no** consulta reloj del sistema, red ni estado externo para caducidad.  
5. Recomputación histórica usa la **misma** `epoca_contexto` citada.

### 1.6 Serialización y versiones

**[LITERAL]** G.1 / INV-14.  
**[PROPUESTA]** Canon por versión; campos desconocidos no tipificados por el Motor salvo tipificación en versión aprobada (§4.2 extensiones).

---

## 2. Validación y fallo seguro

**[LITERAL]** H.1; H.5; G.2 sin salida permisiva; Motor sin inferir huecos.

**[PROPUESTA]** Orden:

| # | Comprobación | Fallo |
|---|---|---|
| V1 | Versión de esquema usable | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_solicitada` ∈ doce | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | Parámetros §3; hijos EF-4; anti-recursión | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | Digest + objeto canónico | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | Solo tipado (§1.3) | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | META/HECHO + `epoca_contexto` (§4) | §4 |
| V7 | H.5 → `clase_aplicada` + atributos; composición (§1.5, §5) | incompatibilidad ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |
| V8 | Si candidatas/aplicada incluyen EF-12 | tipificación descriptiva posible; **fin en DENY** de autorización (§6.4); **sin capacidad** |

**[PROPUESTA]** «Bien formado» (H.1) = V1–V5 (clase solicitada ∈ doce y parámetros tipados); **no** implica que `clase_solicitada` sea la aplicada.

---

## 3. Tabla EF-1…EF-12 — parámetros

**[LITERAL]** §C ejemplos y mínimos.  
**[PROPUESTA]** Contrato de campos. Enums cerrados; ampliar ⇒ nueva versión.

### Tipos compartidos

| Tipo | Semántica **[PROPUESTA]** |
|---|---|
| `Tri` | SI \| NO \| DESCONOCIDO — DESCONOCIDO nunca como NO permisivo |
| `Reversibilidad` | REVERSIBLE \| IRREVERSIBLE \| DESCONOCIDO |
| `DestinatarioClase` | NINGUNO \| SISTEMA \| PERSONA_IDENTIFICADA \| PERSONA_NO_IDENTIFICADA \| PUBLICO \| DESCONOCIDO |
| `ClaseEfecto` | EF-1…EF-12 |
| `RefEfectoHijo` | EfectoTipado embebido o `{ digest_efecto, esquema_version }` recuperable |
| `BytesDigest` | Contenido de negocio opaco (§1.3) |
| `Epoca` | Entero de época de contexto / emisión / expiración |

**[PROPUESTA]** `[NINGUNO]` en `destinatarios` solo donde la fila lo permita.  
Leyenda: **Obl** / **Opc** / **Proh**. Ningún parámetro declara identidad del solicitante.

### EF-1 — Inferencia

**[LITERAL]** §C; mínimo según datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | |
| `destino_modelo` | Obl | Uri\|Id | |
| `contiene_datos_personales` | Obl | Tri | |
| `categoria_especial` | Opc | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` si aún no hay entrega |
| `decide_sobre_personas` | Obl | Tri | |
| `entrada_digest` | Opc | BytesDigest | Opaco (§1.3) |
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
| `payload_digest` | Opc | BytesDigest | |
| `codigo_arbitrario` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-4 — Herramientas (compuesto, no recursivo)

**[LITERAL]** §C; delegado si produce EF-3/5/6/7.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `herramienta_id` | Obl | Id | |
| `efectos_hijos` | Obl | Lista[`RefEfectoHijo`] no vacía | Hijos tipados; **ningún hijo con `clase_solicitada=EF-4`** |
| `argumentos_digest` | Obl | BytesDigest | Opaco |
| `invocacion_directa_no_mediada` | Proh | — | |
| `texto_intencion` | Proh | — | |
| `clases_producidas` (solo nombres) | Proh | — | |
| Hijo EF-4 | Proh | — | §6.1 |

**[PROPUESTA]** `efectos_hijos` no vacía; profundidad 1; digests visitados; ciclo ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

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
| `cuerpo_digest` | Opc | BytesDigest | |
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
| `contenido_digest` | Opc | BytesDigest | |
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
| `resultado_digest` | Opc | BytesDigest | |
| `mediacion_en_inferencia` | Proh | — | |
| `texto_intencion` | Proh | — | |

### EF-9 — Ejecución de código

**[LITERAL]** Eliminar o confinar; INV-11.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum | |
| `autoridad_ambiental` | Obl | Tri | |
| `superficie_atestada` | Opc | BytesDigest | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` permitido |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `artefacto_codigo_digest` | Opc | BytesDigest | Opaco; no política |
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
| `orden_digest` | Obl | BytesDigest | |
| `pep_fisico_presente` | Obl | Tri | |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` o `[SISTEMA]` |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `texto_intencion` | Proh | — | |

### EF-12 — parámetros (solo taxonomía de intento)

**[LITERAL]** §C: DENY; gobernanza humana con doble firma; no emitible a IA.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `objeto_gobierno` | Obl | Enum | Objeto que el intento pretende alterar (descriptivo) |
| `contiene_datos_personales` | Obl | Tri | |
| `destinatarios` | Obl | Lista | `[NINGUNO]` permitido |
| `decide_sobre_personas` | Obl | Tri | |
| `reversibilidad` | Obl | Reversibilidad | |
| `solicitante_es_ia` | Proh | — | Retirado (v1r2) |
| Capacidad / ALLOW / ejecución vía H | Proh | — | §6.4 |

**[PROPUESTA]** Ver §6.4: EF-12 **no** es vía humana ni de IA sobre H.1–H.16.

---

## 4. Procedencia H.5, META de catálogo y HECHO

**[LITERAL]** H.5 tipificación; H.6 hechos firmados / `EVIDENCIA_AUSENTE`; Motor sin inferir.

### 4.0 Distinción de fases

**[PROPUESTA]**

| Fase | Función | Fallo típico |
|---|---|---|
| H.5 | Tipificar; `clase_aplicada` + atributos | `DENY(EFECTO_NO_TIPIFICADO)` |
| H.6 | Evidencia normativa firmada posterior | `DENY(EVIDENCIA_AUSENTE)` |

### 4.1 Fuentes

**[PROPUESTA]** `HECHO` > `META` > `PEP` > `REGLA`. PEP no prevalece sobre META/HECHO.

### 4.2 Contrato mínimo META / HECHO («como mínimo»)

**[PROPUESTA]** Todo registro META o HECHO usable **incluye como mínimo**:

| Campo | Semántica |
|---|---|
| `productor_id` | Productor registrado |
| `firma` | Firma verificable |
| `emitido_en_epoca` | Época de emisión (comparar con `epoca_contexto`) |
| `expira_en_epoca` | Época de caducidad |
| `ambito_recurso` | Ámbito de aplicación |
| `atributo` | Atributo tipado |
| `valor` | Valor tipado |
| `digest_objeto` | Vínculo al objeto del efecto/recurso |

**[PROPUESTA]** Además, todo **META de catálogo** incluye **como mínimo**:

| Campo | Semántica |
|---|---|
| `catalogo_id` | Identificador del catálogo aprobado |
| `catalogo_version` | Versión inmutable del catálogo |
| `autoridad_emisora` | Autoridad que firmó/aprobó el catálogo |
| `digest_catalogo` | Digest que inmoviliza el catálogo en esa versión |
| vigencia | Expresada vía `emitido_en_epoca` / `expira_en_epoca` respecto de `epoca_contexto` |

**[PROPUESTA]** META solo es usable si procede de un **catálogo aprobado, firmado, vigente** (según `epoca_contexto`), **versionado** e **inmovilizado** por `digest_catalogo`. La decisión **cita** `catalogo_id`, `catalogo_version`, `autoridad_emisora` y `digest_catalogo` para recomputación histórica.

**[PROPUESTA]** «Incluye como mínimo» (no «exactamente»): se permiten **extensiones** de campos **solo si** (1) están en una versión de esquema/catálogo **aprobada**, (2) se **canonizan** de forma determinista en el digest, y (3) el Motor **no las interpreta** salvo que esa versión aprobada las **tipifique** explícitamente. Extensión no tipificada ⇒ ignorada para H.5 o, si aparece donde se exige esquema cerrado del efecto, `DENY(EFECTO_NO_TIPIFICADO)`.

### 4.3 Fallos de procedencia

| Defecto | Alimenta H.5 | Solo H.6 |
|---|---|---|
| Firma inválida / productor no registrado | `DENY(EFECTO_NO_TIPIFICADO)` | No entra / `DENY(EVIDENCIA_AUSENTE)` si exigido |
| Caducado vs `epoca_contexto` | `DENY(EFECTO_NO_TIPIFICADO)` si necesario para tipificar | Caducado ⇒ no satisface / `DENY(EVIDENCIA_AUSENTE)` |
| Ámbito no aplicable / digest no vinculado | `DENY(EFECTO_NO_TIPIFICADO)` o no usable | No cuenta |
| Catálogo no aprobado / versión o digest no coincidente / catálogo no vigente en `epoca_contexto` | META no usable; sin base ⇒ `DENY(EFECTO_NO_TIPIFICADO)` | — |

### 4.4 Derivación atributos H.5

**[LITERAL]** Cinco atributos.

**[PROPUESTA]** Clase = `clase_aplicada` (§1.5). Resto: META/HECHO > PEP; DESCONOCIDO con REGLA conservadora (SI / IRREVERSIBLE); no inferir «decide» por mero destinatario persona.

---

## 5. Composición y «más restrictiva»

**[LITERAL]** H.5; sin orden total EF en Matriz; mínimos §C.

**[PROPUESTA]** Sin ranking ordinal EF. Candidatas compatibles ⇒ conjunción de obligaciones/mínimos. Solo precedencias explícitas. Incompatibles ⇒ `DENY(EFECTO_NO_TIPIFICADO)`. Solicitada no oculta candidata más restrictiva (§1.5).

---

## 6. Reglas específicas

### 6.1 EF-4

**[LITERAL]** §C herramienta / produce otras clases.  
**[PROPUESTA]** Hijos tipados; no EF-4 hijo; profundidad 1; ciclos DENY; composición de candidatas incluye clases de hijos.

### 6.2 EF-8

**[LITERAL]** Consumo; artefacto del canal.  
**[PROPUESTA]** `canal_consumo`, `artefacto_autoridad_consumo`, `decide_sobre_personas=SI`.

### 6.3 EF-9

**[LITERAL]** Eliminar/confinar; INV-11.  
**[PROPUESTA]** No reclasificar como «seguro»; código solo digest opaco.

### 6.4 EF-12 — taxonomía, no vía H

**[LITERAL]** §C: siempre DENY; no emitible; cambio solo por gobernanza con doble firma humana.

**[PROPUESTA]**

1. EF-12 es **taxonomía descriptiva** para **clasificación, registro y detección de intentos**.  
2. EF-12 **no** es interfaz de **solicitud autorizable**, **autorización**, **capacidad** ni **ejecución** en la cadena **H.1–H.16**.  
3. **Ningún** solicitante —**IA o humano**— recibe una **capacidad EF-12** por H.1–H.16.  
4. Todo **cambio humano de gobierno** ocurre **exclusivamente fuera** de esa cadena, por la vía de gobernanza aplicable (G.5 / fundacional / G.ET), con **doble firma humana**.  
5. Una petición que llega por **H.1** con `clase_solicitada=EF-12` (o `clase_aplicada`/candidatas que incluyan EF-12) se **registra** y **termina en DENY** de autorización, **con independencia** de la identidad autenticada (IA o humana).  
6. No existe camino ALLOW ni emisión de capacidad EF-12 en H.12.

---

## 7. Compatibilidad e historia

**[LITERAL]** INV-14; citas.  
**[PROPUESTA]** Citar esquema, digests de efecto, `clase_solicitada`, `clase_aplicada`, candidatas, META (incl. ids/digests de catálogo), HECHO, y **`epoca_contexto`**. Recomputación con los mismos valores.

---

## 8. Gobernanza

**[LITERAL]** G.5 = paquetes; no cubre EfectoTipado por omisión.  
**[PROPUESTA]** **8.A** Enmienda fundacional (crea G.ET; no circular). **8.B** G.ET posterior. **D6 bloqueado** hasta habilitación. **No iniciar 8.A desde este borrador.**

---

## 9. No automatizable

**[LITERAL]** INV-16; G.4; R8.  
**[PROPUESTA]** Fundacional; tabla §3; composición no escrita; catálogos aprobados; migraciones; reapertura §C; EF-12/gobierno; tipificación de extensiones META; anidamiento EF-4 futuro.

---

## 10. Vectores de conformidad

**[PROPUESTA]** Incluyen los de v1r2 y, además:

| Caso | Esperado |
|---|---|
| Aceptación / rechazo básicos por EF | Como v1r2 |
| EF-4 hijo EF-4 / ciclo / profundidad >1 | `DENY(EFECTO_NO_TIPIFICADO)` |
| **`clase_solicitada` «menor» / distinta de `clase_aplicada`** (p. ej. solicitada EF-1, aplicada/candidatas imponen EF-8) | Evidencia conserva ambas; aplicación de mínimos de candidatas compatibles **o** `DENY(EFECTO_NO_TIPIFICADO)` si no hay composición; solicitada no elude |
| Solicitada oculta restrictiva sin composición | `DENY(EFECTO_NO_TIPIFICADO)` |
| **META catálogo no aprobado** | No usable; tipificación falla si dependía de él → `DENY(EFECTO_NO_TIPIFICADO)` |
| **Versión o `digest_catalogo` no coincidente** | Idem |
| **Catálogo no vigente** en `epoca_contexto` | Idem |
| Decisión sin citar ids/digests de catálogo usado | No conforme / no recomputable |
| Extensión META no tipificada interpretada por Motor | Prohibido; DENY o ignorar según §4.2 |
| **Petición H.1 EF-12 autenticada como humana** | Registro + **DENY** autorización; **sin** capacidad |
| Petición H.1 EF-12 autenticada como IA | Registro + **DENY** |
| HECHO H.6 ausente tras tipificación ok | `DENY(EVIDENCIA_AUSENTE)` |
| **Recomputación histórica de vigencia** con la **misma** `epoca_contexto` | Mismo resultado bit a bit |
| Recomputación cambiando `epoca_contexto` | Puede diferir; no alegable como el histórico citado |
| Motor consulta reloj del sistema | Prohibido / harness de pureza falla |

---

## 11. Criterio de cierre

**[PROPUESTA]** Solo tras fundacional firmada, tabla operativa habilitada, vectores verdes, y constancia de no implementar D6 antes. **v1r3 no autoriza ese inicio.**

---

## Apéndice A — LITERAL ↔ hueco

| Exigencia | Hoy | v1r3 |
|---|---|---|
| H.1 / H.5 | Hueco de esquema | Borrador §§1–5 |
| Clase solicitada ≠ autoridad | Implícito | §1.5 explícito |
| Catálogo META | Parcial v1r2 | §4.2 completo |
| EF-12 vía H | Riesgo de malentendido | §6.4 cierre |
| Tiempo puro | INV-14 | §1.4 `epoca_contexto` |
| D6 | Bloqueado | Bloqueado |

---

NO VIGENTE · NO APROBADO · NO IMPLEMENTABLE · D6 BLOQUEADO
