# BORRADOR NO VINCULANTE — Enmienda EfectoTipado v1

**Estado:** BORRADOR · **NO VIGENTE** · **NO APROBADO** · **NO IMPLEMENTABLE** como norma.  
**Destino propuesto:** anexo / sección nueva de la Matriz Maestra Canónica v1.1 (p. ej. **§C.bis** o **Anexo ET**), más extensión explícita de gobernanza (§8 de este borrador).  
**Objetivo:** cerrar la omisión entre **H.1** («efecto tipado con clase y parámetros») y **H.5** (derivación de cinco atributos).  
**Fecha de redacción:** 2026-07-30.

### Convención tipográfica de este borrador

| Etiqueta | Significado |
|---|---|
| **[LITERAL]** | Texto o exigencia ya existente en la Matriz v1.1 (u otra cita canónica vigente citada). No se presenta como novedad. |
| **[PROPUESTA]** | Texto nuevo. Requiere aprobación humana/gobernanza antes de ser vinculante. **No** afirma que G.5 ya cubra este artefacto. |

---

## 0. Motivación y alcance

**[LITERAL]** H.1: «Efecto tipado con clase y parámetros. **No lenguaje natural**… Que el efecto está bien formado y su clase es una de las doce… Efecto no tipificable ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.»  
**[LITERAL]** H.5: entradas «Parámetros del efecto»; verifica «Clase, reversibilidad, presencia de datos personales, destinatarios, si decide sobre personas»; «Clasificación ambigua ⇒ se toma la más restrictiva»; evidencia «Clase y atributos aplicados»; responsable «Motor de decisión».  
**[LITERAL]** §C: doce clases; «Un efecto que no encaje en ninguna obliga a reabrir esta sección con decisión firmada.»  
**[LITERAL]** §E Motor: autoridad prohibida incluye «Completar huecos normativos por inferencia»; función pura; sin red, reloj, entropía ni disco.  
**[LITERAL]** INV-16: el Kernel no produce ni certifica interpretación jurídica.  
**[LITERAL]** G.5: gobierna **paquetes normativos**, no (hoy) el contrato de solicitud de efecto.

**[PROPUESTA]** Este documento define el artefacto canónico **EfectoTipado**, el esquema de parámetros por clase, las reglas deterministas de H.5 y un **procedimiento de gobernanza propio** (G.ET), distinto de G.5 salvo remisión explícita.

**[PROPUESTA]** Hasta la activación de la primera versión firmada de EfectoTipado, **D6 (clasificación H.5) permanece bloqueado** por laguna de especificación.

---

## 1. Objeto canónico EfectoTipado, versión y serialización

### 1.1 Definición

**[LITERAL]** Existe la noción de «efecto tipado con clase y parámetros» (H.1) y la lista cerrada `EF-1`…`EF-12` (§C; G.1 campo `clase_de_efecto`).

**[PROPUESTA]** **EfectoTipado** es el objeto canónico de solicitud de efecto. Consta exactamente de:

| Campo | Tipo | Obligatorio | Semántica |
|---|---|---|---|
| `esquema_id` | string fija | sí | Identificador del contrato (p. ej. `efecto-tipado`) |
| `esquema_version` | u32 | sí | Versión del esquema EfectoTipado |
| `clase_declarada` | enum `EF-1`…`EF-12` | sí | Clase afirmada por el punto de aplicación |
| `parametros` | objeto tipado según §3 | sí | Parámetros de la clase (pueden ser vacíos solo si la tabla lo permite) |
| `digest_parametros` | SHA-384 con separación de dominio | sí | Digest del objeto `parametros` en forma canónica |

**[PROPUESTA]** El Motor **no** inventa campos. Solo valida contra la versión de esquema citada y activa.

### 1.2 Serialización determinista

**[LITERAL]** G.1: «serialización determinista y con esquema publicado» (aplicado a normas). INV-14: decisión reproducible.

**[PROPUESTA]** La misma disciplina se aplica a EfectoTipado:

1. Codificación canónica publicada con la versión del esquema.  
2. Orden lexicográfico de claves; sin campos desconocidos tolerados.  
3. `digest_parametros = SHA-384(dominio ‖ canon(parametros))`.  
4. Dos representaciones distintas del mismo contenido semántico están **prohibidas**; el rechazo es `DENY(EFECTO_NO_TIPIFICADO)`.

### 1.3 Versiones

**[PROPUESTA]** Cada versión de EfectoTipado es un artefacto firmado e inmutable (hash + firmas G.ET). La versión activa del dominio se fija por época, análoga en espíritu a G.5.6, pero bajo **G.ET** (§8), no bajo G.5 salvo enmienda que lo unifique.

---

## 2. Reglas comunes de validación y fallo seguro

**[LITERAL]** H.1: bien formado; clase ∈ doce; no tipificable ⇒ `DENY(EFECTO_NO_TIPIFICADO)`; sin lenguaje natural.  
**[LITERAL]** H.5: ambigüedad ⇒ más restrictiva.  
**[LITERAL]** G.2 R2: ínfimo; «En ninguna de las ocho reglas la salida por defecto es permisiva.»  
**[LITERAL]** §E Motor: no completar huecos por inferencia.

**[PROPUESTA]** Orden de validación (determinista, sin salida permisiva por defecto):

| # | Comprobación | Fallo |
|---|---|---|
| V1 | `esquema_version` es la activa o una permitida en reconstrucción histórica | `DENY(EFECTO_NO_TIPIFICADO)` |
| V2 | `clase_declarada` ∈ {EF-1…EF-12} | `DENY(EFECTO_NO_TIPIFICADO)` |
| V3 | `parametros` conforme a la fila de §3 (obligatorios presentes; prohibidos ausentes; tipos correctos) | `DENY(EFECTO_NO_TIPIFICADO)` |
| V4 | `digest_parametros` coincide con el digest recomputado | `DENY(EFECTO_NO_TIPIFICADO)` |
| V5 | No hay campos desconocidos ni lenguaje natural | `DENY(EFECTO_NO_TIPIFICADO)` |
| V6 | Derivación H.5 (§4–§5); si ambigüedad, §5 | atributos aplicados (evidencia H.5) |
| V7 | Si clase derivada ≠ `clase_declarada` | aplicar §5 (restrictiva) y registrar divergencia; **no** ALLOW por la declarada |

**[PROPUESTA]** «Bien formado» (H.1) = V1–V5 satisfechos.

---

## 3. Tabla EF-1…EF-12 — parámetros

**[LITERAL]** §C aporta **ejemplos** y mínimos de garantía; **no** un contrato de campos.  
**[PROPUESTA]** La tabla siguiente es el contrato propuesto. Tipos: `Id`, `Uri`, `Enum`, `Bool`, `BytesDigest`, `Lista[T]`, `Mapa` tipado cerrado.  
**[PROPUESTA]** Valores de enum cerrados se publican con la versión del esquema; ampliar un enum es **nueva versión** G.ET.

### Tipos compartidos (propuestos)

| Tipo | Semántica propuesta |
|---|---|
| `Tri` | `SI` \| `NO` \| `DESCONOCIDO` — nunca se trata `DESCONOCIDO` como `NO` permisivo |
| `Reversibilidad` | `REVERSIBLE` \| `IRREVERSIBLE` \| `DESCONOCIDO` |
| `DestinatarioClase` | `NINGUNO` \| `SISTEMA` \| `PERSONA_IDENTIFICADA` \| `PERSONA_NO_IDENTIFICADA` \| `PUBLICO` \| `DESCONOCIDO` |
| `ClaseEfecto` | `EF-1`…`EF-12` |

### Filas por clase

Leyenda: **Obl** = obligatorio; **Opc** = opcional; **Proh** = prohibido (si aparece ⇒ no tipificable).

#### EF-1 — Inferencia y servicios de modelo

**[LITERAL]** Ejemplos §C: llamada a modelo, embeddings, clasificación, transcripción; mínimo depende de datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica propuesta |
|---|---|---|---|
| `modo` | Obl | Enum(`INFERENCIA`,`EMBEDDING`,`CLASIFICACION`,`TRANSCRIPCION`,`OTRO`) | Tipo de servicio |
| `destino_modelo` | Obl | `Uri` o `Id` de punto de servicio | Destino mediado |
| `contiene_datos_personales` | Obl | `Tri` | Declaración tipada; no lenguaje natural |
| `categoria_especial` | Opc | `Tri` | Solo si `contiene_datos_personales=SI` |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` no vacía | Quién recibe salida |
| `decide_sobre_personas` | Obl | `Tri` | Si la salida alimenta decisión sobre personas |
| `codigo_arbitrario` | Proh | — | Empujar a EF-9 |
| `texto_intencion` | Proh | — | Lenguaje natural (H.1) |

#### EF-2 — Acceso y tratamiento de datos

**[LITERAL]** §C: consulta, lectura, RAG, expediente, transformación; categorías especiales ⇒ delegado.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum(`LECTURA`,`CONSULTA`,`RAG`,`EXPEDIENTE`,`TRANSFORMACION`) | |
| `recurso` | Obl | `Id` | Recurso o almacén |
| `contiene_datos_personales` | Obl | `Tri` | |
| `categoria_especial` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `volumen_max` | Opc | u64 | Límite declarado |
| `escritura` | Proh | — | Empujar a EF-3 |
| `texto_intencion` | Proh | — | |

#### EF-3 — Escritura y cambio de estado

**[LITERAL]** §C: INSERT/UPDATE/borrado/fichero/configuración.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `operacion` | Obl | Enum(`INSERT`,`UPDATE`,`BORRADO`,`FICHERO`,`CONFIG`) | |
| `objetivo` | Obl | `Id` | Recurso mutado |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `codigo_arbitrario` | Proh | — | → EF-9 |
| `texto_intencion` | Proh | — | |

#### EF-4 — Herramientas y conectores

**[LITERAL]** §C: función, MCP, API, webhook; «delegado si la herramienta produce EF-3, EF-5, EF-6 o EF-7».

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `herramienta_id` | Obl | `Id` | Herramienta registrada en pasaporte |
| `clases_producidas` | Obl | `Lista[ClaseEfecto]` no vacía | Efectos que la invocación puede producir (§6) |
| `argumentos_digest` | Obl | `BytesDigest` | Digest de argumentos tipados de la herramienta |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | De la consecuencia más grave en `clases_producidas` |
| `invocacion_directa_no_mediada` | Proh | — | |
| `texto_intencion` | Proh | — | |

#### EF-5 — Operación de negocio

**[LITERAL]** §C: pago, transferencia, orden, contrato, alta/baja, póliza; delegado sin excepción.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_operacion` | Obl | Enum(`PAGO`,`TRANSFERENCIA`,`ORDEN`,`CONTRATO`,`ALTA_BAJA`,`POLIZA`,`OTRO`) | |
| `contraparte` | Obl | `Id` | |
| `importe_digest` | Opc | `BytesDigest` | Si aplica dinero |
| `reversibilidad` | Obl | `Reversibilidad` | Por defecto tipado: si `DESCONOCIDO` ⇒ tratar como IRREVERSIBLE (§5) |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `texto_intencion` | Proh | — | |

#### EF-6 — Comunicaciones con personas

**[LITERAL]** §C: correo, mensajería, llamada, notificación.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal` | Obl | Enum(`CORREO`,`MENSAJERIA`,`LLAMADA`,`NOTIFICACION`) | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` con al menos una clase de persona | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `texto_intencion` | Proh | — | |

#### EF-7 — Publicación

**[LITERAL]** §C: contenido visible a terceros, web, respuesta pública.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `canal_publicacion` | Obl | `Id` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` que incluye `PUBLICO` o persona | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `texto_intencion` | Proh | — | |

#### EF-8 — Decisión sobre personas

**[LITERAL]** §C / precisión: no es una llamada; se media en el **consumo**; custodia del artefacto del canal de consumo.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `tipo_decision` | Obl | Enum(`PUNTUACION`,`SELECCION`,`DENEGACION`,`PRIORIZACION`,`CREDITICIA`,`LABORAL`,`OTRO`) | |
| `canal_consumo` | Obl | `Id` | Punto donde el resultado se entrega/actúa |
| `artefacto_autoridad_consumo` | Obl | `Id` | Artefacto del canal (V1.1-H1) |
| `sujeto_afectado_clase` | Obl | Enum(`PERSONA_IDENTIFICADA`,`PERSONA_NO_IDENTIFICADA`) | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | Debe ser `SI` (§6); otro valor ⇒ contradicción |
| `mediacion_en_inferencia` | Proh | — | Prohibido presentar EF-8 como EF-1 |
| `texto_intencion` | Proh | — | |

#### EF-9 — Ejecución de código

**[LITERAL]** §C: no se media; se elimina o se confina; abierto degrada INV-11.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `modo` | Obl | Enum(`SCRIPT`,`NODO_CODIGO`,`DESPLIEGUE`,`INFRA`) | |
| `autoridad_ambiental` | Obl | `Tri` | `SI` ⇒ EF9 abierto |
| `superficie_atestada` | Opc | `BytesDigest` | Solo si se alega confinamiento |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `capacidad_efector_solicitada` | Proh | — | EF-9 no emite capacidad de efector «como si» estuviera mediado |
| `texto_intencion` | Proh | — | |

#### EF-10 — Movimiento de datos entre dominios

**[LITERAL]** §C: tercero, internacional, exportación; delegado con datos personales.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `destino_dominio` | Obl | `Id` o `Uri` | |
| `jurisdiccion_destino` | Opc | código | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `texto_intencion` | Proh | — | |

#### EF-11 — Efecto físico o ciberfísico

**[LITERAL]** §C: actuador; sin PEP ⇒ fuera de alcance; delegado + aprobación humana previa.

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `actuador_id` | Obl | `Id` | |
| `orden_digest` | Obl | `BytesDigest` | |
| `pep_fisico_presente` | Obl | `Tri` | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | Tipicamente IRREVERSIBLE |
| `texto_intencion` | Proh | — | |

#### EF-12 — Cambio de gobierno del Kernel

**[LITERAL]** §C: siempre `DENY` a IA; cambio solo por gobernanza con doble firma humana; «No emitible…».

| Parámetro | Obl/Opc/Proh | Tipo | Semántica |
|---|---|---|---|
| `objeto_gobierno` | Obl | Enum(`POLITICA`,`CORPUS`,`PERMISOS`,`PASAPORTE`,`IDENTIDAD`,`PROMPT_SISTEMA`,`MEMORIA_AGENTE`,`CONFIG_KERNEL`) | |
| `solicitante_es_ia` | Obl | `Bool` | |
| `contiene_datos_personales` | Obl | `Tri` | |
| `destinatarios` | Obl | `Lista[DestinatarioClase]` | |
| `decide_sobre_personas` | Obl | `Tri` | |
| `reversibilidad` | Obl | `Reversibilidad` | |
| `autorizacion_ia` | Proh | — | Nunca tipificable como permiso a IA |

---

## 4. Derivación determinista de los cinco atributos H.5

**[LITERAL]** H.5 exige derivar: (1) clase, (2) reversibilidad, (3) presencia de datos personales, (4) destinatarios, (5) si decide sobre personas.

**[PROPUESTA]** Función pura `derivar(EfectoTipado) → AtributosH5` (sin I/O; INV-14 / §E Motor):

### 4.1 Clase

1. Partir de `clase_declarada`.  
2. Aplicar reglas §6 (EF-4 compuesto, EF-8, EF-9, EF-12).  
3. Si hay candidatos múltiples ⇒ §5 (más restrictiva sobre el **orden de clases** propuesto abajo).  
4. Resultado = `clase_aplicada` (evidencia H.5).

**[PROPUESTA]** Orden de restricción de clases (de menos a más restrictiva) para desambiguar **solo** cuando varias clases son candidatas válidas:

`EF-1 < EF-2 < EF-4 < EF-3 < EF-10 < EF-7 < EF-6 < EF-5 < EF-11 < EF-8 < EF-9 < EF-12`

(La inclusión de este orden es **normativa humana**; no está en la Matriz actual.)

### 4.2 Reversibilidad

1. Si el parámetro `reversibilidad` está presente y ≠ `DESCONOCIDO` → ese valor.  
2. Si `DESCONOCIDO` o ausente donde la fila lo exige → **IRREVERSIBLE** (cierre conservador).  
3. EF-4: máx. restrictivo entre `clases_producidas` mapeadas a reversibilidad por tabla de política de versión (publicada con el esquema).

### 4.3 Presencia de datos personales

1. Campo `contiene_datos_personales`.  
2. `DESCONOCIDO` → tratar como **SI** para mínimos de garantía y denegaciones dependientes (§C EF-1/EF-10).  
3. Si `categoria_especial=SI` ⇒ `contiene_datos_personales` forzado a SI; contradicción ⇒ §5.

### 4.4 Destinatarios

1. Lista tipada `destinatarios`.  
2. Vacía o solo `DESCONOCIDO` ⇒ **no tipificable** o, si la versión lo permite como ambigüedad, expandir a la lectura más restrictiva: incluir `PUBLICO` + `PERSONA_IDENTIFICADA` (propuesta conservadora).  
3. **[PROPUESTA preferida más simple]:** lista vacía / solo `DESCONOCIDO` ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.

### 4.5 Si decide sobre personas

1. Campo `decide_sobre_personas`.  
2. EF-8: debe ser `SI` (§6).  
3. `DESCONOCIDO` → **SI** (conservador).  
4. Si destinatarios incluyen persona y el campo es `NO` ⇒ contradicción (§5).

---

## 5. Ausencia, contradicción, desconocido y ambigüedad

**[LITERAL]** H.1 no tipificable ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.  
**[LITERAL]** H.5 ambigua ⇒ más restrictiva.  
**[LITERAL]** G.2: sin salida permisiva por defecto.  
**[LITERAL]** R6: campo ausente en predicado ⇒ denegación (contexto normativo; espíritu análogo).

**[PROPUESTA]** Tabla de conductas (sin ALLOW por omisión):

| Situación | Conducta |
|---|---|
| Parámetro **obligatorio ausente** | `DENY(EFECTO_NO_TIPIFICADO)` |
| Parámetro **prohibido presente** | `DENY(EFECTO_NO_TIPIFICADO)` |
| Tipo incorrecto / campo desconocido | `DENY(EFECTO_NO_TIPIFICADO)` |
| Digest no coincide | `DENY(EFECTO_NO_TIPIFICADO)` |
| Valor `DESCONOCIDO` en atributo H.5 | Aplicar §4 (conservador: SI / IRREVERSIBLE / no tipificar destinatarios) — **nunca** como permiso |
| **Contradicción** entre campos o entre clase declarada y reglas §6 | Tomar la lectura **más restrictiva** entre candidatos bien tipados; si no hay candidato coherente ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |
| **Ambigüedad** (varios tipados válidos) | Más restrictiva (H.5 + orden §4.1); evidencia registra candidatos descartados |
| Clase fuera de las doce / no encaje | **[LITERAL]** reabrir §C con decisión firmada; en ejecución ⇒ `DENY(EFECTO_NO_TIPIFICADO)` |

---

## 6. Reglas específicas EF-4, EF-8, EF-9, EF-12

### 6.1 EF-4 compuesto

**[LITERAL]** §C EF-4: mínimo «delegado si la herramienta produce EF-3, EF-5, EF-6 o EF-7».

**[PROPUESTA]**

1. `clases_producidas` no vacía; cada elemento ∈ doce.  
2. La **clase aplicada** para Libro/mínimos es el **máximo restrictivo** de `clases_producidas` ∪ {EF-4} según orden §4.1.  
3. Si `clases_producidas` contiene EF-12 ⇒ tratar como EF-12 (§6.4).  
4. Si contiene EF-8 ⇒ aplicar §6.2 al subconjunto de consumo.  
5. No se autoriza «solo EF-4» para eludir el mínimo de la clase producida.

### 6.2 EF-8

**[LITERAL]** «EF-8 no es una llamada, es una consecuencia… punto de aplicación… donde el resultado se **consume**»; custodia del artefacto del canal de consumo.

**[PROPUESTA]**

1. `decide_sobre_personas` debe ser `SI`; otro ⇒ no tipificable o forzar SI + ambigüedad registrada.  
2. Prohibido clasificar como EF-1/EF-2/EF-3 un efecto cuyo fin es consumo de decisión sobre persona **sin** `canal_consumo`.  
3. Atributos H.5: clase = EF-8; decide_sobre_personas = SI.

### 6.3 EF-9

**[LITERAL]** «EF-9 no se media, se elimina o se confina»; abierto degrada alcanzables a cooperativo (INV-11 / D.3).

**[PROPUESTA]**

1. `autoridad_ambiental=SI` ⇒ hecho de entorno EF9 abierto (fuera de este contrato: Libro); clasificación de solicitud sigue siendo EF-9.  
2. No existe tipificación que convierta código arbitrario en EF-1…EF-8 «seguro».  
3. Reversibilidad por defecto IRREVERSIBLE si desconocida.

### 6.4 EF-12

**[LITERAL]** «EF-12 no se concede nunca»; «Siempre `DENY`»; «solo por la vía de gobernanza con doble firma humana».

**[PROPUESTA]**

1. Tras tipificación válida como EF-12: la **clasificación H.5** produce atributos, pero la **autorización a sistema de IA** es siempre denegación (código alineado a conducta §C; p. ej. denegación por política EF-12 / no emitible).  
2. `solicitante_es_ia=true` ⇒ no existe camino ALLOW en H.5–H.11 para ese efecto.  
3. Cambios reales de gobierno **no** pasan por EfectoTipado de un sujeto IA; pasan por G.5 / G.ET humanos.

---

## 7. Compatibilidad, migración y reproducción histórica

**[LITERAL]** INV-14: misma entrada ⇒ misma salida. G.5 reconstrucción histórica de paquetes. INV-03: cita de hash de paquete normativo.

**[PROPUESTA]**

1. Toda decisión que use H.5 cita `esquema_id` + `esquema_version` + hash del artefacto EfectoTipado activo.  
2. Recomputación histórica usa **exactamente** la versión citada; no la activa actual.  
3. Migración: versión N+1 publica tabla de mapeo N→N+1; campos nuevos obligatorios no se rellenan por inferencia del Motor — las solicitudes antiguas se recomputan con N.  
4. Retirada de un campo: solo en N+1; N sigue válida para historia.  
5. Incompatibilidad sin mapeo ⇒ las solicitudes bajo N siguen tipificables; las nuevas deben usar N+1.

---

## 8. Gobernanza del artefacto EfectoTipado (G.ET) — **no es G.5**

**[LITERAL]** G.5 gobierna **paquetes normativos** (propuesta → revisión jurídica → conformidad + diff → doble firma → sombra 7 días → activación → reversión).  
**[LITERAL]** §C: reabrir clases con **decisión firmada**.  
**[LITERAL]** §E Gobernanza: «Activar sin doble firma ni diff reconocido» está prohibido **para paquetes**.

**[PROPUESTA]** Se introduce el procedimiento **G.ET** (Gobernanza EfectoTipado), artefacto distinto del paquete normativo. G.5 **no** se declara competente por omisión.

### 8.1 Autoridad

**[PROPUESTA]** Autoridad para activar/revocar versiones de EfectoTipado: el mismo órgano de firmantes registrados que G.5, actuando bajo el rol **G.ET**, con registro de que el objeto firmado es `efecto-tipado@vN`, no un paquete de normas.

### 8.2 Etapas (propuestas; espejo deliberado de G.5, **cita no de cobertura**)

| Etapa | Contenido | Quién | Nota |
|---|---|---|---|
| **ET.1 Propuesta** | Borrador de esquema (esta enmienda o sucesor) + vectores de aceptación/rechazo | Cualquiera | |
| **ET.2 Revisión** | Completitud frente a H.1/H.5/§C; marca de ambigüedades residuales | Revisor jurídico **y** revisor técnico, competencias registradas | |
| **ET.3 Prueba de conformidad** | Harness: tipificación, H.5, fallos seguros, EF-4/8/9/12; **diff** de clasificaciones frente a versión anterior; todo cambio de clasificación reconocido y firmado | Automático + reconocimiento humano | Diff no reconocido **bloquea** |
| **ET.4 Doble firma** | Umbral 2 de N; **al menos un firmante jurídico y uno técnico, identidades distintas** | Firmantes registrados | **[LITERAL espíritu G.5.4]** aplicado por propuesta a G.ET |
| **ET.5 Sombra** | Siete días: clasificar en sombra sin aplicar a ALLOW reales | Automático | |
| **ET.6 Activación** | En límite de época; versión anterior conservada indefinidamente | Automático tras ET.4–ET.5 | |
| **ET.7 Reversión** | Reactivar versión anterior por el mismo procedimiento; no borrar historia | Umbral 2 de N | |

**[PROPUESTA]** Mientras G.ET no esté enmendado dentro de la Matriz vigente, **ninguna implementación de D6** puede alegar cobertura G.5.

### 8.3 Relación con reapertura de §C

**[LITERAL]** Efecto que no encaja ⇒ reabrir §C con decisión firmada.  
**[PROPUESTA]** Añadir una clase o cambiar el significado de una clase exige **§C + G.ET** (esquema) coordinados; solo G.ET sin §C no basta para nuevas clases.

---

## 9. Decisiones humanas/normativas no automatizables

**[LITERAL]** INV-16; G.4 materias reservadas; R8 ambigüedad de norma la declara la persona; interpretación obligatoria en G.1.

**[PROPUESTA]** Lista separada — el Motor **no** decide:

1. Aprobar o rechazar este borrador / cualquier versión EfectoTipado.  
2. El **orden de restricción** entre clases (§4.1).  
3. Si un ejemplo de §C se convierte en parámetro obligatorio u opcional.  
4. Si `DESCONOCIDO` en destinatarios deniega o expande (elección entre filas de §5).  
5. Mapeos de migración entre versiones mayores.  
6. Reapertura de §C (nuevas clases o redefinición).  
7. Si G.ET se unifica algún día con G.5 o permanece procedimiento aparte.  
8. Interpretación jurídica de «datos personales», «categoría especial» o «decisión sobre personas» en un caso concreto (hechos tipados entran firmados; el Kernel no los redefine).  
9. Autorizar EF-12 o cualquier cambio de gobierno.  
10. Declarar que una herramienta «produce» ciertas clases si el pasaporte/humano no lo ha tipificado.

---

## 10. Criterio de cierre (para cuando deje de ser borrador)

**[PROPUESTA]** Esta enmienda solo pasa a **vigente** cuando:

1. Texto incorporado a la Matriz (o anexo canónico referenciado por ella).  
2. G.ET ejecutado hasta **ET.6** sobre `efecto-tipado@v1`.  
3. Vectores de conformidad en verde.  
4. Constancia explícita de que **no** se implementó D6 antes del paso 2.

Hasta entonces: **BORRADOR NO VINCULANTE.**

---

## Apéndice A — Mapa rápido LITERAL ↔ hueco

| Exigencia Matriz | ¿Cubierta hoy? | Este borrador |
|---|---|---|
| H.1 efecto tipado | Parcial (clase sí; parámetros no) | §1–§3 |
| H.5 cinco atributos | No hay función de derivación | §4–§5 |
| §C doce clases | Sí (catálogo) | §3 filas + §6 |
| G.5 paquetes | No cubre EfectoTipado | §8 G.ET (propuesta) |
| Motor sin inferir huecos | Sí | §2, §9 |

---

*Fin del borrador. No implementar. No citar como vigente.*
