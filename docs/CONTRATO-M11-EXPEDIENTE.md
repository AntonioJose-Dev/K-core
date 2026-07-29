# Contrato literal — §M 11 (implementado)

Fuente: Matriz Maestra Canónica v1.1, §M fila **11**, secciones **J.1–J.6**, **INV-15**, **INV-16**, **L-08**, **L-09**, **H-4**.  
Este documento **no añade** requisitos. No incluye §M 12.

**Estado:** criterios de aceptación §M 11 ejercidos en `crates/sak-core/tests/m11_expediente.rs` y `sak-verify --self-test` (bloque expediente J.2).

## Entregable (§M 11)

> **Expediente completo, redacciones y retención.** Doce partes, siete etiquetas obligatorias, hash camaleón con trampilla bajo umbral, retención por clase. [V1.1-H4] La cofirma mínima de dos testigos independientes no es un pendiente de este bloque: se exige desde el bloque 3 y sostiene INV-15 desde el corte vertical.

## Invariantes afectados (§M 11)

- **INV-15** — Integridad de la evidencia verificable por tercero sin Kernel ni confianza en el operador.
- **INV-16** — El Kernel no produce, valida ni certifica interpretación jurídica; la aplica, versiona y atribuye.

## Criterio de aceptación demostrable (§M 11)

> Un auditor externo reconstruye las trece preguntas de J.2 con solo el paquete y las claves públicas; el paquete no contiene ningún campo de veredicto; una redacción exige umbral y preserva la raíz.

## Bloqueador si falla (§M 11)

> No para el corte vertical. **Sí** para presentar el sistema ante un tercero.

## Doce partes del expediente (J.1)

1. Sistemas — identidad, versión, huella; medida TCB Kernel; hash lista cerrada de símbolos  
2. Finalidad y contexto — finalidad, usos previstos/excluidos, firma del responsable  
3. Clasificación y obligaciones — riesgo justificado firmado; rol; jurisdicciones; obligaciones L1–L4  
4. Corpus — paquetes del periodo, hash, firmas, diff, textos de interpretación con autor  
5. Riesgos y controles — riesgos, controles, resultado de cada control  
6. Decisiones — solicitud, decisión, código, normas, traza, hechos+productores, pasos  
7. Capacidades y ejecuciones — emisión, alcance, TTL, uso, revocación; recibos; rechazos  
8. Supervisión humana — escalados, identidad, competencia, quórum, independencia, plazo, firma sobre digest, decisión  
9. Libro de Control — nivel por par **con historial temporal**, hechos, bypass residual, plan de elevación  
10. Supuestos y estado — serie temporal de supuestos; transiciones; atestaciones plataforma/confinamiento  
11. Incidentes y cambios — mediación, huecos, reconciliación, redacciones, corpus, correctoras  
12. Cadena criptográfica — cadena por sujeto, Merkle/época, cofirmas, sellos, inclusión, suelo de época  

Generación del paquete: exige capacidad de auditoría y queda registrada.

## Siete etiquetas obligatorias (J.3)

Exactamente una por afirmación; mezcla rechazada por validación del paquete:

`HECHO_VERIFICABLE` · `EVALUACION_AUTOMATICA` · `DECISION_HUMANA` · `INTERPRETACION_JURIDICA` · `EVIDENCIA_AUSENTE` · `RIESGO_RESIDUAL` · `NO_AFIRMADO`

## J.2 — trece preguntas (reconstrucción sin confiar en el operador)

Qué sistema (por artefacto, no autodeclaración); identidad y versión; efecto/clase/parámetros; datos/contexto con productor y digest; norma/versión/jurisdicción/interpretación y autor; qué se decidió y por qué (traza e inertes); capacidad o ejecución+recibo; punto de aplicación; persona/competencia/firma/digest; **nivel del Libro en ese instante**; integridad/sellos/firmas/cofirmas; **qué no pudo comprobarse**; evidencia faltante y riesgo residual abierto.

## J.4 — prohibiciones del paquete

- Sin campo de veredicto de conformidad  
- Sin puntuación de cumplimiento  
- Sin afirmación de que el sistema cumple  
- En su lugar: cuatro recuentos (obligaciones evaluadas; satisfechas por Kernel; que requieren decisión humana; huecos de evidencia)  
- Frase literal: existencia de registros **no** equivale a cumplimiento; responsabilidad jurídica final al operador  

## Redacción / hash camaleón (J.6 + L-08)

- Hojas con posibles datos personales: hash camaleón; redactar preservando la raíz e inclusiones previas  
- Trampilla: umbral **dos entre tres**, ≥1 titular **ajeno al operador**  
- Toda redacción: registro (hoja, autorizante, base jurídica, fecha, digest previo)  
- Formulación: evidencia inalterable sin autorización; alteración autorizada queda probada  
- Prohibido lenguaje de borrado imposible / inmutabilidad absoluta  

## Retención por clase (J.6)

| Clase de registro | Retención |
|---|---|
| Decisión sin contenido | 10 años |
| Registros automáticos sistemas alto riesgo | 12 meses **[VAL-EXT]** suelo legal aplicable |
| Contenido con datos personales | 90 días cifrado |
| Checkpoints y cofirmas | Permanentes |
| Aprobaciones humanas y firmas | 10 años |

**Decisión de implementación PII (no mandato literal Matriz sobre primitiva/KEK):** AES-256-GCM; KEK = HMAC-SHA-384(material_trampilla, `SAK-PII-KEK-v1|`)[0..32]; etiqueta `DECISION_CRIPTO_PII_V1`. No afirma HSM ni titularidad cliente **[DESP]**.

## Verificador (J.5) en alcance §M 11

Binario separado; sin red, sin Kernel, sin confiar en operador; informe incluye redacciones detectadas con autorización y lista de lo no comprobable. Cofirma de testigos: **ya exigida desde §M 3** (no pendiente de §M 11).

## Artefactos (implementación)

| Artefacto | Ubicación |
|---|---|
| Expediente 12 partes + J.3/J.4 | `crates/sak-core/src/evidencia/expediente.rs` |
| Hash camaleón / trampilla 2/3 | `crates/sak-core/src/evidencia/camaleon.rs` |
| Retención por clase | `ClaseRetencion` en `expediente.rs` |
| Verificador offline J.2 | `verificar_expediente` + `sak-verify --self-test` |
| Harness | `crates/sak-core/tests/m11_expediente.rs` |

## Artefactos previstos (derivados del contrato; no inventados)

- Tipo/paquete de expediente con las 12 partes  
- Esquema de afirmación con etiqueta única (J.3)  
- Motor/API de redacción camaleón bajo umbral 2/3 + registro de redacción  
- Política de retención por clase  
- Extensión de `sak-verify` / informe: J.2 reconstruible; rechazo si hay veredicto; raíz preservada tras redacción  
- Harness de generación con capacidad de auditoría registrada  

## Pruebas negativas (mínimo del criterio §M 11 + J.3/J.4/L-08/L-09)

- Paquete con campo de veredicto / score de cumplimiento → rechazo  
- Afirmación con dos etiquetas o sin etiqueta → rechazo  
- Redacción con un solo titular (operador solo) → rechazo; raíz no debe cambiar solo con umbral válido  
- Redacción sin registro (autorizante/base/fecha/digest previo) → rechazo  
- Auditor con solo paquete+públicas no puede responder las 13 de J.2 → fallo de criterio  
- Mezcla de etiqueta `NO_AFIRMADO` omitida cuando cliente=operador sobre resistencia al operador (J.6) → incumplimiento de honestidad del expediente  

## Límites DESP / VAL-EXT / GOB (no cerrables solo con este bloque)

| Etiqueta | Qué permanece fuera / declarado |
|---|---|
| **[DESP]** | HSM/titularidad cliente de clave de firma; que un testigo sea honesto; completitud de atestaciones reales en parte 10 |
| **[VAL-EXT]** | Suelo legal de retención 12 meses; sello de tiempo de autoridad externa; disponibilidad de atestación de plataforma |
| **[GOB]** | Conformidad legal (K: ninguna); competencia del autor de `INTERPRETACION_JURIDICA`; responsabilidad jurídica final del operador |
| **Fuera de §M 11** | §M 12 (confinamiento atestado, multiparte); C5; hardware EF-11; completitud `ALCANZABLES` |

## Fuera de alcance de esta implementación

Todo lo listado en §M **12**. No avanzar perfiles avanzados ni ocho predicados de atestación en este entregable.
