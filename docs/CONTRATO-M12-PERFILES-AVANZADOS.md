# Contrato literal — §M 12 (pendiente de implementación)

Fuente: Matriz Maestra Canónica v1.1, §M fila **12**, I.10 (atestación de confinamiento), D.1/D.3 (`CONFINADO` / C5), C (EF-1…EF-12), K (consistencia distribuida / multiparte), INV-09, INV-11, L-19, L-23, H-2.  
Este documento **no añade** requisitos. **No** incluye etapas posteriores a §M 12. **No** modifica B12–B20 (rebanadas EF-3…EF-11).

**Estado:** contrato preparado; implementación **no** iniciada.

## Entregable (§M 12)

> **Perfiles avanzados.** Confinamiento sin autoridad ambiental con sus ocho predicados de atestación; y perfil de autoridad multiparte con quórum de dos tercios más uno también en el certificado de cambio de vista.

## Invariantes afectados (§M 12)

- **INV-09** — El Kernel no autoriza una clase de efecto cuyo nivel de control medido esté por debajo del mínimo exigido para esa clase.
- **INV-11** — Si un sistema puede ejecutar código con autoridad ambiental, el nivel de toda clase cuyo efector sea alcanzable desde ese código se limita al nivel cooperativo.

(Habilitación de `CONFINADO` / C5 y desaparición de EF-9 como canal ambiental cuando el perfil confinado está atestado; multiparte no sustituye el corte vertical.)

## Criterio de aceptación demostrable (§M 12)

> En confinamiento, la sonda intenta las **doce clases** sin capacidad y obtiene **doce denegaciones**, con resultado firmado. En multiparte, el invariante de seguridad se comprueba y el test de certificado inválido está en verde.

## Bloqueador si falla (§M 12)

> **No.** Elevan la garantía de casos concretos; su ausencia no invalida el resto.

## A. Confinamiento — ocho predicados de atestación (I.10)

Productor del hecho `CONFINADO(s)`: atestación de confinamiento; antigüedad máxima **300 s** (D.3).

Los **ocho predicados** verificados por época (I.10), en orden literal:

1. Construcción del entorno por el propio Kernel con **conjunto ambiental vacío**
2. **Hash** de la superficie expuesta en **lista blanca**
3. **Ausencia de funciones** fuera de esa superficie
4. **Enlazado estático** sin carga dinámica
5. **Puntos de aplicación con latido**
6. **Sonda con diez de diez denegaciones** (predicado I.10; distinto del criterio §M de las doce clases EF — ver §B)
7. **Sonda de egreso** sin ruta alternativa
8. **Autotest criptográfico vigente**

**Qué afirma (I.10):** que el sujeto no puede expresar un efecto fuera de la superficie enumerada.

**Qué no afirma (I.10, D.1 C5):** corrección del anfitrión (entra en el TCB); persuasión de personas; efecto físico sin módulo; resistencia a host, firmware o hardware comprometidos.

### Regla C5 (D.3) — precondiciones

```
CONFINADO(s) ∧ DELEGADO(s,e) ∧ CUSTODIA(s,e) ∧ EXCLUSIVIDAD(s,e)
             ∧ PEP_ATESTADO(s,e) ∧ SONDA_OK(s,e)  →  C5
```

[V1.1-H2] C5 exige explícitamente `CUSTODIA` y `EXCLUSIVIDAD`. Ninguna asignación `CONFINADO ∧ ¬(CUSTODIA ∧ EXCLUSIVIDAD)` produce C5.

## B. Sonda de las doce clases EF (criterio §M 12)

Sin capacidad emitida, la sonda intenta **EF-1 … EF-12** y obtiene **doce denegaciones**, con **resultado firmado**.

| Clase | Efecto (C) |
|---|---|
| EF-1 | Inferencia y servicios de modelo |
| EF-2 | Acceso y tratamiento de datos |
| EF-3 | Escritura y cambio de estado |
| EF-4 | Herramientas y conectores |
| EF-5 | Operación de negocio |
| EF-6 | Comunicaciones con personas |
| EF-7 | Publicación |
| EF-8 | Decisión sobre personas |
| EF-9 | Ejecución de código |
| EF-10 | Movimiento de datos entre dominios |
| EF-11 | Efecto físico o ciberfísico |
| EF-12 | Cambio de gobierno del Kernel (siempre DENY; nunca concedido a IA) |

**Precisión de lectura (no añade requisito):** el predicado I.10 «diez de diez» y el criterio §M «doce denegaciones / doce clases» coexisten en la Matriz; la aceptación §M 12 exige las **doce** clases EF. El «diez de diez» permanece como predicado de la atestación I.10.

## C. Perfil multiparte y certificado de vista (K)

De K — Consistencia distribuida:

- **No hay consenso en la ruta de autoridad** del Kernel ordinario (réplicas recomputan).
- **Autoridad multiparte** es un **perfil distinto**.
- En ese perfil: quórum de **dos tercios más uno**.
- El **certificado de cambio de vista** exige el **mismo** quórum (dos tercios más uno), **nunca la mitad**.

Criterio §M 12 (multiparte): invariante de seguridad comprobado; **test de certificado inválido en verde**.

## D. Integración con EF-9 / B18 (código existente)

- **EF-9** (C, L-19): no se media; se elimina o se confina. Abierto ⇒ degradación INV-11 de clases alcanzables a nivel cooperativo (C2).
- **B18** (`bloque18_ef9` / rebanada EF-9): régimen abierto, inventario, degradación, denegación de capacidad EF-9, **perfil confinado pendiente** sin afirmar C5 — **conservar**; §M 12 debe **integrar** atestación `CONFINADO` y sonda de doce clases **sin rehacer** la rebanada salvo lo exigido por integración.
- Con confinamiento atestado vigente: EF-9 deja de ser canal ambiental; el Libro puede alcanzar C5 solo si se cumplen todas las precondiciones D.3 (incl. CUSTODIA/EXCLUSIVIDAD).
- Completitud de `ALCANZABLES`: supuesto INV-11 / H-3; **no** cerrado por §M 12.

## E. Pruebas positivas (mínimo del criterio)

| # | Prueba | Observable |
|---|---|---|
| P1 | Los ocho predicados I.10 verdaderos en una época ⇒ hecho `CONFINADO` emitible / renovable (≤300 s) | Atestación firmada por época |
| P2 | Sonda EF-1…EF-12 **sin capacidad** ⇒ 12× DENY + paquete/resultado firmado | Criterio §M 12 confinamiento |
| P3 | C5 solo si `CONFINADO ∧ DELEGADO ∧ CUSTODIA ∧ EXCLUSIVIDAD ∧ PEP_ATESTADO ∧ SONDA_OK` | Cálculo Libro |
| P4 | Multiparte: cambio de vista con quórum 2/3+1 válido | Certificado aceptado |
| P5 | Integración: con `CONFINADO` vigente, EF-9 no abre degradación ambiental como canal residual del perfil confinado (coherente con L-19 / INV-11) | Libro / harness |

## F. Pruebas negativas (mínimo)

| # | Prueba | Observable |
|---|---|---|
| N1 | Falta cualquier predicado I.10 ⇒ no `CONFINADO` / no C5 | DENY de atestación o nivel |
| N2 | `CONFINADO ∧ ¬CUSTODIA` o `¬EXCLUSIVIDAD` ⇒ **no** C5 | H-2 |
| N3 | Sonda de clase EF sin denegación (efecto producido) ⇒ fallo de criterio §M 12 | Resultado firmado ≠ 12/12 |
| N4 | Certificado de vista con quórum insuficiente o firma inválida ⇒ rechazo | Test certificado inválido en verde |
| N5 | Intento de conceder EF-12 a un sistema de IA ⇒ siempre DENY | C / EF-12 |
| N6 | Afirmar resistencia a host/firmware/HW o completitud de inventario por el solo hecho de confinamiento ⇒ rechazado / `no_comprobado` | D.1 / I.10 / INV-11 |

## G. Límites DESP / VAL-EXT / GOB (no cerrables solo con §M 12)

| Etiqueta | Qué permanece fuera / declarado |
|---|---|
| **[DESP]** | Corrección del anfitrión (TCB); host/firmware/HW comprometidos; completitud de `ALCANZABLES`; que las sondas cubran rutas no intentadas (límite fundamental I.8 / K) |
| **[VAL-EXT]** | Disponibilidad de atestación de plataforma hardware (I.9); suelos legales ajenos al predicado de confinamiento |
| **[GOB]** | Conformidad legal; persuasión de personas; efecto físico sin módulo PEP |
| **`no_comprobado`** | HSM/titularidad real donde aplique a claves de atestación; TSA; C5 como propiedad del hardware real del host |
| **Fuera de §M 12** | Cualquier etapa o requisito **posterior** a la fila 12 de §M; reescritura de B12–B20 salvo integración mínima |

## H. Artefactos previstos (derivados; no inventados)

- Emisor/verificador de atestación de confinamiento (8 predicados / época)
- Hecho `CONFINADO(s)` enlazado al Libro (D.3)
- Sonda firmada EF-1…EF-12 sin capacidad
- Perfil multiparte: quórum 2/3+1; certificado de cambio de vista; test de certificado inválido
- Harnesses P1–P5 / N1–N6; integración con evaluador EF-9 / B18 existente

## Fuera de alcance de esta preparación

Implementación en código, §M posteriores (no existen en la Matriz), modificación de B12–B20, cierre de límites DESP/VAL-EXT/GOB.
