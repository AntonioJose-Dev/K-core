//! Modelo de datos del resultado de una decisión del Kernel.
//!
//! Fuente canónica: Matriz Maestra v1.1 — R2 (orden conservador), G.3 (códigos
//! de razón), INV-02, INV-03 e INV-14. Este módulo contiene **solo tipos**:
//! no evalúa normas, no calcula precedencia y no decide nada.
//!
//! Restricciones cumplidas aquí: sin código no seguro (`#![forbid(unsafe_code)]`
//! del crate), sin dependencias externas, sin entrada/salida, sin reloj,
//! entropía, red, disco, variables de entorno ni estado global (INV-14).
//!
//! **Preparación para serialización canónica.** No se implementa ninguna
//! serialización externa. Los tipos están construidos para que, cuando exista
//! el codificador del Bloque 3, dos ejecuciones produzcan los mismos bytes:
//! colecciones ordenadas y sin duplicados, enteros de anchura fija, sin coma
//! flotante, sin tablas de dispersión, sin punteros y sin tipos de tiempo.
//! Cada enumeración expone su nombre canónico mediante `token()`.

use std::fmt;

/// Longitud del hash del paquete normativo, en bytes.
///
/// SHA-384 según la suite criptográfica única fijada en L-07.
pub const LONGITUD_HASH_PAQUETE: usize = 48;

// =============================================================================
// Veredicto — el orden conservador R2
// =============================================================================

/// Valor de una decisión, en el orden de R2: `DENY < SUSPEND < ESCALATE < ALLOW`.
///
/// **El orden de declaración de las variantes es R2** y la implementación
/// derivada de `Ord` depende de él: reordenarlas cambiaría el ínfimo y
/// rompería la regla. No se reordenan.
///
/// R2 — Ínfimo de decisiones: «La decisión es el ínfimo sobre todas las normas
/// aplicables […] Una sola denegación decide. No hay ponderación, ni mayoría,
/// ni puntuación.»
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Veredicto {
    Deny = 0,
    Suspend = 1,
    Escalate = 2,
    Allow = 3,
}

impl Veredicto {
    /// Nombre canónico, literal de la Matriz.
    pub const fn token(self) -> &'static str {
        match self {
            Veredicto::Deny => "DENY",
            Veredicto::Suspend => "SUSPEND",
            Veredicto::Escalate => "ESCALATE",
            Veredicto::Allow => "ALLOW",
        }
    }

    /// Ínfimo de dos veredictos según R2.
    ///
    /// No existe elemento neutro ni plegado sobre colecciones: el ínfimo del
    /// conjunto vacío sería `ALLOW`, que es exactamente la salida permisiva por
    /// defecto que la Matriz prohíbe. Combinar los veredictos de un conjunto de
    /// normas es tarea del motor, no de este módulo.
    pub const fn infimo(self, otro: Veredicto) -> Veredicto {
        if (self as u8) <= (otro as u8) {
            self
        } else {
            otro
        }
    }
}

impl fmt::Display for Veredicto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

// =============================================================================
// Códigos de razón — lista cerrada de G.3
// =============================================================================

/// Los códigos de razón de G.3 más el de supervisión humana (H.10).
///
/// G.3 define nueve códigos del motor normativo. `QUORUM_SUPERVISION` no está
/// en G.3: pertenece a la fase 10 de H y se añade aquí en el Bloque 10 para
/// materializar `DENY(QUORUM_SUPERVISION)` sin inventar códigos ajenos a la Matriz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum CodigoRazon {
    /// `DENY`. No existe norma aplicable al caso de uso, o una norma vencida
    /// deja el caso descubierto.
    SinNormaAplicable = 0,
    /// Conflicto entre rangos distintos, resuelto por R1 y R2, sin escalado.
    PrecedenciaAplicada = 1,
    /// `ESCALATE`, y `DENY` al expirar. Conflicto de jurisdicción en el mismo rango.
    ConflictoJurisdiccion = 2,
    /// `DENY`, o `ESCALATE` si la norma lo prevé. Evidencia exigida ausente.
    EvidenciaAusente = 3,
    /// `DENY`. Predicado no evaluable.
    NormaNoEvaluable = 4,
    /// `ESCALATE`. Norma marcada ambigua por el revisor.
    AmbiguedadDeclarada = 5,
    /// `DENY` si es precondición; en otro caso se declara como hueco de
    /// evidencia. Requisito no operacionalizable, `L4`.
    FueraDeAlcanceTecnico = 6,
    /// `DENY` sin evaluar la norma. Nivel del Libro de Control por debajo del
    /// mínimo de la clase.
    ControlInsuficiente = 7,
    /// Solo efectos reversibles hasta recalcular. Perfil normativo no
    /// recalculado tras cambio de corpus.
    PerfilObsoleto = 8,
    /// `DENY` (H.10). Fallo de quórum, independencia, competencia, firma o plazo
    /// en supervisión humana. Nunca autorización tácita.
    QuorumSupervision = 9,
}

impl CodigoRazon {
    /// Nombre canónico, literal de la Matriz (G.3 o H.10).
    pub const fn token(self) -> &'static str {
        match self {
            CodigoRazon::SinNormaAplicable => "SIN_NORMA_APLICABLE",
            CodigoRazon::PrecedenciaAplicada => "PRECEDENCIA_APLICADA",
            CodigoRazon::ConflictoJurisdiccion => "CONFLICTO_JURISDICCION",
            CodigoRazon::EvidenciaAusente => "EVIDENCIA_AUSENTE",
            CodigoRazon::NormaNoEvaluable => "NORMA_NO_EVALUABLE",
            CodigoRazon::AmbiguedadDeclarada => "AMBIGUEDAD_DECLARADA",
            CodigoRazon::FueraDeAlcanceTecnico => "FUERA_DE_ALCANCE_TECNICO",
            CodigoRazon::ControlInsuficiente => "CONTROL_INSUFICIENTE",
            CodigoRazon::PerfilObsoleto => "PERFIL_OBSOLETO",
            CodigoRazon::QuorumSupervision => "QUORUM_SUPERVISION",
        }
    }

    /// Si el código puede acompañar a una decisión permisiva.
    ///
    /// G.3 no define ningún código para `ALLOW`. Solo dos de los códigos G.3 son
    /// compatibles con una salida permisiva: `PRECEDENCIA_APLICADA` y
    /// `PERFIL_OBSOLETO`. `QUORUM_SUPERVISION` es siempre denegatorio.
    pub const fn admisible_en_decision_permitida(self) -> bool {
        matches!(
            self,
            CodigoRazon::PrecedenciaAplicada | CodigoRazon::PerfilObsoleto
        )
    }
}

impl fmt::Display for CodigoRazon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

// =============================================================================
// Identificadores citables — INV-03
// =============================================================================

/// Identificador estable y único de una norma dentro del corpus.
///
/// INV-03: «Toda decisión cita el hash del paquete normativo y los
/// identificadores de las normas aplicadas.»
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdNorma(String);

impl IdNorma {
    /// Rechaza un identificador vacío o compuesto solo de espacios: una cita
    /// que no identifica nada no es una cita.
    pub fn nueva(id: impl Into<String>) -> Result<Self, ErrorDecision> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(ErrorDecision::IdNormaVacio);
        }
        Ok(IdNorma(id))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdNorma {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Hash del paquete normativo con el que se resolvió la decisión.
///
/// Su longitud es la de SHA-384, la suite única de L-07. Este tipo transporta
/// el hash; no lo calcula.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashPaqueteNormativo([u8; LONGITUD_HASH_PAQUETE]);

impl HashPaqueteNormativo {
    pub const fn desde_bytes(bytes: [u8; LONGITUD_HASH_PAQUETE]) -> Self {
        HashPaqueteNormativo(bytes)
    }

    pub fn bytes(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.0
    }
}

// =============================================================================
// Traza de precedencia — dato inmutable y canónico
// =============================================================================

/// Por qué una norma quedó inerte.
///
/// Las tres únicas causas de inercia enunciadas en G.2. El nombre canónico es
/// el identificador de la regla, que es lo literal en la Matriz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum MotivoInercia {
    /// R1 — Restricción monótona: la norma de rango inferior que ampliaría lo
    /// que un rango superior permite es inerte, y su inercia se registra.
    R1RestriccionMonotona = 1,
    /// R4 — Fuente vencida: inerte para decisiones nuevas, conservada para
    /// reconstrucción histórica.
    R4FuenteVencida = 4,
    /// R5 — Fuente no vigente aún: inerte, pero evaluada en sombra.
    ///
    /// El veredicto que la norma produciría en sombra no se modela en el
    /// Bloque 1; se difiere al Bloque 2, con el corpus.
    R5FuenteNoVigenteAun = 5,
}

impl MotivoInercia {
    /// Nombre canónico: el identificador de la regla de G.2.
    pub const fn token(self) -> &'static str {
        match self {
            MotivoInercia::R1RestriccionMonotona => "R1",
            MotivoInercia::R4FuenteVencida => "R4",
            MotivoInercia::R5FuenteNoVigenteAun => "R5",
        }
    }
}

impl fmt::Display for MotivoInercia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Una norma que no se aplicó, con la causa de su inercia.
///
/// [Bloque 2] `veredicto_en_sombra` solo es admisible con motivo R5
/// (fuente no vigente aún): registra la decisión que produciría sin aplicarla.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NormaInerte {
    id: IdNorma,
    motivo: MotivoInercia,
    veredicto_en_sombra: Option<Veredicto>,
}

impl NormaInerte {
    pub fn nueva(id: IdNorma, motivo: MotivoInercia) -> Self {
        NormaInerte {
            id,
            motivo,
            veredicto_en_sombra: None,
        }
    }

    /// R5: inerte con el veredicto que produciría en sombra.
    pub fn con_sombra(id: IdNorma, veredicto: Veredicto) -> Self {
        NormaInerte {
            id,
            motivo: MotivoInercia::R5FuenteNoVigenteAun,
            veredicto_en_sombra: Some(veredicto),
        }
    }

    pub fn id(&self) -> &IdNorma {
        &self.id
    }

    pub fn motivo(&self) -> MotivoInercia {
        self.motivo
    }

    pub fn veredicto_en_sombra(&self) -> Option<Veredicto> {
        self.veredicto_en_sombra
    }
}

/// Traza de precedencia de una decisión: normas aplicadas, normas inertes con
/// su motivo, y pasos consumidos.
///
/// Es inmutable: los campos son privados, no hay métodos de mutación y el
/// constructor es la única vía de entrada.
///
/// **Canonicidad.** El constructor ordena ambas listas por identificador, de
/// modo que la representación no depende del orden de inserción, y rechaza que
/// una norma figure dos veces o que figure a la vez como aplicada e inerte.
/// La traza es, por tanto, un conjunto ordenado, no la secuencia de evaluación.
///
/// `pasos_consumidos` se transporta tal cual: el presupuesto de 10.000 pasos
/// por norma y 100.000 por decisión lo aplica el motor, no este tipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrazaPrecedencia {
    aplicadas: Vec<IdNorma>,
    inertes: Vec<NormaInerte>,
    pasos_consumidos: u32,
}

impl TrazaPrecedencia {
    pub fn nueva(
        mut aplicadas: Vec<IdNorma>,
        mut inertes: Vec<NormaInerte>,
        pasos_consumidos: u32,
    ) -> Result<Self, ErrorDecision> {
        aplicadas.sort();
        if let Some(par) = aplicadas.windows(2).find(|par| par[0] == par[1]) {
            return Err(ErrorDecision::NormaDuplicadaEnTraza(par[0].clone()));
        }

        inertes.sort();
        if let Some(par) = inertes.windows(2).find(|par| par[0].id == par[1].id) {
            return Err(ErrorDecision::NormaDuplicadaEnTraza(par[0].id.clone()));
        }

        for inerte in &inertes {
            if aplicadas.binary_search(&inerte.id).is_ok() {
                return Err(ErrorDecision::NormaAplicadaTambienInerte(inerte.id.clone()));
            }
        }

        Ok(TrazaPrecedencia {
            aplicadas,
            inertes,
            pasos_consumidos,
        })
    }

    pub fn aplicadas(&self) -> &[IdNorma] {
        &self.aplicadas
    }

    pub fn inertes(&self) -> &[NormaInerte] {
        &self.inertes
    }

    pub fn pasos_consumidos(&self) -> u32 {
        self.pasos_consumidos
    }
}

// =============================================================================
// Decisiones — el veredicto se deriva del tipo, nunca se almacena
// =============================================================================

/// Decisión permisiva. Único tipo que el emisor aceptará para materializar una
/// capacidad, conforme a INV-01: «única ruta `emitir(DecisiónPermitida,
/// CompromisoEvidencia)`». Ninguna decisión no permisiva es convertible a este
/// tipo, de modo que el error es de compilación y no de ejecución.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionPermitida {
    hash_paquete: HashPaqueteNormativo,
    traza: TrazaPrecedencia,
    codigo: Option<CodigoRazon>,
}

impl DecisionPermitida {
    /// Rechaza un permiso sin norma citada, aplicación de INV-02 —«ausencia de
    /// permiso sin norma citada»—, y rechaza cualquier código de razón que no
    /// sea compatible con una salida permisiva.
    pub fn nueva(
        hash_paquete: HashPaqueteNormativo,
        traza: TrazaPrecedencia,
        codigo: Option<CodigoRazon>,
    ) -> Result<Self, ErrorDecision> {
        if traza.aplicadas().is_empty() {
            return Err(ErrorDecision::PermisoSinNormaCitada);
        }
        if let Some(codigo) = codigo {
            if !codigo.admisible_en_decision_permitida() {
                return Err(ErrorDecision::CodigoNoAdmisibleEnPermitida(codigo));
            }
        }
        Ok(DecisionPermitida {
            hash_paquete,
            traza,
            codigo,
        })
    }

    pub fn veredicto(&self) -> Veredicto {
        Veredicto::Allow
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    /// Normas citadas, que son las normas aplicadas de la traza. Hay una sola
    /// fuente para esta lista: dos copias podrían divergir.
    pub fn normas_citadas(&self) -> &[IdNorma] {
        self.traza.aplicadas()
    }

    pub fn traza(&self) -> &TrazaPrecedencia {
        &self.traza
    }

    pub fn codigo(&self) -> Option<CodigoRazon> {
        self.codigo
    }
}

/// Decisión denegatoria. Su código de razón es obligatorio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionDenegada {
    hash_paquete: HashPaqueteNormativo,
    traza: TrazaPrecedencia,
    codigo: CodigoRazon,
}

impl DecisionDenegada {
    /// No exige normas citadas: una denegación con `SIN_NORMA_APLICABLE` es
    /// precisamente el caso en el que no hay ninguna norma que aplicar.
    pub fn nueva(
        hash_paquete: HashPaqueteNormativo,
        traza: TrazaPrecedencia,
        codigo: CodigoRazon,
    ) -> Self {
        DecisionDenegada {
            hash_paquete,
            traza,
            codigo,
        }
    }

    pub fn veredicto(&self) -> Veredicto {
        Veredicto::Deny
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    pub fn normas_citadas(&self) -> &[IdNorma] {
        self.traza.aplicadas()
    }

    pub fn traza(&self) -> &TrazaPrecedencia {
        &self.traza
    }

    pub fn codigo(&self) -> CodigoRazon {
        self.codigo
    }
}

/// Decisión escalada a supervisión humana. Su código de razón es obligatorio.
///
/// Las condiciones del escalado —rol, competencia, quórum, independencia y
/// plazo— viven en la norma; el componente `supervision` (Bloque 10 / H.10)
/// comprueba la intervención humana firmada sin interpretar la norma ni
/// sustituir al motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionEscalada {
    hash_paquete: HashPaqueteNormativo,
    traza: TrazaPrecedencia,
    codigo: CodigoRazon,
}

impl DecisionEscalada {
    pub fn nueva(
        hash_paquete: HashPaqueteNormativo,
        traza: TrazaPrecedencia,
        codigo: CodigoRazon,
    ) -> Self {
        DecisionEscalada {
            hash_paquete,
            traza,
            codigo,
        }
    }

    pub fn veredicto(&self) -> Veredicto {
        Veredicto::Escalate
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    pub fn normas_citadas(&self) -> &[IdNorma] {
        self.traza.aplicadas()
    }

    pub fn traza(&self) -> &TrazaPrecedencia {
        &self.traza
    }

    pub fn codigo(&self) -> CodigoRazon {
        self.codigo
    }
}

/// Decisión de suspensión. Su código de razón es obligatorio.
///
/// **Límite declarado del Bloque 1.** `SUSPEND` existe porque R2 lo nombra en
/// el orden, de modo que el orden es representable por completo. Ninguna fila
/// de G.3 produce este veredicto: la suspensión llega de la máquina de estados
/// y del monitor de supuestos, que son bloques posteriores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionSuspendida {
    hash_paquete: HashPaqueteNormativo,
    traza: TrazaPrecedencia,
    codigo: CodigoRazon,
}

impl DecisionSuspendida {
    pub fn nueva(
        hash_paquete: HashPaqueteNormativo,
        traza: TrazaPrecedencia,
        codigo: CodigoRazon,
    ) -> Self {
        DecisionSuspendida {
            hash_paquete,
            traza,
            codigo,
        }
    }

    pub fn veredicto(&self) -> Veredicto {
        Veredicto::Suspend
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    pub fn normas_citadas(&self) -> &[IdNorma] {
        self.traza.aplicadas()
    }

    pub fn traza(&self) -> &TrazaPrecedencia {
        &self.traza
    }

    pub fn codigo(&self) -> CodigoRazon {
        self.codigo
    }
}

/// Resultado de una decisión del Kernel.
///
/// El veredicto no es un campo: es la variante. Una decisión no puede afirmar
/// `ALLOW` siendo una denegación porque no existe ningún sitio donde escribir
/// esa contradicción.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Permitida(DecisionPermitida),
    Denegada(DecisionDenegada),
    Escalada(DecisionEscalada),
    Suspendida(DecisionSuspendida),
}

impl Decision {
    pub fn veredicto(&self) -> Veredicto {
        match self {
            Decision::Permitida(d) => d.veredicto(),
            Decision::Denegada(d) => d.veredicto(),
            Decision::Escalada(d) => d.veredicto(),
            Decision::Suspendida(d) => d.veredicto(),
        }
    }

    /// Hash del paquete normativo, obligatorio en toda decisión por INV-03.
    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        match self {
            Decision::Permitida(d) => d.hash_paquete(),
            Decision::Denegada(d) => d.hash_paquete(),
            Decision::Escalada(d) => d.hash_paquete(),
            Decision::Suspendida(d) => d.hash_paquete(),
        }
    }

    pub fn normas_citadas(&self) -> &[IdNorma] {
        match self {
            Decision::Permitida(d) => d.normas_citadas(),
            Decision::Denegada(d) => d.normas_citadas(),
            Decision::Escalada(d) => d.normas_citadas(),
            Decision::Suspendida(d) => d.normas_citadas(),
        }
    }

    pub fn traza(&self) -> &TrazaPrecedencia {
        match self {
            Decision::Permitida(d) => d.traza(),
            Decision::Denegada(d) => d.traza(),
            Decision::Escalada(d) => d.traza(),
            Decision::Suspendida(d) => d.traza(),
        }
    }

    /// Código de razón. Es `None` únicamente en una decisión permisiva, porque
    /// G.3 no define ningún código para `ALLOW`.
    pub fn codigo(&self) -> Option<CodigoRazon> {
        match self {
            Decision::Permitida(d) => d.codigo(),
            Decision::Denegada(d) => Some(d.codigo()),
            Decision::Escalada(d) => Some(d.codigo()),
            Decision::Suspendida(d) => Some(d.codigo()),
        }
    }
}

impl From<DecisionPermitida> for Decision {
    fn from(d: DecisionPermitida) -> Self {
        Decision::Permitida(d)
    }
}

impl From<DecisionDenegada> for Decision {
    fn from(d: DecisionDenegada) -> Self {
        Decision::Denegada(d)
    }
}

impl From<DecisionEscalada> for Decision {
    fn from(d: DecisionEscalada) -> Self {
        Decision::Escalada(d)
    }
}

impl From<DecisionSuspendida> for Decision {
    fn from(d: DecisionSuspendida) -> Self {
        Decision::Suspendida(d)
    }
}

// =============================================================================
// Errores de construcción
// =============================================================================

/// Estado incoherente rechazado en la construcción de una decisión o de su traza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDecision {
    /// Identificador de norma vacío o compuesto solo de espacios.
    IdNormaVacio,
    /// La misma norma aparece dos veces en la traza.
    NormaDuplicadaEnTraza(IdNorma),
    /// La misma norma figura a la vez como aplicada y como inerte.
    NormaAplicadaTambienInerte(IdNorma),
    /// Decisión permisiva sin ninguna norma citada, contra INV-02.
    PermisoSinNormaCitada,
    /// Código de razón incompatible con una decisión permisiva.
    CodigoNoAdmisibleEnPermitida(CodigoRazon),
}

impl fmt::Display for ErrorDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorDecision::IdNormaVacio => {
                f.write_str("identificador de norma vacio")
            }
            ErrorDecision::NormaDuplicadaEnTraza(id) => {
                write!(f, "norma duplicada en la traza de precedencia: {id}")
            }
            ErrorDecision::NormaAplicadaTambienInerte(id) => {
                write!(f, "norma declarada aplicada e inerte a la vez: {id}")
            }
            ErrorDecision::PermisoSinNormaCitada => {
                f.write_str("decision permisiva sin norma citada")
            }
            ErrorDecision::CodigoNoAdmisibleEnPermitida(codigo) => {
                write!(f, "codigo de razon no admisible en decision permitida: {codigo}")
            }
        }
    }
}

impl std::error::Error for ErrorDecision {}
