//! Emisión de capacidades (H.12).

use super::tipos::{
    Alcance, Capability, ClasificacionEfecto, CompromisoEvidencia, IdCapacidad,
};
use crate::crypto::{self, dominio};
use crate::decision::{DecisionPermitida, LONGITUD_HASH_PAQUETE};
use crate::identidad::IdSistema;
use crate::reloj::{RelojMonotonico, Ticks};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEmision {
    EpocaInvalida,
    EpocaInferiorAlSuelo { epoca: u64, suelo: u64 },
    TtlCero,
    VencimientoInconsistente,
    /// EF-9 no emite capacidades: se prohíbe o se confina (rebanada EF-9; C/INV-11).
    EfectoEf9Prohibido,
}

impl fmt::Display for ErrorEmision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorEmision::EpocaInvalida => write!(f, "epoca invalida (0)"),
            ErrorEmision::EpocaInferiorAlSuelo { epoca, suelo } => {
                write!(f, "epoca {epoca} inferior al suelo {suelo}")
            }
            ErrorEmision::TtlCero => write!(f, "vida util cero"),
            ErrorEmision::VencimientoInconsistente => write!(f, "vencimiento inconsistente"),
            ErrorEmision::EfectoEf9Prohibido => {
                write!(f, "EF-9 no emite capacidades (prohibido o no confinado)")
            }
        }
    }
}

impl std::error::Error for ErrorEmision {}

/// Parámetros de ligadura exigidos además de decisión + compromiso (INV-08).
#[derive(Debug, Clone)]
pub struct ParametrosEmision {
    pub sistema: IdSistema,
    pub digest_efecto: [u8; LONGITUD_HASH_PAQUETE],
    pub alcance: Alcance,
    pub epoca: u64,
    /// Suelo monótono del dominio: la época de emisión no puede quedar por debajo.
    pub epoca_suelo: u64,
    pub ttl_ticks: Ticks,
    pub clasificacion: ClasificacionEfecto,
}

/// Digest canónico del efecto y sus parámetros (ligadura INV-08).
pub fn digest_efecto_canonico(
    clase: &str,
    parametros: &[u8],
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut msg = Vec::with_capacity(clase.len() + 8 + parametros.len());
    msg.extend_from_slice(&(clase.len() as u32).to_le_bytes());
    msg.extend_from_slice(clase.as_bytes());
    msg.extend_from_slice(&(parametros.len() as u32).to_le_bytes());
    msg.extend_from_slice(parametros);
    crypto::sha384_dominio(b"SAK-EFFECT-v1|", &msg)
}

/// Única ruta tipada de creación de autoridad (INV-01 + INV-08).
///
/// # Harness `sin_capacidad_sin_evidencia`
///
/// ```compile_fail
/// use sak_core::capacidad::{emitir, Alcance, ClasificacionEfecto, ParametrosEmision};
/// use sak_core::decision::{
///     DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia,
///     LONGITUD_HASH_PAQUETE,
/// };
/// use sak_core::identidad::IdSistema;
/// use sak_core::reloj::RelojInyectado;
///
/// let hash = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
/// let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-1").unwrap()], vec![], 0).unwrap();
/// let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
/// let reloj = RelojInyectado::nuevo(0);
/// let params = ParametrosEmision {
///     sistema: IdSistema::nuevo("s").unwrap(),
///     digest_efecto: [1u8; LONGITUD_HASH_PAQUETE],
///     alcance: Alcance::minimo(["r"]).unwrap(),
///     epoca: 1,
///     epoca_suelo: 1,
///     ttl_ticks: 100,
///     clasificacion: ClasificacionEfecto::irreversible(),
/// };
/// let _capacidad = emitir(decision, params, &reloj);
/// ```
///
/// # Compromiso inaccesible fuera del crate
///
/// ```compile_fail
/// use sak_core::capacidad::CompromisoEvidencia;
/// use sak_core::decision::LONGITUD_HASH_PAQUETE;
/// let _ = CompromisoEvidencia::tras_confirmacion_durable([0u8; LONGITUD_HASH_PAQUETE]);
/// ```
///
/// ```compile_fail
/// use sak_core::capacidad::emitir;
/// use sak_core::decision::{
///     CodigoRazon, DecisionDenegada, HashPaqueteNormativo, TrazaPrecedencia,
///     LONGITUD_HASH_PAQUETE,
/// };
///
/// let hash = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
/// let traza = TrazaPrecedencia::nueva(vec![], vec![], 0).unwrap();
/// let denegada = DecisionDenegada::nueva(hash, traza, CodigoRazon::SinNormaAplicable);
/// let _ = emitir(denegada, denegada);
/// ```
pub fn emitir(
    decision: DecisionPermitida,
    evidencia: CompromisoEvidencia,
    params: ParametrosEmision,
    reloj: &impl RelojMonotonico,
) -> Result<Capability, ErrorEmision> {
    if params.epoca == 0 {
        return Err(ErrorEmision::EpocaInvalida);
    }
    if params.epoca < params.epoca_suelo {
        return Err(ErrorEmision::EpocaInferiorAlSuelo {
            epoca: params.epoca,
            suelo: params.epoca_suelo,
        });
    }
    if params.ttl_ticks == 0 {
        return Err(ErrorEmision::TtlCero);
    }
    if params
        .alcance
        .tokens()
        .iter()
        .any(|t| t == "EF-9" || t.starts_with("EF-9|") || t.starts_with("ef9:"))
    {
        return Err(ErrorEmision::EfectoEf9Prohibido);
    }
    let emitido_en = reloj.ahora();
    let vive_hasta = emitido_en.saturating_add(params.ttl_ticks);
    if vive_hasta < emitido_en {
        return Err(ErrorEmision::VencimientoInconsistente);
    }

    let id = derivar_id(&evidencia, &params, emitido_en);
    let un_solo_uso = params.clasificacion.exige_un_solo_uso();

    Ok(Capability {
        decision,
        evidencia,
        sistema: params.sistema,
        digest_efecto: params.digest_efecto,
        alcance: params.alcance,
        epoca: params.epoca,
        emitido_en,
        vive_hasta,
        id,
        un_solo_uso,
        irreversible: params.clasificacion.irreversible,
    })
}

fn derivar_id(
    evidencia: &CompromisoEvidencia,
    params: &ParametrosEmision,
    emitido_en: Ticks,
) -> IdCapacidad {
    let mut msg = Vec::new();
    msg.extend_from_slice(evidencia.digest());
    msg.extend_from_slice(params.sistema.como_str().as_bytes());
    msg.push(0);
    msg.extend_from_slice(&params.digest_efecto);
    msg.extend_from_slice(&params.alcance.canonico());
    msg.extend_from_slice(&params.epoca.to_le_bytes());
    msg.extend_from_slice(&emitido_en.to_le_bytes());
    msg.extend_from_slice(&params.ttl_ticks.to_le_bytes());
    let d = crypto::sha384_dominio(dominio::DECISION, &msg);
    // Separación de dominio propia del nonce de capacidad.
    let nonce = crypto::sha384_dominio(b"SAK-CAP-NONCE-v1|", &d);
    IdCapacidad::desde_digest(nonce)
}
