//! Comprobación técnica de quórum, independencia, firmas y competencias.

use crate::crypto::{ErrorCrypto, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::reloj::Ticks;
use crate::supervision::hecho::{FirmaAprobador, HechoSupervision, VeredictoHumano};
use crate::supervision::identidad::RegistroHumanos;
use crate::supervision::solicitud::SolicitudSupervision;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSupervision {
    SolicitudInvalida,
    PlazoVencido,
    FirmaInvalida,
    IdentidadNoRegistrada,
    RolOCompetenciaAusente,
    RolOCompetenciaVencida,
    IdentidadDuplicada,
    FaltaIndependencia,
    QuorumInsuficiente,
    RechazoExplicito,
    DigestContextoDistinto,
    Silencio,
    DecisionOriginalDenegada,
    CampoAlterado,
}

impl fmt::Display for ErrorSupervision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSupervision::SolicitudInvalida => f.write_str("solicitud invalida o incompleta"),
            ErrorSupervision::PlazoVencido => f.write_str("plazo de supervision vencido"),
            ErrorSupervision::FirmaInvalida => f.write_str("firma humana invalida"),
            ErrorSupervision::IdentidadNoRegistrada => f.write_str("aprobador no registrado"),
            ErrorSupervision::RolOCompetenciaAusente => {
                f.write_str("rol o competencia no atestados")
            }
            ErrorSupervision::RolOCompetenciaVencida => {
                f.write_str("rol o competencia no vigentes")
            }
            ErrorSupervision::IdentidadDuplicada => f.write_str("identidad duplicada en quorum"),
            ErrorSupervision::FaltaIndependencia => {
                f.write_str("solicitante no puede aprobar (independencia)")
            }
            ErrorSupervision::QuorumInsuficiente => f.write_str("quorum insuficiente"),
            ErrorSupervision::RechazoExplicito => f.write_str("rechazo humano explicito"),
            ErrorSupervision::DigestContextoDistinto => {
                f.write_str("digest de contexto alterado o distinto")
            }
            ErrorSupervision::Silencio => f.write_str("silencio: sin hecho humano a tiempo"),
            ErrorSupervision::DecisionOriginalDenegada => {
                f.write_str("no se puede aprobar una decision DENY del motor")
            }
            ErrorSupervision::CampoAlterado => f.write_str("campo de solicitud o hecho alterado"),
        }
    }
}

impl std::error::Error for ErrorSupervision {}

/// Firma ML-DSA del digest exacto del contexto (mensaje de dominio supervisión).
pub fn firmar_digest_contexto(
    par: &ParMlDsa87,
    digest_contexto: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<Vec<u8>, ErrorCrypto> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"aprobacion|");
    msg.extend_from_slice(digest_contexto);
    par.firmar(&msg)
}

fn mensaje_firma(digest_contexto: &[u8; LONGITUD_HASH_PAQUETE]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"aprobacion|");
    msg.extend_from_slice(digest_contexto);
    msg
}

/// Verifica una firma individual contra el registro y la solicitud.
pub fn verificar_firma_aprobador(
    solicitud: &SolicitudSupervision,
    firma: &FirmaAprobador,
    registro: &RegistroHumanos,
    ahora: Ticks,
) -> Result<(), ErrorSupervision> {
    if !solicitud.integra() {
        return Err(ErrorSupervision::SolicitudInvalida);
    }
    if ahora > solicitud.plazo_hasta() {
        return Err(ErrorSupervision::PlazoVencido);
    }
    if solicitud.exige_independencia() && firma.id == *solicitud.id_solicitante() {
        return Err(ErrorSupervision::FaltaIndependencia);
    }
    let ident = registro
        .identidad(&firma.id)
        .ok_or(ErrorSupervision::IdentidadNoRegistrada)?;
    let msg = mensaje_firma(solicitud.digest_contexto());
    if ParMlDsa87::verificar(&ident.pk_mldsa, &msg, &firma.firma_mldsa).is_err() {
        return Err(ErrorSupervision::FirmaInvalida);
    }
    if firma.rol_declarado != solicitud.rol_requerido()
        || firma.competencia_declarada != solicitud.competencia_requerida()
    {
        return Err(ErrorSupervision::RolOCompetenciaAusente);
    }
    match registro.competencia_vigente(
        &firma.id,
        solicitud.rol_requerido(),
        solicitud.competencia_requerida(),
        solicitud.clase(),
        ahora,
    ) {
        Some(c) => {
            if c.etiqueta != firma.etiqueta {
                return Err(ErrorSupervision::RolOCompetenciaAusente);
            }
            Ok(())
        }
        None => {
            if registro.tiene_atestacion(
                &firma.id,
                solicitud.rol_requerido(),
                solicitud.competencia_requerida(),
                solicitud.clase(),
            ) {
                Err(ErrorSupervision::RolOCompetenciaVencida)
            } else {
                Err(ErrorSupervision::RolOCompetenciaAusente)
            }
        }
    }
}

/// Verifica el conjunto completo de firmas y el hecho.
pub fn verificar_hecho_completo(
    solicitud: &SolicitudSupervision,
    hecho: &HechoSupervision,
    registro: &RegistroHumanos,
    ahora: Ticks,
) -> Result<(), ErrorSupervision> {
    if !solicitud.integra() || !hecho.integra() {
        return Err(ErrorSupervision::CampoAlterado);
    }
    if hecho.digest_solicitud() != solicitud.digest_solicitud() {
        return Err(ErrorSupervision::CampoAlterado);
    }
    if hecho.digest_contexto() != solicitud.digest_contexto() {
        return Err(ErrorSupervision::DigestContextoDistinto);
    }
    if hecho.epoca() != solicitud.epoca() {
        return Err(ErrorSupervision::CampoAlterado);
    }
    if hecho.plazo_hasta() != solicitud.plazo_hasta() {
        return Err(ErrorSupervision::CampoAlterado);
    }
    if ahora > solicitud.plazo_hasta() || hecho.instante() > solicitud.plazo_hasta() {
        return Err(ErrorSupervision::PlazoVencido);
    }
    if hecho.veredicto() == VeredictoHumano::Rechazado {
        return Err(ErrorSupervision::RechazoExplicito);
    }

    let mut vistos = BTreeSet::new();
    let mut validas = 0u8;
    for firma in hecho.firmas() {
        if !vistos.insert(firma.id.como_str().to_string()) {
            return Err(ErrorSupervision::IdentidadDuplicada);
        }
        verificar_firma_aprobador(solicitud, firma, registro, ahora)?;
        validas = validas.saturating_add(1);
    }
    if validas < solicitud.quorum() {
        return Err(ErrorSupervision::QuorumInsuficiente);
    }
    Ok(())
}

/// Construye un hecho a partir de firmas tras verificación parcial; no autoriza por sí solo.
pub fn construir_hecho(
    solicitud: &SolicitudSupervision,
    veredicto: VeredictoHumano,
    firmas: Vec<FirmaAprobador>,
    instante: Ticks,
) -> HechoSupervision {
    HechoSupervision::nuevo(
        *solicitud.digest_contexto(),
        *solicitud.digest_solicitud(),
        veredicto,
        firmas,
        instante,
        solicitud.epoca(),
        solicitud.plazo_hasta(),
    )
}
