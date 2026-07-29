//! Solicitud de supervisión inmutable y tipada.

use crate::capacidad::Alcance;
use crate::contexto::{ClaseEfecto, Contexto};
use crate::crypto::{self, dominio};
use crate::decision::{
    CodigoRazon, Decision, DecisionEscalada, HashPaqueteNormativo, IdNorma, LONGITUD_HASH_PAQUETE,
};
use crate::identidad::IdSistema;
use crate::norma::Escalado;
use crate::reloj::Ticks;
use crate::supervision::identidad::IdHumano;
use std::fmt;

/// Digest canónico del contexto (H.10: firma sobre el digest exacto).
pub fn digest_contexto(ctx: &Contexto) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut v = Vec::new();
    v.push(ctx.efecto().clase() as u8);
    v.extend_from_slice(ctx.efecto().digest_parametros());
    v.extend_from_slice(&ctx.instante_epoch_dias().to_le_bytes());
    v.extend_from_slice(&(ctx.hechos().len() as u32).to_le_bytes());
    for h in ctx.hechos() {
        let p = h.productor().como_str().as_bytes();
        v.extend_from_slice(&(p.len() as u16).to_le_bytes());
        v.extend_from_slice(p);
        v.extend_from_slice(h.digest());
        // Firma como bytes opacos (productor); longitud + contenido.
        let f = h.firma().bytes();
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(f);
        v.extend_from_slice(&h.antiguedad_segundos().to_le_bytes());
        v.extend_from_slice(&h.antiguedad_maxima_segundos().to_le_bytes());
    }
    crypto::sha384_dominio(dominio::CONTEXTO, &v)
}

/// Requisitos de escalado tomados de la norma (no interpretados por supervisión).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequisitosEscalado {
    pub id_norma: IdNorma,
    pub obligacion: String,
    pub rol: String,
    pub competencia: String,
    pub quorum: u8,
    pub exige_independencia: bool,
    pub plazo_segundos: u64,
}

impl RequisitosEscalado {
    pub fn desde_escalado(id_norma: IdNorma, obligacion: impl Into<String>, e: &Escalado) -> Self {
        RequisitosEscalado {
            id_norma,
            obligacion: obligacion.into(),
            rol: e.rol.clone(),
            competencia: e.competencia.clone(),
            quorum: e.quorum,
            exige_independencia: e.exige_independencia,
            plazo_segundos: e.plazo_segundos,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSolicitud {
    NoEsEscalada,
    CampoObligatorioAusente(&'static str),
    QuorumCero,
    PlazoCero,
}

impl fmt::Display for ErrorSolicitud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorSolicitud::NoEsEscalada => {
                f.write_str("supervision solo acepta Decision::Escalada")
            }
            ErrorSolicitud::CampoObligatorioAusente(c) => {
                write!(f, "campo obligatorio ausente: {c}")
            }
            ErrorSolicitud::QuorumCero => f.write_str("quorum debe ser >= 1"),
            ErrorSolicitud::PlazoCero => f.write_str("plazo debe ser > 0"),
        }
    }
}

impl std::error::Error for ErrorSolicitud {}

/// Solicitud de supervisión inmutable. Si falta o cambia un campo ⇒ inválida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudSupervision {
    digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    id_solicitante: IdHumano,
    sistema: IdSistema,
    clase: ClaseEfecto,
    hash_paquete: HashPaqueteNormativo,
    codigo_escalada: CodigoRazon,
    id_norma: IdNorma,
    obligacion: String,
    rol_requerido: String,
    competencia_requerida: String,
    quorum: u8,
    exige_independencia: bool,
    plazo_hasta: Ticks,
    instante_creacion: Ticks,
    epoca: u64,
    alcance_efecto: Alcance,
    /// Digest de todos los campos anteriores (integridad de la solicitud).
    digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
}

impl SolicitudSupervision {
    pub fn construir(
        decision: &DecisionEscalada,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        id_solicitante: IdHumano,
        sistema: IdSistema,
        clase: ClaseEfecto,
        requisitos: RequisitosEscalado,
        instante_creacion: Ticks,
        epoca: u64,
        alcance_efecto: Alcance,
    ) -> Result<Self, ErrorSolicitud> {
        if requisitos.rol.trim().is_empty() {
            return Err(ErrorSolicitud::CampoObligatorioAusente("rol"));
        }
        if requisitos.competencia.trim().is_empty() {
            return Err(ErrorSolicitud::CampoObligatorioAusente("competencia"));
        }
        if requisitos.obligacion.trim().is_empty() {
            return Err(ErrorSolicitud::CampoObligatorioAusente("obligacion"));
        }
        if requisitos.quorum == 0 {
            return Err(ErrorSolicitud::QuorumCero);
        }
        if requisitos.plazo_segundos == 0 {
            return Err(ErrorSolicitud::PlazoCero);
        }
        let plazo_hasta = instante_creacion.saturating_add(requisitos.plazo_segundos.saturating_mul(1000));
        let mut s = SolicitudSupervision {
            digest_contexto,
            id_solicitante,
            sistema,
            clase,
            hash_paquete: decision.hash_paquete().clone(),
            codigo_escalada: decision.codigo(),
            id_norma: requisitos.id_norma,
            obligacion: requisitos.obligacion,
            rol_requerido: requisitos.rol,
            competencia_requerida: requisitos.competencia,
            quorum: requisitos.quorum,
            exige_independencia: requisitos.exige_independencia,
            plazo_hasta,
            instante_creacion,
            epoca,
            alcance_efecto,
            digest_solicitud: [0u8; LONGITUD_HASH_PAQUETE],
        };
        s.digest_solicitud = s.calcular_digest();
        Ok(s)
    }

    fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.digest_contexto);
        let id = self.id_solicitante.como_str().as_bytes();
        v.extend_from_slice(&(id.len() as u16).to_le_bytes());
        v.extend_from_slice(id);
        let sys = self.sistema.como_str().as_bytes();
        v.extend_from_slice(&(sys.len() as u16).to_le_bytes());
        v.extend_from_slice(sys);
        v.push(self.clase as u8);
        v.extend_from_slice(self.hash_paquete.bytes());
        v.push(self.codigo_escalada as u8);
        let n = self.id_norma.como_str().as_bytes();
        v.extend_from_slice(&(n.len() as u16).to_le_bytes());
        v.extend_from_slice(n);
        let o = self.obligacion.as_bytes();
        v.extend_from_slice(&(o.len() as u16).to_le_bytes());
        v.extend_from_slice(o);
        let r = self.rol_requerido.as_bytes();
        v.extend_from_slice(&(r.len() as u16).to_le_bytes());
        v.extend_from_slice(r);
        let c = self.competencia_requerida.as_bytes();
        v.extend_from_slice(&(c.len() as u16).to_le_bytes());
        v.extend_from_slice(c);
        v.push(self.quorum);
        v.push(u8::from(self.exige_independencia));
        v.extend_from_slice(&self.plazo_hasta.to_le_bytes());
        v.extend_from_slice(&self.instante_creacion.to_le_bytes());
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.alcance_efecto.canonico());
        v
    }

    pub fn calcular_digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::SUPERVISION, &self.cuerpo_canonico())
    }

    /// Invalida si el digest almacenado no coincide con el recálculo (campo alterado).
    pub fn integra(&self) -> bool {
        self.digest_solicitud == self.calcular_digest()
    }

    pub fn serializar_payload(&self) -> Vec<u8> {
        let mut v = self.cuerpo_canonico();
        v.extend_from_slice(&self.digest_solicitud);
        v
    }

    pub fn digest_contexto(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_contexto
    }

    pub fn digest_solicitud(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_solicitud
    }

    pub fn id_solicitante(&self) -> &IdHumano {
        &self.id_solicitante
    }

    pub fn sistema(&self) -> &IdSistema {
        &self.sistema
    }

    pub fn clase(&self) -> ClaseEfecto {
        self.clase
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    pub fn codigo_escalada(&self) -> CodigoRazon {
        self.codigo_escalada
    }

    pub fn id_norma(&self) -> &IdNorma {
        &self.id_norma
    }

    pub fn obligacion(&self) -> &str {
        &self.obligacion
    }

    pub fn rol_requerido(&self) -> &str {
        &self.rol_requerido
    }

    pub fn competencia_requerida(&self) -> &str {
        &self.competencia_requerida
    }

    pub fn quorum(&self) -> u8 {
        self.quorum
    }

    pub fn exige_independencia(&self) -> bool {
        self.exige_independencia
    }

    pub fn plazo_hasta(&self) -> Ticks {
        self.plazo_hasta
    }

    pub fn instante_creacion(&self) -> Ticks {
        self.instante_creacion
    }

    pub fn epoca(&self) -> u64 {
        self.epoca
    }

    pub fn alcance_efecto(&self) -> &Alcance {
        &self.alcance_efecto
    }
}

/// Solo desde `Decision::Escalada`. Una denegación previa no produce solicitud.
pub fn desde_decision(
    decision: &Decision,
    digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    id_solicitante: IdHumano,
    sistema: IdSistema,
    clase: ClaseEfecto,
    requisitos: RequisitosEscalado,
    instante_creacion: Ticks,
    epoca: u64,
    alcance_efecto: Alcance,
) -> Result<SolicitudSupervision, ErrorSolicitud> {
    match decision {
        Decision::Escalada(esc) => SolicitudSupervision::construir(
            esc,
            digest_contexto,
            id_solicitante,
            sistema,
            clase,
            requisitos,
            instante_creacion,
            epoca,
            alcance_efecto,
        ),
        _ => Err(ErrorSolicitud::NoEsEscalada),
    }
}
