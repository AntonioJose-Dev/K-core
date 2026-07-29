//! Serialización de eventos de supervisión para el ledger.

use crate::supervision::hecho::{HechoSupervision, TipoHechoSupervision};
use crate::supervision::solicitud::SolicitudSupervision;

/// Prefijo tipado + cuerpo para `TipoRegistro::Supervision`.
pub fn payload_evento(tipo: TipoHechoSupervision, cuerpo: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(tipo as u8);
    v.extend_from_slice(&(cuerpo.len() as u32).to_le_bytes());
    v.extend_from_slice(cuerpo);
    v
}

pub fn payload_solicitud(s: &SolicitudSupervision) -> Vec<u8> {
    payload_evento(TipoHechoSupervision::Solicitud, &s.serializar_payload())
}

pub fn payload_hecho_aprobacion(h: &HechoSupervision) -> Vec<u8> {
    payload_evento(TipoHechoSupervision::Aprobacion, &h.serializar_payload())
}

pub fn payload_hecho_rechazo(h: &HechoSupervision) -> Vec<u8> {
    payload_evento(TipoHechoSupervision::Rechazo, &h.serializar_payload())
}

pub fn payload_fallo(digest_solicitud: &[u8], motivo: &str) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(digest_solicitud);
    c.extend_from_slice(motivo.as_bytes());
    payload_evento(TipoHechoSupervision::Fallo, &c)
}

pub fn payload_silencio(digest_solicitud: &[u8]) -> Vec<u8> {
    payload_evento(TipoHechoSupervision::Silencio, digest_solicitud)
}

pub fn payload_expiracion(digest_solicitud: &[u8]) -> Vec<u8> {
    payload_evento(TipoHechoSupervision::Expiracion, digest_solicitud)
}
