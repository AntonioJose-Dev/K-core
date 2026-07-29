//! Hecho firmado de aprobación o rechazo de supervisión (H.10).

use crate::crypto::{self, dominio};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::reloj::Ticks;
use crate::supervision::identidad::IdHumano;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VeredictoHumano {
    Aprobado = 1,
    Rechazado = 2,
}

impl VeredictoHumano {
    pub const fn token(self) -> &'static str {
        match self {
            VeredictoHumano::Aprobado => "APROBADO",
            VeredictoHumano::Rechazado => "RECHAZADO",
        }
    }
}

/// Tipo de registro de supervisión para el ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TipoHechoSupervision {
    Solicitud = 1,
    Firma = 2,
    Aprobacion = 3,
    Rechazo = 4,
    Expiracion = 5,
    Fallo = 6,
    Silencio = 7,
}

impl TipoHechoSupervision {
    pub const fn token(self) -> &'static str {
        match self {
            TipoHechoSupervision::Solicitud => "SOLICITUD",
            TipoHechoSupervision::Firma => "FIRMA",
            TipoHechoSupervision::Aprobacion => "APROBACION",
            TipoHechoSupervision::Rechazo => "RECHAZO",
            TipoHechoSupervision::Expiracion => "EXPIRACION",
            TipoHechoSupervision::Fallo => "FALLO",
            TipoHechoSupervision::Silencio => "SILENCIO",
        }
    }
}

/// Firma de un aprobador sobre el digest exacto del contexto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmaAprobador {
    pub id: IdHumano,
    pub rol_declarado: String,
    pub competencia_declarada: String,
    pub etiqueta: crate::supervision::identidad::EtiquetaCompetencia,
    pub firma_mldsa: Vec<u8>,
}

impl FirmaAprobador {
    pub fn serializar(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let id = self.id.como_str().as_bytes();
        v.extend_from_slice(&(id.len() as u16).to_le_bytes());
        v.extend_from_slice(id);
        let r = self.rol_declarado.as_bytes();
        v.extend_from_slice(&(r.len() as u16).to_le_bytes());
        v.extend_from_slice(r);
        let c = self.competencia_declarada.as_bytes();
        v.extend_from_slice(&(c.len() as u16).to_le_bytes());
        v.extend_from_slice(c);
        v.push(self.etiqueta as u8);
        v.extend_from_slice(&(self.firma_mldsa.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.firma_mldsa);
        v
    }
}

/// Hecho firmado de supervisión: aprobación o rechazo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoSupervision {
    digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    veredicto: VeredictoHumano,
    firmas: Vec<FirmaAprobador>,
    instante: Ticks,
    epoca: u64,
    plazo_hasta: Ticks,
    digest_hecho: [u8; LONGITUD_HASH_PAQUETE],
}

impl HechoSupervision {
    pub fn nuevo(
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
        veredicto: VeredictoHumano,
        firmas: Vec<FirmaAprobador>,
        instante: Ticks,
        epoca: u64,
        plazo_hasta: Ticks,
    ) -> Self {
        let mut h = HechoSupervision {
            digest_contexto,
            digest_solicitud,
            veredicto,
            firmas,
            instante,
            epoca,
            plazo_hasta,
            digest_hecho: [0u8; LONGITUD_HASH_PAQUETE],
        };
        h.digest_hecho = h.calcular_digest();
        h
    }

    fn cuerpo(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.digest_contexto);
        v.extend_from_slice(&self.digest_solicitud);
        v.push(self.veredicto as u8);
        v.extend_from_slice(&(self.firmas.len() as u32).to_le_bytes());
        for f in &self.firmas {
            let s = f.serializar();
            v.extend_from_slice(&(s.len() as u32).to_le_bytes());
            v.extend_from_slice(&s);
        }
        v.extend_from_slice(&self.instante.to_le_bytes());
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.plazo_hasta.to_le_bytes());
        v
    }

    pub fn calcular_digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        let mut msg = self.cuerpo();
        msg.extend_from_slice(b"|hecho|");
        crypto::sha384_dominio(dominio::SUPERVISION, &msg)
    }

    pub fn serializar_payload(&self) -> Vec<u8> {
        let mut v = self.cuerpo();
        v.extend_from_slice(&self.digest_hecho);
        v
    }

    pub fn digest_contexto(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_contexto
    }

    pub fn digest_solicitud(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_solicitud
    }

    pub fn digest_hecho(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_hecho
    }

    pub fn veredicto(&self) -> VeredictoHumano {
        self.veredicto
    }

    pub fn firmas(&self) -> &[FirmaAprobador] {
        &self.firmas
    }

    pub fn instante(&self) -> Ticks {
        self.instante
    }

    pub fn epoca(&self) -> u64 {
        self.epoca
    }

    pub fn plazo_hasta(&self) -> Ticks {
        self.plazo_hasta
    }

    pub fn integra(&self) -> bool {
        self.digest_hecho == self.calcular_digest()
    }
}

impl fmt::Display for VeredictoHumano {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
