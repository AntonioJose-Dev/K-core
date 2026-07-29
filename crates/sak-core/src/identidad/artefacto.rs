//! Artefacto de autoridad de workload (certificado de cliente del Kernel).

use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use std::fmt;

/// Identificador estable del sistema de IA (sujeto del certificado).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdSistema(String);

impl IdSistema {
    pub fn nuevo(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err("id sistema vacio");
        }
        Ok(IdSistema(id))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdSistema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Certificado de cliente emitido por la CA del Kernel, ligado a un pasaporte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtefactoCliente {
    pub sistema_id: IdSistema,
    pub pasaporte_id: String,
    pub pasaporte_version: u32,
    /// Clave pública ML-DSA-87 del workload (bytes).
    pub pk_workload: Vec<u8>,
    pub vigente_desde_dias: u32,
    pub vigente_hasta_dias: u32,
    /// Serial del certificado.
    pub serial: u64,
    /// Firma de la CA sobre el cuerpo canónico.
    pub firma_ca: Vec<u8>,
}

impl ArtefactoCliente {
    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-CERT-v1|");
        v.extend_from_slice(self.sistema_id.como_str().as_bytes());
        v.push(0);
        v.extend_from_slice(self.pasaporte_id.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.pasaporte_version.to_le_bytes());
        v.extend_from_slice(&(self.pk_workload.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.pk_workload);
        v.extend_from_slice(&self.vigente_desde_dias.to_le_bytes());
        v.extend_from_slice(&self.vigente_hasta_dias.to_le_bytes());
        v.extend_from_slice(&self.serial.to_le_bytes());
        v
    }

    pub fn digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, &self.cuerpo_canonico())
    }
}

/// Prueba de posesión de la clave del workload (firma sobre el digest de petición).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruebaPosesion {
    /// Digest del mensaje/petición que el cliente firma (inyectado; sin reloj).
    pub digest_peticion: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_workload: Vec<u8>,
}

impl PruebaPosesion {
    pub fn firmar(
        sk_workload: &ParMlDsa87,
        digest_peticion: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let firma = sk_workload.firmar(&digest_peticion)?;
        Ok(PruebaPosesion {
            digest_peticion,
            firma_workload: firma,
        })
    }
}
