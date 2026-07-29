//! Registro firmado y paquete exportable.

use crate::crypto::{self, dominio};
use crate::decision::{Decision, DecisionPermitida, LONGITUD_HASH_PAQUETE};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdSujeto(String);

impl IdSujeto {
    pub fn nuevo(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err("sujeto vacio");
        }
        Ok(IdSujeto(id))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdSujeto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TipoRegistro {
    Decision = 1,
    Recibo = 2,
    /// Transición de máquina de estados (Bloque 9).
    TransicionEstado = 3,
    /// Solicitud / firmas / hecho de supervisión humana (Bloque 10 / H.10).
    Supervision = 4,
    /// Gobernanza de corpus: diffs, firmas, sombra, activación, revocación (Bloque 11).
    Gobernanza = 5,
    /// Catálogo / invocación / delegación de herramientas EF-4 (rebanada repo EF-4).
    Herramienta = 6,
    /// Operación de negocio EF-5: ejecución delegada, recibo/incidente.
    Negocio = 7,
    /// Comunicaciones EF-6: hechos de contacto, envío, recibo/incidente.
    Comunicacion = 8,
    /// Publicación EF-7: autorización, hechos, ejecución, recibo/retirada.
    Publicacion = 9,
    /// Consumo de decisión sobre personas EF-8.
    DecisionPersona = 10,
    /// Régimen EF-9: estado, inventario ALCANZABLES, denegaciones (no mediación).
    Ef9 = 11,
    /// Egreso / movimiento de datos entre dominios EF-10.
    EgresoDatos = 12,
    /// Efecto físico / ciberfísico EF-11.
    EfectoFisico = 13,
}

/// Recibo del efecto (H fase 14). Digests, no contenido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReciboEfecto {
    pub digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_decision: [u8; LONGITUD_HASH_PAQUETE],
    /// Digest canónico de las condiciones aplicadas por el PEP (H.14).
    pub digest_condiciones: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroFirmado {
    pub sujeto: IdSujeto,
    pub epoca: u64,
    pub secuencia: u64,
    pub prev_hash: [u8; LONGITUD_HASH_PAQUETE],
    pub tipo: TipoRegistro,
    pub payload: Vec<u8>,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_mldsa: Vec<u8>,
}

impl RegistroFirmado {
    pub fn cuerpo_para_hash(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.sujeto.como_str().as_bytes());
        v.push(0);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.secuencia.to_le_bytes());
        v.extend_from_slice(&self.prev_hash);
        v.push(self.tipo as u8);
        v.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.payload);
        v
    }

    pub fn calcular_digest(cuerpo: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, cuerpo)
    }
}

/// Serialización canónica mínima de una decisión para el payload del registro.
pub fn serializar_decision(d: &Decision) -> Result<Vec<u8>, crate::evidencia::ErrorEvidencia> {
    // INV-03 / H-5: rechazar decisión sin hash de paquete (imposible por tipo)
    // o sin normas citadas en una permitida.
    if let Decision::Permitida(p) = d {
        if p.normas_citadas().is_empty() {
            return Err(crate::evidencia::ErrorEvidencia::DecisionSinCita);
        }
    }
    let mut out = Vec::new();
    out.push(1); // versión
    out.push(match d.veredicto() {
        crate::decision::Veredicto::Deny => 0,
        crate::decision::Veredicto::Suspend => 1,
        crate::decision::Veredicto::Escalate => 2,
        crate::decision::Veredicto::Allow => 3,
    });
    out.extend_from_slice(d.hash_paquete().bytes());
    let normas = d.normas_citadas();
    out.extend_from_slice(&(normas.len() as u32).to_le_bytes());
    for n in normas {
        let b = n.como_str().as_bytes();
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    }
    out.extend_from_slice(&d.traza().pasos_consumidos().to_le_bytes());
    // Digest de dominio sobre la decisión serializada (para cardinalidad).
    let _ = crypto::sha384_dominio(dominio::DECISION, &out);
    Ok(out)
}

pub fn digest_decision_permitida(d: &DecisionPermitida) -> [u8; LONGITUD_HASH_PAQUETE] {
    let dec: Decision = d.clone().into();
    let bytes = serializar_decision(&dec).expect("permitida con normas");
    crypto::sha384_dominio(dominio::DECISION, &bytes)
}

pub fn serializar_recibo(r: &ReciboEfecto) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(2); // v2: incluye digest_condiciones (H.14 / Bloque 6)
    out.extend_from_slice(&r.digest_parametros);
    out.extend_from_slice(&r.digest_resultado);
    out.extend_from_slice(&r.digest_decision);
    out.extend_from_slice(&r.digest_condiciones);
    out
}

/// Paquete exportable para el verificador independiente (sin Kernel, sin red).
#[derive(Debug, Clone)]
pub struct PaqueteEvidencia {
    pub registros: Vec<RegistroFirmado>,
    pub checkpoints: Vec<crate::evidencia::CheckpointEpoca>,
    pub pk_autoridad_mldsa: Vec<u8>,
    pub pk_testigo_1_slh: Vec<u8>,
    pub pk_testigo_2_slh: Vec<u8>,
}
