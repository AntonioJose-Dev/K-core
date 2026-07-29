//! Registro de transición de estado (causa, supuesto, época, digest, alcance).

use crate::contexto::ClaseEfecto;
use crate::crypto::{self, dominio};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::IdSistema;
use crate::monitor::estados::EstadoMaquina;
use crate::monitor::monitor::{AlcanceAfectado, SupuestoCritico};
use crate::reloj::Ticks;

#[derive(Debug, Clone)]
pub struct RegistroTransicion {
    pub desde: EstadoMaquina,
    pub hacia: EstadoMaquina,
    pub causa: String,
    pub supuesto: Option<SupuestoCritico>,
    pub epoca: u64,
    pub ticks: Ticks,
    pub digest_hecho: [u8; LONGITUD_HASH_PAQUETE],
    pub alcance: AlcanceAfectado,
    pub sistema: Option<IdSistema>,
    pub clase: Option<ClaseEfecto>,
}

impl RegistroTransicion {
    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-TRANS-v1|");
        v.extend_from_slice(self.desde.token().as_bytes());
        v.push(b'>');
        v.extend_from_slice(self.hacia.token().as_bytes());
        v.push(0);
        v.extend_from_slice(self.causa.as_bytes());
        v.push(0);
        if let Some(s) = self.supuesto {
            v.extend_from_slice(s.token().as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.ticks.to_le_bytes());
        v.extend_from_slice(&self.digest_hecho);
        v.extend_from_slice(self.alcance.token().as_bytes());
        v
    }

    pub fn digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, &self.cuerpo_canonico())
    }
}
