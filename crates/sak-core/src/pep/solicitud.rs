//! Solicitud tipada de efecto (H.1). Sin interpretación de lenguaje natural.

use crate::capacidad::digest_efecto_canonico;
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use std::fmt;

/// Clases C de la Matriz. Bloque 6 solo admite EF-1 en el gateway de modelos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClaseEfecto {
    Ef1 = 1,
    Ef2 = 2,
    Ef3 = 3,
    Ef4 = 4,
    Ef5 = 5,
    Ef6 = 6,
    Ef7 = 7,
    Ef8 = 8,
    Ef9 = 9,
    Ef10 = 10,
    Ef11 = 11,
    Ef12 = 12,
}

impl ClaseEfecto {
    pub fn token(self) -> &'static str {
        match self {
            ClaseEfecto::Ef1 => "EF-1",
            ClaseEfecto::Ef2 => "EF-2",
            ClaseEfecto::Ef3 => "EF-3",
            ClaseEfecto::Ef4 => "EF-4",
            ClaseEfecto::Ef5 => "EF-5",
            ClaseEfecto::Ef6 => "EF-6",
            ClaseEfecto::Ef7 => "EF-7",
            ClaseEfecto::Ef8 => "EF-8",
            ClaseEfecto::Ef9 => "EF-9",
            ClaseEfecto::Ef10 => "EF-10",
            ClaseEfecto::Ef11 => "EF-11",
            ClaseEfecto::Ef12 => "EF-12",
        }
    }
}

impl fmt::Display for ClaseEfecto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Solicitud tipada de inferencia (EF-1). Campos cerrados; no hay texto libre de intención.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudInferencia {
    pub modelo: String,
    pub prompt_digest: [u8; LONGITUD_HASH_PAQUETE],
    pub max_tokens: u32,
    pub temperatura_millis: u32,
}

impl SolicitudInferencia {
    pub fn nueva(
        modelo: impl Into<String>,
        prompt_digest: [u8; LONGITUD_HASH_PAQUETE],
        max_tokens: u32,
        temperatura_millis: u32,
    ) -> Result<Self, &'static str> {
        let modelo = modelo.into();
        if modelo.trim().is_empty() {
            return Err("modelo vacio");
        }
        if max_tokens == 0 {
            return Err("max_tokens cero");
        }
        Ok(SolicitudInferencia {
            modelo,
            prompt_digest,
            max_tokens,
            temperatura_millis,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef1
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-1|");
        v.extend_from_slice(&(self.modelo.len() as u32).to_le_bytes());
        v.extend_from_slice(self.modelo.as_bytes());
        v.extend_from_slice(&self.prompt_digest);
        v.extend_from_slice(&self.max_tokens.to_le_bytes());
        v.extend_from_slice(&self.temperatura_millis.to_le_bytes());
        v
    }
}

/// Entrada al PEP: tipada o no tipificable (H.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudCruda {
    Tipada(SolicitudInferencia),
    /// Efecto que no encaja en el vocabulario tipado ⇒ `DENY(EFECTO_NO_TIPIFICADO)`.
    NoTipificable,
    /// Clase distinta de EF-1 presentada a este gateway.
    ClaseNoSoportada(ClaseEfecto),
}

/// Condiciones que el gateway aplica al ejecutar (H.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesAplicadas {
    pub modelo: String,
    pub max_tokens: u32,
    pub temperatura_millis: u32,
    pub clase: ClaseEfecto,
}

impl CondicionesAplicadas {
    pub fn desde_solicitud(s: &SolicitudInferencia) -> Self {
        CondicionesAplicadas {
            modelo: s.modelo.clone(),
            max_tokens: s.max_tokens,
            temperatura_millis: s.temperatura_millis,
            clase: ClaseEfecto::Ef1,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(self.clase.token().as_bytes());
        v.push(0);
        v.extend_from_slice(&(self.modelo.len() as u32).to_le_bytes());
        v.extend_from_slice(self.modelo.as_bytes());
        v.extend_from_slice(&self.max_tokens.to_le_bytes());
        v.extend_from_slice(&self.temperatura_millis.to_le_bytes());
        v
    }
}

pub fn digest_solicitud_inferencia(s: &SolicitudInferencia) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-1", &s.canonico())
}

pub fn canon_condiciones(c: &CondicionesAplicadas) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-COND-v1|", &c.canonico())
}
