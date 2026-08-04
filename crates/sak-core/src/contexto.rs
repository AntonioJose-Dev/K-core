//! Contexto tipado y hechos firmados — entrada del motor (INV-14, H fase 6).
//!
//! Fuente canónica: Matriz Maestra v1.1 — INV-14 («reloj y mediciones inyectados
//! como hechos firmados»), fase 6 de H («Hechos firmados: reloj, mediciones…;
//! Ningún hecho sin firma entra») y las doce clases de efecto de la sección C.
//!
//! **Límite declarado del Bloque 1.** La firma es un campo de datos. La
//! verificación criptográfica del productor llega con los Bloques 3–4. Este
//! módulo rechaza hechos sin firma por construcción de tipos; no verifica la
//! validez criptográfica de esa firma.

use crate::decision::LONGITUD_HASH_PAQUETE;
use std::fmt;

/// Las doce clases de efecto de la sección C. Lista cerrada.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub const fn token(self) -> &'static str {
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

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "EF-1" => Some(ClaseEfecto::Ef1),
            "EF-2" => Some(ClaseEfecto::Ef2),
            "EF-3" => Some(ClaseEfecto::Ef3),
            "EF-4" => Some(ClaseEfecto::Ef4),
            "EF-5" => Some(ClaseEfecto::Ef5),
            "EF-6" => Some(ClaseEfecto::Ef6),
            "EF-7" => Some(ClaseEfecto::Ef7),
            "EF-8" => Some(ClaseEfecto::Ef8),
            "EF-9" => Some(ClaseEfecto::Ef9),
            "EF-10" => Some(ClaseEfecto::Ef10),
            "EF-11" => Some(ClaseEfecto::Ef11),
            "EF-12" => Some(ClaseEfecto::Ef12),
            _ => None,
        }
    }
}

impl fmt::Display for ClaseEfecto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Identificador estable de un productor de hechos.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdProductor(String);

impl IdProductor {
    pub fn nuevo(id: impl Into<String>) -> Result<Self, ErrorContexto> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(ErrorContexto::IdProductorVacio);
        }
        Ok(IdProductor(id))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdProductor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Firma de un productor, como dato. No se verifica en el Bloque 1.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FirmaProductor(Vec<u8>);

impl FirmaProductor {
    /// Rechaza una firma vacía: «Ningún hecho sin firma entra» (H fase 6).
    pub fn nueva(bytes: Vec<u8>) -> Result<Self, ErrorContexto> {
        if bytes.is_empty() {
            return Err(ErrorContexto::FirmaVacia);
        }
        Ok(FirmaProductor(bytes))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Hecho firmado inyectado en el contexto. Inmutable.
///
/// El reloj, las mediciones y cualquier valor de entorno llegan por aquí
/// (INV-14). `antiguedad_segundos` y `antiguedad_maxima_segundos` son datos
/// aportados por el productor o por quien ensambla el contexto; el motor no
/// consulta el reloj del sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoFirmado {
    productor: IdProductor,
    digest: [u8; LONGITUD_HASH_PAQUETE],
    firma: FirmaProductor,
    antiguedad_segundos: u64,
    antiguedad_maxima_segundos: u64,
}

impl HechoFirmado {
    pub fn nuevo(
        productor: IdProductor,
        digest: [u8; LONGITUD_HASH_PAQUETE],
        firma: FirmaProductor,
        antiguedad_segundos: u64,
        antiguedad_maxima_segundos: u64,
    ) -> Self {
        HechoFirmado {
            productor,
            digest,
            firma,
            antiguedad_segundos,
            antiguedad_maxima_segundos,
        }
    }

    pub fn productor(&self) -> &IdProductor {
        &self.productor
    }

    pub fn digest(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest
    }

    pub fn firma(&self) -> &FirmaProductor {
        &self.firma
    }

    pub fn antiguedad_segundos(&self) -> u64 {
        self.antiguedad_segundos
    }

    pub fn antiguedad_maxima_segundos(&self) -> u64 {
        self.antiguedad_maxima_segundos
    }

    /// Hecho caducado según los datos inyectados. Un hecho caducado se evalúa
    /// como falso (INV-10); el motor lo trata en el Bloque 1 como evidencia
    /// ausente cuando se exige.
    pub fn caducado(&self) -> bool {
        self.antiguedad_segundos > self.antiguedad_maxima_segundos
    }
}

/// Efecto tipado solicitado. No es lenguaje natural (H fase 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfectoTipado {
    clase: ClaseEfecto,
    /// Digest canónico de los parámetros tipados. Los parámetros en sí no se
    /// modelan en el Bloque 1: basta su digest para la comparación determinista.
    digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
}

impl EfectoTipado {
    pub fn nuevo(
        clase: ClaseEfecto,
        digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Self {
        EfectoTipado {
            clase,
            digest_parametros,
        }
    }

    pub fn clase(&self) -> ClaseEfecto {
        self.clase
    }

    pub fn digest_parametros(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_parametros
    }
}

/// Contexto tipado de una solicitud de decisión. Inmutable.
///
/// `instante_epoch_dias` es el reloj inyectado como dato (INV-14): el motor no
/// consulta el reloj del sistema. Unidad: días desde 1970-01-01.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contexto {
    efecto: EfectoTipado,
    hechos: Vec<HechoFirmado>,
    instante_epoch_dias: u32,
}

impl Contexto {
    /// Construye un contexto sin instante explícito (epoch 0). Suficiente para
    /// los vectores del Bloque 1 que no evalúan vigencia.
    pub fn nuevo(efecto: EfectoTipado, hechos: Vec<HechoFirmado>) -> Self {
        Contexto {
            efecto,
            hechos,
            instante_epoch_dias: 0,
        }
    }

    pub fn con_instante(
        efecto: EfectoTipado,
        hechos: Vec<HechoFirmado>,
        instante_epoch_dias: u32,
    ) -> Self {
        Contexto {
            efecto,
            hechos,
            instante_epoch_dias,
        }
    }

    pub fn efecto(&self) -> &EfectoTipado {
        &self.efecto
    }

    pub fn hechos(&self) -> &[HechoFirmado] {
        &self.hechos
    }

    pub fn instante_epoch_dias(&self) -> u32 {
        self.instante_epoch_dias
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorContexto {
    IdProductorVacio,
    FirmaVacia,
}

impl fmt::Display for ErrorContexto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorContexto::IdProductorVacio => f.write_str("identificador de productor vacio"),
            ErrorContexto::FirmaVacia => f.write_str("firma de productor vacia"),
        }
    }
}

impl std::error::Error for ErrorContexto {}
