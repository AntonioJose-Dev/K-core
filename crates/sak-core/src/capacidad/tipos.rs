//! Tipos de capacidad y compromiso de evidencia.

use crate::decision::{DecisionPermitida, LONGITUD_HASH_PAQUETE};
use crate::identidad::IdSistema;
use crate::reloj::Ticks;
use std::collections::BTreeSet;
use std::fmt;

/// Compromiso durable de la evidencia de una decisión.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CompromisoEvidencia {
    digest: [u8; LONGITUD_HASH_PAQUETE],
}

impl CompromisoEvidencia {
    /// Solo el ledger de evidencia, tras escritura durable confirmada.
    pub(crate) fn tras_confirmacion_durable(digest: [u8; LONGITUD_HASH_PAQUETE]) -> Self {
        CompromisoEvidencia { digest }
    }

    pub fn digest(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest
    }
}

/// Identificador opaco de capacidad (= nonce de unicidad).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdCapacidad([u8; LONGITUD_HASH_PAQUETE]);

impl IdCapacidad {
    pub fn as_bytes(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.0
    }

    pub(crate) fn desde_digest(d: [u8; LONGITUD_HASH_PAQUETE]) -> Self {
        IdCapacidad(d)
    }

    /// Mango opaco para pruebas / revocación programada (no es emisión).
    pub fn opaco(bytes: [u8; LONGITUD_HASH_PAQUETE]) -> Self {
        IdCapacidad(bytes)
    }
}

/// Alcance mínimo acotado (conjunto de tokens canónicos).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alcance {
    tokens: BTreeSet<String>,
}

impl Alcance {
    pub fn minimo(tokens: impl IntoIterator<Item = impl Into<String>>) -> Result<Self, &'static str> {
        let tokens: BTreeSet<String> = tokens.into_iter().map(Into::into).collect();
        if tokens.is_empty() || tokens.iter().any(|t| t.trim().is_empty()) {
            return Err("alcance vacio o token vacio");
        }
        Ok(Alcance { tokens })
    }

    pub fn tokens(&self) -> &BTreeSet<String> {
        &self.tokens
    }

    /// El solicitado debe ser subconjunto del concedido (sin ampliación).
    pub fn cubre(&self, solicitado: &Alcance) -> bool {
        solicitado.tokens.is_subset(&self.tokens)
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for t in &self.tokens {
            v.extend_from_slice(&(t.len() as u32).to_le_bytes());
            v.extend_from_slice(t.as_bytes());
        }
        v
    }
}

/// Clasificación del efecto (H.5) para unicidad INV-08.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClasificacionEfecto {
    pub irreversible: bool,
    pub afecta_personas: bool,
    pub datos_personales: bool,
}

impl ClasificacionEfecto {
    pub fn exige_un_solo_uso(self) -> bool {
        self.irreversible || self.afecta_personas || self.datos_personales
    }

    pub fn reversible_sin_personas() -> Self {
        ClasificacionEfecto {
            irreversible: false,
            afecta_personas: false,
            datos_personales: false,
        }
    }

    pub fn irreversible() -> Self {
        ClasificacionEfecto {
            irreversible: true,
            afecta_personas: false,
            datos_personales: false,
        }
    }
}

/// Autoridad materializada. Constructor privado (INV-01).
///
/// # Harness `capacidad_exige_decision`
///
/// ```compile_fail
/// use sak_core::capacidad::Capability;
/// use sak_core::decision::{
///     DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia,
///     LONGITUD_HASH_PAQUETE,
/// };
///
/// let hash = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
/// let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-1").unwrap()], vec![], 0).unwrap();
/// let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
/// let _capacidad = Capability { decision, evidencia: decision };
/// ```
#[derive(Debug, Clone)]
pub struct Capability {
    pub(crate) decision: DecisionPermitida,
    pub(crate) evidencia: CompromisoEvidencia,
    pub(crate) sistema: IdSistema,
    pub(crate) digest_efecto: [u8; LONGITUD_HASH_PAQUETE],
    pub(crate) alcance: Alcance,
    pub(crate) epoca: u64,
    pub(crate) emitido_en: Ticks,
    pub(crate) vive_hasta: Ticks,
    pub(crate) id: IdCapacidad,
    pub(crate) un_solo_uso: bool,
    pub(crate) irreversible: bool,
}

impl Capability {
    pub fn decision(&self) -> &DecisionPermitida {
        &self.decision
    }

    pub fn compromiso_evidencia(&self) -> &CompromisoEvidencia {
        &self.evidencia
    }

    pub fn sistema(&self) -> &IdSistema {
        &self.sistema
    }

    pub fn digest_efecto(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_efecto
    }

    pub fn alcance(&self) -> &Alcance {
        &self.alcance
    }

    pub fn epoca(&self) -> u64 {
        self.epoca
    }

    pub fn emitido_en(&self) -> Ticks {
        self.emitido_en
    }

    pub fn vive_hasta(&self) -> Ticks {
        self.vive_hasta
    }

    pub fn id(&self) -> &IdCapacidad {
        &self.id
    }

    pub fn un_solo_uso(&self) -> bool {
        self.un_solo_uso
    }

    pub fn irreversible(&self) -> bool {
        self.irreversible
    }
}

impl fmt::Display for IdCapacidad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
