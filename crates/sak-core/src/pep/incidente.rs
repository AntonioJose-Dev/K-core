//! Incidentes de mediación (H.14): divergencia autorizado vs ejecutado.

use crate::capacidad::IdCapacidad;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::reloj::Ticks;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TipoIncidente {
    /// Parámetros ejecutados ≠ autorizados.
    DivergenciaParametros,
    /// Efecto producido con evidencia incompleta (H.15).
    EvidenciaIncompleta,
    /// Resultado del efector indeterminado (EF-5); sin reintento automático.
    ResultadoIndeterminado,
}

impl fmt::Display for TipoIncidente {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TipoIncidente::DivergenciaParametros => write!(f, "DIVERGENCIA_PARAMETROS"),
            TipoIncidente::EvidenciaIncompleta => write!(f, "EVIDENCIA_INCOMPLETA"),
            TipoIncidente::ResultadoIndeterminado => write!(f, "RESULTADO_INDETERMINADO"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidenteMediacion {
    pub tipo: TipoIncidente,
    pub id_capacidad: Option<IdCapacidad>,
    pub digest_autorizado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_ejecutado: [u8; LONGITUD_HASH_PAQUETE],
    pub ticks: Ticks,
}
