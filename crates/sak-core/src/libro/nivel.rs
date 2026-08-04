//! Niveles C0–C5 del Libro de Control.
//!
//! `NivelControl::C5` como resultado de `calcular_nivel_base` se denomina
//! explícitamente [`C5_CALCULADO_SOBRE_HECHOS_APORTADOS`]. Queda prohibido
//! inferir o declarar [`C5_HOST_REAL_PROHIBIDO`].

use std::fmt;

/// Denominación normativa cuando el cálculo D.3 sobre hechos aportados produce C5.
pub const C5_CALCULADO_SOBRE_HECHOS_APORTADOS: &str = "C5_CALCULADO_SOBRE_HECHOS_APORTADOS";

/// Etiqueta prohibida: no inferir ni declarar C5 como propiedad del host real.
pub const C5_HOST_REAL_PROHIBIDO: &str = "C5_HOST_REAL";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum NivelControl {
    C0 = 0,
    C1 = 1,
    C2 = 2,
    C3 = 3,
    C4 = 4,
    C5 = 5,
}

impl NivelControl {
    pub fn token(self) -> &'static str {
        match self {
            NivelControl::C0 => "C0",
            NivelControl::C1 => "C1",
            NivelControl::C2 => "C2",
            NivelControl::C3 => "C3",
            NivelControl::C4 => "C4",
            NivelControl::C5 => "C5",
        }
    }

    /// Si es C5, la denominación de prueba/auditoría (nunca `C5_HOST_REAL`).
    pub fn denominacion_c5_calculado(self) -> Option<&'static str> {
        if self == NivelControl::C5 {
            Some(C5_CALCULADO_SOBRE_HECHOS_APORTADOS)
        } else {
            None
        }
    }

    pub fn min(self, other: Self) -> Self {
        if self <= other {
            self
        } else {
            other
        }
    }

    pub fn desde_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(NivelControl::C0),
            1 => Some(NivelControl::C1),
            2 => Some(NivelControl::C2),
            3 => Some(NivelControl::C3),
            4 => Some(NivelControl::C4),
            5 => Some(NivelControl::C5),
            _ => None,
        }
    }
}

impl fmt::Display for NivelControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
