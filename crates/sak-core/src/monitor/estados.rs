//! Siete estados canónicos del dominio.

use std::fmt;

/// Máquina única (S0–S6). Tokens alineados con PERFECTO §6.2 y Matriz I.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EstadoMaquina {
    /// S0 — arranque, sin material de clave.
    Cold = 0,
    /// S1 — POST/KAT/entropía de arranque.
    Selftest = 1,
    /// S2 — identidad establecida; corpus/PEP incompletos.
    Sealed = 2,
    /// S3 — operación normal (permisivo pleno).
    Armed = 3,
    /// S4 — supuesto no crítico perdido; solo efectos reversibles.
    Degraded = 4,
    /// S5 — supuesto crítico / incidente; sin autorización.
    Suspended = 5,
    /// S6 — terminal (autotest/TCB); no recuperación en sitio.
    FailStatic = 6,
}

impl EstadoMaquina {
    pub fn token(self) -> &'static str {
        match self {
            EstadoMaquina::Cold => "COLD",
            EstadoMaquina::Selftest => "SELFTEST",
            EstadoMaquina::Sealed => "SEALED",
            EstadoMaquina::Armed => "ARMED",
            EstadoMaquina::Degraded => "DEGRADED",
            EstadoMaquina::Suspended => "SUSPENDED",
            EstadoMaquina::FailStatic => "FAIL_STATIC",
        }
    }

    /// Autorización plena (cualquier clase según norma/Libro).
    pub fn permite_autorizacion_plena(self) -> bool {
        matches!(self, EstadoMaquina::Armed)
    }

    /// Solo efectos reversibles (S4).
    pub fn permite_solo_reversibles(self) -> bool {
        matches!(self, EstadoMaquina::Degraded)
    }

    /// ¿Se puede emitir/ejercer capacidad para este efecto?
    pub fn permite_capacidad(self, efecto_irreversible: bool) -> bool {
        match self {
            EstadoMaquina::Armed => true,
            EstadoMaquina::Degraded => !efecto_irreversible,
            _ => false,
        }
    }

    /// Evidencia sigue escribiéndose en S3–S6 (PERFECTO §6.2).
    pub fn permite_escritura_evidencia(self) -> bool {
        !matches!(self, EstadoMaquina::Cold | EstadoMaquina::Selftest)
    }

    pub fn es_terminal(self) -> bool {
        matches!(self, EstadoMaquina::FailStatic)
    }
}

impl fmt::Display for EstadoMaquina {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
