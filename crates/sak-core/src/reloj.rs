//! Reloj monótono inyectado/verificable (INV-08). No usa reloj ambiente.

use std::cell::Cell;
use std::fmt;

/// Instante monótono en ticks (1 tick ≡ 1 ms de política de antigüedad).
pub type Ticks = u64;

/// Antigüedad máxima de la vista de revocación para efectos reversibles (Matriz L).
pub const MAX_ANTIGUEDAD_VISTA_REVOCACION_MS: Ticks = 5_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorReloj {
    Retroceso { actual: Ticks, propuesto: Ticks },
}

impl fmt::Display for ErrorReloj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorReloj::Retroceso { actual, propuesto } => {
                write!(f, "reloj monotono no retrocede: {actual} -> {propuesto}")
            }
        }
    }
}

impl std::error::Error for ErrorReloj {}

/// Fuente de tiempo verificable: solo avanza.
pub trait RelojMonotonico {
    fn ahora(&self) -> Ticks;
}

/// Reloj inyectado para emisión, verificación y harnesses.
#[derive(Debug)]
pub struct RelojInyectado {
    ticks: Cell<Ticks>,
}

impl RelojInyectado {
    pub fn nuevo(inicio: Ticks) -> Self {
        RelojInyectado {
            ticks: Cell::new(inicio),
        }
    }

    pub fn ahora(&self) -> Ticks {
        self.ticks.get()
    }

    pub fn avanzar(&self, delta: Ticks) -> Result<Ticks, ErrorReloj> {
        let actual = self.ticks.get();
        let siguiente = actual.saturating_add(delta);
        if siguiente < actual {
            return Err(ErrorReloj::Retroceso {
                actual,
                propuesto: siguiente,
            });
        }
        self.ticks.set(siguiente);
        Ok(siguiente)
    }

    /// Fija un instante ≥ al actual. Rechaza retroceso.
    pub fn fijar(&self, ticks: Ticks) -> Result<(), ErrorReloj> {
        let actual = self.ticks.get();
        if ticks < actual {
            return Err(ErrorReloj::Retroceso {
                actual,
                propuesto: ticks,
            });
        }
        self.ticks.set(ticks);
        Ok(())
    }
}

impl RelojMonotonico for RelojInyectado {
    fn ahora(&self) -> Ticks {
        RelojInyectado::ahora(self)
    }
}

impl RelojMonotonico for &RelojInyectado {
    fn ahora(&self) -> Ticks {
        (*self).ahora()
    }
}
