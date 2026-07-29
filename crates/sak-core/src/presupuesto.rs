//! Presupuesto de pasos con interrupción determinista (INV-14, G).
//!
//! Fuente canónica: Matriz Maestra v1.1 — campo `predicado` de G.1 («presupuesto
//! de 10.000 pasos por norma y 100.000 por decisión») e INV-14 («presupuesto
//! con interrupción determinista»; agotado ⇒ `DENY(NORMA_NO_EVALUABLE)`).
//!
//! Sin reloj, sin aleatoriedad: el corte ocurre siempre en el mismo paso.

/// Máximo de pasos por norma evaluada.
pub const PASOS_POR_NORMA: u32 = 10_000;

/// Máximo de pasos por decisión completa.
pub const PASOS_POR_DECISION: u32 = 100_000;

/// Contador determinista de pasos. Inyectable; no observa el sistema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presupuesto {
    restante_decision: u32,
    restante_norma: u32,
    consumidos: u32,
}

impl Presupuesto {
    pub fn nuevo() -> Self {
        Presupuesto {
            restante_decision: PASOS_POR_DECISION,
            restante_norma: PASOS_POR_NORMA,
            consumidos: 0,
        }
    }

    /// Reinicia el cupo por norma al comenzar a evaluar otra norma. No reinicia
    /// el cupo de la decisión.
    pub fn comenzar_norma(&mut self) {
        self.restante_norma = PASOS_POR_NORMA;
    }

    /// Intenta consumir `n` pasos. Devuelve `Err(())` si el cupo de la norma o
    /// el de la decisión no alcanzan: la interrupción es determinista.
    pub fn consumir(&mut self, n: u32) -> Result<(), ()> {
        if n > self.restante_norma || n > self.restante_decision {
            return Err(());
        }
        self.restante_norma -= n;
        self.restante_decision -= n;
        self.consumidos = self.consumidos.saturating_add(n);
        Ok(())
    }

    pub fn consumidos(&self) -> u32 {
        self.consumidos
    }

    pub fn restante_decision(&self) -> u32 {
        self.restante_decision
    }

    pub fn restante_norma(&self) -> u32 {
        self.restante_norma
    }
}

impl Default for Presupuesto {
    fn default() -> Self {
        Self::nuevo()
    }
}
