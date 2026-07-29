//! Época monótona persistida antes de usarse (anti-rollback).

use crate::evidencia::AlmacenEvidencia;
use crate::reloj::Ticks;
use std::fmt;

const CLAVE_SUELO: &[u8] = b"sak/epoca/suelo";
const CLAVE_ACTUAL: &[u8] = b"sak/epoca/actual";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEpoca {
    Retroceso { suelo: u64, propuesto: u64 },
    Persistencia,
    PerdidaSuelo,
}

impl fmt::Display for ErrorEpoca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorEpoca::Retroceso { suelo, propuesto } => {
                write!(f, "epoca no retrocede: suelo={suelo} propuesto={propuesto}")
            }
            ErrorEpoca::Persistencia => write!(f, "fallo al persistir epoca"),
            ErrorEpoca::PerdidaSuelo => write!(f, "suelo de epoca perdido o corrupto"),
        }
    }
}

impl std::error::Error for ErrorEpoca {}

/// Época monótona: el suelo se persiste **antes** de exponerse al resto del dominio.
#[derive(Debug, Clone)]
pub struct EpocaMonotonica {
    actual: u64,
    suelo: u64,
}

impl EpocaMonotonica {
    /// Carga o inicializa el suelo desde almacén durable, luego lo usa.
    pub fn cargar_o_iniciar(almacen: &mut dyn AlmacenEvidencia, inicio: u64) -> Result<Self, ErrorEpoca> {
        let inicio = inicio.max(1);
        let suelo = match almacen.leer(CLAVE_SUELO) {
            Some(bytes) if bytes.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&bytes);
                u64::from_le_bytes(a)
            }
            Some(_) => return Err(ErrorEpoca::PerdidaSuelo),
            None => {
                almacen
                    .escribir_durable(CLAVE_SUELO, &inicio.to_le_bytes())
                    .map_err(|_| ErrorEpoca::Persistencia)?;
                almacen
                    .escribir_durable(CLAVE_ACTUAL, &inicio.to_le_bytes())
                    .map_err(|_| ErrorEpoca::Persistencia)?;
                inicio
            }
        };
        let actual = match almacen.leer(CLAVE_ACTUAL) {
            Some(bytes) if bytes.len() == 8 => {
                let mut a = [0u8; 8];
                a.copy_from_slice(&bytes);
                u64::from_le_bytes(a).max(suelo)
            }
            _ => suelo,
        };
        if actual < suelo {
            return Err(ErrorEpoca::Retroceso {
                suelo,
                propuesto: actual,
            });
        }
        Ok(EpocaMonotonica { actual, suelo })
    }

    pub fn actual(&self) -> u64 {
        self.actual
    }

    pub fn suelo(&self) -> u64 {
        self.suelo
    }

    /// Avanza época: persiste el nuevo suelo **antes** de devolverlo.
    pub fn avanzar(&mut self, almacen: &mut dyn AlmacenEvidencia) -> Result<u64, ErrorEpoca> {
        let nuevo = self.actual.saturating_add(1);
        if nuevo < self.suelo {
            return Err(ErrorEpoca::Retroceso {
                suelo: self.suelo,
                propuesto: nuevo,
            });
        }
        almacen
            .escribir_durable(CLAVE_SUELO, &nuevo.to_le_bytes())
            .map_err(|_| ErrorEpoca::Persistencia)?;
        almacen
            .escribir_durable(CLAVE_ACTUAL, &nuevo.to_le_bytes())
            .map_err(|_| ErrorEpoca::Persistencia)?;
        self.suelo = nuevo;
        self.actual = nuevo;
        Ok(nuevo)
    }

    /// Detecta rollback: valor propuesto inferior al suelo persistido ⇒ pérdida.
    pub fn validar_no_retroceso(&self, propuesto: u64) -> Result<(), ErrorEpoca> {
        if propuesto < self.suelo {
            Err(ErrorEpoca::Retroceso {
                suelo: self.suelo,
                propuesto,
            })
        } else {
            Ok(())
        }
    }

    pub fn ticks_marcados(&self) -> Ticks {
        self.actual
    }
}
