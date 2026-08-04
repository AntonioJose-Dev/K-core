//! Canal operador local — Observar (`obs.*`) + andamiaje Conectar/Custodiar/Gobernar (`ops`).
//!
//! Conforme a `docs/CONTRATO-IPC-OPERADOR-LOCAL.md`.
//! Sin bind público. Sin telemetría. Sin secretos exportables.
//! Fase 0: `ops` reconoce allowlist MVP y responde `FASE0_SIN_HANDLER` (sin negocio).

pub mod obs;
pub mod ops;
pub mod sujeto;

pub use sujeto::{FronteraSujeto, ResultadoDecidir, ResultadoEjercer};
