//! sak-core — Núcleo autoritativo del Sovereign AI Kernel.
//!
//! Alcance de código: entregables §M 1–12 (plan Matriz) más rebanadas de
//! repositorio para PEPs EF-1…EF-8, EF-10–EF-11 y régimen EF-9 (C/E/F; **no**
//! son filas §M posteriores a 12). Ver `docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md`.
//! No afirma C5_HOST_REAL, HSM, atestación de plataforma real, hardware real,
//! despliegue real, completitud de inventario ni conformidad legal.
//!
//! Restricciones: `#![forbid(unsafe_code)]` en la ruta de decisión. El módulo
//! `crypto` usa crates auditados FIPS 204/205 sin `unsafe` propio.

#![forbid(unsafe_code)]

pub mod capacidad;
pub mod contexto;
pub mod crypto;
pub mod custodia;
pub mod decision;
pub mod evidencia;
pub mod gobernanza;
pub mod identidad;
pub mod libro;
pub mod monitor;
pub mod motor;
pub mod norma;
pub mod pep;
pub mod perfil;
pub mod precedencia;
pub mod predicado;
pub mod presupuesto;
pub mod reloj;
pub mod supervision;
