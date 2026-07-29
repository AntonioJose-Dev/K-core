//! Identidad de workload, autoridad de certificación y registro soberano (Bloque 4).
//!
//! INV-04, INV-05; fases 2 y 3 de H.
//!
//! - La identidad efectiva se deriva **solo** del artefacto de autoridad.
//! - El campo de identidad autodeclarado de la petición se ignora siempre.
//! - Sin pasaporte vigente/firmado/versionado ⇒ `DENY(SIN_REGISTRO)` + hallazgo.
//! - Artefacto no verificable ⇒ `DENY(IDENTIDAD)`.

mod artefacto;
mod authn;
mod ca;
mod pasaporte;
mod puerta;
mod registro;

pub use artefacto::{ArtefactoCliente, IdSistema, PruebaPosesion};
pub use authn::{autenticar_artefacto, autenticar_mutua, IdentidadResuelta};
pub use ca::AutoridadCertificacion;
pub use pasaporte::{Pasaporte, PasaporteVigente};
pub use puerta::{
    resolver_puerta_h2_h3, CodigoPuerta, ContextoAutorizado, HallazgoSistemaNoRegistrado,
    PeticionIdentidad, ResultadoPuerta,
};
pub use registro::RegistroSoberano;
