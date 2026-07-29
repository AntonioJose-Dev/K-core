//! Capacidad: emisor y verificador (Bloque 5 — INV-01, INV-07, INV-08; H.12–H.13).
//!
//! - Constructor privado; única ruta [`emitir`].
//! - Ligadura a decisión permisiva, compromiso durable, sistema autenticado,
//!   digest canónico del efecto, alcance mínimo, época y vida útil.
//! - Sin ampliación, prórroga, transferencia, reactivación ni caché permisiva.

mod emision;
mod tipos;
mod verificacion;

pub use emision::{digest_efecto_canonico, emitir, ErrorEmision, ParametrosEmision};
pub use tipos::{
    Alcance, Capability, ClasificacionEfecto, CompromisoEvidencia, IdCapacidad,
};
pub use verificacion::{
    CausaDenegacion, IntentoUso, RegistroDenegacionUso, ResultadoVerificacion,
    VerificadorCapacidades, VistaRevocacion,
};
