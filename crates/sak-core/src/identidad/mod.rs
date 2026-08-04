//! Identidad de workload, autoridad de certificación y registro soberano (Bloque 4).
//!
//! INV-04, INV-05; fases 2 y 3 de H.
//!
//! Perfil local: **ESCRITORIO-VAL-EXT** (Matriz §E): verificación local del
//! certificado presentado al proceso. **No afirma mTLS ni identidad fuerte de red.**
//!
//! - La identidad efectiva se deriva **solo** del artefacto de autoridad.
//! - El campo de identidad autodeclarado de la petición se ignora siempre.
//! - Sin pasaporte vigente/firmado/versionado ⇒ `DENY(SIN_REGISTRO)` + hallazgo.
//! - Artefacto no verificable ⇒ `DENY(IDENTIDAD)`.

mod artefacto;
mod authn;
mod ca;
mod ca_durable;
mod pasaporte;
mod puerta;
mod registro;
mod registro_durable;

pub use artefacto::{ArtefactoCliente, IdSistema, PruebaPosesion};
pub use authn::{autenticar_artefacto, autenticar_mutua, IdentidadResuelta};
pub use ca::{
    AutoridadCertificacion, ErrorEmisionCert, ErrorVerificacionCert,
    PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT,
};
pub use ca_durable::{cargar_ca_desde_almacen, conservar_ca, ErrorCaDurable};
pub use pasaporte::{DeclaracionResponsable, Pasaporte, PasaporteVigente};
pub use puerta::{
    resolver_puerta_h2_h3, CodigoPuerta, ContextoAutorizado, HallazgoSistemaNoRegistrado,
    PeticionIdentidad, ResultadoPuerta,
};
pub use registro::{ErrorRegistro, RegistroSoberano};
pub use registro_durable::{
    cargar_registro_desde_almacen, clave_almacen_pasaporte, conservar_pasaporte,
    registrar_desde_declaracion_y_conservar, registrar_y_conservar, resolver_pasaporte,
    ErrorRegistroDurable,
};
