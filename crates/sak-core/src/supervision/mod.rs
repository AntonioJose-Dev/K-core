//! Supervisión humana firmada (Bloque 10 — H.10; INV-12, INV-16).
//!
//! Limitada a solicitudes de escalado ya producidas por el motor. No interpreta
//! la norma, no sustituye el motor, no crea capacidades, no relaja el Libro de
//! Control, no recupera estados por vía técnica y no aprueba efectos que el
//! motor haya denegado.
//!
//! La competencia no la «decide» el Kernel: se consume como atestación humana
//! o externa firmada y se etiqueta como supuesto / `VAL-EXT`.

mod flujo;
mod hecho;
mod identidad;
mod ledger_payload;
mod solicitud;
mod verificar;

pub use flujo::{
    continuar_tras_supervision, crear_solicitud_desde_escalada, denegar_silencio,
    denegar_vencimiento, resolver_firmas, resolver_silencio, ResultadoSupervision,
};
pub use hecho::{
    FirmaAprobador, HechoSupervision, TipoHechoSupervision, VeredictoHumano,
};
pub use identidad::{
    CompetenciaAtestada, EtiquetaCompetencia, IdHumano, IdentidadHumana, RegistroHumanos,
};
pub use ledger_payload::{
    payload_evento, payload_expiracion, payload_fallo, payload_hecho_aprobacion,
    payload_hecho_rechazo, payload_silencio, payload_solicitud,
};
pub use solicitud::{
    digest_contexto, desde_decision, ErrorSolicitud, RequisitosEscalado, SolicitudSupervision,
};
pub use verificar::{
    construir_hecho, firmar_digest_contexto, verificar_firma_aprobador, verificar_hecho_completo,
    ErrorSupervision,
};
