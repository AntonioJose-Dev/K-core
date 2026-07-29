//! Gobernanza de cambios normativos (Bloque 11 — G.5; INV-03, INV-13, INV-16).
//!
//! El Kernel aplica interpretaciones aprobadas; no crea, valida ni certifica
//! interpretación jurídica. Competencias y calidad de citas/interpretaciones
//! dependientes de terceros se etiquetan `GOB` o `VAL-EXT`.

mod activacion;
mod conformidad;
mod corpus;
mod firmantes;
mod propuesta;

pub use activacion::{
    activar_en_limite_epoca, entrar_en_sombra, revocar_paquete, ErrorActivacion, VENTANA_SOMBRA_MS,
};
pub use conformidad::{
    decision_cita_construible, exigir_diff_reconocido, resultado_diff, CasoConformidad,
    CambioDecision, DiffDecisiones, ErrorDiff, ReconocimientoCambio,
};
pub use corpus::{EstadoPropuesta, EtiquetaGob, GobernanzaCorpus, VersionCorpus};
pub use firmantes::{
    verificar_doble_firma, ErrorFirmas, FirmaPaquete, FirmanteGobernanza, RegistroFirmantesGob,
    RolFirmante,
};
pub use propuesta::{
    validar_paquete_gobernado, AprobacionInterpretacion, EntradaCita, ErrorPropuesta,
    PropuestaNormativa, RegistroAprobacionesInterp, RegistroCitas, ESQUEMA_REQUERIDO,
};
