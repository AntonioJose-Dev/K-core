//! Máquina de estados y monitor de supuestos (Bloque 9 — INV-12, H.16, I.1).
//!
//! Siete estados canónicos (PERFECTO §6.2 / L-05). Autorización solo en estados
//! explícitamente permisivos. Recuperación desde SUSPENDED exige gobernanza
//! (representada como pendiente, no como bypass técnico).

mod epoca;
mod estados;
mod monitor;
mod transicion;
mod umbrales;

pub use epoca::{EpocaMonotonica, ErrorEpoca};
pub use estados::EstadoMaquina;
pub use monitor::{
    encadenar_transiciones_en_ledger, monitor_armado_prueba, AlcanceAfectado, ErrorMonitor,
    MonitorDominio, SupuestoCritico,
};
pub use transicion::RegistroTransicion;
pub use umbrales::{
    UMBRAL_ATESTACION_SUSPEND_MS, UMBRAL_COFIRMA_DEGRADED_MS, UMBRAL_COFIRMA_SUSPEND_MS,
    UMBRAL_PEP_SILENCIO_MS, UMBRAL_RECONCILIACION_SUSPEND_PCT,
};
