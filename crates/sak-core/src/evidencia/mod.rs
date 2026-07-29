//! Evidencia durable y encadenada (§M 3 + §M 11): INV-07, INV-15, J, H.12/14/15.

mod camaleon;
mod estado;
mod expediente;
mod ledger;
mod merkle;
mod registro;
mod verificar;

pub use camaleon::{
    derivar_kek_pii, redactar_hoja, CustodiaTrampilla, ErrorCamaleon, HojaCamaleon, IdTitular,
    RegistroRedaccion, DECISION_CRIPTO_PII_V1, DOMINIO_PII_KEK_V1,
};
pub use estado::{ErrorEvidencia, EstadoDominio};
pub use expediente::{
    alcance_auditoria, capacidad_autoriza_auditoria, contiene_patron_prohibido_j4, reconstruir_j2,
    verificar_expediente, Afirmacion, ClaseRetencion, ConstructorExpediente, ErrorExpediente,
    EtiquetaAfirmacion, Expediente, ExpedienteBorrador, HechoContexto, InformeExpediente,
    ParteCadena, ParteCapacidades, ParteClasificacion, ParteCorpus, ParteDecisiones,
    ParteFinalidad, ParteIncidentes, ParteLibro, ParteRiesgos, ParteSistemas, ParteSupervision,
    ParteSupuestos, RecuentosObligaciones, RespuestasJ2, FRASE_REGISTROS_NO_CUMPLIMIENTO,
    ID_LISTA_PATRONES_J4_V1, PATRONES_PROHIBIDOS_J4_V1,
};
pub use ledger::{AlmacenEvidencia, LedgerEvidencia, MemoriaDurable};
pub use merkle::{
    emitir_prueba_inclusion, merkle_raiz, verificar_inclusion, CheckpointEpoca, PruebaInclusion,
};
pub use registro::{
    IdSujeto, PaqueteEvidencia, ReciboEfecto, RegistroFirmado, TipoRegistro,
};
pub use verificar::{verificar_paquete, InformeVerificacion};

/// Esquema publicado del registro de evidencia (§M 3).
pub const ESQUEMA_REGISTRO_V1: &str = include_str!("../../../../schemas/registro_evidencia_v1.cddl");
