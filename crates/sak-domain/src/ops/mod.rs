//! Canal operador no-Observar: Conectar + Custodiar + Gobernar MVP.

pub mod conectar;
pub mod custodiar;
pub mod despacho;
pub mod estado;
pub mod gobernar;
pub mod schema;

pub use despacho::{despachar, despachar_con_estado, despachar_linea};
pub use estado::{EstadoOps, HistRotacion, PepMapa, RefCustodia};
pub use schema::{
    campo_str_raw, es_deny_fijo_ops, es_op_mvp_fase0, familia_de, parsear_op, RespuestaOps,
    OPS_DENY_FIJO, OPS_MVP_CONECTAR, OPS_MVP_CUSTODIAR, OPS_MVP_GOBERNAR, SCHEMA_V,
};
