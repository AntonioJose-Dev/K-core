//! Familia Observar — canal operador local D3.

pub mod canal;
pub mod despacho;
pub mod schema;
pub mod vista;

pub use canal::{
    addr_escucha_es_local, atender_stream, atender_stream_con_ops, enrutar_operador, es_peer_local,
    in_process, in_process_con_ops, listener_loopback, validar_bind_operador,
};
pub use despacho::{despachar, despachar_peticion};
pub use schema::{parsear_peticion, Peticion, Respuesta, OPS_LECTURA, SCHEMA_V};
// Respuesta re-exportada para harness Bloque A / tests e2e.
pub use vista::{contiene_secreto_prohibido, ObsVista};
