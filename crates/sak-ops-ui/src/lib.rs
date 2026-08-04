//! UI operador local — Observar + Conectar + Custodiar + Gobernar MVP (Fase 3).
//!
//! Sin autoridad. Sin activación de época. Solo loopback.

pub mod allowlist;
pub mod anti_engano;
pub mod cliente;
pub mod pantallas;
pub mod servidor;

pub use allowlist::{
    op_permitida, op_permitida_mvp_ops, op_permitida_obs, rechazar_si_no_observar,
    rechazar_si_no_permitida_ui, PANEL_OPS,
};
pub use anti_engano::{payload_contiene_secreto, VistaAntiEngano};
pub use cliente::{
    parse_obs_addr, ClienteCanalMock, ClienteCanalTcp, ObsCliente, ObsClienteMock, ObsClienteTcp,
    OpsCliente, OpsClienteMock, OpsClienteTcp,
};
pub use pantallas::{
    html_auditar, html_conectar, html_consola, html_custodiar, html_gobernar, html_shell,
    html_stub_familia, scrub_secreto_ui, FamiliaNav,
};
pub use servidor::{servir_con_listener, servir_loopback, validar_bind_ui};
