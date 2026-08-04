//! Allowlists UI por familia (Fase 0).
//! Observar = lectura. Conectar/Custodiar/Gobernar MVP = reconocidas; negocio Fase 1+.

use sak_domain::obs::OPS_LECTURA;
use sak_domain::ops::{
    es_deny_fijo_ops, es_op_mvp_fase0, OPS_DENY_FIJO, OPS_MVP_CONECTAR, OPS_MVP_CUSTODIAR,
    OPS_MVP_GOBERNAR,
};

/// Paneles Observar ↔ ops (sin cambio de autoridad).
pub const PANEL_OPS: &[(&str, &str)] = &[
    ("estado", "obs.estado"),
    ("salud", "obs.salud"),
    ("version", "obs.version"),
    ("canal", "obs.describir_canal"),
    ("libro", "obs.libro.matriz"),
    ("hechos", "obs.hechos.listar"),
    ("decisiones", "obs.decisiones.listar"),
    ("decision_get", "obs.decisiones.get"),
    ("incidentes", "obs.incidentes"),
    ("limites", "obs.limites"),
    ("evidencia_exportar", "obs.evidencia.exportar"),
    ("evidencia_verificar", "obs.evidencia.verificar"),
    ("expediente", "obs.expediente.get"),
];

pub fn op_permitida_obs(op: &str) -> bool {
    OPS_LECTURA.contains(&op) && op.starts_with("obs.")
}

/// Alias histórico D4.
pub fn op_permitida(op: &str) -> bool {
    op_permitida_obs(op)
}

pub fn op_permitida_mvp_ops(op: &str) -> bool {
    es_op_mvp_fase0(op) && !es_deny_fijo_ops(op)
}

pub fn op_para_panel(panel: &str) -> Option<&'static str> {
    PANEL_OPS
        .iter()
        .find(|(p, _)| *p == panel)
        .map(|(_, op)| *op)
}

pub fn rechazar_si_no_observar(op: &str) -> Result<(), String> {
    if !op_permitida_obs(op) {
        return Err(format!(
            "UI DENY: op `{op}` no es Observar de lectura (solo obs.* allowlist)"
        ));
    }
    if es_deny_fijo_ops(op) || op.starts_with("obs.diagnostico.") {
        return Err(format!("UI DENY: `{op}` prohibida"));
    }
    Ok(())
}

/// Cliente multi-familia: obs lectura **o** MVP con/cus/gob (Fase 0 → canal responde FASE0_SIN_HANDLER).
pub fn rechazar_si_no_permitida_ui(op: &str) -> Result<(), String> {
    if es_deny_fijo_ops(op)
        || op.starts_with("telemetry.")
        || op.starts_with("cap.")
        || op == "libro.elevar"
        || op.starts_with("obs.diagnostico.")
    {
        return Err(format!("UI DENY: `{op}` denegada por esquema fijo"));
    }
    if op_permitida_obs(op) || op_permitida_mvp_ops(op) {
        return Ok(());
    }
    Err(format!(
        "UI DENY: op `{op}` fuera de allowlist Observar/MVP Fase 0"
    ))
}

pub fn ops_mvp_conectar() -> &'static [&'static str] {
    OPS_MVP_CONECTAR
}
pub fn ops_mvp_custodiar() -> &'static [&'static str] {
    OPS_MVP_CUSTODIAR
}
pub fn ops_mvp_gobernar() -> &'static [&'static str] {
    OPS_MVP_GOBERNAR
}
pub fn ops_deny_fijo() -> &'static [&'static str] {
    OPS_DENY_FIJO
}
