//! Despacho operador no-obs: Conectar + Custodiar + Gobernar MVP; resto stub/DENY.

use super::conectar;
use super::custodiar;
use super::estado::EstadoOps;
use super::gobernar;
use super::schema::{
    es_deny_fijo_ops, es_op_mvp_fase0, familia_de, parsear_op, RespuestaOps, SCHEMA_V,
    OPS_MVP_CONECTAR, OPS_MVP_CUSTODIAR, OPS_MVP_GOBERNAR,
};

/// Despacha sin estado (solo DENY / stubs).
pub fn despachar_linea(raw: &str) -> RespuestaOps {
    despachar_con_estado(raw, None)
}

pub fn despachar_con_estado(raw: &str, estado: Option<&mut EstadoOps>) -> RespuestaOps {
    let (op, req_id, schema_v) = match parsear_op(raw) {
        Ok(t) => t,
        Err(e) => return RespuestaOps::deny("sin-id", "SCHEMA", &e),
    };
    despachar(&op, &req_id, schema_v, raw, estado)
}

pub fn despachar(
    op: &str,
    req_id: &str,
    schema_v: u32,
    raw: &str,
    estado: Option<&mut EstadoOps>,
) -> RespuestaOps {
    if schema_v != SCHEMA_V {
        return RespuestaOps::deny(req_id, "SCHEMA_V", "schema_v no soportado");
    }
    if op.starts_with("obs.") {
        return RespuestaOps::deny(
            req_id,
            "USAR_CANAL_OBS",
            "ops.* no-obs no despacha Observar; use canal obs.*",
        );
    }
    if es_deny_fijo_ops(op) {
        return RespuestaOps::deny(req_id, "DENY_FIJO", "operación prohibida por esquema IPC");
    }
    if OPS_MVP_CONECTAR.contains(&op) {
        return match estado {
            Some(st) => conectar::manejar(st, op, req_id, raw),
            None => RespuestaOps::deny(
                req_id,
                "SIN_ESTADO_CONECTAR",
                "requiere EstadoOps (dominio run / test con estado)",
            ),
        };
    }
    if OPS_MVP_CUSTODIAR.contains(&op) {
        return match estado {
            Some(st) => custodiar::manejar(st, op, req_id, raw),
            None => RespuestaOps::deny(
                req_id,
                "SIN_ESTADO_CUSTODIAR",
                "requiere EstadoOps (dominio run / test con estado)",
            ),
        };
    }
    if OPS_MVP_GOBERNAR.contains(&op) {
        return match estado {
            Some(st) => gobernar::manejar(st, op, req_id, raw),
            None => RespuestaOps::deny(
                req_id,
                "SIN_ESTADO_GOBERNAR",
                "requiere EstadoOps (dominio run / test con estado)",
            ),
        };
    }
    if es_op_mvp_fase0(op) {
        let fam = familia_de(op).unwrap_or("?");
        return RespuestaOps::deny(
            req_id,
            "FASE0_SIN_HANDLER",
            &format!("op `{op}` allowlist {fam}; handler en fase posterior"),
        );
    }
    if op.starts_with("gob.")
        || op.starts_with("cus.")
        || op.starts_with("con.")
        || op.starts_with("sup.")
    {
        return RespuestaOps::deny(
            req_id,
            "FUERA_MVP",
            "op de familia operador fuera del allowlist MVP",
        );
    }
    RespuestaOps::deny(req_id, "OP_DESCONOCIDA", "operación no reconocida en canal operador")
}
