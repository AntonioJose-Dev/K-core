//! Fase 0 — canal ops: allowlist MVP + DENY fijo + stubs.

use sak_domain::ops::{
    despachar, despachar_linea, es_deny_fijo_ops, es_op_mvp_fase0, OPS_MVP_CONECTAR,
    OPS_MVP_CUSTODIAR, OPS_MVP_GOBERNAR,
};

#[test]
fn mvp_ops_reconocidas() {
    for op in OPS_MVP_CONECTAR
        .iter()
        .chain(OPS_MVP_CUSTODIAR.iter())
        .chain(OPS_MVP_GOBERNAR.iter())
    {
        assert!(es_op_mvp_fase0(op), "{op}");
        assert!(!es_deny_fijo_ops(op), "{op} no debe ser DENY_FIJO");
    }
    let r = despachar(
        "cus.alta_referencia",
        "t1",
        1,
        r#"{"op":"cus.alta_referencia","req_id":"t1","schema_v":1}"#,
        None,
    );
    assert_eq!(r.codigo, "SIN_ESTADO_CUSTODIAR");
    let r_gob = despachar(
        "gob.proponer",
        "t1b",
        1,
        r#"{"op":"gob.proponer","req_id":"t1b","schema_v":1}"#,
        None,
    );
    assert_eq!(r_gob.codigo, "SIN_ESTADO_GOBERNAR");
    let r2 = despachar_linea(r#"{"op":"con.sistema.alta","req_id":"t","schema_v":1}"#);
    assert_eq!(r2.codigo, "SIN_ESTADO_CONECTAR");
}

#[test]
fn deny_fijo_cap_elevar_reveal_telemetry() {
    for op in [
        "cap.emitir",
        "libro.elevar",
        "cus.reveal",
        "cus.export_raiz",
        "telemetry.ping",
        "cap.emitir",
        "net.bind_public",
        "conceder_ef12",
    ] {
        assert!(es_deny_fijo_ops(op) || op.starts_with("telemetry."), "{op}");
        let raw = format!(r#"{{"op":"{op}","req_id":"t2","schema_v":1}}"#);
        let r = despachar(op, "t2", 1, &raw, None);
        assert_eq!(r.resultado, "DENY", "{op}");
        assert!(
            r.codigo == "DENY_FIJO" || r.codigo == "FUERA_MVP" || r.codigo == "OP_DESCONOCIDA",
            "{op} -> {}",
            r.codigo
        );
    }
}

#[test]
fn obs_no_se_despacha_en_ops() {
    let raw = r#"{"op":"obs.estado","req_id":"x","schema_v":1}"#;
    let r = despachar_linea(raw);
    assert_eq!(r.codigo, "USAR_CANAL_OBS");
}

#[test]
fn schema_v_malo() {
    let r = despachar(
        "con.sistema.alta",
        "x",
        99,
        r#"{"op":"con.sistema.alta","req_id":"x","schema_v":99}"#,
        None,
    );
    assert_eq!(r.codigo, "SCHEMA_V");
}
