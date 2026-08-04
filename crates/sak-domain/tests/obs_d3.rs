//! Pruebas D3 — canal obs.* local, lectura, sin secretos, familia Observar.

use sak_core::evidencia::{LedgerEvidencia, MemoriaDurable};
use sak_core::reloj::Ticks;
use sak_domain::obs::{
    addr_escucha_es_local, contiene_secreto_prohibido, despachar, in_process, listener_loopback,
    validar_bind_operador, ObsVista, OPS_LECTURA,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

fn vista_vacia() -> ObsVista {
    let almacen = MemoriaDurable::default();
    let ledger = LedgerEvidencia::nuevo(almacen).expect("ledger");
    ObsVista::desde_ledger(
        "demo-d3",
        Path::new("/tmp/sak-d3-test"),
        &ledger,
        None,
        0,
        0,
        "-",
        "-",
        1_000 as Ticks,
    )
}

#[test]
fn canal_solo_loopback() {
    let l = listener_loopback(0).expect("bind 127.0.0.1");
    let addr = l.local_addr().unwrap();
    assert!(addr_escucha_es_local(addr));
    assert!(validar_bind_operador(addr).is_ok());

    let publico = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 9_999);
    assert!(validar_bind_operador(publico).is_err());
    let lan = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 9_999);
    assert!(validar_bind_operador(lan).is_err());
}

#[test]
fn operaciones_son_lectura_y_deny_mutacion() {
    let v = vista_vacia();
    let elev = despachar(
        &v,
        r#"{"op":"libro.elevar","req_id":"1","schema_v":1,"operador_id":"t"}"#,
    );
    assert_eq!(elev.resultado, "DENY");
    assert!(elev.codigo.contains("DENY") || elev.codigo == "DENY_FIJO");

    let gob = despachar(
        &v,
        r#"{"op":"gob.proponer","req_id":"2","schema_v":1,"operador_id":"t"}"#,
    );
    assert_eq!(gob.resultado, "DENY");

    let tel = despachar(
        &v,
        r#"{"op":"telemetry.ping","req_id":"3","schema_v":1,"operador_id":"t"}"#,
    );
    assert_eq!(tel.resultado, "DENY");

    let cap = despachar(
        &v,
        r#"{"op":"cap.emitir","req_id":"4","schema_v":1,"operador_id":"t"}"#,
    );
    assert_eq!(cap.resultado, "DENY");

    // Lectura no muta: dos obs.estado idénticos
    let a = despachar(
        &v,
        r#"{"op":"obs.estado","req_id":"a","schema_v":1,"operador_id":"t","dominio_id":"demo-d3"}"#,
    );
    let b = despachar(
        &v,
        r#"{"op":"obs.estado","req_id":"b","schema_v":1,"operador_id":"t","dominio_id":"demo-d3"}"#,
    );
    assert_eq!(a.resultado, "OK");
    assert_eq!(b.resultado, "OK");
    assert_eq!(a.cuerpo, b.cuerpo);
}

#[test]
fn no_devuelve_secretos_en_export() {
    let v = vista_vacia();
    let r = despachar(
        &v,
        r#"{"op":"obs.evidencia.exportar","req_id":"e","schema_v":1,"operador_id":"t","confirmacion_explicita":true}"#,
    );
    assert_eq!(r.resultado, "OK");
    let json = r.a_json();
    assert!(!contiene_secreto_prohibido(&json));
    assert!(json.contains("prohibido") || json.contains("huella_pk"));
    assert!(!json.to_ascii_lowercase().contains("begin private"));
}

#[test]
fn cada_handler_es_familia_observar() {
    let v = vista_vacia();
    for op in OPS_LECTURA {
        assert!(op.starts_with("obs."), "{op}");
        let raw = format!(
            r#"{{"op":"{op}","req_id":"x","schema_v":1,"operador_id":"t","dominio_id":"demo-d3","confirmacion_explicita":true}}"#
        );
        let r = despachar(&v, &raw);
        // OK o DENY de negocio (expediente ausente); nunca conceder fuera de Observar
        assert!(
            r.resultado == "OK" || r.resultado == "DENY",
            "{op} => {}",
            r.resultado
        );
        if r.resultado == "DENY" {
            assert!(
                r.codigo == "EXPEDIENTE_AUSENTE"
                    || r.codigo == "NO_ENCONTRADO"
                    || r.codigo == "SIN_CONFIRMACION"
                    || r.codigo == "DOMINIO",
                "{op} deny inesperado {}",
                r.codigo
            );
        }
        assert!(!contiene_secreto_prohibido(&r.a_json()));
    }

    let diag = despachar(
        &v,
        r#"{"op":"obs.diagnostico.decidir","req_id":"d","schema_v":1,"operador_id":"t"}"#,
    );
    assert_eq!(diag.resultado, "DENY");
}

#[test]
fn in_process_version_y_canal() {
    let v = vista_vacia();
    let out = in_process(
        &v,
        r#"{"op":"obs.describir_canal","req_id":"c","schema_v":1,"operador_id":"t"}"#,
    );
    assert!(out.contains("Observar") || out.contains("loopback"));
    assert!(out.contains("\"resultado\":\"OK\""));
}
