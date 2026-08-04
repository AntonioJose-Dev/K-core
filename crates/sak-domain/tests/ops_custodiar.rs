//! Fase 2 — MVP-CUSTODIAR: referencias/handles sin material.

use sak_core::crypto::ParMlDsa87;
use sak_domain::ops::{despachar, despachar_con_estado, EstadoOps};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cuerpo_canonico(alias: &str, clase_ef: &str, handle: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-CUS-REF-v1");
    v.push(0);
    v.extend_from_slice(alias.as_bytes());
    v.push(0);
    v.extend_from_slice(clase_ef.as_bytes());
    v.push(0);
    v.extend_from_slice(handle.as_bytes());
    v
}

fn firma_alta(alias: &str, clase: &str, handle: &str) -> (String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let cuerpo = cuerpo_canonico(alias, clase, handle);
    let firma = hex(&par.firmar(&cuerpo).unwrap());
    let pk = hex(&par.public);
    (pk, firma)
}

fn body_alta(alias: &str, clase: &str, handle: &str, pk: &str, firma: &str, extra: &str) -> String {
    format!(
        r#"{{"op":"cus.alta_referencia","req_id":"t1","schema_v":1,"operador_id":"op","alias":"{alias}","clase_ef":"{clase}","handle":"{handle}","firma_operador_hex":"{firma}","pk_operador_hex":"{pk}"{extra}}}"#
    )
}

#[test]
fn alta_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let raw = r#"{"op":"cus.alta_referencia","req_id":"a","schema_v":1,"alias":"a1","clase_ef":"EF-1","handle":"kms:proj/key"}"#;
    let r = despachar_con_estado(raw, Some(&mut st));
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn alta_con_pem_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (pk, firma) = firma_alta("a-pem", "EF-1", "kms:x");
    let raw = body_alta(
        "a-pem",
        "EF-1",
        "kms:x",
        &pk,
        &firma,
        r#","pem":"-----BEGIN PRIVATE KEY-----""#,
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SECRETO_PROHIBIDO");
}

#[test]
fn alta_con_material_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (pk, firma) = firma_alta("a-mat", "EF-2", "pkcs11:slot=0;id=ab");
    let raw = body_alta(
        "a-mat",
        "EF-2",
        "pkcs11:slot=0;id=ab",
        &pk,
        &firma,
        r#","material":"deadbeef""#,
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SECRETO_PROHIBIDO");
}

#[test]
fn alta_y_estado_sin_bytes() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let alias = "kms-demo";
    let clase = "EF-1";
    let handle = "kms:proj/key-1";
    let (pk, firma) = firma_alta(alias, clase, handle);
    let raw = body_alta(alias, clase, handle, &pk, &firma, "");
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("secreto_id"));
    assert!(r.cuerpo.contains("huella"));
    assert!(r.cuerpo.contains("\"material\":null"));
    assert!(!r.cuerpo.to_ascii_lowercase().contains("private_key"));
    assert!(!r.cuerpo.contains("BEGIN PRIVATE"));

    let e = despachar_con_estado(
        r#"{"op":"cus.estado","req_id":"e","schema_v":1,"alias":"kms-demo"}"#,
        Some(&mut st),
    );
    assert_eq!(e.resultado, "OK", "{}", e.a_json());
    assert!(e.cuerpo.contains("tiene_raiz_encapsulada\":true"));
    assert!(e.cuerpo.contains("\"material\":null"));
    assert!(e.cuerpo.contains("huella"));
    assert!(!e.cuerpo.contains("\"seed\""));

    let lista = despachar_con_estado(
        r#"{"op":"cus.estado","req_id":"l","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(lista.resultado, "OK");
    assert!(lista.cuerpo.contains("kms-demo"));
    assert!(lista.cuerpo.contains("n_referencias\":1"));
}

#[test]
fn pedir_raw_en_estado_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"cus.estado","req_id":"x","schema_v":1,"pedir_raw":true}"#,
        Some(&mut st),
    );
    assert_eq!(r.codigo, "REVEAL_PROHIBIDO");
}

#[test]
fn reveal_y_export_raiz_deny_fijo() {
    for op in ["cus.reveal", "cus.export_raiz"] {
        let raw = format!(r#"{{"op":"{op}","req_id":"d","schema_v":1}}"#);
        let r = despachar(op, "d", 1, &raw, None);
        assert_eq!(r.resultado, "DENY", "{op}");
        assert_eq!(r.codigo, "DENY_FIJO", "{op} -> {}", r.codigo);
    }
}

#[test]
fn sin_estado_deny() {
    let r = despachar(
        "cus.alta_referencia",
        "t",
        1,
        r#"{"op":"cus.alta_referencia","req_id":"t","schema_v":1}"#,
        None,
    );
    assert_eq!(r.codigo, "SIN_ESTADO_CUSTODIAR");
}
