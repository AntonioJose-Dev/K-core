//! Fase 5.1 — cus.rotar IRREVERSIBLE: historial, anti-engaño, sin material.

use sak_core::crypto::ParMlDsa87;
use sak_domain::ops::{despachar, despachar_con_estado, EstadoOps};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn cuerpo_alta(alias: &str, clase_ef: &str, handle: &str) -> Vec<u8> {
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

fn cuerpo_rotar(
    secreto_id: &str,
    huella_anterior: &str,
    nuevo_handle: &str,
    epoca: u64,
    rol: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-CUS-ROTAR-v1");
    v.push(0);
    v.extend_from_slice(secreto_id.as_bytes());
    v.push(0);
    v.extend_from_slice(huella_anterior.as_bytes());
    v.push(0);
    v.extend_from_slice(nuevo_handle.as_bytes());
    v.push(0);
    v.extend_from_slice(&epoca.to_le_bytes());
    v.push(0);
    v.extend_from_slice(rol.as_bytes());
    v
}

fn alta_ok(st: &mut EstadoOps, alias: &str, handle: &str) -> (String, String, String) {
    let clase = "EF-1";
    let par = ParMlDsa87::generar().unwrap();
    let cuerpo = cuerpo_alta(alias, clase, handle);
    let firma = hex(&par.firmar(&cuerpo).unwrap());
    let pk = hex(&par.public);
    let raw = format!(
        r#"{{"op":"cus.alta_referencia","req_id":"a","schema_v":1,"operador_id":"op","alias":"{alias}","clase_ef":"{clase}","handle":"{handle}","firma_operador_hex":"{firma}","pk_operador_hex":"{pk}"}}"#
    );
    let r = despachar_con_estado(&raw, Some(st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    let sid = {
        let m = "\"secreto_id\":\"";
        let i = r.cuerpo.find(m).unwrap();
        let rest = &r.cuerpo[i + m.len()..];
        rest.split('"').next().unwrap().to_string()
    };
    let huella = {
        let m = "\"huella\":\"";
        let i = r.cuerpo.find(m).unwrap();
        let rest = &r.cuerpo[i + m.len()..];
        rest.split('"').next().unwrap().to_string()
    };
    (sid, huella, handle.to_string())
}

#[test]
fn rotar_ok_conserva_historial() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (sid, huella_ant, handle_ant) = alta_ok(&mut st, "rot-demo", "kms:proj/key-1");
    let nuevo = "kms:proj/key-2";
    let epoca = 7u64;
    let rol = "operador-custodia";
    let par = ParMlDsa87::generar().unwrap();
    let cuerpo = cuerpo_rotar(&sid, &huella_ant, nuevo, epoca, rol);
    let firma = hex(&par.firmar(&cuerpo).unwrap());
    let pk = hex(&par.public);
    let raw = format!(
        r#"{{"op":"cus.rotar","req_id":"r","schema_v":1,"secreto_id":"{sid}","nuevo_handle":"{nuevo}","epoca_vista":{epoca},"rol":"{rol}","identidad":"operador-rot","confirmacion_independiente":true,"firma_operador_hex":"{firma}","pk_operador_hex":"{pk}"}}"#
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert_eq!(r.codigo, "ROTAR_OK");
    assert!(r.cuerpo.contains("huella_anterior"));
    assert!(r.cuerpo.contains(&huella_ant));
    assert!(r.cuerpo.contains(&handle_ant));
    assert!(r.cuerpo.contains("historial"));
    assert!(r.cuerpo.contains("n_rotaciones\":1"));
    assert!(r.cuerpo.contains("\"material\":null"));
    assert!(r.cuerpo.contains("anti_engano"));
    assert!(r.cuerpo.contains("confirmacion_independiente\":true"));
    assert!(r.cuerpo.contains("digest"));
    assert!(r.cuerpo.contains("objeto_canonico"));
    assert!(!r.cuerpo.to_ascii_lowercase().contains("private_key"));
    assert!(r.limites.iter().any(|l| *l == "IRREVERSIBLE"));

    let e = despachar_con_estado(
        &format!(r#"{{"op":"cus.estado","req_id":"e","schema_v":1,"secreto_id":"{sid}"}}"#),
        Some(&mut st),
    );
    assert_eq!(e.resultado, "OK", "{}", e.a_json());
    assert!(e.cuerpo.contains("rotado\":true"));
    assert!(e.cuerpo.contains(&huella_ant));
    assert!(e.cuerpo.contains(nuevo));
    assert!(e.cuerpo.contains("historial"));
}

#[test]
fn rotar_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (sid, _, _) = alta_ok(&mut st, "rot-sf", "kms:a/1");
    let raw = format!(
        r#"{{"op":"cus.rotar","req_id":"r","schema_v":1,"secreto_id":"{sid}","nuevo_handle":"kms:a/2","epoca_vista":1,"rol":"operador-custodia","identidad":"op","confirmacion_independiente":true}}"#
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn rotar_material_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (sid, huella_ant, _) = alta_ok(&mut st, "rot-mat", "kms:b/1");
    let nuevo = "kms:b/2";
    let par = ParMlDsa87::generar().unwrap();
    let cuerpo = cuerpo_rotar(&sid, &huella_ant, nuevo, 1, "operador-custodia");
    let firma = hex(&par.firmar(&cuerpo).unwrap());
    let pk = hex(&par.public);
    let raw = format!(
        r#"{{"op":"cus.rotar","req_id":"r","schema_v":1,"secreto_id":"{sid}","nuevo_handle":"{nuevo}","epoca_vista":1,"rol":"operador-custodia","identidad":"op","confirmacion_independiente":true,"firma_operador_hex":"{firma}","pk_operador_hex":"{pk}","material":"deadbeef"}}"#
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SECRETO_PROHIBIDO");
}

#[test]
fn rotar_sin_confirmacion_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (sid, _, _) = alta_ok(&mut st, "rot-nc", "kms:c/1");
    let raw = format!(
        r#"{{"op":"cus.rotar","req_id":"r","schema_v":1,"secreto_id":"{sid}","nuevo_handle":"kms:c/2","epoca_vista":1,"rol":"operador-custodia","identidad":"op","confirmacion_independiente":false,"firma_operador_hex":"aa","pk_operador_hex":"bb"}}"#
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SIN_CONFIRMACION");
}

#[test]
fn reveal_y_export_raiz_siguen_deny_fijo() {
    for op in ["cus.reveal", "cus.export_raiz"] {
        let raw = format!(r#"{{"op":"{op}","req_id":"d","schema_v":1}}"#);
        let r = despachar(op, "d", 1, &raw, None);
        assert_eq!(r.resultado, "DENY", "{op}");
        assert_eq!(r.codigo, "DENY_FIJO", "{op}");
    }
}

#[test]
fn rotar_ya_no_es_deny_fijo() {
    let r = despachar(
        "cus.rotar",
        "t",
        1,
        r#"{"op":"cus.rotar","req_id":"t","schema_v":1}"#,
        None,
    );
    assert_eq!(r.codigo, "SIN_ESTADO_CUSTODIAR");
}
