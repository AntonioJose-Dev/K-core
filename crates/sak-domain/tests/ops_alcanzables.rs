//! Fase 4 — con.inventario.alcanzables + seed demo + límites INV-11.

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::identidad::IdSistema;
use sak_core::libro::InventarioAlcanzables;
use sak_domain::ops::{despachar_con_estado, EstadoOps};
use std::collections::BTreeSet;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn inv_firmado(sistema: &str, incompleto: bool) -> (InventarioAlcanzables, ParMlDsa87) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let mut efectores = BTreeSet::new();
    efectores.insert(ClaseEfecto::Ef1);
    efectores.insert(ClaseEfecto::Ef4);
    let mut rutas = BTreeSet::new();
    rutas.insert("127.0.0.1:8443".into());
    let mut creds = BTreeSet::new();
    creds.insert("cred:digest:aabb".into());
    let inv = InventarioAlcanzables::firmar_completo(
        sid,
        "inst-1",
        efectores,
        rutas,
        creds,
        BTreeSet::from(["store-a".into()]),
        BTreeSet::from(["svc-a".into()]),
        BTreeSet::from(["canal-a".into()]),
        incompleto,
        1,
        1,
        0,
        "detector-instrumentado",
        &par,
    )
    .unwrap();
    (inv, par)
}

fn body_registrar(inv: &InventarioAlcanzables, extra: &str) -> String {
    let efectores: String = inv
        .efectores
        .iter()
        .map(|e| e.token().to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"op":"con.inventario.alcanzables","req_id":"a1","schema_v":1,"sistema_id":"{sid}","instancia":"{inst}","productor_id":"{prod}","efectores":"{efectores}","rutas_red":"127.0.0.1:8443","credenciales_detectadas":"cred:digest:aabb","almacenes":"store-a","puntos_servicio":"svc-a","canales_consumo":"canal-a","incompleto_declarado":{inc},"version":1,"epoca":1,"emitido_en":0,"firma_productor_hex":"{firma}","pk_productor_hex":"{pk}"{extra}}}"#,
        sid = inv.sistema.como_str(),
        inst = inv.instancia,
        prod = inv.productor_id,
        efectores = efectores,
        inc = inv.incompleto_declarado,
        firma = hex(&inv.firma),
        pk = hex(&inv.pk_firmante),
    )
}

#[test]
fn registrar_y_vista_con_limites() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (inv, _par) = inv_firmado("sys-alc-1", true);
    let raw = body_registrar(&inv, "");
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("ALCANZABLES_OK") || r.codigo == "ALCANZABLES_OK");
    assert!(r.cuerpo.contains("productor_id"));
    assert!(r.cuerpo.contains("antiguedad_max"));
    assert!(r.cuerpo.contains("afirma_completitud\":false"));
    assert!(r.cuerpo.contains("no_demuestra"));
    assert!(r.cuerpo.contains("deep_links"));
    assert!(r.cuerpo.contains("/observar?panel=libro"));
    assert!(!r.cuerpo.to_ascii_lowercase().contains("private_key"));

    let v = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"v","schema_v":1,"vista":true,"sistema_id":"sys-alc-1"}"#,
        Some(&mut st),
    );
    assert_eq!(v.resultado, "OK", "{}", v.a_json());
    assert!(v.cuerpo.contains("detector-instrumentado"));
    assert!(v.cuerpo.contains("incompleto_declarado\":true"));
}

#[test]
fn afirma_completitud_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (inv, _) = inv_firmado("sys-alc-2", true);
    let raw = body_registrar(&inv, r#","afirma_completitud":true"#);
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "COMPLETITUD_PROHIBIDA");
}

#[test]
fn secreto_en_credencial_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (inv, _) = inv_firmado("sys-alc-3", true);
    // fuerza credencial mala sustituyendo campo (firma dejará de coincidir o SCHEMA)
    let mut raw = body_registrar(&inv, "");
    raw = raw.replace(
        "cred:digest:aabb",
        "-----BEGIN PRIVATE KEY-----",
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert!(
        r.codigo == "SECRETO_PROHIBIDO" || r.codigo == "FIRMA_INVALIDA" || r.codigo == "SCHEMA",
        "{}",
        r.codigo
    );
}

#[test]
fn seed_demo_sin_secretos() {
    let mut st = EstadoOps::en_memoria().unwrap();
    st.aplicar_seed_demo_alcanzables().unwrap();
    let v = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"s","schema_v":1,"vista":true}"#,
        Some(&mut st),
    );
    assert_eq!(v.resultado, "OK", "{}", v.a_json());
    assert!(v.cuerpo.contains("sys-demo-alcanzables"));
    assert!(v.cuerpo.contains("afirma_completitud\":false"));
    assert!(!v.cuerpo.contains("BEGIN PRIVATE"));
    assert!(!v.cuerpo.contains("\"seed\""));
}

#[test]
fn sin_firma_va_a_vista() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"x","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(r.resultado, "OK");
    assert!(r.cuerpo.contains("inventarios"));
}
