//! Fase 1 — MVP-CONECTAR: alta, pasaporte, PEP, denegaciones.

use sak_core::crypto::ParMlDsa87;
use sak_core::identidad::{DeclaracionResponsable, IdSistema};
use sak_domain::ops::{despachar_con_estado, EstadoOps};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decl_firmada(sistema: &str) -> (DeclaracionResponsable, String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let d = DeclaracionResponsable::firmar(
        &par,
        sid,
        "responsable@org",
        "asistencia",
        "modelo-x",
        "EU",
        "datos",
        "ef1:asistido",
        "herramienta-a",
        "efector-a",
        "limitado",
        10_000,
        50_000,
    )
    .unwrap();
    let firma = hex(d.firma_responsable());
    let pk = hex(&par.public);
    (d, pk, firma)
}

fn body_alta(sistema: &str, firma_hex: &str, pk_hex: &str, extra: &str) -> String {
    format!(
        r#"{{"op":"con.sistema.alta","req_id":"t1","schema_v":1,"operador_id":"op","sistema_id":"{sistema}","pasaporte_id":"{sistema}","responsable":"responsable@org","finalidad":"asistencia","modelos":"modelo-x","jurisdiccion":"EU","datos":"datos","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma_hex}","pk_responsable_hex":"{pk_hex}"{extra}}}"#
    )
}

#[test]
fn alta_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let raw = r#"{"op":"con.sistema.alta","req_id":"a","schema_v":1,"sistema_id":"sys-a","responsable":"r","finalidad":"f","modelos":"m","jurisdiccion":"EU","datos":"d","autonomia_por_clase":"a","herramientas":"h","efectores":"e","clasificacion_riesgo":"limitado","vigente_desde_dias":1,"vigente_hasta_dias":9}"#;
    let r = despachar_con_estado(raw, Some(&mut st));
    assert_eq!(r.resultado, "DENY");
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn alta_con_secreto_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (d, pk, firma) = decl_firmada("sys-sec");
    let _ = d;
    let raw = body_alta(
        "sys-sec",
        &firma,
        &pk,
        r#","api_key":"sk-live-secret""#,
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "SECRETO_PROHIBIDO");
}

#[test]
fn alta_intento_autorizar_efectos_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (d, pk, firma) = decl_firmada("sys-auth");
    let _ = d;
    let raw = body_alta(
        "sys-auth",
        &firma,
        &pk,
        r#","autorizar_efectos":true"#,
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "INTENTO_AUTORIZAR");
}

#[test]
fn alta_emitir_get_pasaporte_persistente() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let (d, pk, firma) = decl_firmada("sys-ok");
    assert!(d.firma_valida());
    let raw_alta = body_alta("sys-ok", &firma, &pk, "");
    let r = despachar_con_estado(&raw_alta, Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("autoriza_efectos\":false"));

    let raw_emit = format!(
        r#"{{"op":"con.pasaporte.emitir","req_id":"e","schema_v":1,"sistema_id":"sys-ok","pasaporte_id":"sys-ok","version":1,"responsable":"responsable@org","finalidad":"asistencia","modelos":"modelo-x","jurisdiccion":"EU","datos":"datos","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let e = despachar_con_estado(&raw_emit, Some(&mut st));
    assert_eq!(e.resultado, "OK", "{}", e.a_json());
    assert!(e.cuerpo.contains("editable\":false"));

    // No reescribir misma versión
    let e2 = despachar_con_estado(&raw_emit, Some(&mut st));
    assert_eq!(e2.codigo, "VERSION_YA_EXISTE");

    let raw_get = r#"{"op":"con.pasaporte.get","req_id":"g","schema_v":1,"pasaporte_id":"sys-ok","version":1}"#;
    let g = despachar_con_estado(raw_get, Some(&mut st));
    assert_eq!(g.resultado, "OK", "{}", g.a_json());
    assert!(g.cuerpo.contains("sys-ok"));
    assert!(g.cuerpo.contains("firma_valida\":true"));
    assert!(g.cuerpo.contains("editable\":false"));

    let lista = despachar_con_estado(
        r#"{"op":"con.sistemas.listar","req_id":"l","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(lista.resultado, "OK");
    assert!(lista.cuerpo.contains("sys-ok"));
}

#[test]
fn pep_vista_y_config_sin_secretos() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let v = despachar_con_estado(
        r#"{"op":"con.pep.vista","req_id":"v","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(v.resultado, "OK");
    assert!(v.cuerpo.contains("GatewayModelos"));

    let c = despachar_con_estado(
        r#"{"op":"con.pep.configurar","req_id":"c","schema_v":1,"mapa_json":"{\"EF-1\":{\"pep\":\"GatewayModelos\",\"egreso\":[\"127.0.0.1\"]}}"}"#,
        Some(&mut st),
    );
    assert_eq!(c.resultado, "OK", "{}", c.a_json());

    let bad = despachar_con_estado(
        r#"{"op":"con.pep.configurar","req_id":"c2","schema_v":1,"mapa_json":"{}","api_key":"x"}"#,
        Some(&mut st),
    );
    assert_eq!(bad.codigo, "SECRETO_PROHIBIDO");
}

#[test]
fn alcanzables_implementado_fase4() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"a","schema_v":1,"vista":true}"#,
        Some(&mut st),
    );
    assert_eq!(r.resultado, "OK");
    assert_eq!(r.codigo, "ALCANZABLES_LISTA");
}
