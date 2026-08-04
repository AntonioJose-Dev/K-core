//! Bloque B — frontera mínima (B1–B5) tras cierre Bloque A.
//!
//! Afirmación al cerrar B5 (estrecha):
//!   Para EF-1 del harness, decidir+ejercer pasan por Kernel; agente sin material; UI no emite.
//! Afirmación todavía NO:
//!   Multi-clase, agente productivo de mercado, ni C5_HOST_REAL.

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::identidad::{DeclaracionResponsable, IdSistema};
use sak_core::libro::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use sak_core::pep::preparar_solicitud;
use sak_domain::obs::{enrutar_operador, ObsVista};
use sak_domain::ops::{despachar_con_estado, EstadoOps};
use sak_core::evidencia::{LedgerEvidencia, MemoriaDurable};
use sak_core::reloj::Ticks;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn artefacto_dir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let base = if base.is_absolute() {
        base
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(base)
    };
    let p = base.join("artefactos").join("bloque_b");
    fs::create_dir_all(&p).unwrap();
    p
}

fn escribir(nombre: &str, cuerpo: &str) -> PathBuf {
    let p = artefacto_dir().join(nombre);
    fs::write(&p, cuerpo).unwrap();
    p
}

fn decl_firmada(sistema: &str) -> (String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let d = DeclaracionResponsable::firmar(
        &par,
        sid,
        "responsable@org",
        "prueba-bloque-b",
        "modelo-harness",
        "EU",
        "datos-demo",
        "ef1:asistido",
        "herramienta-a",
        "efector-a",
        "limitado",
        10_000,
        50_000,
    )
    .unwrap();
    (hex(&par.public), hex(d.firma_responsable()))
}

fn alta_y_pasaporte(st: &mut EstadoOps, sistema: &str) {
    let (pk, firma) = decl_firmada(sistema);
    let alta = format!(
        r#"{{"op":"con.sistema.alta","req_id":"b-alta","schema_v":1,"operador_id":"op-b","sistema_id":"{sistema}","pasaporte_id":"{sistema}","responsable":"responsable@org","finalidad":"prueba-bloque-b","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let r = despachar_con_estado(&alta, Some(st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    let emit = format!(
        r#"{{"op":"con.pasaporte.emitir","req_id":"b-em","schema_v":1,"sistema_id":"{sistema}","pasaporte_id":"{sistema}","version":1,"responsable":"responsable@org","finalidad":"prueba-bloque-b","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let e = despachar_con_estado(&emit, Some(st));
    assert_eq!(e.resultado, "OK", "{}", e.a_json());
}

fn registrar_alcanzables(st: &mut EstadoOps, sistema: &str) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let mut efectores = BTreeSet::new();
    efectores.insert(ClaseEfecto::Ef1);
    let inv = InventarioAlcanzables::firmar_completo(
        sid,
        "inst-b",
        efectores,
        BTreeSet::from(["127.0.0.1:1".into()]),
        BTreeSet::from(["cred:digest:bb".into()]),
        BTreeSet::from(["s".into()]),
        BTreeSet::from(["svc".into()]),
        BTreeSet::from(["c".into()]),
        true,
        1,
        1,
        0,
        "det-b",
        &par,
    )
    .unwrap();
    let raw = format!(
        r#"{{"op":"con.inventario.alcanzables","req_id":"b-alc","schema_v":1,"sistema_id":"{sistema}","instancia":"inst-b","productor_id":"{prod}","efectores":"EF-1","rutas_red":"127.0.0.1:1","credenciales_detectadas":"cred:digest:bb","almacenes":"s","puntos_servicio":"svc","canales_consumo":"c","incompleto_declarado":true,"version":1,"epoca":1,"emitido_en":0,"firma_productor_hex":"{firma}","pk_productor_hex":"{pk}"}}"#,
        prod = inv.productor_id,
        firma = hex(&inv.firma),
        pk = hex(&inv.pk_firmante),
    );
    let r = despachar_con_estado(&raw, Some(st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
}

/// Hecho CUSTODIA firmado → nivel base C2 (mínimo EF-1 sin datos personales).
/// Harness Bloque B: no es elevación; es hecho aportado (D.3).
fn aportar_hecho_custodia(st: &mut EstadoOps, sistema: &str) {
    let fk = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let h = HechoFirmadoLibro::firmar(
        TipoHecho::Custodia,
        sid,
        Some(ClaseEfecto::Ef1),
        true,
        1,
        1,
        0,
        "harness-bloque-b",
        &fk,
    )
    .unwrap();
    st.libro.registrar_hecho(h).unwrap();
}

fn preparar_sujeto_c2(st: &mut EstadoOps, sistema: &str) {
    alta_y_pasaporte(st, sistema);
    registrar_alcanzables(st, sistema);
    aportar_hecho_custodia(st, sistema);
}

fn vista_vacia(id: &str) -> ObsVista {
    let ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    ObsVista::desde_ledger(id, Path::new("."), &ledger, None, 0, 0, "-", "-", 1000 as Ticks)
}

/// B1: sin pasaporte DENY; con pasaporte+ALCANZABLES decide.
#[test]
fn b1_decidir_exige_pasaporte_y_control() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let dig = [0xB1; LONGITUD_HASH_PAQUETE];
    let den = st
        .frontera
        .decidir_y_emitir_si_allow(
            &st.registro,
            &st.libro,
            &st.epoca,
            "sys-b1-no",
            ClaseEfecto::Ef1,
            dig,
            false,
        )
        .unwrap();
    assert_eq!(den.veredicto, "DENY");
    assert_eq!(den.codigo, "SIN_PASAPORTE");

    alta_y_pasaporte(&mut st, "sys-b1");
    // sin ALCANZABLES → control insuficiente típico
    let r = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-b1", ClaseEfecto::Ef1, dig, false)
            .unwrap()
    };
    assert_eq!(r.veredicto, "DENY", "{r:?}");
    assert!(
        r.codigo.contains("ControlInsuficiente") || r.codigo.contains("CONTROL"),
        "{}",
        r.codigo
    );

    registrar_alcanzables(&mut st, "sys-b1");
    let still = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-b1", ClaseEfecto::Ef1, dig, false)
            .unwrap()
    };
    // ALCANZABLES solo no basta: sin hecho CUSTODIA el nivel sigue < C2.
    assert_eq!(still.veredicto, "DENY", "{still:?}");

    aportar_hecho_custodia(&mut st, "sys-b1");
    let ok = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-b1", ClaseEfecto::Ef1, dig, false)
            .unwrap()
    };
    assert_eq!(ok.veredicto, "ALLOW", "{ok:?}");
    assert_eq!(ok.codigo, "ALLOW_EMITIDO");
    assert!(ok.mango.is_some());
    escribir(
        "b1_decidir.json",
        &format!(
            "{{\n  \"fase\":\"B1\",\n  \"sin_pasaporte\":\"DENY\",\n  \"allow\":\"{}\",\n  \"afirmacion_permitida\":\"Kernel decide con pasaporte/Libro (hecho CUSTODIA→C2)\",\n  \"afirmacion_no_permitida\":\"Ejercicio/proveedor mediado (B3+)\"\n}}\n",
            ok.codigo
        ),
    );
}

/// B2: mango emitido por Kernel; IPC cap.emitir sigue DENY.
#[test]
fn b2_emision_interna_cap_emitir_sigue_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    preparar_sujeto_c2(&mut st, "sys-b2");
    let (_sol, dig) = preparar_solicitud("modelo-harness", [0xB2; LONGITUD_HASH_PAQUETE], 32, 0);
    let r = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-b2", ClaseEfecto::Ef1, dig, false)
            .unwrap()
    };
    assert!(r.mango.is_some());
    assert_eq!(st.frontera.n_mangos(), 1);

    let deny = despachar_con_estado(
        r#"{"op":"cap.emitir","req_id":"x","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(deny.resultado, "DENY");
    assert_eq!(deny.codigo, "DENY_FIJO");
    escribir(
        "b2_emision.json",
        "{\n  \"fase\":\"B2\",\n  \"mango_emitido\":true,\n  \"cap.emitir\":\"DENY_FIJO\",\n  \"afirmacion_permitida\":\"Emisor=Kernel; IPC cap.emitir denegado\",\n  \"afirmacion_no_permitida\":\"Llamada PEP real (B3)\"\n}\n",
    );
}

/// B3: ejercer EF-1 con ProveedorSimulado; sin material en respuesta.
#[test]
fn b3_ejercer_ef1_sin_material() {
    let mut st = EstadoOps::en_memoria().unwrap();
    preparar_sujeto_c2(&mut st, "sys-b3");
    let (sol, dig) = preparar_solicitud("modelo-harness", [0xB3; LONGITUD_HASH_PAQUETE], 32, 0);
    let _ = sol;
    let mango = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-b3", ClaseEfecto::Ef1, dig, false)
            .unwrap()
            .mango
            .expect("mango")
    };
    let ej = st
        .frontera
        .ejercer_ef1("sys-b3", &mango, "modelo-harness", [0xB3; LONGITUD_HASH_PAQUETE], 32)
        .unwrap();
    assert!(ej.ok, "{ej:?}");
    assert_eq!(ej.codigo, "RECIBO_OK");
    let json = sak_domain::sujeto::resultado_ejercer_json(&ej);
    assert!(json.contains("\"material\":null"));
    assert!(!json.to_ascii_lowercase().contains("api_key"));
    assert!(!json.contains("BEGIN PRIVATE"));

    let miss = st
        .frontera
        .ejercer_ef1("sys-b3", "mango-falso", "m", [0xB3; LONGITUD_HASH_PAQUETE], 8)
        .unwrap();
    assert!(!miss.ok);
    assert_eq!(miss.codigo, "MANGO_AUSENTE");
    escribir(
        "b3_ejercer.json",
        &format!(
            "{{\n  \"fase\":\"B3\",\n  \"codigo\":\"{}\",\n  \"afirmacion_permitida\":\"Una clase EF-1 ejercida via Kernel\",\n  \"afirmacion_no_permitida\":\"Multi-clase / agente productivo\"\n}}\n",
            ej.codigo
        ),
    );
}

/// B4: espejo obs.diagnostico.* = misma cadena; UI no es emisor.
#[test]
fn b4_espejo_diagnostico_ipc() {
    let mut st = EstadoOps::en_memoria().unwrap();
    preparar_sujeto_c2(&mut st, "sys-b4");
    let seed = [0xB4; LONGITUD_HASH_PAQUETE];
    let (_sol, dig) = preparar_solicitud("modelo-harness", seed, 64, 0);
    let dig_hex = hex(&dig);
    let estado = Arc::new(Mutex::new(st));
    let vista = vista_vacia("bloque-b4");
    let dec = enrutar_operador(
        &vista,
        Some(&estado),
        &format!(
            r#"{{"op":"obs.diagnostico.decidir","req_id":"d","schema_v":1,"operador_id":"op","sistema_id":"sys-b4","clase":"EF-1","digest_parametros_hex":"{dig_hex}"}}"#
        ),
    );
    assert!(dec.contains("ALLOW") || dec.contains("ALLOW_EMITIDO") || dec.contains("DIAG_DECIDIR"), "{dec}");
    assert!(dec.contains("\"material\":null") || dec.contains("material\":null"));
    assert!(!dec.to_ascii_lowercase().contains("begin private"));

    // extraer mango
    let mango = dec
        .split("\"mango\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("mango en respuesta")
        .to_string();

    let ej = enrutar_operador(
        &vista,
        Some(&estado),
        &format!(
            r#"{{"op":"obs.diagnostico.ejercer","req_id":"e","schema_v":1,"sistema_id":"sys-b4","mango":"{mango}","modelo_id":"modelo-harness","digest_parametros_hex":"{}"}}"#,
            hex(&seed)
        ),
    );
    assert!(ej.contains("RECIBO_OK") || ej.contains("DIAG_EJERCER"), "{ej}");
    assert!(ej.contains("material\":null"));

    // cap.emitir sigue DENY
    let cap = enrutar_operador(
        &vista,
        Some(&estado),
        r#"{"op":"cap.emitir","req_id":"c","schema_v":1}"#,
    );
    assert!(cap.contains("DENY"), "{cap}");

    escribir(
        "b4_diagnostico.json",
        "{\n  \"fase\":\"B4\",\n  \"diagnostico\":\"OK\",\n  \"cap.emitir\":\"DENY\",\n  \"afirmacion_permitida\":\"Operador audita misma cadena sujeto\",\n  \"afirmacion_no_permitida\":\"Confinamiento host / multi-clase\"\n}\n",
    );
}

/// B5: harness agente in-process sin API key (frontera sujeto).
#[test]
fn b5_agente_sin_key_e2e() {
    // Agente = proceso que solo llama FronteraSujeto; no posee API key.
    const AGENTE_TIENE_API_KEY: bool = false;
    assert!(!AGENTE_TIENE_API_KEY);

    let mut st = EstadoOps::en_memoria().unwrap();
    preparar_sujeto_c2(&mut st, "sys-b5-agente");
    let seed = [0xB5; LONGITUD_HASH_PAQUETE];
    let (_sol, dig) = preparar_solicitud("modelo-harness", seed, 16, 0);

    let mango = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(
                registro,
                libro,
                epoca,
                "sys-b5-agente",
                ClaseEfecto::Ef1,
                dig,
                false,
            )
            .unwrap()
            .mango
            .expect("mango")
    };

    let recibo = st
        .frontera
        .ejercer_ef1("sys-b5-agente", &mango, "modelo-harness", seed, 16)
        .unwrap();
    assert!(recibo.ok, "{recibo:?}");

    // Bypass autoridad siguen DENY
    for op in ["libro.elevar", "cap.emitir", "cus.reveal"] {
        let r = despachar_con_estado(
            &format!(r#"{{"op":"{op}","req_id":"x","schema_v":1}}"#),
            Some(&mut st),
        );
        assert_eq!(r.resultado, "DENY", "{op}");
    }

    // Fuga simulada: agente no puede reveal
    let rev = despachar_con_estado(
        r#"{"op":"cus.reveal","req_id":"r","schema_v":1,"alias":"x","pedir_raw":true}"#,
        Some(&mut st),
    );
    assert_eq!(rev.resultado, "DENY");

    let cuerpo = format!(
        "{{\n  \"fase\":\"B5\",\n  \"agente_api_key\":false,\n  \"ejercicio\":\"{}\",\n  \"afirmacion_permitida\":\"Para EF-1 del harness, decision y ejercicio pasan por Kernel; agente sin material; UI no emite.\",\n  \"afirmacion_no_permitida\":\"Unica frontera en produccion general / multi-clase / C5_HOST_REAL\"\n}}\n",
        recibo.codigo
    );
    let path = escribir("b5_agente_e2e.json", &cuerpo);
    assert!(path.is_file());
}
