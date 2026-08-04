//! Corte 2A — GatewayModelos → ProveedorLoopbackEf1 (probe-mediado).
//!
//! Afirmación máxima:
//!   En probe-mediado, el Kernel/GatewayModelos ejecuta EF-1 contra un efector
//!   loopback autenticado; el adaptador no recibe material y no puede producir
//!   llamada válida al mock sin pasar por el Kernel.
//! No comprobado: socket del agente, EXCLUSIVIDAD, C3–C5, L3, control total.

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::evidencia::{LedgerEvidencia, MemoriaDurable};
use sak_core::identidad::IdSistema;
use sak_core::libro::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use sak_core::pep::{
    generar_clave_efimera, llamada_directa_sin_sello, preparar_solicitud, MockEf1Loopback,
    HANDLE_EF1_PROBE_MEDIADO,
};
use sak_core::reloj::Ticks;
use sak_domain::obs::{enrutar_operador, ObsVista};
use sak_domain::ops::{despachar_con_estado, EstadoOps};
use sak_domain::sujeto::FronteraSujeto;
use sak_core::identidad::DeclaracionResponsable;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn decl_firmada(sistema: &str) -> (String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let d = DeclaracionResponsable::firmar(
        &par,
        sid,
        "responsable@org",
        "prueba-corte2a",
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
        r#"{{"op":"con.sistema.alta","req_id":"c2a-alta","schema_v":1,"operador_id":"op","sistema_id":"{sistema}","pasaporte_id":"{sistema}","responsable":"responsable@org","finalidad":"prueba-corte2a","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let r = despachar_con_estado(&alta, Some(st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    let emit = format!(
        r#"{{"op":"con.pasaporte.emitir","req_id":"c2a-em","schema_v":1,"sistema_id":"{sistema}","pasaporte_id":"{sistema}","version":1,"responsable":"responsable@org","finalidad":"prueba-corte2a","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
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
        "inst-c2a",
        efectores,
        BTreeSet::from(["127.0.0.1:1".into()]),
        BTreeSet::from(["cred:digest:c2a".into()]),
        BTreeSet::from(["s".into()]),
        BTreeSet::from(["svc".into()]),
        BTreeSet::from(["c".into()]),
        true,
        1,
        1,
        0,
        "det-c2a",
        &par,
    )
    .unwrap();
    let raw = format!(
        r#"{{"op":"con.inventario.alcanzables","req_id":"c2a-alc","schema_v":1,"sistema_id":"{sistema}","instancia":"inst-c2a","productor_id":"{prod}","efectores":"EF-1","rutas_red":"127.0.0.1:1","credenciales_detectadas":"cred:digest:c2a","almacenes":"s","puntos_servicio":"svc","canales_consumo":"c","incompleto_declarado":true,"version":1,"epoca":1,"emitido_en":0,"firma_productor_hex":"{firma}","pk_productor_hex":"{pk}"}}"#,
        prod = inv.productor_id,
        firma = hex(&inv.firma),
        pk = hex(&inv.pk_firmante),
    );
    let r = despachar_con_estado(&raw, Some(st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
}

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
        "harness-corte2a",
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

fn st_con_loopback(addr: std::net::SocketAddr, handle: &str, clave: [u8; 32]) -> EstadoOps {
    let mut st = EstadoOps::en_memoria().unwrap();
    st.frontera = FronteraSujeto::nueva_loopback(addr, handle, clave).unwrap();
    st
}

#[test]
fn corte2a_decidir_ejercer_mock_recibo_sin_material() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).unwrap();
    let mut st = st_con_loopback(mock.addr(), HANDLE_EF1_PROBE_MEDIADO, clave);
    assert!(st.frontera.es_loopback_ef1());
    preparar_sujeto_c2(&mut st, "sys-c2a");
    let seed = [0xC2; LONGITUD_HASH_PAQUETE];
    let (_sol, dig) = preparar_solicitud("modelo-harness", seed, 32, 0);
    let mango = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-c2a", ClaseEfecto::Ef1, dig, false)
            .unwrap()
            .mango
            .expect("mango")
    };
    let ej = st
        .frontera
        .ejercer_ef1("sys-c2a", &mango, "modelo-harness", seed, 32)
        .unwrap();
    assert!(ej.ok, "{ej:?}");
    assert_eq!(ej.codigo, "RECIBO_OK");
    let json = sak_domain::sujeto::resultado_ejercer_json(&ej);
    assert!(json.contains("\"material\":null"));
    assert!(!json.to_ascii_lowercase().contains("api_key"));
    mock.detener();
}

#[test]
fn corte2a_llamada_directa_sin_sello() {
    let mock = MockEf1Loopback::arrancar(generar_clave_efimera()).unwrap();
    let line = llamada_directa_sin_sello(mock.addr()).unwrap();
    assert!(line.contains("NO_SELLO"), "{line}");
    mock.detener();
}

#[test]
fn corte2a_handle_inexistente() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).unwrap();
    let mut st = st_con_loopback(mock.addr(), "handle-fantasma", clave);
    preparar_sujeto_c2(&mut st, "sys-c2a-h");
    let seed = [0xC3; LONGITUD_HASH_PAQUETE];
    let (_sol, dig) = preparar_solicitud("modelo-harness", seed, 32, 0);
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
                "sys-c2a-h",
                ClaseEfecto::Ef1,
                dig,
                false,
            )
            .unwrap()
            .mango
            .expect("mango")
    };
    let ej = st
        .frontera
        .ejercer_ef1("sys-c2a-h", &mango, "modelo-harness", seed, 32)
        .unwrap();
    assert!(!ej.ok, "debe fallar sin handle válido");
    mock.detener();
}

#[test]
fn corte2a_digest_distinto_y_reuso_mango() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).unwrap();
    let mut st = st_con_loopback(mock.addr(), HANDLE_EF1_PROBE_MEDIADO, clave);
    preparar_sujeto_c2(&mut st, "sys-c2a-r");
    let seed = [0xC4; LONGITUD_HASH_PAQUETE];
    let (_sol, dig) = preparar_solicitud("modelo-harness", seed, 32, 0);
    let mango = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-c2a-r", ClaseEfecto::Ef1, dig, false)
            .unwrap()
            .mango
            .expect("mango")
    };
    let malo = [0xEE; LONGITUD_HASH_PAQUETE];
    let ej_bad = st
        .frontera
        .ejercer_ef1("sys-c2a-r", &mango, "modelo-harness", malo, 32)
        .unwrap();
    assert!(!ej_bad.ok);

    // Re-emitir y ejercer OK, luego reuso → MANGO_AUSENTE.
    let mango2 = {
        let EstadoOps {
            ref mut frontera,
            ref registro,
            ref libro,
            ref epoca,
            ..
        } = st;
        frontera
            .decidir_y_emitir_si_allow(registro, libro, epoca, "sys-c2a-r", ClaseEfecto::Ef1, dig, false)
            .unwrap()
            .mango
            .expect("mango2")
    };
    let ej_ok = st
        .frontera
        .ejercer_ef1("sys-c2a-r", &mango2, "modelo-harness", seed, 32)
        .unwrap();
    assert!(ej_ok.ok, "{ej_ok:?}");
    let ej_reuse = st
        .frontera
        .ejercer_ef1("sys-c2a-r", &mango2, "modelo-harness", seed, 32)
        .unwrap();
    assert!(!ej_reuse.ok);
    assert_eq!(ej_reuse.codigo, "MANGO_AUSENTE");
    mock.detener();
}

#[test]
fn corte2a_sin_env_sigue_simulado() {
    std::env::remove_var("SAK_PROBE_MEDIADO_LOOPBACK");
    std::env::remove_var("SAK_PROBE_MEDIADO_LOOPBACK_KEY");
    let f = FronteraSujeto::nueva().unwrap();
    assert!(!f.es_loopback_ef1());
}

#[test]
fn corte2a_loopback_exige_dominio_probe_mediado() {
    let clave = generar_clave_efimera();
    let clave_hex: String = clave.iter().map(|b| format!("{b:02x}")).collect();
    // Puerto efímero no conectado: solo importa la selección de backend.
    std::env::set_var("SAK_PROBE_MEDIADO_LOOPBACK", "127.0.0.1:1");
    std::env::set_var("SAK_PROBE_MEDIADO_LOOPBACK_KEY", &clave_hex);

    let otro = FronteraSujeto::nueva_para_dominio("ops-demo").unwrap();
    assert!(
        !otro.es_loopback_ef1(),
        "ops-demo no debe activar loopback aunque haya env"
    );
    let otro2 = FronteraSujeto::nueva_para_dominio("probe-externo").unwrap();
    assert!(!otro2.es_loopback_ef1());

    let ok = FronteraSujeto::nueva_para_dominio("probe-mediado").unwrap();
    assert!(
        ok.es_loopback_ef1(),
        "probe-mediado + env debe activar loopback"
    );

    // en_memoria / nueva() siguen simulado aunque la env esté puesta
    let mem = FronteraSujeto::nueva().unwrap();
    assert!(!mem.es_loopback_ef1());

    std::env::remove_var("SAK_PROBE_MEDIADO_LOOPBACK");
    std::env::remove_var("SAK_PROBE_MEDIADO_LOOPBACK_KEY");
}

#[test]
fn corte2a_denys_ipc() {
    let mut st = EstadoOps::en_memoria().unwrap();
    preparar_sujeto_c2(&mut st, "sys-c2a-deny");
    let estado = Arc::new(Mutex::new(st));
    let vista = vista_vacia("corte2a-deny");

    let den = despachar_con_estado(
        r#"{"op":"cap.emitir","req_id":"x","schema_v":1}"#,
        Some(&mut *estado.lock().unwrap()),
    );
    assert_eq!(den.resultado, "DENY");

    let den = despachar_con_estado(
        r#"{"op":"libro.elevar","req_id":"x","schema_v":1}"#,
        Some(&mut *estado.lock().unwrap()),
    );
    assert_eq!(den.resultado, "DENY");

    let den = despachar_con_estado(
        r#"{"op":"cus.reveal","req_id":"x","schema_v":1,"alias":"x"}"#,
        Some(&mut *estado.lock().unwrap()),
    );
    assert_eq!(den.resultado, "DENY");

    let sin_pass = enrutar_operador(
        &vista,
        Some(&estado),
        r#"{"op":"obs.diagnostico.decidir","req_id":"d1","schema_v":1,"operador_id":"op","sistema_id":"sys-inexistente","clase":"EF-1","digest_parametros_hex":"aa"}"#,
    );
    assert!(sin_pass.contains("DENY"), "{sin_pass}");

    let sin_mango = enrutar_operador(
        &vista,
        Some(&estado),
        r#"{"op":"obs.diagnostico.ejercer","req_id":"d2","schema_v":1,"operador_id":"op","sistema_id":"sys-c2a-deny","mango":"deadbeef","modelo_id":"m","digest_parametros_hex":"aa"}"#,
    );
    assert!(sin_mango.contains("DENY"), "{sin_mango}");
}
