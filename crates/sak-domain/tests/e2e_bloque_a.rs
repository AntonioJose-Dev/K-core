//! Bloque A — harness comprobable y auditable (fases A1 + A3).
//!
//! Afirmación permitida al cerrar A1+A3:
//!   el dominio custodia identidad/refs/inventario y deniega autoridad en IPC.
//! Afirmación todavía NO permitida:
//!   mediación end-to-end de efectos del agente (modelo/herramientas/datos).

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::evidencia::{LedgerEvidencia, MemoriaDurable};
use sak_core::identidad::{DeclaracionResponsable, IdSistema};
use sak_core::libro::InventarioAlcanzables;
use sak_core::reloj::Ticks;
use sak_domain::obs::{contiene_secreto_prohibido, despachar as obs_despachar, ObsVista, Respuesta};
use sak_domain::ops::{despachar_con_estado, EstadoOps, OPS_DENY_FIJO, RespuestaOps};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const AFIRMACION_A: &str = "Bloque A: registro + custodia de referencias + DENY en canal operador. No afirma frontera unica de efectos del agente.";
const SISTEMA: &str = "sys-bloque-a-e2e";

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
    let p = base.join("artefactos").join("bloque_a");
    fs::create_dir_all(&p).expect("crear dir artefactos bloque_a");
    p
}

fn escribir_artefacto(nombre: &str, cuerpo: &str) -> PathBuf {
    let path = artefacto_dir().join(nombre);
    fs::write(&path, cuerpo).expect("escribir artefacto");
    path
}

fn decl_firmada(sistema: &str) -> (DeclaracionResponsable, String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let d = DeclaracionResponsable::firmar(
        &par,
        sid,
        "responsable@org",
        "prueba-bloque-a",
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
    let firma = hex(d.firma_responsable());
    (d, hex(&par.public), firma)
}

fn body_alta(sistema: &str, firma_hex: &str, pk_hex: &str, extra: &str) -> String {
    format!(
        r#"{{"op":"con.sistema.alta","req_id":"a1-alta","schema_v":1,"operador_id":"op-a","sistema_id":"{sistema}","pasaporte_id":"{sistema}","responsable":"responsable@org","finalidad":"prueba-bloque-a","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma_hex}","pk_responsable_hex":"{pk_hex}"{extra}}}"#
    )
}

fn inv_firmado(sistema: &str) -> InventarioAlcanzables {
    let par = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let mut efectores = BTreeSet::new();
    efectores.insert(ClaseEfecto::Ef1);
    efectores.insert(ClaseEfecto::Ef4);
    InventarioAlcanzables::firmar_completo(
        sid,
        "inst-bloque-a",
        efectores,
        BTreeSet::from(["127.0.0.1:8443".into()]),
        BTreeSet::from(["cred:digest:aabb".into()]),
        BTreeSet::from(["store-a".into()]),
        BTreeSet::from(["svc-a".into()]),
        BTreeSet::from(["canal-a".into()]),
        true,
        1,
        1,
        0,
        "detector-bloque-a",
        &par,
    )
    .unwrap()
}

fn body_alcanzables(inv: &InventarioAlcanzables) -> String {
    let efectores: String = inv
        .efectores
        .iter()
        .map(|e| e.token().to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"op":"con.inventario.alcanzables","req_id":"a1-alc","schema_v":1,"sistema_id":"{sid}","instancia":"{inst}","productor_id":"{prod}","efectores":"{efectores}","rutas_red":"127.0.0.1:8443","credenciales_detectadas":"cred:digest:aabb","almacenes":"store-a","puntos_servicio":"svc-a","canales_consumo":"canal-a","incompleto_declarado":true,"version":1,"epoca":1,"emitido_en":0,"firma_productor_hex":"{firma}","pk_productor_hex":"{pk}"}}"#,
        sid = inv.sistema.como_str(),
        inst = inv.instancia,
        prod = inv.productor_id,
        efectores = efectores,
        firma = hex(&inv.firma),
        pk = hex(&inv.pk_firmante),
    )
}

fn cuerpo_cus(alias: &str, clase_ef: &str, handle: &str) -> Vec<u8> {
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

fn firma_cus(alias: &str, clase: &str, handle: &str) -> (String, String) {
    let par = ParMlDsa87::generar().unwrap();
    let firma = hex(&par.firmar(&cuerpo_cus(alias, clase, handle)).unwrap());
    (hex(&par.public), firma)
}

fn vista_desde_estado(st: &EstadoOps) -> ObsVista {
    let ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).expect("ledger");
    ObsVista::desde_ledger(
        "bloque-a-e2e",
        Path::new("."),
        &ledger,
        Some(&st.libro),
        st.registro.n_versiones(),
        0,
        "-",
        "-",
        1_000 as Ticks,
    )
}

fn assert_ok(label: &str, r: &RespuestaOps) {
    assert_eq!(r.resultado, "OK", "{label}: {}", r.a_json());
    assert!(!contiene_secreto_prohibido(&r.a_json()), "{label}: secreto");
}

fn assert_ok_obs(label: &str, r: &Respuesta) {
    assert_eq!(r.resultado, "OK", "{label}: {}", r.a_json());
    assert!(!contiene_secreto_prohibido(&r.a_json()), "{label}: secreto");
}

/// A1 — flujo completo registro → custodia → lectura → evidencia.
#[test]
fn a1_flujo_completo_escribe_artefacto() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let mut log = String::from("{\n  \"fase\": \"A1\",\n  \"pasos\": [\n");

    let salud = obs_despachar(
        &vista_desde_estado(&st),
        r#"{"op":"obs.salud","req_id":"s","schema_v":1,"operador_id":"op-a"}"#,
    );
    assert_ok_obs("obs.salud", &salud);
    log.push_str(&format!(
        "    {{\"op\":\"obs.salud\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        salud.resultado, salud.codigo
    ));

    let (_d, pk, firma) = decl_firmada(SISTEMA);
    let alta = despachar_con_estado(&body_alta(SISTEMA, &firma, &pk, ""), Some(&mut st));
    assert_ok("con.sistema.alta", &alta);
    assert!(alta.cuerpo.contains("autoriza_efectos\":false"));
    log.push_str(&format!(
        "    {{\"op\":\"con.sistema.alta\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        alta.resultado, alta.codigo
    ));

    let emit = despachar_con_estado(
        &format!(
            r#"{{"op":"con.pasaporte.emitir","req_id":"e","schema_v":1,"sistema_id":"{SISTEMA}","pasaporte_id":"{SISTEMA}","version":1,"responsable":"responsable@org","finalidad":"prueba-bloque-a","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
        ),
        Some(&mut st),
    );
    assert_ok("con.pasaporte.emitir", &emit);
    assert!(emit.cuerpo.contains("editable\":false"));
    log.push_str(&format!(
        "    {{\"op\":\"con.pasaporte.emitir\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        emit.resultado, emit.codigo
    ));

    let get = despachar_con_estado(
        &format!(
            r#"{{"op":"con.pasaporte.get","req_id":"g","schema_v":1,"pasaporte_id":"{SISTEMA}","version":1}}"#
        ),
        Some(&mut st),
    );
    assert_ok("con.pasaporte.get", &get);
    assert!(get.cuerpo.contains("firma_valida\":true"));
    log.push_str(&format!(
        "    {{\"op\":\"con.pasaporte.get\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        get.resultado, get.codigo
    ));

    let pep = despachar_con_estado(
        r#"{"op":"con.pep.vista","req_id":"p","schema_v":1}"#,
        Some(&mut st),
    );
    assert_ok("con.pep.vista", &pep);
    assert!(pep.cuerpo.contains("GatewayModelos"));
    log.push_str(&format!(
        "    {{\"op\":\"con.pep.vista\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        pep.resultado, pep.codigo
    ));

    let inv = inv_firmado(SISTEMA);
    let alc = despachar_con_estado(&body_alcanzables(&inv), Some(&mut st));
    assert_ok("con.inventario.alcanzables", &alc);
    assert!(alc.cuerpo.contains("incompleto_declarado\":true"));
    assert!(alc.cuerpo.contains("afirma_completitud\":false"));
    log.push_str(&format!(
        "    {{\"op\":\"con.inventario.alcanzables\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        alc.resultado, alc.codigo
    ));

    let alias = "ref-bloque-a-ef1";
    let clase = "EF-1";
    let handle = "kms:bloque-a/key-1";
    let (pk_op, firma_op) = firma_cus(alias, clase, handle);
    let cus = despachar_con_estado(
        &format!(
            r#"{{"op":"cus.alta_referencia","req_id":"c","schema_v":1,"operador_id":"op-a","alias":"{alias}","clase_ef":"{clase}","handle":"{handle}","firma_operador_hex":"{firma_op}","pk_operador_hex":"{pk_op}"}}"#
        ),
        Some(&mut st),
    );
    assert_ok("cus.alta_referencia", &cus);
    assert!(cus.cuerpo.contains("\"material\":null"));
    log.push_str(&format!(
        "    {{\"op\":\"cus.alta_referencia\",\"resultado\":\"{}\",\"codigo\":\"{}\"}},\n",
        cus.resultado, cus.codigo
    ));

    let cus_st = despachar_con_estado(
        &format!(r#"{{"op":"cus.estado","req_id":"ce","schema_v":1,"alias":"{alias}"}}"#),
        Some(&mut st),
    );
    assert_ok("cus.estado", &cus_st);
    assert!(cus_st.cuerpo.contains("\"material\":null"));

    let lista = despachar_con_estado(
        r#"{"op":"con.sistemas.listar","req_id":"l","schema_v":1}"#,
        Some(&mut st),
    );
    assert_ok("con.sistemas.listar", &lista);
    assert!(lista.cuerpo.contains(SISTEMA));

    let vista = vista_desde_estado(&st);
    let estado = obs_despachar(
        &vista,
        r#"{"op":"obs.estado","req_id":"e","schema_v":1,"operador_id":"op-a"}"#,
    );
    assert_ok_obs("obs.estado", &estado);

    let libro = obs_despachar(
        &vista,
        r#"{"op":"obs.libro.matriz","req_id":"lb","schema_v":1,"operador_id":"op-a"}"#,
    );
    assert_ok_obs("obs.libro.matriz", &libro);

    let hechos = obs_despachar(
        &vista,
        r#"{"op":"obs.hechos.listar","req_id":"h","schema_v":1,"operador_id":"op-a"}"#,
    );
    assert_ok_obs("obs.hechos.listar", &hechos);

    let exp = obs_despachar(
        &vista,
        r#"{"op":"obs.evidencia.exportar","req_id":"ex","schema_v":1,"operador_id":"op-a","confirmacion_explicita":true}"#,
    );
    assert_ok_obs("obs.evidencia.exportar", &exp);
    assert!(!contiene_secreto_prohibido(&exp.a_json()));

    let ver = obs_despachar(
        &vista,
        r#"{"op":"obs.evidencia.verificar","req_id":"v","schema_v":1,"operador_id":"op-a"}"#,
    );
    assert_ok_obs("obs.evidencia.verificar", &ver);
    assert!(ver.a_json().contains("no_comprobado") || ver.cuerpo.contains("no_comprobado"));

    log.push_str("    {\"op\":\"obs.evidencia.verificar\",\"resultado\":\"OK\"}\n");
    log.push_str("  ],\n");
    log.push_str(&format!(
        "  \"afirmacion_permitida\": \"{AFIRMACION_A}\",\n"
    ));
    log.push_str(
        "  \"afirmacion_no_permitida\": \"mediacion end-to-end agente→modelo/herramientas/datos via Kernel\"\n}\n",
    );

    let path = escribir_artefacto("a1_flujo.json", &log);
    let export_path = escribir_artefacto("a1_evidencia_export.json", &exp.a_json());
    assert!(path.is_file());
    assert!(export_path.is_file());
}

/// A3 — matriz DENY obligatoria (falla el build si algún DENY pasa a OK).
#[test]
fn a3_matriz_deny_escribe_artefacto() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let mut filas = Vec::new();

    let r = despachar_con_estado(
        r#"{"op":"con.sistema.alta","req_id":"d1","schema_v":1,"sistema_id":"sys-deny-a3","responsable":"r","finalidad":"f","modelos":"m","jurisdiccion":"EU","datos":"d","autonomia_por_clase":"a","herramientas":"h","efectores":"e","clasificacion_riesgo":"limitado","vigente_desde_dias":1,"vigente_hasta_dias":9}"#,
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SIN_FIRMA", "{}", r.a_json());
    filas.push(format!(
        r#"{{"caso":"alta_sin_firma","codigo":"{}","esperado":"SIN_FIRMA"}}"#,
        r.codigo
    ));

    let (_d, pk, firma) = decl_firmada("sys-deny-a3");
    let r = despachar_con_estado(
        &body_alta("sys-deny-a3", &firma, &pk, r#","api_key":"sk-live-secret""#),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SECRETO_PROHIBIDO", "{}", r.a_json());
    filas.push(format!(
        r#"{{"caso":"alta_api_key","codigo":"{}","esperado":"SECRETO_PROHIBIDO"}}"#,
        r.codigo
    ));

    let (_d2, pk2, firma2) = decl_firmada("sys-deny-auth");
    let r = despachar_con_estado(
        &body_alta(
            "sys-deny-auth",
            &firma2,
            &pk2,
            r#","autorizar_efectos":true"#,
        ),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "INTENTO_AUTORIZAR", "{}", r.a_json());
    filas.push(format!(
        r#"{{"caso":"autorizar_efectos","codigo":"{}","esperado":"INTENTO_AUTORIZAR"}}"#,
        r.codigo
    ));

    let r = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"d4","schema_v":1,"vista":false,"afirma_completitud":true,"firma_productor_hex":"aa","pk_productor_hex":"bb","sistema_id":"sys-x"}"#,
        Some(&mut st),
    );
    assert_eq!(r.codigo, "COMPLETITUD_PROHIBIDA", "{}", r.a_json());
    filas.push(format!(
        r#"{{"caso":"completitud","codigo":"{}","esperado":"COMPLETITUD_PROHIBIDA"}}"#,
        r.codigo
    ));

    for op in OPS_DENY_FIJO {
        let raw = format!(
            r#"{{"op":"{op}","req_id":"df","schema_v":1,"operador_id":"op-a","confirmacion_explicita":true}}"#
        );
        let r = despachar_con_estado(&raw, Some(&mut st));
        assert_eq!(r.resultado, "DENY", "{op} debe DENY: {}", r.a_json());
        assert!(
            r.codigo == "DENY_FIJO"
                || r.codigo == "USAR_CANAL_OBS"
                || r.codigo.contains("DENY"),
            "{op} codigo={}",
            r.codigo
        );
        filas.push(format!(
            r#"{{"caso":"deny_fijo:{op}","codigo":"{}","esperado":"DENY"}}"#,
            r.codigo
        ));
    }

    let vista = vista_desde_estado(&st);
    for op in ["obs.diagnostico.decidir", "obs.diagnostico.ejercer"] {
        let raw = format!(r#"{{"op":"{op}","req_id":"dx","schema_v":1,"operador_id":"op-a"}}"#);
        let r = obs_despachar(&vista, &raw);
        assert_eq!(r.resultado, "DENY", "{op} {}", r.a_json());
        filas.push(format!(
            r#"{{"caso":"{op}","codigo":"{}","esperado":"DENY"}}"#,
            r.codigo
        ));
    }

    let r = despachar_con_estado(
        r#"{"op":"cus.reveal","req_id":"rv","schema_v":1,"alias":"x"}"#,
        Some(&mut st),
    );
    assert_eq!(r.resultado, "DENY");
    filas.push(format!(
        r#"{{"caso":"cus.reveal","codigo":"{}","esperado":"DENY"}}"#,
        r.codigo
    ));

    let tel = despachar_con_estado(
        r#"{"op":"telemetry.ping","req_id":"t","schema_v":1}"#,
        Some(&mut st),
    );
    assert_eq!(tel.resultado, "DENY");
    filas.push(format!(
        r#"{{"caso":"telemetry.ping","codigo":"{}","esperado":"DENY"}}"#,
        tel.codigo
    ));

    let cuerpo = format!(
        "{{\n  \"fase\": \"A3\",\n  \"filas\": [\n    {}\n  ],\n  \"afirmacion_permitida\": \"Atajos de autoridad cerrados en IPC (DENY fijo + denegaciones Conectar/Custodiar).\",\n  \"afirmacion_no_permitida\": \"Que el proceso agente no pueda fugarse por SDK directo fuera del canal.\"\n}}\n",
        filas.join(",\n    ")
    );
    let path = escribir_artefacto("a3_matriz_deny.json", &cuerpo);
    assert!(path.is_file());
}
