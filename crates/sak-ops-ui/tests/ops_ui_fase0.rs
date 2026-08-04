//! Fase 0 — denegaciones UI: shell, allowlist, anti-engaño, sin secretos.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sak_ops_ui::allowlist::{
    op_permitida_mvp_ops, op_permitida_obs, rechazar_si_no_observar, rechazar_si_no_permitida_ui,
};
use sak_ops_ui::anti_engano::{payload_contiene_secreto, VistaAntiEngano};
use sak_ops_ui::cliente::{ClienteCanalMock, ObsCliente, OpsCliente};
use sak_ops_ui::pantallas::{html_auditar, html_conectar, html_consola, html_custodiar, html_gobernar};
use sak_ops_ui::servidor::servir_con_listener;

#[test]
fn deny_fijo_en_ui() {
    for op in [
        "cap.emitir",
        "libro.elevar",
        "cus.reveal",
        "telemetry.x",
        "cap.emitir",
        "obs.diagnostico.decidir",
        "net.bind_public",
    ] {
        assert!(
            rechazar_si_no_permitida_ui(op).is_err(),
            "debía DENY {op}"
        );
    }
}

#[test]
fn mvp_allowlist_pasa_ui_pero_obs_cliente_no() {
    let mock = ClienteCanalMock {
        respuestas: BTreeMap::new(),
    };
    assert!(op_permitida_mvp_ops("con.sistema.alta"));
    assert!(rechazar_si_no_permitida_ui("con.sistema.alta").is_ok());
    assert!(rechazar_si_no_observar("con.sistema.alta").is_err());
    assert!(mock.pedir_obs("con.sistema.alta", "r", "").is_err());
    let r = mock.pedir("con.sistema.alta", "r", "").unwrap();
    assert!(r.contains("FASE0_SIN_HANDLER"), "{r}");
}

#[test]
fn payload_pem_denegado() {
    assert!(payload_contiene_secreto("-----BEGIN PRIVATE KEY-----"));
    let mock = ClienteCanalMock {
        respuestas: BTreeMap::new(),
    };
    assert!(mock
        .pedir(
            "cus.alta_referencia",
            "r",
            r#""pem":"BEGIN PRIVATE KEY""#
        )
        .is_err());
}

#[test]
fn anti_engano_requiere_campos() {
    let mut v = VistaAntiEngano {
        objeto_canonico: "{}".into(),
        digest: "aa".into(),
        identidad: "u".into(),
        rol: "operador".into(),
        consecuencias: "ninguna en fase0".into(),
        epoca: "1".into(),
        confirmacion_independiente: false,
    };
    assert!(v.validar_completo().is_ok());
    v.digest.clear();
    assert!(v.validar_completo().is_err());
    let html = VistaAntiEngano {
        objeto_canonico: "{}".into(),
        digest: "aa".into(),
        identidad: "u".into(),
        rol: "operador".into(),
        consecuencias: "x".into(),
        epoca: "1".into(),
        confirmacion_independiente: true,
    }
    .html_panel();
    assert!(html.contains("anti-engano"));
    assert!(html.contains("Digest"));
    assert!(!html.to_ascii_lowercase().contains("private_key"));
}

#[test]
fn shell_tiene_nav_sin_botones_mutacion_cap() {
    let html = html_consola("demo", "127.0.0.1:1");
    assert!(html.contains("/conectar"));
    assert!(html.contains("/custodiar"));
    assert!(html.contains("/gobernar"));
    assert!(html.contains("UI sin autoridad"));
    assert!(html.contains("No firma capacidades"));
    assert!(!html.contains("cap.emitir\">"));
    assert!(!html.contains("method: 'POST'"));
    let aud = html_auditar("demo", "127.0.0.1:1");
    assert!(aud.contains("¿Está el Kernel vivo") || aud.contains("vivo y custodiando"));
    assert!(aud.contains("KERNEL VALIDA"));
    assert!(aud.contains("UI MUESTRA"));
    assert!(aud.contains("BLOQUEADO"));
    assert!(aud.contains("btn-latido"));
    assert!(aud.contains("Latido del dominio"));
    assert!(aud.contains("Sistemas e identidades"));
    assert!(aud.contains("Custodia"));
    assert!(aud.contains("Control real"));
    assert!(aud.contains("ALCANZABLES"));
    assert!(aud.contains("Evidencia verificable"));
    assert!(aud.contains("Bloqueos por diseño"));
    assert!(aud.contains("no certifica") || aud.contains("No certifica") || aud.contains("no certifica cumplimiento"));
    assert!(!aud.contains("conformidad_certificada\":true"));
    assert!(aud.contains("Qué comprueba"));
    assert!(aud.contains("Qué no es"));
    // A2 — checklist aceptación Bloque A
    assert!(aud.contains("checklist-bloque-a"));
    assert!(aud.contains("data-check=\"latido\""));
    assert!(aud.contains("data-check=\"deny\""));
    // A4 — disclaimer alcance (no mediación E2E)
    assert!(aud.contains("data-alcance=\"bloque-a\""));
    assert!(aud.contains("No afirma"));
    assert!(aud.contains("frontera única de efectos del agente") || aud.contains("frontera unica de efectos del agente"));
    let stub_gone = html_gobernar("demo", "127.0.0.1:1");
    assert!(stub_gone.contains("gob.proponer"));
    assert!(stub_gone.contains("gob.doble_firma"));
    assert!(stub_gone.contains("gob.entrar_sombra"));
    assert!(stub_gone.contains("gob.estado_sombra"));
    assert!(stub_gone.contains("gob.activar_epoca"));
    assert!(stub_gone.contains("gob.revocar"));
    assert!(stub_gone.contains("gob.revertir"));
    assert!(stub_gone.contains("IRREVERSIBLE"));
    assert!(stub_gone.contains("conformidad"));
    assert!(!stub_gone.contains("FASE0_SIN_HANDLER"));
    assert!(stub_gone.contains("btn-revocar"));
    assert!(stub_gone.contains("btn-revertir"));
    assert!(stub_gone.contains("postOps('gob.revocar'"));
    assert!(stub_gone.contains("postOps('gob.revertir'"));
    assert!(!stub_gone.contains("borrar_historia"));
    let con = html_conectar("demo", "127.0.0.1:1");
    assert!(con.contains("C1"));
    assert!(con.contains("C5"));
    assert!(con.contains("con.sistema.alta"));
    assert!(con.contains("con.sistemas.listar"));
    assert!(con.contains("con.inventario.alcanzables"));
    assert!(con.contains("/observar?panel=libro"));
    let cus = html_custodiar("demo", "127.0.0.1:1");
    assert!(cus.contains("cus.rotar"));
    assert!(cus.contains("IRREVERSIBLE"));
    assert!(!cus.contains("FASE0_SIN_HANDLER"));
}

#[test]
fn http_deny_cap_y_probe_fase0() {
    let cliente = Arc::new(ClienteCanalMock {
        respuestas: BTreeMap::new(),
    });
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let c = Arc::clone(&cliente);
    thread::spawn(move || {
        let _ = servir_con_listener(listener, c, "demo".into(), "127.0.0.1:1".into());
    });
    thread::sleep(Duration::from_millis(80));

    let deny = http_get(addr, "/ops?op=cap.emitir");
    assert!(deny.contains("DENY") || deny.contains("UI_DENY"), "{deny}");

    let elev = http_get(addr, "/ops?op=libro.elevar");
    assert!(elev.contains("DENY") || elev.contains("UI_DENY"), "{elev}");

    let tel = http_get(addr, "/ops?op=telemetry.x");
    assert!(tel.contains("DENY") || tel.contains("UI_DENY"), "{tel}");

    let mvp = http_get(addr, "/ops?op=con.sistema.alta");
    assert!(mvp.contains("FASE0_SIN_HANDLER"), "{mvp}");

    let post_vacio = http_raw(
        addr,
        "POST /ops HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(
        post_vacio.contains("400") || post_vacio.contains("DENY"),
        "{post_vacio}"
    );

    let post_ok = http_raw(
        addr,
        "POST /ops HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 78\r\n\r\n{\"op\":\"con.sistemas.listar\",\"req_id\":\"t\",\"schema_v\":1,\"operador_id\":\"op\"}\n",
    );
    assert!(post_ok.contains("200") || post_ok.contains("FASE0_SIN_HANDLER") || post_ok.contains("LISTA") || post_ok.contains("resultado"), "{post_ok}");

    let home = http_get(addr, "/");
    assert!(
        home.contains("vivo") || home.contains("Verificación") || home.contains("Latido"),
        "{home}"
    );
    assert!(home.contains("KERNEL VALIDA"));
    assert!(home.contains("UI MUESTRA"));
    assert!(home.contains("Control real") || home.contains("Custodia"));

    let home_con = http_get(addr, "/conectar");
    assert!(home_con.contains("Conectar"));
    assert!(home_con.contains("C5"));
    assert!(home_con.contains("con.inventario.alcanzables"));
    assert!(home_con.contains("/observar?panel=libro"));

    let obs_dl = http_get(addr, "/observar?panel=libro");
    assert!(obs_dl.contains("Observar"));
    assert!(obs_dl.contains("deep-link") || obs_dl.contains("panel") || obs_dl.contains("libro"));

    let cus = http_get(addr, "/custodiar");
    assert!(cus.contains("Custodiar"));
    assert!(cus.contains("cus.rotar"));
    assert!(cus.contains("IRREVERSIBLE"));
    assert!(!cus.contains("FASE0_SIN_HANDLER"));

    let gob = http_get(addr, "/gobernar");
    assert!(gob.contains("Gobernar"));
    assert!(gob.contains("gob.proponer"));
    assert!(gob.contains("gob.diff_conformidad"));
    assert!(gob.contains("gob.entrar_sombra"));
    assert!(gob.contains("gob.estado_sombra"));
    assert!(gob.contains("gob.activar_epoca"));
    assert!(gob.contains("gob.revocar"));
    assert!(gob.contains("gob.revertir"));
    assert!(gob.contains("btn-activar"));
    assert!(gob.contains("btn-revocar"));
    assert!(!gob.contains("FASE0_SIN_HANDLER"));

    assert!(op_permitida_obs("obs.estado"));
    assert!(!op_permitida_obs("con.sistema.alta"));
}

fn http_get(addr: SocketAddr, path: &str) -> String {
    http_raw(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"),
    )
}

fn http_raw(addr: SocketAddr, req: &str) -> String {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect(addr).expect("connect ui");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}
