//! D4 — UI solo consume obs.*, no muta, no muestra secretos, bind local.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sak_domain::obs::OPS_LECTURA;
use sak_ops_ui::allowlist::{op_permitida, rechazar_si_no_observar, PANEL_OPS};
use sak_ops_ui::cliente::{parse_obs_addr, ObsCliente, ObsClienteMock};
use sak_ops_ui::pantallas::{html_consola, scrub_secreto_ui};
use sak_ops_ui::servidor::{servir_con_listener, validar_bind_ui};

#[test]
fn paneles_solo_ops_lectura_obs() {
    for (panel, op) in PANEL_OPS {
        assert!(op.starts_with("obs."), "panel {panel} no es obs.*");
        assert!(
            OPS_LECTURA.contains(op),
            "panel {panel} op {op} fuera de OPS_LECTURA D3"
        );
        assert!(op_permitida(op));
        assert!(rechazar_si_no_observar(op).is_ok());
    }
    for op in OPS_LECTURA {
        assert!(
            PANEL_OPS.iter().any(|(_, o)| o == op),
            "op canal {op} sin panel UI"
        );
    }
}

#[test]
fn ui_deniega_mutacion_y_fuera_de_familia() {
    // Observar-cliente: sigue denegando todo lo no-obs (incl. MVP con/cus/gob).
    let prohibidas_obs = [
        "gob.proponer",
        "gob.activar_epoca",
        "cus.reveal",
        "cus.alta_referencia",
        "cap.emitir",
        "libro.elevar",
        "telemetry.ping",
        "obs.diagnostico.decidir",
        "obs.diagnostico.ejercer",
        "con.sistema.alta",
        "net.bind_public",
    ];
    let mock = ObsClienteMock {
        respuestas: BTreeMap::new(),
    };
    for op in prohibidas_obs {
        assert!(
            rechazar_si_no_observar(op).is_err(),
            "Observar debía DENY {op}"
        );
        assert!(
            mock.pedir_obs(op, "r1", "").is_err(),
            "cliente Observar no debe emitir {op}"
        );
        assert!(!op_permitida(op));
    }
}

#[test]
fn html_sin_rutas_ni_botones_de_mutacion() {
    let html = html_consola("demo", "127.0.0.1:1");
    let ban = [
        "cap.emitir",
        "libro.elevar",
        "cus.reveal",
        "method: 'POST'",
        "method: \"POST\"",
        "diagnostico",
    ];
    for b in ban {
        assert!(
            !html.contains(b),
            "HTML no debe contener mutación/ruta prohibida: {b}"
        );
    }
    assert!(html.contains("obs.estado"));
    assert!(html.contains("obs.expediente.get"));
    assert!(html.contains("Observar"));
    assert!(!html.contains("private_key"));
}

#[test]
fn scrub_rechaza_secretos() {
    assert!(scrub_secreto_ui(r#"{"digest":"abc"}"#).is_ok());
    assert!(scrub_secreto_ui(r#"{"private_key":"x"}"#).is_err());
    assert!(scrub_secreto_ui("BEGIN PRIVATE KEY").is_err());
    assert!(scrub_secreto_ui(r#"{"seed":"deadbeef"}"#).is_err());
}

#[test]
fn bind_ui_solo_loopback() {
    assert!(validar_bind_ui("127.0.0.1:0".parse().unwrap()).is_ok());
    assert!(validar_bind_ui("[::1]:0".parse().unwrap()).is_ok());
    assert!(validar_bind_ui("0.0.0.0:8790".parse().unwrap()).is_err());
    assert!(validar_bind_ui("8.8.8.8:8790".parse().unwrap()).is_err());
    assert!(parse_obs_addr("127.0.0.1:9000").is_ok());
    assert!(parse_obs_addr("0.0.0.0:9000").is_err());
    assert!(parse_obs_addr("192.168.1.1:9000").is_err());
}

#[test]
fn http_proxy_solo_get_obs_allowlist() {
    let mut map = BTreeMap::new();
    map.insert(
        "obs.estado".into(),
        r#"{"req_id":"t","resultado":"OK","codigo":"OK","digest_respuesta":"aa","limites":[],"cuerpo":{"estado":"ok"}}"#.into(),
    );
    map.insert(
        "obs.expediente.get".into(),
        r#"{"req_id":"t","resultado":"DENY","codigo":"EXPEDIENTE_AUSENTE","digest_respuesta":"00","limites":[],"cuerpo":{}}"#.into(),
    );
    let cliente = Arc::new(ObsClienteMock { respuestas: map });
    let listener = std::net::TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();

    let c = Arc::clone(&cliente);
    thread::spawn(move || {
        let _ = servir_con_listener(listener, c, "demo".into(), "127.0.0.1:1".into());
    });
    thread::sleep(Duration::from_millis(80));

    // GET obs.estado OK
    let body = http_get(addr, "/obs?op=obs.estado");
    assert!(body.contains("OK") || body.contains("estado"), "{body}");

    // DENY gob.*
    let deny = http_get(addr, "/obs?op=gob.proponer");
    assert!(deny.contains("DENY") || deny.contains("UI_DENY") || deny.contains("403"), "{deny}");

    // POST rechazado
    let post = http_raw(addr, "POST /obs?op=obs.estado HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
    assert!(
        post.contains("405") || post.contains("DENY") || post.contains("solo GET"),
        "{post}"
    );

    // Expediente ausente visible
    let exp = http_get(addr, "/obs?op=obs.expediente.get&expediente_id=x");
    assert!(exp.contains("EXPEDIENTE_AUSENTE"), "{exp}");

    // Página raíz sin secretos
    let home = http_get(addr, "/");
    assert!(home.contains("Observar"));
    assert!(!home.to_ascii_lowercase().contains("private_key"));
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
