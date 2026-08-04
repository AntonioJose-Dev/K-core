//! Servidor HTTP loopback: Observar GET + Conectar POST /ops + stubs Custodiar/Gobernar.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;

use sak_domain::obs::es_peer_local;

use crate::allowlist::{
    op_para_panel, op_permitida_obs, rechazar_si_no_observar, rechazar_si_no_permitida_ui,
};
use sak_domain::ops::campo_str_raw;
use crate::anti_engano::payload_contiene_secreto;
use crate::cliente::{ObsCliente, OpsCliente};
use crate::pantallas::{
    html_anti_engano_demo, html_auditar, html_conectar, html_consola, html_custodiar,
    html_gobernar,
};

/// Solo 127.0.0.1 / ::1 — DENY bind público (contrato IPC §2).
pub fn validar_bind_ui(addr: SocketAddr) -> Result<(), String> {
    if !es_peer_local(addr) {
        return Err("UI DENY: bind no es loopback (net.bind_public)".into());
    }
    match addr.ip() {
        IpAddr::V4(v) if v.is_loopback() => Ok(()),
        IpAddr::V6(v) if v.is_loopback() => Ok(()),
        _ => Err("UI DENY: bind no loopback".into()),
    }
}

pub fn servir_loopback<C: OpsCliente + ObsCliente + Send + Sync + 'static>(
    bind: SocketAddr,
    cliente: Arc<C>,
    dominio_id: String,
    obs_addr_display: String,
) -> Result<(), String> {
    validar_bind_ui(bind)?;
    let listener = TcpListener::bind(bind).map_err(|e| format!("bind UI: {e}"))?;
    servir_con_listener(listener, cliente, dominio_id, obs_addr_display)
}

pub fn servir_con_listener<C: OpsCliente + ObsCliente + Send + Sync + 'static>(
    listener: TcpListener,
    cliente: Arc<C>,
    dominio_id: String,
    obs_addr_display: String,
) -> Result<(), String> {
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    validar_bind_ui(local)?;
    eprintln!("sak-ops-ui listening={local} dominio={dominio_id} canal={obs_addr_display}");
    eprintln!("fase=5.4 shell=Auditoría|Observar|Conectar|Custodiar|Gobernar autoridad=ninguna");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        if let Ok(peer) = stream.peer_addr() {
            if !es_peer_local(peer) {
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
                continue;
            }
        }
        let c = Arc::clone(&cliente);
        let dom = dominio_id.clone();
        let obs_disp = obs_addr_display.clone();
        let _ = atender_http(&mut stream, c.as_ref(), &dom, &obs_disp);
    }
    Ok(())
}

fn atender_http<C: OpsCliente + ObsCliente>(
    stream: &mut TcpStream,
    cliente: &C,
    dominio_id: &str,
    obs_disp: &str,
) -> Result<(), String> {
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let linea = req.lines().next().unwrap_or("");
    let mut parts = linea.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");

    // GET páginas; POST solo /ops allowlist (Fase 1 Conectar).
    if method != "GET" && !(method == "POST" && path_only_is_ops(path)) {
        return responder(
            stream,
            405,
            "text/plain; charset=utf-8",
            "UI DENY: solo GET o POST /ops allowlist",
        );
    }

    let path_only = path.split('?').next().unwrap_or(path);

    if method == "POST" && path_only == "/ops" {
        return manejar_ops_post(stream, &req, cliente);
    }

    match path_only {
        "/" | "/auditar" => {
            let html = html_auditar(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        "/observar" => {
            let html = html_consola(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        "/conectar" => {
            let html = html_conectar(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        "/custodiar" => {
            let html = html_custodiar(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        "/gobernar" => {
            let html = html_gobernar(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        "/anti-engano" => {
            let html = html_anti_engano_demo(dominio_id, obs_disp);
            return responder(stream, 200, "text/html; charset=utf-8", &html);
        }
        _ => {}
    }

    if path.starts_with("/obs") {
        return manejar_obs(stream, path, cliente);
    }
    if path.starts_with("/ops") {
        return manejar_ops_probe(stream, path, cliente);
    }

    responder(stream, 404, "text/plain; charset=utf-8", "no encontrado")
}

fn manejar_obs<C: ObsCliente>(
    stream: &mut TcpStream,
    path: &str,
    cliente: &C,
) -> Result<(), String> {
    let q = path.split('?').nth(1).unwrap_or("");
    let mut op = None::<String>;
    let mut panel = None::<String>;
    let mut id = None::<String>;
    let mut expediente_id = None::<String>;
    for pair in q.split('&') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = url_decode(kv.next().unwrap_or(""));
        match k {
            "op" => op = Some(v),
            "panel" => panel = Some(v),
            "id" => id = Some(v),
            "expediente_id" => expediente_id = Some(v),
            _ => {}
        }
    }

    let op = if let Some(o) = op {
        o
    } else if let Some(p) = panel.as_deref() {
        op_para_panel(p)
            .ok_or_else(|| format!("panel desconocido: {p}"))?
            .to_string()
    } else {
        return responder(stream, 400, "text/plain; charset=utf-8", "falta op|panel");
    };

    if let Err(e) = rechazar_si_no_observar(&op) {
        return responder(stream, 403, "application/json; charset=utf-8", &json_err(&e));
    }
    if !op_permitida_obs(&op) {
        return responder(
            stream,
            403,
            "application/json; charset=utf-8",
            &json_err("op no allowlist Observar"),
        );
    }

    let mut extra = String::new();
    if op == "obs.evidencia.exportar" {
        extra.push_str(r#""confirmacion_explicita":true"#);
    }
    if op == "obs.decisiones.get" {
        if let Some(i) = id {
            if !extra.is_empty() {
                extra.push(',');
            }
            extra.push_str(&format!(r#""id":"{i}""#));
        }
    }
    if op == "obs.expediente.get" {
        let eid = expediente_id.unwrap_or_else(|| "default".into());
        if !extra.is_empty() {
            extra.push(',');
        }
        extra.push_str(&format!(r#""expediente_id":"{eid}""#));
    }

    let req_id = format!(
        "ui-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    match cliente.pedir_obs(&op, &req_id, &extra) {
        Ok(body) => responder(stream, 200, "application/json; charset=utf-8", &body),
        Err(e) => responder(stream, 403, "application/json; charset=utf-8", &json_err(&e)),
    }
}

fn path_only_is_ops(path: &str) -> bool {
    path.split('?').next().unwrap_or(path) == "/ops"
}

fn body_http(req: &str) -> &str {
    if let Some(i) = req.find("\r\n\r\n") {
        &req[i + 4..]
    } else if let Some(i) = req.find("\n\n") {
        &req[i + 2..]
    } else {
        ""
    }
}

/// POST /ops — cuerpo JSON allowlist (Conectar Fase 1).
fn manejar_ops_post<C: OpsCliente>(
    stream: &mut TcpStream,
    req: &str,
    cliente: &C,
) -> Result<(), String> {
    let body = body_http(req).trim();
    if body.is_empty() {
        return responder(
            stream,
            400,
            "application/json; charset=utf-8",
            &json_err("POST /ops requiere cuerpo JSON"),
        );
    }
    if payload_contiene_secreto(body) {
        return responder(
            stream,
            403,
            "application/json; charset=utf-8",
            &json_err("UI DENY: material de clave"),
        );
    }
    let op = match campo_str_raw(body, "op") {
        Some(o) => o,
        None => {
            return responder(
                stream,
                400,
                "application/json; charset=utf-8",
                &json_err("falta op"),
            );
        }
    };
    if let Err(e) = rechazar_si_no_permitida_ui(&op) {
        return responder(stream, 403, "application/json; charset=utf-8", &json_err(&e));
    }
    let req_id = campo_str_raw(body, "req_id").unwrap_or_else(|| format!("ui-ops-{op}"));
    let extra = extra_campos_sin_envelope(body);
    match cliente.pedir(&op, &req_id, &extra) {
        Ok(resp) => responder(stream, 200, "application/json; charset=utf-8", &resp),
        Err(e) => responder(stream, 403, "application/json; charset=utf-8", &json_err(&e)),
    }
}

/// Quita op/req_id/schema_v/operador_id/dominio_id del JSON; deja el resto como campos extra.
fn extra_campos_sin_envelope(body: &str) -> String {
    let inner = body.trim().trim_start_matches('{').trim_end_matches('}').trim();
    if inner.is_empty() {
        return String::new();
    }
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    let mut start = 0usize;
    let bytes = inner.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if in_str {
            if esc {
                esc = false;
            } else if b == b'\\' {
                esc = true;
            } else if b == b'"' {
                in_str = false;
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' | b'[' => depth += 1,
            b'}' | b']' => depth -= 1,
            b',' if depth == 0 => {
                let chunk = inner[start..i].trim();
                if !es_clave_envelope(chunk) {
                    parts.push(chunk.to_string());
                }
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() && !es_clave_envelope(last) {
        parts.push(last.to_string());
    }
    parts.join(",")
}

fn es_clave_envelope(chunk: &str) -> bool {
    chunk.starts_with("\"op\"")
        || chunk.starts_with("\"req_id\"")
        || chunk.starts_with("\"schema_v\"")
        || chunk.starts_with("\"operador_id\"")
        || chunk.starts_with("\"dominio_id\"")
}

/// Probe GET /ops?op=… → allowlist; Conectar real o stub según canal.
fn manejar_ops_probe<C: OpsCliente>(
    stream: &mut TcpStream,
    path: &str,
    cliente: &C,
) -> Result<(), String> {
    let q = path.split('?').nth(1).unwrap_or("");
    let mut op = None::<String>;
    let mut extra = String::new();
    for pair in q.split('&') {
        let mut kv = pair.splitn(2, '=');
        let k = kv.next().unwrap_or("");
        let v = url_decode(kv.next().unwrap_or(""));
        match k {
            "op" => op = Some(v),
            "extra" => extra = v,
            _ => {}
        }
    }
    let op = match op {
        Some(o) => o,
        None => {
            return responder(stream, 400, "text/plain; charset=utf-8", "falta op");
        }
    };
    if let Err(e) = rechazar_si_no_permitida_ui(&op) {
        return responder(stream, 403, "application/json; charset=utf-8", &json_err(&e));
    }
    if payload_contiene_secreto(&extra) {
        return responder(
            stream,
            403,
            "application/json; charset=utf-8",
            &json_err("UI DENY: material de clave"),
        );
    }
    let req_id = format!("ui-ops-{}", op);
    match cliente.pedir(&op, &req_id, &extra) {
        Ok(body) => responder(stream, 200, "application/json; charset=utf-8", &body),
        Err(e) => responder(stream, 403, "application/json; charset=utf-8", &json_err(&e)),
    }
}

fn json_err(msg: &str) -> String {
    let esc = msg.replace('\\', "\\\\").replace('"', "\\\"");
    format!(r#"{{"resultado":"DENY","codigo":"UI_DENY","mensaje":"{esc}"}}"#)
}

fn responder(
    stream: &mut TcpStream,
    code: u16,
    ctype: &str,
    body: &str,
) -> Result<(), String> {
    let status = match code {
        200 => "200 OK",
        400 => "400 Bad Request",
        403 => "403 Forbidden",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        _ => "500 Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).map_err(|e| e.to_string())
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = hex(bytes[i + 1], bytes[i + 2]);
                out.push(h.unwrap_or(b'?'));
                i += 3;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(a: u8, b: u8) -> Option<u8> {
    let n = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    };
    Some((n(a)? << 4) | n(b)?)
}
