//! Transporte local del canal operador: in-process, stdio y loopback 127.0.0.1.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use super::despacho::despachar;
use super::vista::ObsVista;
use crate::ops::{self, EstadoOps};
use std::sync::{Arc, Mutex};

/// Solo admite bind en loopback IPv4. Cualquier otra dirección ⇒ error.
pub fn listener_loopback(puerto: u16) -> Result<TcpListener, String> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto);
    TcpListener::bind(addr).map_err(|e| format!("bind loopback: {e}"))
}

/// Política de arranque: solo loopback. Direcciones no locales ⇒ DENY.
pub fn validar_bind_operador(addr: SocketAddr) -> Result<(), String> {
    if !es_peer_local(addr) {
        return Err("DENY bind no local / público (contrato IPC operador)".into());
    }
    Ok(())
}

/// Política: dirección remota debe ser loopback.
pub fn es_peer_local(addr: SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Atiende una conexión: una línea JSON de petición → una línea JSON de respuesta.
pub fn atender_stream(vista: &ObsVista, mut stream: TcpStream) -> Result<(), String> {
    atender_stream_con_ops(vista, None, stream)
}

pub fn atender_stream_con_ops(
    vista: &ObsVista,
    estado_ops: Option<Arc<Mutex<EstadoOps>>>,
    mut stream: TcpStream,
) -> Result<(), String> {
    let peer = stream
        .peer_addr()
        .map_err(|e| format!("peer: {e}"))?;
    if !es_peer_local(peer) {
        let deny = super::schema::Respuesta::deny("peer", "NO_LOCAL", "peer no loopback");
        let _ = writeln!(stream, "{}", deny.a_json());
        return Err("peer no local".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
                if buf.len() > 1_000_000 {
                    return Err("petición demasiado grande".into());
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    let raw = String::from_utf8_lossy(&buf);
    let linea = raw.lines().next().unwrap_or("").trim();
    let out = enrutar_operador(vista, estado_ops.as_ref(), linea);
    if super::vista::contiene_secreto_prohibido(&out) {
        let scrub = super::schema::Respuesta::deny(
            "scrub",
            "SECRETO_BLOQUEADO",
            "respuesta contenía patrón de secreto; no se emite",
        );
        writeln!(stream, "{}", scrub.a_json()).map_err(|e| e.to_string())?;
        return Err("secreto bloqueado".into());
    }
    writeln!(stream, "{out}").map_err(|e| e.to_string())?;
    Ok(())
}

/// Enruta `obs.*` → Observar; `con.*` → EstadoOps; resto stubs.
pub fn enrutar_operador(
    vista: &ObsVista,
    estado_ops: Option<&Arc<Mutex<EstadoOps>>>,
    raw: &str,
) -> String {
    let op = ops::parsear_op(raw)
        .map(|(o, _, _)| o)
        .unwrap_or_default();
    if op.starts_with("obs.diagnostico.") {
        let resp = if let Some(st) = estado_ops {
            let mut guard = st.lock().expect("estado ops");
            let (op_n, req_id, schema_v) = match ops::parsear_op(raw) {
                Ok(t) => t,
                Err(e) => {
                    return ops::RespuestaOps::deny("sin-id", "SCHEMA", &e).a_json();
                }
            };
            if schema_v != ops::SCHEMA_V {
                return ops::RespuestaOps::deny(&req_id, "SCHEMA_V", "schema_v no soportado")
                    .a_json();
            }
            crate::sujeto::manejar_diagnostico(&mut guard, &op_n, &req_id, raw)
        } else {
            ops::RespuestaOps::deny(
                "sin-id",
                "SIN_ESTADO",
                "obs.diagnostico.* requiere EstadoOps",
            )
        };
        let out = resp.a_json();
        if super::vista::contiene_secreto_prohibido(&out) {
            return ops::RespuestaOps::deny(
                &resp.req_id,
                "SECRETO_BLOQUEADO",
                "respuesta contenía patrón de secreto; no se emite",
            )
            .a_json();
        }
        return out;
    }
    if op.starts_with("obs.") || op.is_empty() {
        let resp = despachar(vista, raw);
        let out = resp.a_json();
        if super::vista::contiene_secreto_prohibido(&out) {
            return super::schema::Respuesta::deny(
                &resp.req_id,
                "SECRETO_BLOQUEADO",
                "respuesta contenía patrón de secreto; no se emite",
            )
            .a_json();
        }
        return out;
    }
    let resp = if let Some(st) = estado_ops {
        let mut guard = st.lock().expect("estado ops");
        ops::despachar_con_estado(raw, Some(&mut guard))
    } else {
        ops::despachar_linea(raw)
    };
    let out = resp.a_json();
    if super::vista::contiene_secreto_prohibido(&out) {
        return ops::RespuestaOps::deny(
            &resp.req_id,
            "SECRETO_BLOQUEADO",
            "respuesta contenía patrón de secreto; no se emite",
        )
        .a_json();
    }
    out
}

/// In-process Observar (sin estado Conectar).
pub fn in_process(vista: &ObsVista, raw: &str) -> String {
    enrutar_operador(vista, None, raw)
}

/// In-process con EstadoOps (tests / stdio Conectar).
pub fn in_process_con_ops(
    vista: &ObsVista,
    estado: &Arc<Mutex<EstadoOps>>,
    raw: &str,
) -> String {
    enrutar_operador(vista, Some(estado), raw)
}

/// Verifica que un SocketAddr de escucha es estrictamente loopback.
pub fn addr_escucha_es_local(addr: SocketAddr) -> bool {
    es_peer_local(addr)
}
