//! Cliente UI → canal operador loopback (Observar + MVP ops Fase 0).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

use sak_domain::obs::{es_peer_local, SCHEMA_V};

use crate::allowlist::{rechazar_si_no_observar, rechazar_si_no_permitida_ui};
use crate::anti_engano::payload_contiene_secreto;
use crate::pantallas::scrub_secreto_ui;

pub trait OpsCliente {
    /// Envía petición JSON allowlist (obs.* o MVP con/cus/gob).
    fn pedir(&self, op: &str, req_id: &str, extra_json_fields: &str) -> Result<String, String>;
}

/// Compat D4: solo Observar.
pub trait ObsCliente {
    fn pedir_obs(&self, op: &str, req_id: &str, extra_json_fields: &str) -> Result<String, String>;
}

pub struct ClienteCanalTcp {
    pub addr: SocketAddr,
    pub dominio_id: String,
    pub operador_id: String,
}

pub type OpsClienteTcp = ClienteCanalTcp;
pub type ObsClienteTcp = ClienteCanalTcp;

impl ClienteCanalTcp {
    pub fn nuevo(addr: SocketAddr, dominio_id: impl Into<String>) -> Result<Self, String> {
        if !es_peer_local(addr) {
            return Err("UI DENY: destino canal no es loopback".into());
        }
        Ok(ClienteCanalTcp {
            addr,
            dominio_id: dominio_id.into(),
            operador_id: "operador-ui-local".into(),
        })
    }
}

impl OpsCliente for ClienteCanalTcp {
    fn pedir(&self, op: &str, req_id: &str, extra_json_fields: &str) -> Result<String, String> {
        rechazar_si_no_permitida_ui(op)?;
        if payload_contiene_secreto(extra_json_fields) {
            return Err("UI DENY: payload con patrón de material de clave".into());
        }
        enviar_tcp(
            self.addr,
            &self.operador_id,
            &self.dominio_id,
            op,
            req_id,
            extra_json_fields,
        )
    }
}

impl ObsCliente for ClienteCanalTcp {
    fn pedir_obs(&self, op: &str, req_id: &str, extra: &str) -> Result<String, String> {
        rechazar_si_no_observar(op)?;
        self.pedir(op, req_id, extra)
    }
}

pub struct ClienteCanalMock {
    pub respuestas: BTreeMap<String, String>,
}

pub type OpsClienteMock = ClienteCanalMock;
pub type ObsClienteMock = ClienteCanalMock;

impl OpsCliente for ClienteCanalMock {
    fn pedir(&self, op: &str, req_id: &str, extra: &str) -> Result<String, String> {
        rechazar_si_no_permitida_ui(op)?;
        if payload_contiene_secreto(extra) {
            return Err("UI DENY: payload con patrón de material de clave".into());
        }
        if let Some(r) = self.respuestas.get(op) {
            return scrub_secreto_ui(r);
        }
        Ok(format!(
            r#"{{"req_id":"{req_id}","resultado":"DENY","codigo":"FASE0_SIN_HANDLER","digest_respuesta":"00","limites":[],"cuerpo":{{"op":"{op}","fase":0}}}}"#
        ))
    }
}

impl ObsCliente for ClienteCanalMock {
    fn pedir_obs(&self, op: &str, req_id: &str, _extra: &str) -> Result<String, String> {
        rechazar_si_no_observar(op)?;
        if let Some(r) = self.respuestas.get(op) {
            return scrub_secreto_ui(r);
        }
        Ok(format!(
            r#"{{"req_id":"{req_id}","resultado":"OK","codigo":"MOCK","digest_respuesta":"00","limites":[],"cuerpo":{{"op":"{op}","mock":true}}}}"#
        ))
    }
}

fn enviar_tcp(
    addr: SocketAddr,
    operador_id: &str,
    dominio_id: &str,
    op: &str,
    req_id: &str,
    extra_json_fields: &str,
) -> Result<String, String> {
    let mut body = format!(
        r#"{{"op":"{op}","req_id":"{req_id}","schema_v":{schema},"operador_id":"{oper}","dominio_id":"{dom}""#,
        schema = SCHEMA_V,
        oper = operador_id,
        dom = dominio_id,
    );
    if !extra_json_fields.is_empty() {
        body.push(',');
        body.push_str(extra_json_fields.trim_start_matches(','));
    }
    body.push('}');
    body.push('\n');

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .map_err(|e| format!("connect: {e}"))?;
    if let Ok(peer) = stream.peer_addr() {
        if !es_peer_local(peer) {
            return Err("UI DENY: peer no local tras connect".into());
        }
    }
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream
        .write_all(body.as_bytes())
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.contains(&b'\n') {
                    break;
                }
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    let raw = String::from_utf8_lossy(&buf);
    let linea = raw.lines().next().unwrap_or("").to_string();
    scrub_secreto_ui(&linea)
}

pub fn parse_obs_addr(s: &str) -> Result<SocketAddr, String> {
    let addr: SocketAddr = s.parse().map_err(|e| format!("addr inválida: {e}"))?;
    if !es_peer_local(addr) {
        return Err("UI DENY: --obs debe ser loopback".into());
    }
    match addr.ip() {
        IpAddr::V4(v) if v.is_loopback() => Ok(addr),
        IpAddr::V6(v) if v.is_loopback() => Ok(addr),
        _ => Err("UI DENY: --obs no loopback".into()),
    }
}
