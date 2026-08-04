//! Proveedor EF-1 loopback autenticado (Corte 2A + 3B pipe).
//!
//! Clave de arranque: efímera, inyectada. Nonce aleatorio por llamada (anti-replay
//! de mensaje en el mock). Nunca en IPC.
//!
//! Corte 3B: si `SAK_PROBE_MEDIADO_LOOPBACK_PIPE` está definido, la llamada usa
//! Named Pipe Windows. `SAK_PROBE_MEDIADO_LOOPBACK=127.0.0.1:<placeholder>` es solo
//! compat shim para no tocar `sujeto.rs` (el TCP placeholder no es el efector).

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::{
    tomar_contexto_ejercicio_ef1, ContextoEjercicioEf1, CredencialProveedor, ErrorProveedor,
    ProveedorModelo, RespuestaModelo,
};
use crate::pep::solicitud::SolicitudInferencia;
use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Handle canónico resuelto dentro del Kernel para probe-mediado.
pub const HANDLE_EF1_PROBE_MEDIADO: &str = "ef1-probe-mediado";

/// Env: path Named Pipe (`\\.\pipe\...`). Solo leído aquí (no en sujeto).
pub const ENV_LOOPBACK_PIPE: &str = "SAK_PROBE_MEDIADO_LOOPBACK_PIPE";

const PROTO: &str = "SAK-EF1-LB-1";
const TICKET_DOM: &[u8] = b"SAK-EF1-TICKET-v2|";

/// Destino + credencial encapsulada + handle esperado.
pub struct ProveedorLoopbackEf1 {
    destino: SocketAddr,
    credencial: CredencialProveedor,
    handle: String,
    ctx: Option<ContextoEjercicioEf1>,
    pub llamadas_delegadas: u32,
    /// Último nonce emitido (solo harness/tests; no IPC).
    pub ultimo_nonce: Option<[u8; 32]>,
}

impl std::fmt::Debug for ProveedorLoopbackEf1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProveedorLoopbackEf1")
            .field("destino", &self.destino)
            .field("handle", &self.handle)
            .field("credencial", &"REDACTED")
            .field("llamadas_delegadas", &self.llamadas_delegadas)
            .finish()
    }
}

impl ProveedorLoopbackEf1 {
    /// `clave` efímera de arranque (32 bytes). No hay constante pública de prueba.
    pub fn nuevo(destino: SocketAddr, handle: impl Into<String>, clave: [u8; 32]) -> Self {
        ProveedorLoopbackEf1 {
            destino,
            credencial: CredencialProveedor::desde_semilla(clave),
            handle: handle.into(),
            ctx: None,
            llamadas_delegadas: 0,
            ultimo_nonce: None,
        }
    }

    pub fn destino(&self) -> SocketAddr {
        self.destino
    }

    pub fn handle(&self) -> &str {
        &self.handle
    }

    pub fn handle_valido(&self) -> bool {
        self.handle == HANDLE_EF1_PROBE_MEDIADO
    }

    pub(crate) fn sello_con_nonce(
        &self,
        canon: &[u8],
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
        nonce: &[u8; 32],
    ) -> [u8; LONGITUD_HASH_PAQUETE] {
        let mut msg = Vec::with_capacity(canon.len() + LONGITUD_HASH_PAQUETE + 32);
        msg.extend_from_slice(canon);
        msg.extend_from_slice(digest_autorizado);
        msg.extend_from_slice(nonce);
        self.credencial.firmar_llamada(&msg)
    }
}

impl ProveedorModelo for ProveedorLoopbackEf1 {
    fn preparar_contexto_ejercicio(&mut self, ctx: &ContextoEjercicioEf1) {
        self.ctx = Some(ctx.clone());
    }

    fn inferir_delegado(
        &mut self,
        solicitud: &SolicitudInferencia,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<RespuestaModelo, ErrorProveedor> {
        if !self.handle_valido() {
            return Err(ErrorProveedor::NoAutorizado);
        }
        let digest_params = crate::pep::solicitud::digest_solicitud_inferencia(solicitud);
        if digest_params != *digest_autorizado {
            return Err(ErrorProveedor::DivergenciaParametros);
        }
        if !self.destino.ip().is_loopback() {
            return Err(ErrorProveedor::NoAutorizado);
        }

        // Contexto desde hook directo o TLS (Gateway → BackendEf1 sin tocar sujeto).
        let ctx = self
            .ctx
            .take()
            .or_else(tomar_contexto_ejercicio_ef1)
            .ok_or(ErrorProveedor::NoAutorizado)?;
        if ctx.digest != *digest_autorizado {
            return Err(ErrorProveedor::DivergenciaParametros);
        }
        if ctx.ahora > ctx.vive_hasta {
            return Err(ErrorProveedor::NoAutorizado);
        }

        let canon = solicitud.canonico();
        let nonce = generar_nonce_aleatorio();
        let sello = self.sello_con_nonce(&canon, digest_autorizado, &nonce);
        let ticket = emitir_ticket_v2(&self.credencial, &ctx, &nonce);
        let req = format!(
            "{{\"v\":\"{PROTO}\",\"sello\":\"{}\",\"digest\":\"{}\",\"canon\":\"{}\",\"nonce\":\"{}\",\"ticket\":\"{}\",\"cap_id\":\"{}\",\"epoca\":{},\"vive_hasta\":{},\"ahora\":{}}}\n",
            hex(&sello),
            hex(digest_autorizado),
            hex(&canon),
            hex(&nonce),
            hex(&ticket),
            hex(&ctx.cap_id),
            ctx.epoca,
            ctx.vive_hasta,
            ctx.ahora,
        );
        self.ultimo_nonce = Some(nonce);

        let line = roundtrip_ef1(&self.destino, req.as_bytes())?;
        let resp = parse_respuesta_ok(&line).ok_or(ErrorProveedor::FalloInterno)?;
        self.llamadas_delegadas += 1;
        Ok(resp)
    }
}

/// Path del pipe desde env (None si ausente o vacío).
pub fn pipe_desde_env() -> Option<String> {
    std::env::var(ENV_LOOPBACK_PIPE)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn roundtrip_ef1(destino_tcp: &SocketAddr, req: &[u8]) -> Result<String, ErrorProveedor> {
    if let Some(pipe) = pipe_desde_env() {
        return roundtrip_pipe(&pipe, req);
    }
    let mut stream = TcpStream::connect_timeout(destino_tcp, Duration::from_secs(2))
        .map_err(|_| ErrorProveedor::FalloInterno)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ErrorProveedor::FalloInterno)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| ErrorProveedor::FalloInterno)?;
    escribir_y_leer_linea(&mut stream, req)
}

fn roundtrip_pipe(pipe_path: &str, req: &[u8]) -> Result<String, ErrorProveedor> {
    #[cfg(not(windows))]
    {
        let _ = (pipe_path, req);
        return Err(ErrorProveedor::FalloInterno);
    }
    #[cfg(windows)]
    {
        let mut last = ErrorProveedor::FalloInterno;
        for _ in 0..40 {
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pipe_path)
            {
                Ok(mut f) => return escribir_y_leer_linea(&mut f, req),
                Err(_) => {
                    last = ErrorProveedor::FalloInterno;
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Err(last)
    }
}

fn escribir_y_leer_linea(stream: &mut dyn ReadWrite, req: &[u8]) -> Result<String, ErrorProveedor> {
    stream
        .write_all(req)
        .map_err(|_| ErrorProveedor::FalloInterno)?;
    if !req.ends_with(b"\n") {
        stream
            .write_all(b"\n")
            .map_err(|_| ErrorProveedor::FalloInterno)?;
    }
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|_| ErrorProveedor::FalloInterno)?;
    Ok(line)
}

/// Helper para tests/harness: open+R/W a un Named Pipe (Windows).
pub fn enviar_linea_pipe(pipe_path: &str, line: &str) -> Result<String, String> {
    #[cfg(not(windows))]
    {
        let _ = (pipe_path, line);
        return Err("named pipe solo Windows".into());
    }
    #[cfg(windows)]
    {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_path)
            .map_err(|e| e.to_string())?;
        let mut payload = line.as_bytes().to_vec();
        if !payload.ends_with(b"\n") {
            payload.push(b'\n');
        }
        f.write_all(&payload).map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(f);
        let mut out = String::new();
        reader.read_line(&mut out).map_err(|e| e.to_string())?;
        Ok(out)
    }
}

/// Intento de apertura del pipe (prueba ACL). Ok(()) si abre; Err con código OS.
pub fn intentar_abrir_pipe(pipe_path: &str) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = pipe_path;
        return Err("named pipe solo Windows".into());
    }
    #[cfg(windows)]
    {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe_path)
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("os_error={} kind={:?}", e.raw_os_error().unwrap_or(-1), e.kind())),
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Parsea 64 hex → 32 bytes (clave de arranque).
pub fn parse_clave_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex_decode(s.trim()).ok_or_else(|| "clave hex inválida".to_string())?;
    if v.len() != 32 {
        return Err("clave debe ser 32 bytes (64 hex)".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

/// Clave/nonce efímero para tests/harness in-process.
pub fn generar_clave_efimera() -> [u8; 32] {
    generar_nonce_aleatorio()
}

/// Nonce aleatorio de 32 bytes (una vez por llamada delegada).
pub fn generar_nonce_aleatorio() -> [u8; 32] {
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = u128::from(std::process::id());
    let n = u128::from(COUNTER.fetch_add(1, Ordering::SeqCst));
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let shift = (i % 16) * 8;
        let t = (nanos >> shift) as u8;
        let p = (pid >> ((i % 4) * 8)) as u8;
        let c = (n >> ((i % 8) * 8)) as u8;
        *b = t ^ p ^ c ^ (i as u8).wrapping_mul(31) ^ 0xA7;
    }
    for round in 0..5u8 {
        let mut h: u64 = 0xcbf29ce484222325;
        for b in &out {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x100000001b3);
        }
        h ^= u64::from(round) << 17;
        h ^= COUNTER.load(Ordering::SeqCst).wrapping_mul(0x9e3779b97f4a7c15);
        for (i, b) in out.iter_mut().enumerate() {
            *b ^= ((h >> ((i % 8) * 8)) as u8).wrapping_add(round.wrapping_mul(13));
        }
    }
    out
}

fn campo_json<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let after = &raw[i + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if rest.starts_with('"') {
        let end = rest[1..].find('"')?;
        Some(&rest[1..1 + end])
    } else if rest.starts_with("true") {
        Some("true")
    } else if rest.starts_with("false") {
        Some("false")
    } else {
        None
    }
}

fn parse_respuesta_ok(line: &str) -> Option<RespuestaModelo> {
    if campo_json(line, "ok") != Some("true") {
        return None;
    }
    let dr = hex_decode(campo_json(line, "digest_resultado")?)?;
    let dp = hex_decode(campo_json(line, "digest_parametros_ejecutados")?)?;
    if dr.len() != LONGITUD_HASH_PAQUETE || dp.len() != LONGITUD_HASH_PAQUETE {
        return None;
    }
    let mut digest_resultado = [0u8; LONGITUD_HASH_PAQUETE];
    let mut digest_parametros_ejecutados = [0u8; LONGITUD_HASH_PAQUETE];
    digest_resultado.copy_from_slice(&dr);
    digest_parametros_ejecutados.copy_from_slice(&dp);
    let referencia_minima = campo_json(line, "ref")
        .unwrap_or("ref:lb")
        .to_string();
    Some(RespuestaModelo {
        digest_resultado,
        referencia_minima,
        digest_parametros_ejecutados,
    })
}

/// Ticket v2: HMAC(clave, "SAK-EF1-TICKET-v2|" ‖ digest ‖ nonce ‖ cap_id ‖ epoca ‖ vive_hasta ‖ ahora).
pub fn emitir_ticket_bytes(
    clave: &[u8; 32],
    ctx: &ContextoEjercicioEf1,
    nonce: &[u8; 32],
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let cred = CredencialProveedor::desde_semilla(*clave);
    emitir_ticket_v2(&cred, ctx, nonce)
}

fn emitir_ticket_v2(
    cred: &CredencialProveedor,
    ctx: &ContextoEjercicioEf1,
    nonce: &[u8; 32],
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut msg = Vec::with_capacity(TICKET_DOM.len() + LONGITUD_HASH_PAQUETE * 2 + 32 + 24);
    msg.extend_from_slice(TICKET_DOM);
    msg.extend_from_slice(&ctx.digest);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(&ctx.cap_id);
    msg.extend_from_slice(&ctx.epoca.to_le_bytes());
    msg.extend_from_slice(&ctx.vive_hasta.to_le_bytes());
    msg.extend_from_slice(&ctx.ahora.to_le_bytes());
    cred.firmar_llamada(&msg)
}

pub fn verificar_ticket_v2(
    clave: &[u8; 32],
    ticket: &[u8],
    ctx: &ContextoEjercicioEf1,
    nonce: &[u8; 32],
) -> bool {
    if ticket.len() != LONGITUD_HASH_PAQUETE {
        return false;
    }
    let esperada = emitir_ticket_bytes(clave, ctx, nonce);
    ticket == esperada.as_slice()
}

/// HMAC(clave, canon ‖ digest ‖ nonce).
pub fn verificar_sello_con_nonce(
    clave: &[u8; 32],
    sello: &[u8],
    canon: &[u8],
    digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    nonce: &[u8; 32],
) -> bool {
    if sello.len() != LONGITUD_HASH_PAQUETE {
        return false;
    }
    let cred = CredencialProveedor::desde_semilla(*clave);
    let mut msg = Vec::with_capacity(canon.len() + LONGITUD_HASH_PAQUETE + 32);
    msg.extend_from_slice(canon);
    msg.extend_from_slice(digest_autorizado);
    msg.extend_from_slice(nonce);
    let esperada = cred.firmar_llamada(&msg);
    sello == esperada.as_slice()
}

/// Sello del protocolo antiguo (sin nonce) — solo para pruebas adversarias.
pub fn sello_protocolo_antiguo(
    clave: &[u8; 32],
    canon: &[u8],
    digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let cred = CredencialProveedor::desde_semilla(*clave);
    let mut msg = Vec::with_capacity(canon.len() + LONGITUD_HASH_PAQUETE);
    msg.extend_from_slice(canon);
    msg.extend_from_slice(digest_autorizado);
    cred.firmar_llamada(&msg)
}

/// Construye petición firmada con ticket v2 (harness/tests).
pub fn construir_peticion_con_nonce(
    clave: &[u8; 32],
    canon: &[u8],
    ctx: &ContextoEjercicioEf1,
    nonce: &[u8; 32],
) -> String {
    let cred = CredencialProveedor::desde_semilla(*clave);
    let mut msg = Vec::with_capacity(canon.len() + LONGITUD_HASH_PAQUETE + 32);
    msg.extend_from_slice(canon);
    msg.extend_from_slice(&ctx.digest);
    msg.extend_from_slice(nonce);
    let sello = cred.firmar_llamada(&msg);
    let ticket = emitir_ticket_v2(&cred, ctx, nonce);
    format!(
        "{{\"v\":\"{PROTO}\",\"sello\":\"{}\",\"digest\":\"{}\",\"canon\":\"{}\",\"nonce\":\"{}\",\"ticket\":\"{}\",\"cap_id\":\"{}\",\"epoca\":{},\"vive_hasta\":{},\"ahora\":{}}}\n",
        hex(&sello),
        hex(&ctx.digest),
        hex(canon),
        hex(nonce),
        hex(&ticket),
        hex(&ctx.cap_id),
        ctx.epoca,
        ctx.vive_hasta,
        ctx.ahora,
    )
}

fn campo_u64_json(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let after = &raw[i + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

pub fn atender_peticion_mock(
    clave: &[u8; 32],
    line: &str,
    vistos: &mut HashSet<[u8; 32]>,
) -> String {
    let sello_h = campo_json(line, "sello").unwrap_or("");
    let digest_h = campo_json(line, "digest").unwrap_or("");
    let canon_h = campo_json(line, "canon").unwrap_or("");
    let nonce_h = campo_json(line, "nonce").unwrap_or("");
    let ticket_h = campo_json(line, "ticket").unwrap_or("");
    let cap_h = campo_json(line, "cap_id").unwrap_or("");
    if sello_h.is_empty() {
        return "{\"ok\":false,\"codigo\":\"NO_SELLO\"}\n".into();
    }
    if nonce_h.is_empty() {
        return "{\"ok\":false,\"codigo\":\"NO_NONCE\"}\n".into();
    }
    if ticket_h.is_empty() {
        return "{\"ok\":false,\"codigo\":\"NO_TICKET\"}\n".into();
    }
    if cap_h.is_empty() {
        return "{\"ok\":false,\"codigo\":\"NO_CAP_ID\"}\n".into();
    }
    let Some(epoca) = campo_u64_json(line, "epoca") else {
        return "{\"ok\":false,\"codigo\":\"NO_EPOCA\"}\n".into();
    };
    let Some(vive_hasta) = campo_u64_json(line, "vive_hasta") else {
        return "{\"ok\":false,\"codigo\":\"NO_VIVE_HASTA\"}\n".into();
    };
    let Some(ahora) = campo_u64_json(line, "ahora") else {
        return "{\"ok\":false,\"codigo\":\"NO_AHORA\"}\n".into();
    };
    let sello = match hex_decode(sello_h) {
        Some(s) => s,
        None => return "{\"ok\":false,\"codigo\":\"SELLO_INVALIDO\"}\n".into(),
    };
    let digest_v = match hex_decode(digest_h) {
        Some(d) if d.len() == LONGITUD_HASH_PAQUETE => d,
        _ => return "{\"ok\":false,\"codigo\":\"DIGEST_INVALIDO\"}\n".into(),
    };
    let canon = match hex_decode(canon_h) {
        Some(c) if !c.is_empty() => c,
        _ => return "{\"ok\":false,\"codigo\":\"CANON_INVALIDO\"}\n".into(),
    };
    let nonce_v = match hex_decode(nonce_h) {
        Some(n) if n.len() == 32 => n,
        _ => return "{\"ok\":false,\"codigo\":\"NONCE_INVALIDO\"}\n".into(),
    };
    let ticket_v = match hex_decode(ticket_h) {
        Some(t) if t.len() == LONGITUD_HASH_PAQUETE => t,
        _ => return "{\"ok\":false,\"codigo\":\"TICKET_INVALIDO\"}\n".into(),
    };
    let cap_v = match hex_decode(cap_h) {
        Some(c) if c.len() == LONGITUD_HASH_PAQUETE => c,
        _ => return "{\"ok\":false,\"codigo\":\"CAP_ID_INVALIDO\"}\n".into(),
    };
    let mut digest = [0u8; LONGITUD_HASH_PAQUETE];
    digest.copy_from_slice(&digest_v);
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&nonce_v);
    let mut cap_id = [0u8; LONGITUD_HASH_PAQUETE];
    cap_id.copy_from_slice(&cap_v);
    let ctx = ContextoEjercicioEf1 {
        cap_id,
        digest,
        epoca,
        vive_hasta,
        ahora,
    };
    if !verificar_sello_con_nonce(clave, &sello, &canon, &digest, &nonce) {
        return "{\"ok\":false,\"codigo\":\"SELLO_INVALIDO\"}\n".into();
    }
    if !verificar_ticket_v2(clave, &ticket_v, &ctx, &nonce) {
        return "{\"ok\":false,\"codigo\":\"TICKET_INVALIDO\"}\n".into();
    }
    if ahora > vive_hasta {
        return "{\"ok\":false,\"codigo\":\"TICKET_EXPIRADO\"}\n".into();
    }
    if !vistos.insert(nonce) {
        return "{\"ok\":false,\"codigo\":\"REPLAY\"}\n".into();
    }
    let mut ref_msg = Vec::new();
    ref_msg.extend_from_slice(b"ok-lb|");
    ref_msg.extend_from_slice(&sello);
    let digest_resultado = crypto::sha384_dominio(b"SAK-MODEL-OUT-v1|", &ref_msg);
    format!(
        "{{\"ok\":true,\"digest_resultado\":\"{}\",\"digest_parametros_ejecutados\":\"{}\",\"ref\":\"ref:{}\"}}\n",
        hex(&digest_resultado),
        hex(&digest),
        &hex(&digest_resultado)[..16],
    )
}

/// Mock TCP loopback en hilo (tests). Clave inyectada; nonces one-shot; solo 127.0.0.1.
pub struct MockEf1Loopback {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl MockEf1Loopback {
    pub fn arrancar(clave: [u8; 32]) -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        if !addr.ip().is_loopback() {
            return Err("mock exige loopback".into());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_t = Arc::clone(&stop);
        let vistos: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
        let vistos_t = Arc::clone(&vistos);
        listener
            .set_nonblocking(true)
            .map_err(|e| e.to_string())?;
        let join = thread::spawn(move || {
            while !stop_t.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let mut reader = BufReader::new(&stream);
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_ok() {
                            let resp = {
                                let mut g = vistos_t.lock().expect("vistos");
                                atender_peticion_mock(&clave, &line, &mut g)
                            };
                            let _ = (&stream).write_all(resp.as_bytes());
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(MockEf1Loopback {
            addr,
            stop,
            join: Some(join),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn detener(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for MockEf1Loopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

pub fn llamada_directa_sin_sello(addr: SocketAddr) -> Result<String, String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    stream
        .write_all(b"{\"v\":\"SAK-EF1-LB-1\",\"sello\":\"\",\"digest\":\"\",\"canon\":\"\"}\n")
        .map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|e| e.to_string())?;
    Ok(line)
}

pub fn enviar_linea_mock(addr: SocketAddr, line: &str) -> Result<String, String> {
    let mut stream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    stream
        .write_all(line.as_bytes())
        .map_err(|e| e.to_string())?;
    if !line.ends_with('\n') {
        stream.write_all(b"\n").map_err(|e| e.to_string())?;
    }
    let mut reader = BufReader::new(stream);
    let mut out = String::new();
    reader.read_line(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}
