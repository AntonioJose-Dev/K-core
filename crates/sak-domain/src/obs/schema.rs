//! Esquema IPC operador local (envelope + ops Observar).

pub const SCHEMA_V: u32 = 1;
pub const FAMILIA: &str = "Observar";
pub const NOTA_CANAL: &str =
    "canal operador local (obs.*) ≠ ABI sujeto de 8 símbolos (E.1); sin autoridad";

/// Operaciones de lectura permitidas (MVP-OBSERVAR + límites del contrato §5.1).
pub const OPS_LECTURA: &[&str] = &[
    "obs.estado",
    "obs.salud",
    "obs.version",
    "obs.describir_canal",
    "obs.libro.matriz",
    "obs.hechos.listar",
    "obs.decisiones.listar",
    "obs.decisiones.get",
    "obs.evidencia.exportar",
    "obs.evidencia.verificar",
    "obs.expediente.get",
    "obs.limites",
    "obs.incidentes",
];

/// DENY fijo de esquema (contrato §5.1 / §6).
pub const OPS_DENY_FIJO: &[&str] = &[
    "libro.elevar",
    "cap.emitir",
    "cus.reveal",
    "cus.export_raiz",
    "conceder_ef12",
    "net.bind_public",
    "telemetry.any",
];

/// Diagnóstico operador (Bloque B): no es lectura pura; se enruta con EstadoOps.
pub const OPS_DIAGNOSTICO: &[&str] = &["obs.diagnostico.decidir", "obs.diagnostico.ejercer"];

pub fn es_op_observar(op: &str) -> bool {
    op.starts_with("obs.") && OPS_LECTURA.contains(&op)
}

pub fn es_op_diagnostico(op: &str) -> bool {
    OPS_DIAGNOSTICO.contains(&op)
}

pub fn es_deny_fijo(op: &str) -> bool {
    if OPS_DENY_FIJO.contains(&op) {
        return true;
    }
    if op.starts_with("telemetry.") {
        return true;
    }
    if op.starts_with("gob.") || op.starts_with("cus.") || op.starts_with("con.") || op.starts_with("sup.")
    {
        return true;
    }
    if op == "libro.elevar" || op.starts_with("cap.") {
        return true;
    }
    false
}

#[derive(Debug, Clone)]
pub struct Peticion {
    pub op: String,
    pub req_id: String,
    pub schema_v: u32,
    pub operador_id: String,
    pub dominio_id: Option<String>,
    pub sistema: Option<String>,
    pub clase: Option<u8>,
    pub sujeto: Option<String>,
    pub seq: Option<u64>,
    pub id: Option<String>,
    pub expediente_id: Option<String>,
    pub confirmacion_explicita: bool,
    pub epoca_vista: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct Respuesta {
    pub req_id: String,
    pub resultado: &'static str,
    pub codigo: String,
    pub digest_respuesta: String,
    pub limites: Vec<String>,
    pub cuerpo: String,
}

impl Respuesta {
    pub fn ok(req_id: &str, codigo: &str, cuerpo: String, limites: Vec<String>) -> Self {
        let digest = hex::digest_sha384(cuerpo.as_bytes());
        Respuesta {
            req_id: req_id.to_string(),
            resultado: "OK",
            codigo: codigo.to_string(),
            digest_respuesta: digest,
            limites,
            cuerpo,
        }
    }

    pub fn deny(req_id: &str, codigo: &str, detalle: &str) -> Self {
        let cuerpo = format!(r#"{{"detalle":{}}}"#, json_str(detalle));
        let digest = hex::digest_sha384(cuerpo.as_bytes());
        Respuesta {
            req_id: req_id.to_string(),
            resultado: "DENY",
            codigo: codigo.to_string(),
            digest_respuesta: digest,
            limites: vec![],
            cuerpo,
        }
    }

    pub fn error(req_id: &str, codigo: &str, detalle: &str) -> Self {
        let cuerpo = format!(r#"{{"detalle":{}}}"#, json_str(detalle));
        let digest = hex::digest_sha384(cuerpo.as_bytes());
        Respuesta {
            req_id: req_id.to_string(),
            resultado: "ERROR",
            codigo: codigo.to_string(),
            digest_respuesta: digest,
            limites: vec![],
            cuerpo,
        }
    }

    pub fn a_json(&self) -> String {
        let lim: String = self
            .limites
            .iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            r#"{{"req_id":{},"resultado":{},"codigo":{},"digest_respuesta":{},"limites":[{}],"cuerpo":{}}}"#,
            json_str(&self.req_id),
            json_str(self.resultado),
            json_str(&self.codigo),
            json_str(&self.digest_respuesta),
            lim,
            self.cuerpo
        )
    }
}

pub fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Parser mínimo de petición JSON (campos del contrato). Sin dependencias serde.
pub fn parsear_peticion(raw: &str) -> Result<Peticion, String> {
    let op = campo_str(raw, "op").ok_or("falta op")?;
    let req_id = campo_str(raw, "req_id").unwrap_or_else(|| "sin-id".into());
    let schema_v = campo_u64(raw, "schema_v").unwrap_or(SCHEMA_V as u64) as u32;
    let operador_id = campo_str(raw, "operador_id").unwrap_or_else(|| "anon".into());
    Ok(Peticion {
        op,
        req_id,
        schema_v,
        operador_id,
        dominio_id: campo_str(raw, "dominio_id"),
        sistema: campo_str(raw, "sistema"),
        clase: campo_u64(raw, "clase").map(|v| v as u8),
        sujeto: campo_str(raw, "sujeto"),
        seq: campo_u64(raw, "seq"),
        id: campo_str(raw, "id"),
        expediente_id: campo_str(raw, "expediente_id"),
        confirmacion_explicita: campo_bool(raw, "confirmacion_explicita").unwrap_or(false),
        epoca_vista: campo_u64(raw, "epoca_vista"),
    })
}

fn campo_str(raw: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    if rest.starts_with("null") {
        return None;
    }
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let bytes = rest.as_bytes();
    let mut j = 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' if j + 1 < bytes.len() => {
                match bytes[j + 1] {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'n' => out.push('\n'),
                    c => out.push(c as char),
                }
                j += 2;
            }
            b'"' => return Some(out),
            c => {
                out.push(c as char);
                j += 1;
            }
        }
    }
    None
}

fn campo_u64(raw: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    let num: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num.parse().ok()
}

fn campo_bool(raw: &str, key: &str) -> Option<bool> {
    let pat = format!("\"{key}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let rest = rest.trim_start();
    if !rest.starts_with(':') {
        return None;
    }
    let rest = rest[1..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

pub mod hex {
    use sak_core::crypto;

    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn digest_sha384(data: &[u8]) -> String {
        encode(&crypto::sha384_dominio(crypto::dominio::REGISTRO, data))
    }

    pub fn huella_pk(pk: &[u8]) -> String {
        encode(&crypto::sha384_dominio(crypto::dominio::REGISTRO, pk))
    }
}
