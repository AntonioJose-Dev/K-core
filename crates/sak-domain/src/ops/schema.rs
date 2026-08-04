//! Esquema IPC operador — familias Conectar / Custodiar / Gobernar (andamiaje Fase 0).

pub const SCHEMA_V: u32 = 1;

/// MVP-CONECTAR (§9.2) + listar C1.
pub const OPS_MVP_CONECTAR: &[&str] = &[
    "con.sistema.alta",
    "con.pasaporte.emitir",
    "con.pasaporte.get",
    "con.sistemas.listar",
    "con.pep.configurar",
    "con.pep.vista",
    "con.inventario.alcanzables",
];

/// MVP-CUSTODIAR (§9.3) + rotación Fase 5.1.
pub const OPS_MVP_CUSTODIAR: &[&str] = &["cus.alta_referencia", "cus.estado", "cus.rotar"];

/// MVP-GOBERNAR completo G.5 ops (Fase 5.4 incluye revocar/revertir).
pub const OPS_MVP_GOBERNAR: &[&str] = &[
    "gob.proponer",
    "gob.revision_juridica",
    "gob.diff_conformidad",
    "gob.reconocer_diff",
    "gob.doble_firma",
    "gob.entrar_sombra",
    "gob.estado_sombra",
    "gob.activar_epoca",
    "gob.revocar",
    "gob.revertir",
];

/// DENY fijo de esquema (IPC §5 / §6) — nunca allowlist.
pub const OPS_DENY_FIJO: &[&str] = &[
    "libro.elevar",
    "cap.emitir",
    "cus.reveal",
    "cus.export_raiz",
    // cus.rotar: allowlist Fase 5.1 (IRREVERSIBLE)
    "conceder_ef12",
    "net.bind_public",
    "telemetry.any",
    // gob.activar_epoca / revocar / revertir: allowlist Fase 5.3–5.4
    // obs.diagnostico.*: espejo Bloque B (B4) — misma cadena sujeto; UI no emite
];

pub fn es_op_mvp_fase0(op: &str) -> bool {
    OPS_MVP_CONECTAR.contains(&op)
        || OPS_MVP_CUSTODIAR.contains(&op)
        || OPS_MVP_GOBERNAR.contains(&op)
}

pub fn es_deny_fijo_ops(op: &str) -> bool {
    if OPS_DENY_FIJO.contains(&op) {
        return true;
    }
    if op.starts_with("telemetry.") {
        return true;
    }
    if op.starts_with("cap.") {
        return true;
    }
    if op == "libro.elevar" {
        return true;
    }
    // Completo no-MVP: revelar/export/cap/telemetry en DENY_FIJO.
    false
}

pub fn familia_de(op: &str) -> Option<&'static str> {
    if op.starts_with("con.") {
        Some("Conectar")
    } else if op.starts_with("cus.") {
        Some("Custodiar")
    } else if op.starts_with("gob.") {
        Some("Gobernar")
    } else if op.starts_with("sup.") {
        Some("Supervision")
    } else if op.starts_with("obs.") {
        Some("Observar")
    } else {
        None
    }
}

/// Extrae `op` de un JSON mínimo sin parser completo.
pub fn parsear_op(raw: &str) -> Result<(String, String, u32), String> {
    let op = campo_str_raw(raw, "op").ok_or_else(|| "falta op".to_string())?;
    let req_id = campo_str_raw(raw, "req_id").unwrap_or_else(|| "sin-id".into());
    let schema_v = campo_u32_raw(raw, "schema_v").unwrap_or(0);
    Ok((op, req_id, schema_v))
}

pub fn campo_str_raw(raw: &str, clave: &str) -> Option<String> {
    let pat = format!("\"{clave}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let colon = rest.find(':')?;
    let mut s = rest[colon + 1..].trim_start();
    if !s.starts_with('"') {
        return None;
    }
    s = &s[1..];
    let end = s.find('"')?;
    Some(s[..end].to_string())
}

pub fn campo_u32_raw(raw: &str, clave: &str) -> Option<u32> {
    let pat = format!("\"{clave}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let colon = rest.find(':')?;
    let s = rest[colon + 1..].trim_start();
    let num: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    num.parse().ok()
}

pub fn campo_bool_raw(raw: &str, clave: &str) -> Option<bool> {
    let pat = format!("\"{clave}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let colon = rest.find(':')?;
    let s = rest[colon + 1..].trim_start();
    if s.starts_with("true") {
        Some(true)
    } else if s.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn campo_str(raw: &str, clave: &str) -> Option<String> {
    campo_str_raw(raw, clave)
}

fn campo_u32(raw: &str, clave: &str) -> Option<u32> {
    campo_u32_raw(raw, clave)
}

#[derive(Debug, Clone)]
pub struct RespuestaOps {
    pub req_id: String,
    pub resultado: &'static str,
    pub codigo: String,
    pub cuerpo: String,
    pub limites: Vec<&'static str>,
}

impl RespuestaOps {
    pub fn deny(req_id: &str, codigo: &str, detalle: &str) -> Self {
        Self {
            req_id: req_id.into(),
            resultado: "DENY",
            codigo: codigo.into(),
            cuerpo: format!(r#"{{"detalle":{}}}"#, json_str(detalle)),
            limites: vec![],
        }
    }

    pub fn ok(req_id: &str, codigo: &str, cuerpo_json: &str, limites: Vec<&'static str>) -> Self {
        Self {
            req_id: req_id.into(),
            resultado: "OK",
            codigo: codigo.into(),
            cuerpo: cuerpo_json.to_string(),
            limites,
        }
    }

    pub fn a_json(&self) -> String {
        let lim: Vec<String> = self.limites.iter().map(|l| format!("\"{l}\"")).collect();
        format!(
            r#"{{"req_id":{},"resultado":{},"codigo":{},"digest_respuesta":"00","limites":[{}],"cuerpo":{}}}"#,
            json_str(&self.req_id),
            json_str(self.resultado),
            json_str(&self.codigo),
            lim.join(","),
            self.cuerpo
        )
    }
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}
