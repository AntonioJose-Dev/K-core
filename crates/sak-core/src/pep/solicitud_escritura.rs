//! Solicitud tipada EF-3: escritura y cambio de estado (H.1 / Matriz C).

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::collections::BTreeSet;
use std::fmt;

/// Operaciones tipadas de EF-3. Sin lenguaje natural.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperacionEscritura {
    Insert,
    Update,
    Borrado,
    EscrituraFichero,
    CambioConfiguracion,
}

impl OperacionEscritura {
    pub fn token(self) -> &'static str {
        match self {
            OperacionEscritura::Insert => "insert",
            OperacionEscritura::Update => "update",
            OperacionEscritura::Borrado => "borrado",
            OperacionEscritura::EscrituraFichero => "escritura_fichero",
            OperacionEscritura::CambioConfiguracion => "cambio_configuracion",
        }
    }
}

impl fmt::Display for OperacionEscritura {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Solicitud tipada de escritura. Alcance explícito y canónico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudEscritura {
    pub operacion: OperacionEscritura,
    pub recurso: String,
    /// Digest del selector / clave / ruta.
    pub digest_selector: [u8; LONGITUD_HASH_PAQUETE],
    /// Precondición de versión para CAS; `None` si el efector no la exige.
    pub version_precondicion: Option<u64>,
    pub campos: BTreeSet<String>,
    pub digest_valores: [u8; LONGITUD_HASH_PAQUETE],
    pub limite_filas: u32,
    pub destinatario: String,
    pub reversible: bool,
    pub datos_personales: bool,
    /// Hash del paquete normativo bajo el que se autorizó (ligadura INV-03).
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl SolicitudEscritura {
    pub fn nueva(
        operacion: OperacionEscritura,
        recurso: impl Into<String>,
        digest_selector: [u8; LONGITUD_HASH_PAQUETE],
        version_precondicion: Option<u64>,
        campos: impl IntoIterator<Item = impl Into<String>>,
        digest_valores: [u8; LONGITUD_HASH_PAQUETE],
        limite_filas: u32,
        destinatario: impl Into<String>,
        reversible: bool,
        datos_personales: bool,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, &'static str> {
        let recurso = recurso.into();
        let destinatario = destinatario.into();
        let campos: BTreeSet<String> = campos.into_iter().map(Into::into).collect();
        if recurso.trim().is_empty() {
            return Err("recurso vacio");
        }
        if destinatario.trim().is_empty() {
            return Err("destinatario vacio");
        }
        if campos.is_empty() || campos.iter().any(|c| c.trim().is_empty()) {
            return Err("campos vacios");
        }
        if limite_filas == 0 {
            return Err("limite filas cero");
        }
        Ok(SolicitudEscritura {
            operacion,
            recurso,
            digest_selector,
            version_precondicion,
            campos,
            digest_valores,
            limite_filas,
            destinatario,
            reversible,
            datos_personales,
            hash_paquete,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef3
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-3|");
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        v.extend_from_slice(&(self.recurso.len() as u32).to_le_bytes());
        v.extend_from_slice(self.recurso.as_bytes());
        v.extend_from_slice(&self.digest_selector);
        match self.version_precondicion {
            None => v.push(0),
            Some(ver) => {
                v.push(1);
                v.extend_from_slice(&ver.to_le_bytes());
            }
        }
        for c in &self.campos {
            v.extend_from_slice(&(c.len() as u16).to_le_bytes());
            v.extend_from_slice(c.as_bytes());
        }
        v.push(0xff);
        v.extend_from_slice(&self.digest_valores);
        v.extend_from_slice(&self.limite_filas.to_le_bytes());
        v.extend_from_slice(&(self.destinatario.len() as u32).to_le_bytes());
        v.extend_from_slice(self.destinatario.as_bytes());
        v.push(u8::from(self.reversible));
        v.push(u8::from(self.datos_personales));
        v.extend_from_slice(&self.hash_paquete);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudEscrituraCruda {
    Tipada(SolicitudEscritura),
    NoTipificable,
    ClaseNoSoportada(ClaseEfecto),
}

/// Condiciones aplicadas al escribir (H.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesEscritura {
    pub recurso: String,
    pub operacion: OperacionEscritura,
    pub digest_selector: [u8; LONGITUD_HASH_PAQUETE],
    pub version_precondicion: Option<u64>,
    pub campos: BTreeSet<String>,
    pub digest_valores: [u8; LONGITUD_HASH_PAQUETE],
    pub limite_filas: u32,
}

impl CondicionesEscritura {
    pub fn desde_solicitud(s: &SolicitudEscritura) -> Self {
        CondicionesEscritura {
            recurso: s.recurso.clone(),
            operacion: s.operacion,
            digest_selector: s.digest_selector,
            version_precondicion: s.version_precondicion,
            campos: s.campos.clone(),
            digest_valores: s.digest_valores,
            limite_filas: s.limite_filas,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-3-COND|");
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        v.extend_from_slice(self.recurso.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.digest_selector);
        match self.version_precondicion {
            None => v.push(0),
            Some(ver) => {
                v.push(1);
                v.extend_from_slice(&ver.to_le_bytes());
            }
        }
        for c in &self.campos {
            v.extend_from_slice(c.as_bytes());
            v.push(b',');
        }
        v.extend_from_slice(&self.digest_valores);
        v.extend_from_slice(&self.limite_filas.to_le_bytes());
        v
    }
}

pub fn digest_solicitud_escritura(s: &SolicitudEscritura) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-3", &s.canonico())
}

pub fn digest_condiciones_escritura(c: &CondicionesEscritura) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-WRITE-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Alcance mínimo canónico (sin ampliación / prórroga / transferencia).
pub fn alcance_ef3(s: &SolicitudEscritura) -> Alcance {
    let mut tokens = vec![
        "EF-3".to_string(),
        format!("recurso:{}", s.recurso),
        format!("op:{}", s.operacion.token()),
        format!("sel:{}", hex48(&s.digest_selector)),
        format!("val:{}", hex48(&s.digest_valores)),
        format!("dest:{}", s.destinatario),
        format!("filas:{}", s.limite_filas),
        format!("rev:{}", u8::from(s.reversible)),
        format!("dp:{}", u8::from(s.datos_personales)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
    ];
    if let Some(ver) = s.version_precondicion {
        tokens.push(format!("ver:{ver}"));
    } else {
        tokens.push("ver:none".into());
    }
    for c in &s.campos {
        tokens.push(format!("campo:{c}"));
    }
    Alcance::minimo(tokens).expect("alcance EF-3")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoEscritura {
    pub recurso: String,
    pub operacion: String,
    pub digest_selector: [u8; LONGITUD_HASH_PAQUETE],
    pub version_precondicion: Option<u64>,
    pub campos: BTreeSet<String>,
    pub digest_valores: [u8; LONGITUD_HASH_PAQUETE],
    pub destinatario: String,
    pub limite_filas: u32,
    pub reversible: bool,
    pub datos_personales: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoEscritura {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-3") {
            return Err("falta EF-3");
        }
        let mut recurso = None;
        let mut operacion = None;
        let mut sel_hex = None;
        let mut val_hex = None;
        let mut dest = None;
        let mut filas = None;
        let mut rev = None;
        let mut dp = None;
        let mut pkg_hex = None;
        let mut ver: Option<Option<u64>> = None;
        let mut campos = BTreeSet::new();
        for t in a.tokens() {
            if let Some(r) = t.strip_prefix("recurso:") {
                recurso = Some(r.to_string());
            } else if let Some(o) = t.strip_prefix("op:") {
                operacion = Some(o.to_string());
            } else if let Some(s) = t.strip_prefix("sel:") {
                sel_hex = Some(s.to_string());
            } else if let Some(v) = t.strip_prefix("val:") {
                val_hex = Some(v.to_string());
            } else if let Some(d) = t.strip_prefix("dest:") {
                dest = Some(d.to_string());
            } else if let Some(f) = t.strip_prefix("filas:") {
                filas = Some(f.parse::<u32>().map_err(|_| "filas invalido")?);
            } else if let Some(r) = t.strip_prefix("rev:") {
                rev = Some(r == "1");
            } else if let Some(d) = t.strip_prefix("dp:") {
                dp = Some(d == "1");
            } else if let Some(p) = t.strip_prefix("pkg:") {
                pkg_hex = Some(p.to_string());
            } else if let Some(v) = t.strip_prefix("ver:") {
                ver = Some(if v == "none" {
                    None
                } else {
                    Some(v.parse::<u64>().map_err(|_| "ver invalido")?)
                });
            } else if let Some(c) = t.strip_prefix("campo:") {
                campos.insert(c.to_string());
            }
        }
        Ok(AlcanceAutorizadoEscritura {
            recurso: recurso.ok_or("falta recurso")?,
            operacion: operacion.ok_or("falta op")?,
            digest_selector: parse_hex48(&sel_hex.ok_or("falta sel")?)?,
            version_precondicion: ver.ok_or("falta ver")?,
            campos,
            digest_valores: parse_hex48(&val_hex.ok_or("falta val")?)?,
            destinatario: dest.ok_or("falta dest")?,
            limite_filas: filas.ok_or("falta filas")?,
            reversible: rev.ok_or("falta rev")?,
            datos_personales: dp.ok_or("falta dp")?,
            hash_paquete: parse_hex48(&pkg_hex.ok_or("falta pkg")?)?,
        })
    }
}

fn parse_hex48(s: &str) -> Result<[u8; LONGITUD_HASH_PAQUETE], &'static str> {
    if s.len() != LONGITUD_HASH_PAQUETE * 2 {
        return Err("hex longitud");
    }
    let mut out = [0u8; LONGITUD_HASH_PAQUETE];
    for i in 0..LONGITUD_HASH_PAQUETE {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "hex")?;
    }
    Ok(out)
}

/// Precondiciones de la cadena H antes de tocar el efector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf3 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    pub libro_suficiente: bool,
    pub monitor_permisivo: bool,
    /// Si la escritura declara `consecuencia_ef8`, exige consumo EF-8 previo autorizado.
    pub consumo_ef8_autorizado: bool,
}

impl PrecondicionesPepEf3 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf3 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_suficiente: true,
            monitor_permisivo: true,
            consumo_ef8_autorizado: false,
        }
    }
}
