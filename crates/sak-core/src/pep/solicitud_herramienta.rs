//! Solicitud tipada EF-4: invocación de herramienta / MCP / API / webhook.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::fmt;

/// Solicitud canónica de invocación. Sin argumentos libres no tipificables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudHerramienta {
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub operacion: String,
    pub digest_esquema_args: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    pub destino: String,
    pub efecto_subyacente: ClaseEfecto,
    pub reversible: bool,
    pub datos_personales: bool,
    pub cuota: u32,
    pub timeout_ms: u64,
    pub digest_condiciones: [u8; LONGITUD_HASH_PAQUETE],
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl SolicitudHerramienta {
    pub fn nueva(
        id_herramienta: impl Into<String>,
        version: impl Into<String>,
        servidor: impl Into<String>,
        operacion: impl Into<String>,
        digest_esquema_args: [u8; LONGITUD_HASH_PAQUETE],
        digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
        destino: impl Into<String>,
        efecto_subyacente: ClaseEfecto,
        reversible: bool,
        datos_personales: bool,
        cuota: u32,
        timeout_ms: u64,
        digest_condiciones: [u8; LONGITUD_HASH_PAQUETE],
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, &'static str> {
        let id_herramienta = id_herramienta.into();
        let version = version.into();
        let servidor = servidor.into();
        let operacion = operacion.into();
        let destino = destino.into();
        if id_herramienta.trim().is_empty()
            || version.trim().is_empty()
            || servidor.trim().is_empty()
            || operacion.trim().is_empty()
        {
            return Err("campo tipado vacio");
        }
        if cuota == 0 || timeout_ms == 0 {
            return Err("cuota o timeout cero");
        }
        Ok(SolicitudHerramienta {
            id_herramienta,
            version,
            servidor,
            operacion,
            digest_esquema_args,
            digest_argumentos,
            destino,
            efecto_subyacente,
            reversible,
            datos_personales,
            cuota,
            timeout_ms,
            digest_condiciones,
            hash_paquete,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef4
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-4|");
        escribir(&mut v, &self.id_herramienta);
        escribir(&mut v, &self.version);
        escribir(&mut v, &self.servidor);
        escribir(&mut v, &self.operacion);
        v.extend_from_slice(&self.digest_esquema_args);
        v.extend_from_slice(&self.digest_argumentos);
        escribir(&mut v, &self.destino);
        v.push(self.efecto_subyacente as u8);
        v.push(u8::from(self.reversible));
        v.push(u8::from(self.datos_personales));
        v.extend_from_slice(&self.cuota.to_le_bytes());
        v.extend_from_slice(&self.timeout_ms.to_le_bytes());
        v.extend_from_slice(&self.digest_condiciones);
        v.extend_from_slice(&self.hash_paquete);
        v
    }
}

fn escribir(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudHerramientaCruda {
    Tipada(SolicitudHerramienta),
    NoTipificable,
    ClaseNoSoportada(ClaseEfecto),
    /// Intento de redirección a destino no tipificado / no declarado.
    Redireccion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesHerramienta {
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub operacion: String,
    pub destino: String,
    pub efecto_subyacente: ClaseEfecto,
}

impl CondicionesHerramienta {
    pub fn desde_solicitud(s: &SolicitudHerramienta) -> Self {
        CondicionesHerramienta {
            id_herramienta: s.id_herramienta.clone(),
            version: s.version.clone(),
            servidor: s.servidor.clone(),
            operacion: s.operacion.clone(),
            destino: s.destino.clone(),
            efecto_subyacente: s.efecto_subyacente,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-4-COND|");
        escribir(&mut v, &self.id_herramienta);
        escribir(&mut v, &self.version);
        escribir(&mut v, &self.servidor);
        escribir(&mut v, &self.operacion);
        escribir(&mut v, &self.destino);
        v.push(self.efecto_subyacente as u8);
        v
    }
}

pub fn digest_solicitud_herramienta(s: &SolicitudHerramienta) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-4", &s.canonico())
}

pub fn digest_condiciones_herramienta(c: &CondicionesHerramienta) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-TOOL-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef4(s: &SolicitudHerramienta) -> Alcance {
    Alcance::minimo([
        "EF-4".to_string(),
        format!("tool:{}", s.id_herramienta),
        format!("ver:{}", s.version),
        format!("srv:{}", s.servidor),
        format!("op:{}", s.operacion),
        format!("esquema:{}", hex48(&s.digest_esquema_args)),
        format!("args:{}", hex48(&s.digest_argumentos)),
        format!("dest:{}", s.destino),
        format!("sub:{}", s.efecto_subyacente.token()),
        format!("rev:{}", u8::from(s.reversible)),
        format!("dp:{}", u8::from(s.datos_personales)),
        format!("cuota:{}", s.cuota),
        format!("to:{}", s.timeout_ms),
        format!("cond:{}", hex48(&s.digest_condiciones)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
    ])
    .expect("alcance EF-4")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoHerramienta {
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub operacion: String,
    pub digest_esquema_args: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    pub destino: String,
    pub efecto_subyacente: String,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoHerramienta {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-4") {
            return Err("falta EF-4");
        }
        let mut tool = None;
        let mut ver = None;
        let mut srv = None;
        let mut op = None;
        let mut esquema = None;
        let mut args = None;
        let mut dest = None;
        let mut sub = None;
        let mut pkg = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("tool:") {
                tool = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("ver:") {
                ver = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("srv:") {
                srv = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("op:") {
                op = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("esquema:") {
                esquema = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("args:") {
                args = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("dest:") {
                dest = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("sub:") {
                sub = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            }
        }
        Ok(AlcanceAutorizadoHerramienta {
            id_herramienta: tool.ok_or("falta tool")?,
            version: ver.ok_or("falta ver")?,
            servidor: srv.ok_or("falta srv")?,
            operacion: op.ok_or("falta op")?,
            digest_esquema_args: esquema.ok_or("falta esquema")?,
            digest_argumentos: args.ok_or("falta args")?,
            destino: dest.ok_or("falta dest")?,
            efecto_subyacente: sub.ok_or("falta sub")?,
            hash_paquete: pkg.ok_or("falta pkg")?,
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

/// Precondiciones de cadena H antes de invocar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf4 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    pub libro_suficiente: bool,
    pub monitor_permisivo: bool,
}

impl PrecondicionesPepEf4 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf4 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_suficiente: true,
            monitor_permisivo: true,
        }
    }
}

impl fmt::Display for SolicitudHerramienta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}:{}:{}",
            self.id_herramienta, self.version, self.servidor, self.operacion
        )
    }
}
