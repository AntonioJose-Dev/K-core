//! Solicitud tipada EF-2: acceso y tratamiento de datos (H.1).

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::collections::BTreeSet;
use std::fmt;

/// Operaciones tipadas de EF-2 (Matriz C).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperacionDatos {
    Consulta,
    LecturaDocumental,
    RecuperacionRag,
    AccesoExpediente,
    Transformacion,
}

impl OperacionDatos {
    pub fn token(self) -> &'static str {
        match self {
            OperacionDatos::Consulta => "consulta",
            OperacionDatos::LecturaDocumental => "lectura_documental",
            OperacionDatos::RecuperacionRag => "recuperacion_rag",
            OperacionDatos::AccesoExpediente => "acceso_expediente",
            OperacionDatos::Transformacion => "transformacion",
        }
    }
}

impl fmt::Display for OperacionDatos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Solicitud tipada de datos. Sin lenguaje natural ni intención libre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudDatos {
    pub operacion: OperacionDatos,
    pub recurso: String,
    pub digest_filtro: [u8; LONGITUD_HASH_PAQUETE],
    pub campos: BTreeSet<String>,
    pub destinatario: String,
    pub limite_volumen: u32,
}

impl SolicitudDatos {
    pub fn nueva(
        operacion: OperacionDatos,
        recurso: impl Into<String>,
        digest_filtro: [u8; LONGITUD_HASH_PAQUETE],
        campos: impl IntoIterator<Item = impl Into<String>>,
        destinatario: impl Into<String>,
        limite_volumen: u32,
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
        if limite_volumen == 0 {
            return Err("volumen cero");
        }
        Ok(SolicitudDatos {
            operacion,
            recurso,
            digest_filtro,
            campos,
            destinatario,
            limite_volumen,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef2
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-2|");
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        v.extend_from_slice(&(self.recurso.len() as u32).to_le_bytes());
        v.extend_from_slice(self.recurso.as_bytes());
        v.extend_from_slice(&self.digest_filtro);
        for c in &self.campos {
            v.extend_from_slice(&(c.len() as u16).to_le_bytes());
            v.extend_from_slice(c.as_bytes());
        }
        v.push(0xff);
        v.extend_from_slice(&(self.destinatario.len() as u32).to_le_bytes());
        v.extend_from_slice(self.destinatario.as_bytes());
        v.extend_from_slice(&self.limite_volumen.to_le_bytes());
        v
    }
}

/// Entrada al gateway de datos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudDatosCruda {
    Tipada(SolicitudDatos),
    NoTipificable,
    ClaseNoSoportada(ClaseEfecto),
}

/// Condiciones de minimización aplicadas (H.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesMinimizacion {
    pub recurso: String,
    pub operacion: OperacionDatos,
    pub campos: BTreeSet<String>,
    pub limite_volumen: u32,
    pub destinatario: String,
}

impl CondicionesMinimizacion {
    pub fn desde_solicitud(s: &SolicitudDatos) -> Self {
        CondicionesMinimizacion {
            recurso: s.recurso.clone(),
            operacion: s.operacion,
            campos: s.campos.clone(),
            limite_volumen: s.limite_volumen,
            destinatario: s.destinatario.clone(),
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-2-MIN|");
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        v.extend_from_slice(self.recurso.as_bytes());
        v.push(0);
        for c in &self.campos {
            v.extend_from_slice(c.as_bytes());
            v.push(b',');
        }
        v.extend_from_slice(&self.limite_volumen.to_le_bytes());
        v.extend_from_slice(self.destinatario.as_bytes());
        v
    }
}

pub fn digest_solicitud_datos(s: &SolicitudDatos) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-2", &s.canonico())
}

pub fn digest_condiciones_min(c: &CondicionesMinimizacion) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-DATA-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Alcance mínimo ligado a la solicitud autorizada (sin ampliación).
pub fn alcance_ef2(s: &SolicitudDatos) -> Alcance {
    let mut tokens = vec![
        "EF-2".to_string(),
        format!("recurso:{}", s.recurso),
        format!("op:{}", s.operacion.token()),
        format!("filtro:{}", hex48(&s.digest_filtro)),
        format!("dest:{}", s.destinatario),
        format!("vol:{}", s.limite_volumen),
    ];
    for c in &s.campos {
        tokens.push(format!("campo:{c}"));
    }
    Alcance::minimo(tokens).expect("alcance EF-2")
}

/// Autorización materializada desde tokens de alcance de la capacidad.
#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoDatos {
    pub recurso: String,
    pub operacion: String,
    pub digest_filtro: [u8; LONGITUD_HASH_PAQUETE],
    pub campos: BTreeSet<String>,
    pub destinatario: String,
    pub limite_volumen: u32,
}

impl AlcanceAutorizadoDatos {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-2") {
            return Err("falta EF-2");
        }
        let mut recurso = None;
        let mut operacion = None;
        let mut filtro_hex = None;
        let mut dest = None;
        let mut vol = None;
        let mut campos = BTreeSet::new();
        for t in a.tokens() {
            if let Some(r) = t.strip_prefix("recurso:") {
                recurso = Some(r.to_string());
            } else if let Some(o) = t.strip_prefix("op:") {
                operacion = Some(o.to_string());
            } else if let Some(f) = t.strip_prefix("filtro:") {
                filtro_hex = Some(f.to_string());
            } else if let Some(d) = t.strip_prefix("dest:") {
                dest = Some(d.to_string());
            } else if let Some(v) = t.strip_prefix("vol:") {
                vol = Some(v.parse::<u32>().map_err(|_| "vol invalido")?);
            } else if let Some(c) = t.strip_prefix("campo:") {
                campos.insert(c.to_string());
            }
        }
        let filtro_hex = filtro_hex.ok_or("falta filtro")?;
        if filtro_hex.len() != LONGITUD_HASH_PAQUETE * 2 {
            return Err("filtro hex longitud");
        }
        let mut digest_filtro = [0u8; LONGITUD_HASH_PAQUETE];
        for i in 0..LONGITUD_HASH_PAQUETE {
            digest_filtro[i] = u8::from_str_radix(&filtro_hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| "filtro hex")?;
        }
        Ok(AlcanceAutorizadoDatos {
            recurso: recurso.ok_or("falta recurso")?,
            operacion: operacion.ok_or("falta op")?,
            digest_filtro,
            campos,
            destinatario: dest.ok_or("falta dest")?,
            limite_volumen: vol.ok_or("falta vol")?,
        })
    }
}
