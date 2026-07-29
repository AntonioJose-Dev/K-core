//! Solicitud tipada EF-8: consumo de decisión sobre personas.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use crate::pep::solicitud_comunicacion::EtiquetaHecho;
use std::fmt;

/// Clases tipadas de decisión sobre personas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseDecisionPersona {
    Puntuacion,
    Seleccion,
    Denegacion,
    Priorizacion,
    Credito,
    Empleo,
    Otra,
}

impl ClaseDecisionPersona {
    pub fn token(self) -> &'static str {
        match self {
            ClaseDecisionPersona::Puntuacion => "puntuacion",
            ClaseDecisionPersona::Seleccion => "seleccion",
            ClaseDecisionPersona::Denegacion => "denegacion",
            ClaseDecisionPersona::Priorizacion => "priorizacion",
            ClaseDecisionPersona::Credito => "credito",
            ClaseDecisionPersona::Empleo => "empleo",
            ClaseDecisionPersona::Otra => "otra",
        }
    }
}

/// Hechos firmados exigidos por el corpus (L2/L3). El gateway no certifica equidad ni legalidad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TipoHechoDecision {
    SupervisionHumana,
    Competencia,
    Independencia,
    Quorum,
    Plazo,
    DerechoRevision,
    ExplicacionNotificacion,
    EvaluacionImpacto,
    ClasificacionRiesgo,
}

impl TipoHechoDecision {
    pub fn token(self) -> &'static str {
        match self {
            TipoHechoDecision::SupervisionHumana => "supervision_humana",
            TipoHechoDecision::Competencia => "competencia",
            TipoHechoDecision::Independencia => "independencia",
            TipoHechoDecision::Quorum => "quorum",
            TipoHechoDecision::Plazo => "plazo",
            TipoHechoDecision::DerechoRevision => "derecho_revision",
            TipoHechoDecision::ExplicacionNotificacion => "explicacion_notificacion",
            TipoHechoDecision::EvaluacionImpacto => "evaluacion_impacto",
            TipoHechoDecision::ClasificacionRiesgo => "clasificacion_riesgo",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoDecisionExigido {
    pub tipo: TipoHechoDecision,
    pub etiqueta: EtiquetaHecho,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    /// Vigencia hasta (ticks). Vencido ⇒ DENY.
    pub vigente_hasta: u64,
}

/// Solicitud canónica de consumo de decisión sobre persona.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudConsumoDecisionPersona {
    /// Identificador pseudonimizado del sujeto afectado.
    pub id_sujeto_afectado: String,
    pub clase: ClaseDecisionPersona,
    pub sistema_canal: String,
    pub destinatario: String,
    pub accion_habilitada: String,
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub fuente_resultado: String,
    pub version_resultado: String,
    pub finalidad: String,
    pub categoria_impacto: String,
    pub datos_personales: bool,
    pub categorias_especiales: bool,
    pub reversible: bool,
    pub validez_desde: u64,
    pub validez_hasta: u64,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub hechos_exigidos: Vec<HechoDecisionExigido>,
}

impl SolicitudConsumoDecisionPersona {
    pub fn nueva(
        id_sujeto_afectado: impl Into<String>,
        clase: ClaseDecisionPersona,
        sistema_canal: impl Into<String>,
        destinatario: impl Into<String>,
        accion_habilitada: impl Into<String>,
        digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
        fuente_resultado: impl Into<String>,
        version_resultado: impl Into<String>,
        finalidad: impl Into<String>,
        categoria_impacto: impl Into<String>,
        datos_personales: bool,
        categorias_especiales: bool,
        reversible: bool,
        validez_desde: u64,
        validez_hasta: u64,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        hechos_exigidos: Vec<HechoDecisionExigido>,
    ) -> Result<Self, &'static str> {
        let id_sujeto_afectado = id_sujeto_afectado.into();
        let sistema_canal = sistema_canal.into();
        let destinatario = destinatario.into();
        let accion_habilitada = accion_habilitada.into();
        let fuente_resultado = fuente_resultado.into();
        let version_resultado = version_resultado.into();
        let finalidad = finalidad.into();
        let categoria_impacto = categoria_impacto.into();
        if id_sujeto_afectado.trim().is_empty() || id_sujeto_afectado == "*" {
            return Err("sujeto no identificable");
        }
        if sistema_canal.trim().is_empty()
            || destinatario.trim().is_empty()
            || accion_habilitada.trim().is_empty()
            || fuente_resultado.trim().is_empty()
            || version_resultado.trim().is_empty()
            || finalidad.trim().is_empty()
        {
            return Err("campo tipado vacio o decision ambigua");
        }
        if accion_habilitada == "*" || destinatario == "*" {
            return Err("accion o canal no declarado");
        }
        if validez_hasta < validez_desde {
            return Err("periodo de validez invalido");
        }
        Ok(SolicitudConsumoDecisionPersona {
            id_sujeto_afectado,
            clase,
            sistema_canal,
            destinatario,
            accion_habilitada,
            digest_resultado,
            fuente_resultado,
            version_resultado,
            finalidad,
            categoria_impacto,
            datos_personales,
            categorias_especiales,
            reversible,
            validez_desde,
            validez_hasta,
            hash_paquete,
            epoca,
            digest_contexto,
            hechos_exigidos,
        })
    }

    pub fn clase_efecto(&self) -> ClaseEfecto {
        ClaseEfecto::Ef8
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-8|");
        escribir(&mut v, &self.id_sujeto_afectado);
        v.extend_from_slice(self.clase.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.sistema_canal);
        escribir(&mut v, &self.destinatario);
        escribir(&mut v, &self.accion_habilitada);
        v.extend_from_slice(&self.digest_resultado);
        escribir(&mut v, &self.fuente_resultado);
        escribir(&mut v, &self.version_resultado);
        escribir(&mut v, &self.finalidad);
        escribir(&mut v, &self.categoria_impacto);
        v.push(u8::from(self.datos_personales));
        v.push(u8::from(self.categorias_especiales));
        v.push(u8::from(self.reversible));
        v.extend_from_slice(&self.validez_desde.to_le_bytes());
        v.extend_from_slice(&self.validez_hasta.to_le_bytes());
        v.extend_from_slice(&self.hash_paquete);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.digest_contexto);
        for h in &self.hechos_exigidos {
            v.extend_from_slice(h.tipo.token().as_bytes());
            v.push(0);
            v.extend_from_slice(h.etiqueta.token().as_bytes());
            v.push(0);
            v.extend_from_slice(&h.digest);
            v.extend_from_slice(&h.vigente_hasta.to_le_bytes());
        }
        v
    }
}

fn escribir(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudConsumoCruda {
    Tipada(SolicitudConsumoDecisionPersona),
    NoTipificable,
    Malformada(&'static str),
    ClaseNoSoportada(ClaseEfecto),
}

pub fn digest_solicitud_consumo(s: &SolicitudConsumoDecisionPersona) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-8", &s.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef8(s: &SolicitudConsumoDecisionPersona) -> Alcance {
    let mut tokens = vec![
        "EF-8".to_string(),
        format!("suj:{}", s.id_sujeto_afectado),
        format!("clase:{}", s.clase.token()),
        format!("canal:{}", s.sistema_canal),
        format!("dest:{}", s.destinatario),
        format!("accion:{}", s.accion_habilitada),
        format!("res:{}", hex48(&s.digest_resultado)),
        format!("fuente:{}", s.fuente_resultado),
        format!("ver:{}", s.version_resultado),
        format!("fin:{}", s.finalidad),
        format!("imp:{}", s.categoria_impacto),
        format!("dp:{}", u8::from(s.datos_personales)),
        format!("ce:{}", u8::from(s.categorias_especiales)),
        format!("rev:{}", u8::from(s.reversible)),
        format!("vd:{}", s.validez_desde),
        format!("vh:{}", s.validez_hasta),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("ep:{}", s.epoca),
        format!("ctx:{}", hex48(&s.digest_contexto)),
    ];
    for h in &s.hechos_exigidos {
        tokens.push(format!(
            "hecho:{}:{}:{}:{}",
            h.tipo.token(),
            h.etiqueta.token(),
            hex48(&h.digest),
            h.vigente_hasta
        ));
    }
    Alcance::minimo(tokens).expect("alcance EF-8")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoConsumo {
    pub id_sujeto_afectado: String,
    pub clase: String,
    pub sistema_canal: String,
    pub destinatario: String,
    pub accion_habilitada: String,
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub finalidad: String,
    pub version_resultado: String,
    pub validez_desde: u64,
    pub validez_hasta: u64,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoConsumo {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-8") {
            return Err("falta EF-8");
        }
        let mut suj = None;
        let mut clase = None;
        let mut canal = None;
        let mut dest = None;
        let mut accion = None;
        let mut res = None;
        let mut fin = None;
        let mut ver = None;
        let mut vd = None;
        let mut vh = None;
        let mut pkg = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("suj:") {
                suj = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("clase:") {
                clase = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("canal:") {
                canal = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("dest:") {
                dest = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("accion:") {
                accion = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("res:") {
                res = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("fin:") {
                fin = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("ver:") {
                ver = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("vd:") {
                vd = Some(x.parse().map_err(|_| "vd")?);
            } else if let Some(x) = t.strip_prefix("vh:") {
                vh = Some(x.parse().map_err(|_| "vh")?);
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            }
        }
        Ok(AlcanceAutorizadoConsumo {
            id_sujeto_afectado: suj.ok_or("falta suj")?,
            clase: clase.ok_or("falta clase")?,
            sistema_canal: canal.ok_or("falta canal")?,
            destinatario: dest.ok_or("falta dest")?,
            accion_habilitada: accion.ok_or("falta accion")?,
            digest_resultado: res.ok_or("falta res")?,
            finalidad: fin.ok_or("falta fin")?,
            version_resultado: ver.ok_or("falta ver")?,
            validez_desde: vd.ok_or("falta vd")?,
            validez_hasta: vh.ok_or("falta vh")?,
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

/// Campo tipado en EF-3 que declara materialización de EF-8.
pub const CAMPO_CONSECUENCIA_EF8: &str = "consecuencia_ef8";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf8 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    /// Libro de Control ≥ C3 (custodia) para EF-8.
    pub libro_c3: bool,
    pub monitor_permisivo: bool,
    pub hechos_ok: bool,
    /// False si existe vía de consumo no mediada ⇒ EXCLUSIVIDAD falsa.
    pub exclusividad_canal: bool,
}

impl PrecondicionesPepEf8 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf8 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c3: true,
            monitor_permisivo: true,
            hechos_ok: true,
            exclusividad_canal: true,
        }
    }
}

impl fmt::Display for ClaseDecisionPersona {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
