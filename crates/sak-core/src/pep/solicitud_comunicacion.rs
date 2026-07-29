//! Solicitud tipada EF-6: comunicaciones con personas.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::collections::BTreeSet;
use std::fmt;

/// Canales tipados. Sin redirecciones ni compuestos opacos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanalComunicacion {
    Correo,
    Mensajeria,
    Sms,
    Llamada,
    Notificacion,
}

impl CanalComunicacion {
    pub fn token(self) -> &'static str {
        match self {
            CanalComunicacion::Correo => "correo",
            CanalComunicacion::Mensajeria => "mensajeria",
            CanalComunicacion::Sms => "sms",
            CanalComunicacion::Llamada => "llamada",
            CanalComunicacion::Notificacion => "notificacion",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "correo" | "email" => Some(CanalComunicacion::Correo),
            "mensajeria" => Some(CanalComunicacion::Mensajeria),
            "sms" => Some(CanalComunicacion::Sms),
            "llamada" => Some(CanalComunicacion::Llamada),
            "notificacion" => Some(CanalComunicacion::Notificacion),
            _ => None,
        }
    }
}

/// Etiqueta de procedencia del hecho exigido (no decide el Kernel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtiquetaHecho {
    /// Dependiente de gobernanza humana.
    Gob,
    /// Requiere validación externa.
    ValExt,
}

impl EtiquetaHecho {
    pub fn token(self) -> &'static str {
        match self {
            EtiquetaHecho::Gob => "GOB",
            EtiquetaHecho::ValExt => "VAL-EXT",
        }
    }
}

/// Tipo de hecho de contacto exigido por el corpus (el PEP no lo certifica).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TipoHechoContacto {
    Consentimiento,
    BaseContacto,
    ExclusionSupresion,
    AprobacionHumana,
}

impl TipoHechoContacto {
    pub fn token(self) -> &'static str {
        match self {
            TipoHechoContacto::Consentimiento => "consentimiento",
            TipoHechoContacto::BaseContacto => "base_contacto",
            TipoHechoContacto::ExclusionSupresion => "exclusion_supresion",
            TipoHechoContacto::AprobacionHumana => "aprobacion_humana",
        }
    }
}

/// Hecho firmado exigido. El gateway solo comprueba presencia/digest, no licitud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoContactoExigido {
    pub tipo: TipoHechoContacto,
    pub etiqueta: EtiquetaHecho,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
}

/// Conjunto cerrado de destinatarios con digest canónico.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConjuntoDestinatarios {
    pub destinatarios: BTreeSet<String>,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub cardinalidad_maxima: u32,
}

impl ConjuntoDestinatarios {
    pub fn nuevo(
        destinatarios: impl IntoIterator<Item = impl Into<String>>,
        cardinalidad_maxima: u32,
    ) -> Result<Self, &'static str> {
        let destinatarios: BTreeSet<String> = destinatarios.into_iter().map(Into::into).collect();
        if destinatarios.is_empty() {
            return Err("conjunto destinatarios vacio");
        }
        if destinatarios.iter().any(|d| d.trim().is_empty() || d == "*") {
            return Err("destinatario ambiguo o lista abierta");
        }
        if destinatarios.len() as u32 > cardinalidad_maxima {
            return Err("cardinalidad excedida");
        }
        let mut canon = Vec::new();
        for d in &destinatarios {
            canon.extend_from_slice(&(d.len() as u32).to_le_bytes());
            canon.extend_from_slice(d.as_bytes());
        }
        let digest = crypto::sha384_dominio(b"SAK-COMM-DEST-v1|", &canon);
        Ok(ConjuntoDestinatarios {
            destinatarios,
            digest,
            cardinalidad_maxima,
        })
    }

    pub fn abierto_rechazado() -> SolicitudComunicacionCruda {
        SolicitudComunicacionCruda::Malformada("lista abierta")
    }
}

/// Condiciones normativas que el gateway aplica (no decide).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesComunicacion {
    pub plantilla_obligatoria: bool,
    pub marcado_obligatorio: bool,
    pub enlace_baja: bool,
    pub hora_desde: u8,
    pub hora_hasta: u8,
    pub frecuencia_max_periodo: u32,
    pub retencion_minima_dias: u32,
}

impl CondicionesComunicacion {
    pub fn tipicas() -> Self {
        CondicionesComunicacion {
            plantilla_obligatoria: true,
            marcado_obligatorio: true,
            enlace_baja: true,
            hora_desde: 8,
            hora_hasta: 20,
            frecuencia_max_periodo: 3,
            retencion_minima_dias: 90,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-6-COND|");
        v.push(u8::from(self.plantilla_obligatoria));
        v.push(u8::from(self.marcado_obligatorio));
        v.push(u8::from(self.enlace_baja));
        v.push(self.hora_desde);
        v.push(self.hora_hasta);
        v.extend_from_slice(&self.frecuencia_max_periodo.to_le_bytes());
        v.extend_from_slice(&self.retencion_minima_dias.to_le_bytes());
        v
    }
}

/// Solicitud canónica e inmutable de comunicación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudComunicacion {
    pub canal: CanalComunicacion,
    pub proveedor: String,
    pub identidad_remitente: String,
    pub destinatarios: ConjuntoDestinatarios,
    pub id_plantilla: String,
    pub digest_cuerpo: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_adjuntos: [u8; LONGITUD_HASH_PAQUETE],
    pub idioma: String,
    pub finalidad: String,
    pub clasificacion_datos: String,
    pub destinatario_personal: bool,
    pub destinatario_vulnerable: bool,
    pub ventana_desde_ticks: u64,
    pub ventana_hasta_ticks: u64,
    pub limite_volumen: u32,
    pub frecuencia_periodo: u32,
    pub urgencia: u8,
    pub reversible: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub condiciones: CondicionesComunicacion,
    pub hechos_exigidos: Vec<HechoContactoExigido>,
}

impl SolicitudComunicacion {
    pub fn nueva(
        canal: CanalComunicacion,
        proveedor: impl Into<String>,
        identidad_remitente: impl Into<String>,
        destinatarios: ConjuntoDestinatarios,
        id_plantilla: impl Into<String>,
        digest_cuerpo: [u8; LONGITUD_HASH_PAQUETE],
        digest_adjuntos: [u8; LONGITUD_HASH_PAQUETE],
        idioma: impl Into<String>,
        finalidad: impl Into<String>,
        clasificacion_datos: impl Into<String>,
        destinatario_personal: bool,
        destinatario_vulnerable: bool,
        ventana_desde_ticks: u64,
        ventana_hasta_ticks: u64,
        limite_volumen: u32,
        frecuencia_periodo: u32,
        urgencia: u8,
        reversible: bool,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        condiciones: CondicionesComunicacion,
        hechos_exigidos: Vec<HechoContactoExigido>,
    ) -> Result<Self, &'static str> {
        let proveedor = proveedor.into();
        let identidad_remitente = identidad_remitente.into();
        let id_plantilla = id_plantilla.into();
        let idioma = idioma.into();
        let finalidad = finalidad.into();
        let clasificacion_datos = clasificacion_datos.into();
        if proveedor.trim().is_empty()
            || identidad_remitente.trim().is_empty()
            || id_plantilla.trim().is_empty()
            || idioma.trim().is_empty()
            || finalidad.trim().is_empty()
        {
            return Err("campo tipado vacio");
        }
        if idioma.len() != 2 || !idioma.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err("idioma no tipificado");
        }
        if ventana_hasta_ticks < ventana_desde_ticks {
            return Err("ventana temporal invalida");
        }
        if limite_volumen == 0 || frecuencia_periodo == 0 {
            return Err("limites cero");
        }
        if frecuencia_periodo > condiciones.frecuencia_max_periodo {
            return Err("frecuencia excedida");
        }
        if destinatarios.destinatarios.len() as u32 > limite_volumen {
            return Err("volumen excedido");
        }
        Ok(SolicitudComunicacion {
            canal,
            proveedor,
            identidad_remitente,
            destinatarios,
            id_plantilla,
            digest_cuerpo,
            digest_adjuntos,
            idioma,
            finalidad,
            clasificacion_datos,
            destinatario_personal,
            destinatario_vulnerable,
            ventana_desde_ticks,
            ventana_hasta_ticks,
            limite_volumen,
            frecuencia_periodo,
            urgencia,
            reversible,
            hash_paquete,
            epoca,
            digest_contexto,
            condiciones,
            hechos_exigidos,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef6
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-6|");
        v.extend_from_slice(self.canal.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.proveedor);
        escribir(&mut v, &self.identidad_remitente);
        v.extend_from_slice(&self.destinatarios.digest);
        v.extend_from_slice(&self.destinatarios.cardinalidad_maxima.to_le_bytes());
        for d in &self.destinatarios.destinatarios {
            escribir(&mut v, d);
        }
        escribir(&mut v, &self.id_plantilla);
        v.extend_from_slice(&self.digest_cuerpo);
        v.extend_from_slice(&self.digest_adjuntos);
        escribir(&mut v, &self.idioma);
        escribir(&mut v, &self.finalidad);
        escribir(&mut v, &self.clasificacion_datos);
        v.push(u8::from(self.destinatario_personal));
        v.push(u8::from(self.destinatario_vulnerable));
        v.extend_from_slice(&self.ventana_desde_ticks.to_le_bytes());
        v.extend_from_slice(&self.ventana_hasta_ticks.to_le_bytes());
        v.extend_from_slice(&self.limite_volumen.to_le_bytes());
        v.extend_from_slice(&self.frecuencia_periodo.to_le_bytes());
        v.push(self.urgencia);
        v.push(u8::from(self.reversible));
        v.extend_from_slice(&self.hash_paquete);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.digest_contexto);
        v.extend_from_slice(&self.condiciones.canonico());
        for h in &self.hechos_exigidos {
            v.extend_from_slice(h.tipo.token().as_bytes());
            v.push(0);
            v.extend_from_slice(h.etiqueta.token().as_bytes());
            v.push(0);
            v.extend_from_slice(&h.digest);
        }
        v
    }
}

fn escribir(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudComunicacionCruda {
    Tipada(SolicitudComunicacion),
    NoTipificable,
    Malformada(&'static str),
    ClaseNoSoportada(ClaseEfecto),
}

pub fn digest_solicitud_comunicacion(s: &SolicitudComunicacion) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-6", &s.canonico())
}

pub fn digest_condiciones_comunicacion(c: &CondicionesComunicacion) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-COMM-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef6(s: &SolicitudComunicacion) -> Alcance {
    let mut tokens = vec![
        "EF-6".to_string(),
        format!("canal:{}", s.canal.token()),
        format!("prov:{}", s.proveedor),
        format!("from:{}", s.identidad_remitente),
        format!("dest:{}", hex48(&s.destinatarios.digest)),
        format!("card:{}", s.destinatarios.cardinalidad_maxima),
        format!("tpl:{}", s.id_plantilla),
        format!("body:{}", hex48(&s.digest_cuerpo)),
        format!("att:{}", hex48(&s.digest_adjuntos)),
        format!("lang:{}", s.idioma),
        format!("fin:{}", s.finalidad),
        format!("cls:{}", s.clasificacion_datos),
        format!("pers:{}", u8::from(s.destinatario_personal)),
        format!("vuln:{}", u8::from(s.destinatario_vulnerable)),
        format!("vd:{}", s.ventana_desde_ticks),
        format!("vh:{}", s.ventana_hasta_ticks),
        format!("vol:{}", s.limite_volumen),
        format!("freq:{}", s.frecuencia_periodo),
        format!("urg:{}", s.urgencia),
        format!("rev:{}", u8::from(s.reversible)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("ep:{}", s.epoca),
        format!("ctx:{}", hex48(&s.digest_contexto)),
        format!("cond:{}", hex48(&digest_condiciones_comunicacion(&s.condiciones))),
    ];
    for h in &s.hechos_exigidos {
        tokens.push(format!(
            "hecho:{}:{}:{}",
            h.tipo.token(),
            h.etiqueta.token(),
            hex48(&h.digest)
        ));
    }
    Alcance::minimo(tokens).expect("alcance EF-6")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoComunicacion {
    pub canal: String,
    pub proveedor: String,
    pub identidad_remitente: String,
    pub digest_destinatarios: [u8; LONGITUD_HASH_PAQUETE],
    pub id_plantilla: String,
    pub digest_cuerpo: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_adjuntos: [u8; LONGITUD_HASH_PAQUETE],
    pub idioma: String,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub ventana_desde_ticks: u64,
    pub ventana_hasta_ticks: u64,
    pub frecuencia_periodo: u32,
}

impl AlcanceAutorizadoComunicacion {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-6") {
            return Err("falta EF-6");
        }
        let mut canal = None;
        let mut prov = None;
        let mut from = None;
        let mut dest = None;
        let mut tpl = None;
        let mut body = None;
        let mut att = None;
        let mut lang = None;
        let mut pkg = None;
        let mut vd = None;
        let mut vh = None;
        let mut freq = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("canal:") {
                canal = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("prov:") {
                prov = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("from:") {
                from = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("dest:") {
                dest = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("tpl:") {
                tpl = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("body:") {
                body = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("att:") {
                att = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("lang:") {
                lang = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("vd:") {
                vd = Some(x.parse().map_err(|_| "vd")?);
            } else if let Some(x) = t.strip_prefix("vh:") {
                vh = Some(x.parse().map_err(|_| "vh")?);
            } else if let Some(x) = t.strip_prefix("freq:") {
                freq = Some(x.parse().map_err(|_| "freq")?);
            }
        }
        Ok(AlcanceAutorizadoComunicacion {
            canal: canal.ok_or("falta canal")?,
            proveedor: prov.ok_or("falta prov")?,
            identidad_remitente: from.ok_or("falta from")?,
            digest_destinatarios: dest.ok_or("falta dest")?,
            id_plantilla: tpl.ok_or("falta tpl")?,
            digest_cuerpo: body.ok_or("falta body")?,
            digest_adjuntos: att.ok_or("falta att")?,
            idioma: lang.ok_or("falta lang")?,
            hash_paquete: pkg.ok_or("falta pkg")?,
            ventana_desde_ticks: vd.ok_or("falta vd")?,
            ventana_hasta_ticks: vh.ok_or("falta vh")?,
            frecuencia_periodo: freq.ok_or("falta freq")?,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf6 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    pub libro_c4: bool,
    pub monitor_permisivo: bool,
    /// Hechos exigidos presentes (el PEP no certifica su licitud).
    pub hechos_contacto_ok: bool,
    /// Destinatario fuera del dominio declarado.
    pub cruza_dominio: bool,
    pub egreso_ef10_autorizado: bool,
    /// Presentar/comunicar una orden física no sustituye EF-11.
    pub presenta_orden_fisica: bool,
}

impl PrecondicionesPepEf6 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf6 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c4: true,
            monitor_permisivo: true,
            hechos_contacto_ok: true,
            cruza_dominio: false,
            egreso_ef10_autorizado: false,
            presenta_orden_fisica: false,
        }
    }
}

impl fmt::Display for CanalComunicacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Traduce herramienta EF-4 tipada a solicitud EF-6 (sin enviar).
pub fn traducir_comunicacion_desde_herramienta(
    id_herramienta: &str,
    servidor: &str,
    operacion: &str,
    destino: &str,
    digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    datos_personales: bool,
    reversible: bool,
) -> Result<SolicitudComunicacion, &'static str> {
    let canal = CanalComunicacion::desde_token(operacion).ok_or("canal desconocido")?;
    let dest = ConjuntoDestinatarios::nuevo([destino], 1)?;
    let hecho = HechoContactoExigido {
        tipo: TipoHechoContacto::Consentimiento,
        etiqueta: EtiquetaHecho::Gob,
        digest: digest_argumentos,
    };
    SolicitudComunicacion::nueva(
        canal,
        servidor,
        format!("from:{id_herramienta}"),
        dest,
        "tpl-default",
        digest_argumentos,
        [0u8; LONGITUD_HASH_PAQUETE],
        "es",
        "servicio",
        if datos_personales { "personal" } else { "general" },
        datos_personales,
        false,
        0,
        u64::MAX,
        10,
        1,
        1,
        reversible,
        hash_paquete,
        1,
        digest_argumentos,
        CondicionesComunicacion::tipicas(),
        vec![hecho],
    )
}
