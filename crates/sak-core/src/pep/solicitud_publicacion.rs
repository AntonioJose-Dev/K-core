//! Solicitud tipada EF-7: publicación con audiencia externa.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use crate::pep::solicitud_comunicacion::{EtiquetaHecho, TipoHechoContacto};
use std::fmt;

/// Canales tipados de publicación.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanalPublicacion {
    Web,
    RedesSociales,
    Comunicado,
    DocumentoPublico,
    RespuestaPublica,
}

impl CanalPublicacion {
    pub fn token(self) -> &'static str {
        match self {
            CanalPublicacion::Web => "web",
            CanalPublicacion::RedesSociales => "redes",
            CanalPublicacion::Comunicado => "comunicado",
            CanalPublicacion::DocumentoPublico => "documento",
            CanalPublicacion::RespuestaPublica => "respuesta",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "web" | "publicar" => Some(CanalPublicacion::Web),
            "redes" => Some(CanalPublicacion::RedesSociales),
            "comunicado" => Some(CanalPublicacion::Comunicado),
            "documento" => Some(CanalPublicacion::DocumentoPublico),
            "respuesta" => Some(CanalPublicacion::RespuestaPublica),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperacionPublicacion {
    Crear,
    Actualizar,
    Retirar,
}

impl OperacionPublicacion {
    pub fn token(self) -> &'static str {
        match self {
            OperacionPublicacion::Crear => "crear",
            OperacionPublicacion::Actualizar => "actualizar",
            OperacionPublicacion::Retirar => "retirar",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "crear" | "publicar" => Some(OperacionPublicacion::Crear),
            "actualizar" => Some(OperacionPublicacion::Actualizar),
            "retirar" => Some(OperacionPublicacion::Retirar),
            _ => None,
        }
    }
}

/// Hecho firmado exigido para publicar (el PEP no certifica veracidad/licitud).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoPublicacionExigido {
    pub tipo: TipoHechoContacto,
    pub etiqueta: EtiquetaHecho,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
}

/// Condiciones normativas aplicadas por el gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesPublicacion {
    pub marcado_obligatorio: bool,
    pub plantilla_obligatoria: bool,
    pub audiencia_limitada: bool,
    pub retencion_dias: u32,
    pub revision_humana: bool,
}

impl CondicionesPublicacion {
    pub fn tipicas() -> Self {
        CondicionesPublicacion {
            marcado_obligatorio: true,
            plantilla_obligatoria: true,
            audiencia_limitada: true,
            retencion_dias: 90,
            revision_humana: false,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-7-COND|");
        v.push(u8::from(self.marcado_obligatorio));
        v.push(u8::from(self.plantilla_obligatoria));
        v.push(u8::from(self.audiencia_limitada));
        v.extend_from_slice(&self.retencion_dias.to_le_bytes());
        v.push(u8::from(self.revision_humana));
        v
    }
}

/// Solicitud canónica e inmutable de publicación.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudPublicacion {
    pub canal: CanalPublicacion,
    pub proveedor: String,
    pub cuenta_publicadora: String,
    /// Destino exacto: sitio, ruta, comunidad o audiencia cerrada.
    pub destino: String,
    pub operacion: OperacionPublicacion,
    pub titulo: String,
    pub digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_medios: [u8; LONGITUD_HASH_PAQUETE],
    pub idioma: String,
    pub etiquetas: String,
    pub audiencia: String,
    pub visibilidad: String,
    pub ventana_desde: u64,
    pub ventana_hasta: u64,
    pub finalidad: String,
    pub clasificacion_datos: String,
    pub reversible: bool,
    /// True si el contenido es canónico tipado (sin HTML/script activo).
    pub contenido_canonico: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub condiciones: CondicionesPublicacion,
    pub hechos_exigidos: Vec<HechoPublicacionExigido>,
    pub exige_supervision: bool,
}

impl SolicitudPublicacion {
    pub fn nueva(
        canal: CanalPublicacion,
        proveedor: impl Into<String>,
        cuenta_publicadora: impl Into<String>,
        destino: impl Into<String>,
        operacion: OperacionPublicacion,
        titulo: impl Into<String>,
        digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
        digest_medios: [u8; LONGITUD_HASH_PAQUETE],
        idioma: impl Into<String>,
        etiquetas: impl Into<String>,
        audiencia: impl Into<String>,
        visibilidad: impl Into<String>,
        ventana_desde: u64,
        ventana_hasta: u64,
        finalidad: impl Into<String>,
        clasificacion_datos: impl Into<String>,
        reversible: bool,
        contenido_canonico: bool,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        condiciones: CondicionesPublicacion,
        hechos_exigidos: Vec<HechoPublicacionExigido>,
        exige_supervision: bool,
    ) -> Result<Self, &'static str> {
        let proveedor = proveedor.into();
        let cuenta_publicadora = cuenta_publicadora.into();
        let destino = destino.into();
        let titulo = titulo.into();
        let idioma = idioma.into();
        let etiquetas = etiquetas.into();
        let audiencia = audiencia.into();
        let visibilidad = visibilidad.into();
        let finalidad = finalidad.into();
        let clasificacion_datos = clasificacion_datos.into();
        if proveedor.trim().is_empty()
            || cuenta_publicadora.trim().is_empty()
            || destino.trim().is_empty()
            || titulo.trim().is_empty()
            || audiencia.trim().is_empty()
            || visibilidad.trim().is_empty()
        {
            return Err("campo tipado vacio");
        }
        if audiencia == "*" || audiencia.eq_ignore_ascii_case("abierta") {
            return Err("audiencia abierta no representable");
        }
        if destino.contains("://redirect") || destino == "*" {
            return Err("destino alternativo o redireccion");
        }
        if !contenido_canonico {
            return Err("contenido no canonico o activo");
        }
        if idioma.len() != 2 || !idioma.bytes().all(|b| b.is_ascii_lowercase()) {
            return Err("idioma no tipificado");
        }
        if ventana_hasta < ventana_desde {
            return Err("ventana invalida");
        }
        Ok(SolicitudPublicacion {
            canal,
            proveedor,
            cuenta_publicadora,
            destino,
            operacion,
            titulo,
            digest_contenido,
            digest_medios,
            idioma,
            etiquetas,
            audiencia,
            visibilidad,
            ventana_desde,
            ventana_hasta,
            finalidad,
            clasificacion_datos,
            reversible,
            contenido_canonico,
            hash_paquete,
            epoca,
            digest_contexto,
            condiciones,
            hechos_exigidos,
            exige_supervision,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef7
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-7|");
        v.extend_from_slice(self.canal.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.proveedor);
        escribir(&mut v, &self.cuenta_publicadora);
        escribir(&mut v, &self.destino);
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.titulo);
        v.extend_from_slice(&self.digest_contenido);
        v.extend_from_slice(&self.digest_medios);
        escribir(&mut v, &self.idioma);
        escribir(&mut v, &self.etiquetas);
        escribir(&mut v, &self.audiencia);
        escribir(&mut v, &self.visibilidad);
        v.extend_from_slice(&self.ventana_desde.to_le_bytes());
        v.extend_from_slice(&self.ventana_hasta.to_le_bytes());
        escribir(&mut v, &self.finalidad);
        escribir(&mut v, &self.clasificacion_datos);
        v.push(u8::from(self.reversible));
        v.push(u8::from(self.contenido_canonico));
        v.extend_from_slice(&self.hash_paquete);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.digest_contexto);
        v.extend_from_slice(&self.condiciones.canonico());
        v.push(u8::from(self.exige_supervision));
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
pub enum SolicitudPublicacionCruda {
    Tipada(SolicitudPublicacion),
    NoTipificable,
    Malformada(&'static str),
    ContenidoActivo,
    ClaseNoSoportada(ClaseEfecto),
}

pub fn digest_solicitud_publicacion(s: &SolicitudPublicacion) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-7", &s.canonico())
}

pub fn digest_condiciones_publicacion(c: &CondicionesPublicacion) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-PUB-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef7(s: &SolicitudPublicacion) -> Alcance {
    let mut tokens = vec![
        "EF-7".to_string(),
        format!("canal:{}", s.canal.token()),
        format!("prov:{}", s.proveedor),
        format!("cuenta:{}", s.cuenta_publicadora),
        format!("dest:{}", s.destino),
        format!("op:{}", s.operacion.token()),
        format!("tit:{}", s.titulo),
        format!("body:{}", hex48(&s.digest_contenido)),
        format!("media:{}", hex48(&s.digest_medios)),
        format!("lang:{}", s.idioma),
        format!("tag:{}", s.etiquetas),
        format!("aud:{}", s.audiencia),
        format!("vis:{}", s.visibilidad),
        format!("vd:{}", s.ventana_desde),
        format!("vh:{}", s.ventana_hasta),
        format!("fin:{}", s.finalidad),
        format!("cls:{}", s.clasificacion_datos),
        format!("rev:{}", u8::from(s.reversible)),
        format!("can:{}", u8::from(s.contenido_canonico)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("ep:{}", s.epoca),
        format!("ctx:{}", hex48(&s.digest_contexto)),
        format!("cond:{}", hex48(&digest_condiciones_publicacion(&s.condiciones))),
        format!("sup:{}", u8::from(s.exige_supervision)),
    ];
    for h in &s.hechos_exigidos {
        tokens.push(format!(
            "hecho:{}:{}:{}",
            h.tipo.token(),
            h.etiqueta.token(),
            hex48(&h.digest)
        ));
    }
    Alcance::minimo(tokens).expect("alcance EF-7")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoPublicacion {
    pub canal: String,
    pub proveedor: String,
    pub cuenta_publicadora: String,
    pub destino: String,
    pub operacion: String,
    pub digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_medios: [u8; LONGITUD_HASH_PAQUETE],
    pub idioma: String,
    pub etiquetas: String,
    pub audiencia: String,
    pub visibilidad: String,
    pub ventana_desde: u64,
    pub ventana_hasta: u64,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoPublicacion {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-7") {
            return Err("falta EF-7");
        }
        let mut canal = None;
        let mut prov = None;
        let mut cuenta = None;
        let mut dest = None;
        let mut op = None;
        let mut body = None;
        let mut media = None;
        let mut lang = None;
        let mut tag = None;
        let mut aud = None;
        let mut vis = None;
        let mut vd = None;
        let mut vh = None;
        let mut pkg = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("canal:") {
                canal = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("prov:") {
                prov = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("cuenta:") {
                cuenta = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("dest:") {
                dest = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("op:") {
                op = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("body:") {
                body = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("media:") {
                media = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("lang:") {
                lang = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("tag:") {
                tag = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("aud:") {
                aud = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("vis:") {
                vis = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("vd:") {
                vd = Some(x.parse().map_err(|_| "vd")?);
            } else if let Some(x) = t.strip_prefix("vh:") {
                vh = Some(x.parse().map_err(|_| "vh")?);
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            }
        }
        Ok(AlcanceAutorizadoPublicacion {
            canal: canal.ok_or("falta canal")?,
            proveedor: prov.ok_or("falta prov")?,
            cuenta_publicadora: cuenta.ok_or("falta cuenta")?,
            destino: dest.ok_or("falta dest")?,
            operacion: op.ok_or("falta op")?,
            digest_contenido: body.ok_or("falta body")?,
            digest_medios: media.ok_or("falta media")?,
            idioma: lang.ok_or("falta lang")?,
            etiquetas: tag.ok_or("falta tag")?,
            audiencia: aud.ok_or("falta aud")?,
            visibilidad: vis.ok_or("falta vis")?,
            ventana_desde: vd.ok_or("falta vd")?,
            ventana_hasta: vh.ok_or("falta vh")?,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf7 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    pub libro_c4: bool,
    pub monitor_permisivo: bool,
    pub hechos_ok: bool,
    pub supervision_ok: bool,
    /// Audiencia/destino fuera del dominio declarado.
    pub cruza_dominio: bool,
    pub egreso_ef10_autorizado: bool,
    /// Presentar/publicar una orden física no sustituye EF-11.
    pub presenta_orden_fisica: bool,
}

impl PrecondicionesPepEf7 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf7 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c4: true,
            monitor_permisivo: true,
            hechos_ok: true,
            supervision_ok: true,
            cruza_dominio: false,
            egreso_ef10_autorizado: false,
            presenta_orden_fisica: false,
        }
    }
}

impl fmt::Display for CanalPublicacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Traduce herramienta EF-4 tipada a solicitud EF-7 (sin publicar).
pub fn traducir_publicacion_desde_herramienta(
    id_herramienta: &str,
    servidor: &str,
    operacion: &str,
    destino: &str,
    digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    datos_personales: bool,
    reversible: bool,
) -> Result<SolicitudPublicacion, &'static str> {
    let canal = CanalPublicacion::desde_token(operacion)
        .or_else(|| {
            if operacion == "publicar" {
                Some(CanalPublicacion::Web)
            } else {
                None
            }
        })
        .ok_or("canal publicacion desconocido")?;
    let op = OperacionPublicacion::Crear;
    let hecho = HechoPublicacionExigido {
        tipo: TipoHechoContacto::AprobacionHumana,
        etiqueta: EtiquetaHecho::Gob,
        digest: digest_argumentos,
    };
    SolicitudPublicacion::nueva(
        canal,
        servidor,
        format!("acct:{id_herramienta}"),
        destino,
        op,
        "titulo-canonico",
        digest_argumentos,
        [0u8; LONGITUD_HASH_PAQUETE],
        "es",
        "tag:pub",
        "audiencia-cerrada",
        "restringida",
        0,
        u64::MAX,
        "informacion",
        if datos_personales { "personal" } else { "general" },
        reversible,
        true,
        hash_paquete,
        1,
        digest_argumentos,
        CondicionesPublicacion::tipicas(),
        vec![hecho],
        false,
    )
}
