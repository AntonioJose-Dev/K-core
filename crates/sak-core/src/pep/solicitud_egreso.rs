//! Solicitud tipada EF-10: egreso / movimiento de datos entre dominios.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use crate::pep::solicitud_comunicacion::{EtiquetaHecho, TipoHechoContacto};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocoloEgreso {
    Https,
    Sftp,
    Mtls,
    ColaMensajes,
    Otro,
}

impl ProtocoloEgreso {
    pub fn token(self) -> &'static str {
        match self {
            ProtocoloEgreso::Https => "https",
            ProtocoloEgreso::Sftp => "sftp",
            ProtocoloEgreso::Mtls => "mtls",
            ProtocoloEgreso::ColaMensajes => "cola",
            ProtocoloEgreso::Otro => "otro",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "https" => Some(ProtocoloEgreso::Https),
            "sftp" => Some(ProtocoloEgreso::Sftp),
            "mtls" => Some(ProtocoloEgreso::Mtls),
            "cola" => Some(ProtocoloEgreso::ColaMensajes),
            "otro" => Some(ProtocoloEgreso::Otro),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperacionEgreso {
    EnvioTercero,
    TransferenciaInternacional,
    ExportacionMasiva,
    SincronizacionTenant,
    CargaSaas,
    DescargaExterna,
}

impl OperacionEgreso {
    pub fn token(self) -> &'static str {
        match self {
            OperacionEgreso::EnvioTercero => "envio_tercero",
            OperacionEgreso::TransferenciaInternacional => "transferencia_internacional",
            OperacionEgreso::ExportacionMasiva => "exportacion_masiva",
            OperacionEgreso::SincronizacionTenant => "sincronizacion_tenant",
            OperacionEgreso::CargaSaas => "carga_saas",
            OperacionEgreso::DescargaExterna => "descarga_externa",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "envio_tercero" | "egresar" | "egress" => Some(OperacionEgreso::EnvioTercero),
            "transferencia_internacional" => Some(OperacionEgreso::TransferenciaInternacional),
            "exportacion_masiva" | "export" => Some(OperacionEgreso::ExportacionMasiva),
            "sincronizacion_tenant" | "sync" => Some(OperacionEgreso::SincronizacionTenant),
            "carga_saas" => Some(OperacionEgreso::CargaSaas),
            "descarga_externa" => Some(OperacionEgreso::DescargaExterna),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoEgresoExigido {
    pub tipo: TipoHechoContacto,
    pub etiqueta: EtiquetaHecho,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesEgreso {
    pub cifrado_obligatorio: bool,
    pub minimizacion: bool,
    pub frecuencia_max: u32,
    pub transferencias_ulteriores: bool,
}

impl CondicionesEgreso {
    pub fn tipicas() -> Self {
        CondicionesEgreso {
            cifrado_obligatorio: true,
            minimizacion: true,
            frecuencia_max: 10,
            transferencias_ulteriores: false,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-10-COND|");
        v.push(u8::from(self.cifrado_obligatorio));
        v.push(u8::from(self.minimizacion));
        v.extend_from_slice(&self.frecuencia_max.to_le_bytes());
        v.push(u8::from(self.transferencias_ulteriores));
        v
    }
}

/// Solicitud canónica e inmutable de egreso de datos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudEgresoDatos {
    pub dominio_origen: String,
    pub dominio_destino: String,
    pub proveedor: String,
    pub endpoint: String,
    /// Ruta canónica resuelta (sin redirección ni wildcard).
    pub ruta_canonica: String,
    pub jurisdiccion_destino: String,
    pub protocolo: ProtocoloEgreso,
    pub operacion: OperacionEgreso,
    pub conjunto_datos: String,
    pub clasificacion: String,
    pub digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
    pub volumen_max_bytes: u64,
    pub max_objetos: u32,
    pub destinatario_tenant: String,
    pub finalidad: String,
    pub retencion_dias: u32,
    pub reversible: bool,
    pub transferencias_ulteriores: bool,
    pub cifrado_exigido: bool,
    pub datos_personales: bool,
    pub categorias_especiales: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub condiciones: CondicionesEgreso,
    pub hechos_exigidos: Vec<HechoEgresoExigido>,
}

impl SolicitudEgresoDatos {
    #[allow(clippy::too_many_arguments)]
    pub fn nueva(
        dominio_origen: impl Into<String>,
        dominio_destino: impl Into<String>,
        proveedor: impl Into<String>,
        endpoint: impl Into<String>,
        ruta_canonica: impl Into<String>,
        jurisdiccion_destino: impl Into<String>,
        protocolo: ProtocoloEgreso,
        operacion: OperacionEgreso,
        conjunto_datos: impl Into<String>,
        clasificacion: impl Into<String>,
        digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
        volumen_max_bytes: u64,
        max_objetos: u32,
        destinatario_tenant: impl Into<String>,
        finalidad: impl Into<String>,
        retencion_dias: u32,
        reversible: bool,
        transferencias_ulteriores: bool,
        cifrado_exigido: bool,
        datos_personales: bool,
        categorias_especiales: bool,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        condiciones: CondicionesEgreso,
        hechos_exigidos: Vec<HechoEgresoExigido>,
    ) -> Result<Self, &'static str> {
        let dominio_origen = dominio_origen.into();
        let dominio_destino = dominio_destino.into();
        let proveedor = proveedor.into();
        let endpoint = endpoint.into();
        let ruta_canonica = ruta_canonica.into();
        let jurisdiccion_destino = jurisdiccion_destino.into();
        let conjunto_datos = conjunto_datos.into();
        let clasificacion = clasificacion.into();
        let destinatario_tenant = destinatario_tenant.into();
        let finalidad = finalidad.into();

        if dominio_origen.trim().is_empty()
            || dominio_destino.trim().is_empty()
            || dominio_origen == "*"
            || dominio_destino == "*"
        {
            return Err("dominio ambiguo o vacio");
        }
        if endpoint.contains('*')
            || ruta_canonica.contains('*')
            || endpoint.trim().is_empty()
            || ruta_canonica.trim().is_empty()
        {
            return Err("endpoint/ruta wildcard o vacio");
        }
        if endpoint.contains("://") && !endpoint.starts_with("https://") && protocolo == ProtocoloEgreso::Https
        {
            // tipado: endpoint canónico sin esquemas ambiguos salvo https tipado
        }
        if proveedor.trim().is_empty()
            || conjunto_datos.trim().is_empty()
            || clasificacion.trim().is_empty()
            || clasificacion == "*"
            || clasificacion == "indeterminada"
            || destinatario_tenant.trim().is_empty()
            || destinatario_tenant == "*"
            || finalidad.trim().is_empty()
        {
            return Err("campo tipado vacio, wildcard o clasificacion indeterminada");
        }
        if volumen_max_bytes == 0 || max_objetos == 0 {
            return Err("volumen u objetos cero");
        }
        if condiciones.cifrado_obligatorio && !cifrado_exigido {
            return Err("cifrado exigido por condiciones");
        }
        Ok(SolicitudEgresoDatos {
            dominio_origen,
            dominio_destino,
            proveedor,
            endpoint,
            ruta_canonica,
            jurisdiccion_destino,
            protocolo,
            operacion,
            conjunto_datos,
            clasificacion,
            digest_contenido,
            volumen_max_bytes,
            max_objetos,
            destinatario_tenant,
            finalidad,
            retencion_dias,
            reversible,
            transferencias_ulteriores,
            cifrado_exigido,
            datos_personales,
            categorias_especiales,
            hash_paquete,
            epoca,
            digest_contexto,
            condiciones,
            hechos_exigidos,
        })
    }

    pub fn clase_efecto(&self) -> ClaseEfecto {
        ClaseEfecto::Ef10
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-10|");
        escribir(&mut v, &self.dominio_origen);
        escribir(&mut v, &self.dominio_destino);
        escribir(&mut v, &self.proveedor);
        escribir(&mut v, &self.endpoint);
        escribir(&mut v, &self.ruta_canonica);
        escribir(&mut v, &self.jurisdiccion_destino);
        v.extend_from_slice(self.protocolo.token().as_bytes());
        v.push(0);
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.conjunto_datos);
        escribir(&mut v, &self.clasificacion);
        v.extend_from_slice(&self.digest_contenido);
        v.extend_from_slice(&self.volumen_max_bytes.to_le_bytes());
        v.extend_from_slice(&self.max_objetos.to_le_bytes());
        escribir(&mut v, &self.destinatario_tenant);
        escribir(&mut v, &self.finalidad);
        v.extend_from_slice(&self.retencion_dias.to_le_bytes());
        v.push(u8::from(self.reversible));
        v.push(u8::from(self.transferencias_ulteriores));
        v.push(u8::from(self.cifrado_exigido));
        v.push(u8::from(self.datos_personales));
        v.push(u8::from(self.categorias_especiales));
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
pub enum SolicitudEgresoCruda {
    Tipada(SolicitudEgresoDatos),
    NoTipificable,
    Malformada(&'static str),
    Wildcard,
    Redireccion,
    ProxyNoDeclarado,
    FormatoNoTipificable,
    ClaseNoSoportada(ClaseEfecto),
}

pub fn digest_solicitud_egreso(s: &SolicitudEgresoDatos) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-10", &s.canonico())
}

pub fn digest_condiciones_egreso(c: &CondicionesEgreso) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-10-COND", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef10(s: &SolicitudEgresoDatos) -> Alcance {
    let mut tokens = vec![
        "EF-10".to_string(),
        format!("orig:{}", s.dominio_origen),
        format!("dest:{}", s.dominio_destino),
        format!("prov:{}", s.proveedor),
        format!("ep:{}", s.endpoint),
        format!("ruta:{}", s.ruta_canonica),
        format!("jur:{}", s.jurisdiccion_destino),
        format!("proto:{}", s.protocolo.token()),
        format!("op:{}", s.operacion.token()),
        format!("set:{}", s.conjunto_datos),
        format!("cls:{}", s.clasificacion),
        format!("man:{}", hex48(&s.digest_contenido)),
        format!("vol:{}", s.volumen_max_bytes),
        format!("obj:{}", s.max_objetos),
        format!("tenant:{}", s.destinatario_tenant),
        format!("fin:{}", s.finalidad),
        format!("cif:{}", u8::from(s.cifrado_exigido)),
        format!("dp:{}", u8::from(s.datos_personales)),
        format!("ce:{}", u8::from(s.categorias_especiales)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("epc:{}", s.epoca),
    ];
    for h in &s.hechos_exigidos {
        tokens.push(format!(
            "hecho:{}:{}:{}",
            h.tipo.token(),
            h.etiqueta.token(),
            hex48(&h.digest)
        ));
    }
    Alcance::minimo(tokens).expect("alcance EF-10")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlcanceAutorizadoEgreso {
    pub dominio_origen: String,
    pub dominio_destino: String,
    pub proveedor: String,
    pub endpoint: String,
    pub ruta_canonica: String,
    pub jurisdiccion_destino: String,
    pub protocolo: String,
    pub destinatario_tenant: String,
    pub clasificacion: String,
    pub digest_contenido: [u8; LONGITUD_HASH_PAQUETE],
    pub volumen_max_bytes: u64,
    pub finalidad: String,
    pub cifrado_exigido: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoEgreso {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-10") {
            return Err("falta EF-10");
        }
        let mut orig = None;
        let mut dest = None;
        let mut prov = None;
        let mut ep = None;
        let mut ruta = None;
        let mut jur = None;
        let mut proto = None;
        let mut tenant = None;
        let mut cls = None;
        let mut man = None;
        let mut vol = None;
        let mut fin = None;
        let mut cif = None;
        let mut pkg = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("orig:") {
                orig = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("dest:") {
                dest = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("prov:") {
                prov = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("ep:") {
                ep = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("ruta:") {
                ruta = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("jur:") {
                jur = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("proto:") {
                proto = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("tenant:") {
                tenant = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("cls:") {
                cls = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("man:") {
                man = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("vol:") {
                vol = Some(x.parse().map_err(|_| "vol")?);
            } else if let Some(x) = t.strip_prefix("fin:") {
                fin = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("cif:") {
                cif = Some(x == "1");
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            }
        }
        Ok(AlcanceAutorizadoEgreso {
            dominio_origen: orig.ok_or("falta orig")?,
            dominio_destino: dest.ok_or("falta dest")?,
            proveedor: prov.ok_or("falta prov")?,
            endpoint: ep.ok_or("falta ep")?,
            ruta_canonica: ruta.ok_or("falta ruta")?,
            jurisdiccion_destino: jur.ok_or("falta jur")?,
            protocolo: proto.ok_or("falta proto")?,
            destinatario_tenant: tenant.ok_or("falta tenant")?,
            clasificacion: cls.ok_or("falta cls")?,
            digest_contenido: man.ok_or("falta man")?,
            volumen_max_bytes: vol.ok_or("falta vol")?,
            finalidad: fin.ok_or("falta fin")?,
            cifrado_exigido: cif.ok_or("falta cif")?,
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
pub struct PrecondicionesPepEf10 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    /// Libro ≥ C3 (o C4 si datos personales / especiales vía `libro_c4`).
    pub libro_c3: bool,
    pub libro_c4: bool,
    pub monitor_permisivo: bool,
    pub hechos_ok: bool,
}

impl PrecondicionesPepEf10 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf10 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c3: true,
            libro_c4: true,
            monitor_permisivo: true,
            hechos_ok: true,
        }
    }

    pub fn exige_c4(self, sol: &SolicitudEgresoDatos) -> bool {
        sol.datos_personales || sol.categorias_especiales
    }
}

/// Traduce EF-4 tipada a solicitud EF-10 (sin transferir).
pub fn traducir_egreso_desde_herramienta(
    id_herramienta: &str,
    servidor: &str,
    operacion: &str,
    destino: &str,
    digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    datos_personales: bool,
    reversible: bool,
) -> Result<SolicitudEgresoDatos, &'static str> {
    let op = OperacionEgreso::desde_token(operacion).unwrap_or(OperacionEgreso::EnvioTercero);
    let hecho = HechoEgresoExigido {
        tipo: TipoHechoContacto::AprobacionHumana,
        etiqueta: EtiquetaHecho::Gob,
        digest: digest_argumentos,
    };
    SolicitudEgresoDatos::nueva(
        "dominio-local",
        destino,
        servidor,
        format!("https://{servidor}/egreso/{id_herramienta}"),
        format!("/{id_herramienta}/out"),
        "ES",
        ProtocoloEgreso::Https,
        op,
        "conjunto-tipado",
        if datos_personales { "personal" } else { "general" },
        digest_argumentos,
        1_048_576,
        100,
        format!("tenant:{id_herramienta}"),
        "sincronizacion",
        30,
        reversible,
        false,
        true,
        datos_personales,
        false,
        hash_paquete,
        1,
        digest_argumentos,
        CondicionesEgreso::tipicas(),
        vec![hecho],
    )
}

impl fmt::Display for OperacionEgreso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
