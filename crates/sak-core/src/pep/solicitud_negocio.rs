//! Solicitud tipada EF-5: operación de negocio (pago, transferencia, orden, etc.).

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::fmt;

/// Tipos tipados de operación de negocio. Sin compuestos opacos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoOperacionNegocio {
    Pago,
    Transferencia,
    Orden,
    Contrato,
    Alta,
    Baja,
    EmisionPoliza,
}

impl TipoOperacionNegocio {
    pub fn token(self) -> &'static str {
        match self {
            TipoOperacionNegocio::Pago => "pago",
            TipoOperacionNegocio::Transferencia => "transferencia",
            TipoOperacionNegocio::Orden => "orden",
            TipoOperacionNegocio::Contrato => "contrato",
            TipoOperacionNegocio::Alta => "alta",
            TipoOperacionNegocio::Baja => "baja",
            TipoOperacionNegocio::EmisionPoliza => "emision_poliza",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "pago" => Some(TipoOperacionNegocio::Pago),
            "transferencia" => Some(TipoOperacionNegocio::Transferencia),
            "orden" => Some(TipoOperacionNegocio::Orden),
            "contrato" => Some(TipoOperacionNegocio::Contrato),
            "alta" => Some(TipoOperacionNegocio::Alta),
            "baja" => Some(TipoOperacionNegocio::Baja),
            "emision_poliza" => Some(TipoOperacionNegocio::EmisionPoliza),
            _ => None,
        }
    }
}

impl fmt::Display for TipoOperacionNegocio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Importe normalizado en unidades menores (enteras, no fraccionales libres).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImporteNormalizado {
    pub unidades_menores: u64,
}

impl ImporteNormalizado {
    pub fn nuevo(unidades_menores: u64) -> Result<Self, &'static str> {
        if unidades_menores == 0 {
            return Err("importe cero");
        }
        Ok(ImporteNormalizado { unidades_menores })
    }
}

/// Solicitud canónica e inmutable de operación de negocio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudOperacionNegocio {
    pub tipo: TipoOperacionNegocio,
    pub sistema_efector: String,
    pub cuenta: String,
    pub contraparte: String,
    pub moneda: String,
    pub importe: ImporteNormalizado,
    /// Digest del objeto contractual / de negocio (no texto libre).
    pub digest_objeto: [u8; LONGITUD_HASH_PAQUETE],
    /// Inicio y fin de validez en ticks (alcance temporal).
    pub vigencia_desde: u64,
    pub vigencia_hasta: u64,
    pub idempotency_key: [u8; 32],
    pub reversible: bool,
    /// Digest de condiciones previas tipadas.
    pub digest_condiciones_previas: [u8; LONGITUD_HASH_PAQUETE],
    pub datos_personales: bool,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    /// Si true, exige hecho de supervisión humana antes de ejercer.
    pub exige_supervision: bool,
}

impl SolicitudOperacionNegocio {
    pub fn nueva(
        tipo: TipoOperacionNegocio,
        sistema_efector: impl Into<String>,
        cuenta: impl Into<String>,
        contraparte: impl Into<String>,
        moneda: impl Into<String>,
        importe: ImporteNormalizado,
        digest_objeto: [u8; LONGITUD_HASH_PAQUETE],
        vigencia_desde: u64,
        vigencia_hasta: u64,
        idempotency_key: [u8; 32],
        reversible: bool,
        digest_condiciones_previas: [u8; LONGITUD_HASH_PAQUETE],
        datos_personales: bool,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        exige_supervision: bool,
    ) -> Result<Self, &'static str> {
        let sistema_efector = sistema_efector.into();
        let cuenta = cuenta.into();
        let contraparte = contraparte.into();
        let moneda = moneda.into();
        if sistema_efector.trim().is_empty()
            || cuenta.trim().is_empty()
            || contraparte.trim().is_empty()
        {
            return Err("destinatario o cuenta ambigua");
        }
        if moneda.len() != 3 || !moneda.bytes().all(|b| b.is_ascii_uppercase()) {
            return Err("moneda no normalizada");
        }
        if vigencia_hasta < vigencia_desde {
            return Err("alcance temporal invalido");
        }
        if idempotency_key == [0u8; 32] {
            return Err("idempotency key nula");
        }
        Ok(SolicitudOperacionNegocio {
            tipo,
            sistema_efector,
            cuenta,
            contraparte,
            moneda,
            importe,
            digest_objeto,
            vigencia_desde,
            vigencia_hasta,
            idempotency_key,
            reversible,
            digest_condiciones_previas,
            datos_personales,
            hash_paquete,
            epoca,
            digest_contexto,
            exige_supervision,
        })
    }

    pub fn clase(&self) -> ClaseEfecto {
        ClaseEfecto::Ef5
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-5|");
        v.extend_from_slice(self.tipo.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.sistema_efector);
        escribir(&mut v, &self.cuenta);
        escribir(&mut v, &self.contraparte);
        escribir(&mut v, &self.moneda);
        v.extend_from_slice(&self.importe.unidades_menores.to_le_bytes());
        v.extend_from_slice(&self.digest_objeto);
        v.extend_from_slice(&self.vigencia_desde.to_le_bytes());
        v.extend_from_slice(&self.vigencia_hasta.to_le_bytes());
        v.extend_from_slice(&self.idempotency_key);
        v.push(u8::from(self.reversible));
        v.extend_from_slice(&self.digest_condiciones_previas);
        v.push(u8::from(self.datos_personales));
        v.extend_from_slice(&self.hash_paquete);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.digest_contexto);
        v.push(u8::from(self.exige_supervision));
        v
    }
}

fn escribir(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudNegocioCruda {
    Tipada(SolicitudOperacionNegocio),
    NoTipificable,
    /// Importes no normalizados, campos libres, compuestos opacos, redirecciones.
    Malformada(&'static str),
    ClaseNoSoportada(ClaseEfecto),
}

/// Condiciones aplicadas en la ejecución delegada (H.14).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CondicionesNegocio {
    pub tipo: TipoOperacionNegocio,
    pub sistema_efector: String,
    pub contraparte: String,
    pub moneda: String,
    pub importe: u64,
    pub digest_objeto: [u8; LONGITUD_HASH_PAQUETE],
    pub idempotency_key: [u8; 32],
}

impl CondicionesNegocio {
    pub fn desde_solicitud(s: &SolicitudOperacionNegocio) -> Self {
        CondicionesNegocio {
            tipo: s.tipo,
            sistema_efector: s.sistema_efector.clone(),
            contraparte: s.contraparte.clone(),
            moneda: s.moneda.clone(),
            importe: s.importe.unidades_menores,
            digest_objeto: s.digest_objeto,
            idempotency_key: s.idempotency_key,
        }
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-5-COND|");
        v.extend_from_slice(self.tipo.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.sistema_efector);
        escribir(&mut v, &self.contraparte);
        escribir(&mut v, &self.moneda);
        v.extend_from_slice(&self.importe.to_le_bytes());
        v.extend_from_slice(&self.digest_objeto);
        v.extend_from_slice(&self.idempotency_key);
        v
    }
}

pub fn digest_solicitud_negocio(s: &SolicitudOperacionNegocio) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-5", &s.canonico())
}

pub fn digest_condiciones_negocio(c: &CondicionesNegocio) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-BIZ-COND-v1|", &c.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(d: &[u8; 32]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Alcance mínimo canónico comparable exactamente con la capacidad.
pub fn alcance_ef5(s: &SolicitudOperacionNegocio) -> Alcance {
    let tokens = vec![
        "EF-5".to_string(),
        format!("tipo:{}", s.tipo.token()),
        format!("efector:{}", s.sistema_efector),
        format!("cuenta:{}", s.cuenta),
        format!("contra:{}", s.contraparte),
        format!("ccy:{}", s.moneda),
        format!("imp:{}", s.importe.unidades_menores),
        format!("obj:{}", hex48(&s.digest_objeto)),
        format!("idem:{}", hex32(&s.idempotency_key)),
        format!("rev:{}", u8::from(s.reversible)),
        format!("dp:{}", u8::from(s.datos_personales)),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("ep:{}", s.epoca),
        format!("ctx:{}", hex48(&s.digest_contexto)),
        format!("sup:{}", u8::from(s.exige_supervision)),
        format!("vd:{}", s.vigencia_desde),
        format!("vh:{}", s.vigencia_hasta),
        format!("cond:{}", hex48(&s.digest_condiciones_previas)),
    ];
    Alcance::minimo(tokens).expect("alcance EF-5")
}

#[derive(Debug, Clone)]
pub struct AlcanceAutorizadoNegocio {
    pub tipo: String,
    pub sistema_efector: String,
    pub cuenta: String,
    pub contraparte: String,
    pub moneda: String,
    pub importe: u64,
    pub digest_objeto: [u8; LONGITUD_HASH_PAQUETE],
    pub idempotency_key: [u8; 32],
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
}

impl AlcanceAutorizadoNegocio {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-5") {
            return Err("falta EF-5");
        }
        let mut tipo = None;
        let mut efector = None;
        let mut cuenta = None;
        let mut contra = None;
        let mut ccy = None;
        let mut imp = None;
        let mut obj = None;
        let mut idem = None;
        let mut pkg = None;
        let mut ep = None;
        for t in a.tokens() {
            if let Some(x) = t.strip_prefix("tipo:") {
                tipo = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("efector:") {
                efector = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("cuenta:") {
                cuenta = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("contra:") {
                contra = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("ccy:") {
                ccy = Some(x.to_string());
            } else if let Some(x) = t.strip_prefix("imp:") {
                imp = Some(x.parse().map_err(|_| "importe")?);
            } else if let Some(x) = t.strip_prefix("obj:") {
                obj = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("idem:") {
                idem = Some(parse_hex32(x)?);
            } else if let Some(x) = t.strip_prefix("pkg:") {
                pkg = Some(parse_hex48(x)?);
            } else if let Some(x) = t.strip_prefix("ep:") {
                ep = Some(x.parse().map_err(|_| "epoca")?);
            }
        }
        Ok(AlcanceAutorizadoNegocio {
            tipo: tipo.ok_or("falta tipo")?,
            sistema_efector: efector.ok_or("falta efector")?,
            cuenta: cuenta.ok_or("falta cuenta")?,
            contraparte: contra.ok_or("falta contra")?,
            moneda: ccy.ok_or("falta ccy")?,
            importe: imp.ok_or("falta imp")?,
            digest_objeto: obj.ok_or("falta obj")?,
            idempotency_key: idem.ok_or("falta idem")?,
            hash_paquete: pkg.ok_or("falta pkg")?,
            epoca: ep.ok_or("falta ep")?,
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

fn parse_hex32(s: &str) -> Result<[u8; 32], &'static str> {
    if s.len() != 64 {
        return Err("hex32 longitud");
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "hex")?;
    }
    Ok(out)
}

/// Precondiciones de cadena H antes de ejecutar EF-5 (mínimo C4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf5 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    /// Libro de Control ≥ C4 para la clase EF-5.
    pub libro_c4: bool,
    pub monitor_permisivo: bool,
    /// True si supervisión no se exige, o si el hecho firmado está presente.
    pub supervision_ok: bool,
    /// False cuando la decisión normativa fue DENY (sin capacidad emitible).
    pub decision_permitida: bool,
    /// La operación ordena transferencia de información a un tercero.
    pub ordena_egreso_datos: bool,
    /// Cadena EF-10 autorizada cuando `ordena_egreso_datos`.
    pub egreso_ef10_autorizado: bool,
    /// La operación produce una orden a un actuador físico.
    pub ordena_efecto_fisico: bool,
    /// Cadena EF-11 autorizada cuando `ordena_efecto_fisico`.
    pub efecto_fisico_ef11_autorizado: bool,
}

impl PrecondicionesPepEf5 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf5 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c4: true,
            monitor_permisivo: true,
            supervision_ok: true,
            decision_permitida: true,
            ordena_egreso_datos: false,
            egreso_ef10_autorizado: false,
            ordena_efecto_fisico: false,
            efecto_fisico_ef11_autorizado: false,
        }
    }
}

/// Traduce una invocación EF-4 tipada a solicitud EF-5 (sin invocar proveedor).
pub fn traducir_desde_herramienta(
    id_herramienta: &str,
    servidor: &str,
    operacion: &str,
    destino: &str,
    digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    digest_condiciones: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    datos_personales: bool,
    reversible: bool,
) -> Result<SolicitudOperacionNegocio, &'static str> {
    let tipo = TipoOperacionNegocio::desde_token(operacion).ok_or("operacion negocio desconocida")?;
    // Importe/moneda/idem derivados de digests tipados (sin campos libres).
    let mut importe_bytes = [0u8; 8];
    importe_bytes.copy_from_slice(&digest_argumentos[0..8]);
    let unidades = u64::from_le_bytes(importe_bytes);
    let importe = ImporteNormalizado::nuevo(unidades.max(1))?;
    let moneda = match digest_argumentos[8] % 3 {
        0 => "EUR",
        1 => "USD",
        _ => "GBP",
    };
    let mut idem = [0u8; 32];
    idem.copy_from_slice(&digest_argumentos[16..48]);
    if idem == [0u8; 32] {
        idem[0] = 1;
    }
    SolicitudOperacionNegocio::nueva(
        tipo,
        servidor,
        format!("acct:{id_herramienta}"),
        destino,
        moneda,
        importe,
        digest_argumentos,
        0,
        u64::MAX,
        idem,
        reversible,
        digest_condiciones,
        datos_personales,
        hash_paquete,
        1,
        digest_argumentos,
        false,
    )
}
