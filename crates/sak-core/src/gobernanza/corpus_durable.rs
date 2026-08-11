//! Conservación indefinida del paquete normativo activado (INV-03 / G.5).
//!
//! Escritura durable write-once en [`AlmacenEvidencia`]. Sin UI/red/API.

use crate::contexto::{ClaseEfecto, HechoConValor, IdProductor, ValorHecho};
use crate::decision::{HashPaqueteNormativo, LONGITUD_HASH_PAQUETE, Veredicto};
use crate::evidencia::{AlmacenEvidencia, ErrorEvidencia, LedgerEvidencia};
use crate::gobernanza::conformidad::ReconocimientoCambio;
use crate::gobernanza::corpus::{EstadoPropuesta, GobernanzaCorpus, VersionCorpus};
use crate::gobernanza::firmantes::{FirmaPaquete, RolFirmante};
use crate::norma::{
    Alcance, Escalado, ErrorCarga, Fecha, Interpretacion, Monitorizacion, Naturaleza, Norma,
    Operacionalidad, PaqueteNormativo, RequisitoEvidencia, Vigencia,
};
use crate::perfil::Rango;
use crate::predicado::{CampoContexto, Predicado, Valor};
use crate::supervision::IdHumano;
use sha2::{Digest, Sha384};
use std::fmt;

const MAGIC: &[u8] = b"SAKCORP2";
const PREF_PKG: &[u8] = b"corpus/v1/pkg/";
const CLAVE_ACTIVO: &[u8] = b"corpus/v1/activo";
const CLAVE_HIST: &[u8] = b"corpus/v1/historial";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCorpusDurable {
    YaExiste,
    NoEncontrado,
    Corrupto,
    NoActivo,
    EstadoNoActivado,
    Codificacion,
    Carga(ErrorCarga),
}

impl fmt::Display for ErrorCorpusDurable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCorpusDurable::YaExiste => {
                f.write_str("paquete activado ya conservado (no sobrescribible)")
            }
            ErrorCorpusDurable::NoEncontrado => f.write_str("paquete no encontrado en almacen"),
            ErrorCorpusDurable::Corrupto => f.write_str("paquete corrupto o hash no coincide"),
            ErrorCorpusDurable::NoActivo => f.write_str("no hay paquete activo en almacen"),
            ErrorCorpusDurable::EstadoNoActivado => f.write_str("solo se conservan paquetes Activa"),
            ErrorCorpusDurable::Codificacion => f.write_str("error de codificacion del paquete"),
            ErrorCorpusDurable::Carga(e) => write!(f, "carga norma: {e}"),
        }
    }
}

impl std::error::Error for ErrorCorpusDurable {}

fn clave_pkg(hash: &HashPaqueteNormativo) -> Vec<u8> {
    let mut k = PREF_PKG.to_vec();
    for b in hash.bytes() {
        k.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    k
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

struct Lector<'a> {
    buf: &'a [u8],
    i: usize,
}

impl<'a> Lector<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ErrorCorpusDurable> {
        if self.i + n > self.buf.len() {
            return Err(ErrorCorpusDurable::Corrupto);
        }
        let s = &self.buf[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ErrorCorpusDurable> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ErrorCorpusDurable> {
        let mut a = [0u8; 2];
        a.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(a))
    }
    fn u32(&mut self) -> Result<u32, ErrorCorpusDurable> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    fn u64(&mut self) -> Result<u64, ErrorCorpusDurable> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ErrorCorpusDurable> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, ErrorCorpusDurable> {
        let b = self.bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| ErrorCorpusDurable::Corrupto)
    }
    fn arr48(&mut self) -> Result<[u8; LONGITUD_HASH_PAQUETE], ErrorCorpusDurable> {
        let mut a = [0u8; LONGITUD_HASH_PAQUETE];
        a.copy_from_slice(self.take(LONGITUD_HASH_PAQUETE)?);
        Ok(a)
    }
}

fn encode_version(v: &VersionCorpus) -> Result<Vec<u8>, ErrorCorpusDurable> {
    if !matches!(v.estado, EstadoPropuesta::Activa { .. }) {
        return Err(ErrorCorpusDurable::EstadoNoActivado);
    }
    let epoca = v.epoca_activacion.unwrap_or(0);
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(v.hash.bytes());
    put_u64(&mut out, epoca);
    // Texto canónico por norma + commitment del paquete.
    put_u32(&mut out, v.paquete.normas().len() as u32);
    for n in v.paquete.normas() {
        put_bytes(&mut out, &n.serializar_texto_canonico());
    }
    put_bytes(&mut out, &v.paquete.serializar_canonico());
    let diff = v
        .diff
        .as_ref()
        .map(GobernanzaCorpus::serializar_diff)
        .unwrap_or_default();
    put_bytes(&mut out, &diff);
    put_u32(&mut out, v.firmas.len() as u32);
    for f in &v.firmas {
        put_str(&mut out, f.id.como_str());
        out.push(f.rol_declarado as u8);
        put_bytes(&mut out, &f.firma_mldsa);
    }
    put_u32(&mut out, v.reconocimientos.len() as u32);
    for ack in &v.reconocimientos {
        out.extend_from_slice(&ack.digest_cambio);
        put_str(&mut out, ack.id_humano.como_str());
        put_bytes(&mut out, &ack.firma_mldsa);
    }
    Ok(out)
}

fn decode_predicado(r: &mut Lector<'_>) -> Result<Predicado, ErrorCorpusDurable> {
    match r.u8()? {
        1 => {
            let v = match r.u8()? {
                0 => Veredicto::Deny,
                1 => Veredicto::Suspend,
                2 => Veredicto::Escalate,
                3 => Veredicto::Allow,
                _ => return Err(ErrorCorpusDurable::Corrupto),
            };
            Ok(Predicado::Fijo(v))
        }
        2 => {
            let campo = match r.u8()? {
                1 => CampoContexto::ClaseEfecto,
                _ => return Err(ErrorCorpusDurable::Corrupto),
            };
            let valor = match r.u8()? {
                1 => Valor::Clase(clase_efecto(r.u8()?)?),
                2 => Valor::Entero(r.u64()?),
                _ => return Err(ErrorCorpusDurable::Corrupto),
            };
            Ok(Predicado::Eq(campo, valor))
        }
        3 => {
            let p = IdProductor::nuevo(leer_str_u16(r)?).map_err(|_| ErrorCorpusDurable::Corrupto)?;
            Ok(Predicado::HechoVigente(p))
        }
        8 => {
            let p = IdProductor::nuevo(leer_str_u16(r)?).map_err(|_| ErrorCorpusDurable::Corrupto)?;
            let token_str = leer_str_u16(r)?;
            let valor = ValorHecho::token(token_str).map_err(|_| ErrorCorpusDurable::Corrupto)?;
            let hcv = HechoConValor::nuevo(p, valor);
            Ok(Predicado::HechoConValor(hcv))
        }
        4 => {
            let n = r.u32()? as usize;
            let mut xs = Vec::with_capacity(n);
            for _ in 0..n {
                xs.push(decode_predicado(r)?);
            }
            Ok(Predicado::Y(xs))
        }
        5 => {
            let n = r.u32()? as usize;
            let mut xs = Vec::with_capacity(n);
            for _ in 0..n {
                xs.push(decode_predicado(r)?);
            }
            Ok(Predicado::O(xs))
        }
        6 => Ok(Predicado::No(Box::new(decode_predicado(r)?))),
        7 => Ok(Predicado::Si {
            cond: Box::new(decode_predicado(r)?),
            entonces: Box::new(decode_predicado(r)?),
            si_no: Box::new(decode_predicado(r)?),
        }),
        _ => Err(ErrorCorpusDurable::Corrupto),
    }
}

fn clase_efecto(v: u8) -> Result<ClaseEfecto, ErrorCorpusDurable> {
    match v {
        1 => Ok(ClaseEfecto::Ef1),
        2 => Ok(ClaseEfecto::Ef2),
        3 => Ok(ClaseEfecto::Ef3),
        4 => Ok(ClaseEfecto::Ef4),
        5 => Ok(ClaseEfecto::Ef5),
        6 => Ok(ClaseEfecto::Ef6),
        7 => Ok(ClaseEfecto::Ef7),
        8 => Ok(ClaseEfecto::Ef8),
        9 => Ok(ClaseEfecto::Ef9),
        10 => Ok(ClaseEfecto::Ef10),
        11 => Ok(ClaseEfecto::Ef11),
        12 => Ok(ClaseEfecto::Ef12),
        _ => Err(ErrorCorpusDurable::Corrupto),
    }
}


/// Decodifica un `Predicado` desde bytes en formato canonico (para tests).
pub fn decode_predicado_from_bytes(bytes: &[u8]) -> Result<Predicado, ErrorCorpusDurable> {
    let mut r = Lector::new(bytes);
    decode_predicado(&mut r)
}

fn leer_str_u16(r: &mut Lector<'_>) -> Result<String, ErrorCorpusDurable> {
    let n = r.u16()? as usize;
    let b = r.take(n)?;
    String::from_utf8(b.to_vec()).map_err(|_| ErrorCorpusDurable::Corrupto)
}

fn decode_norma_texto(bytes: &[u8]) -> Result<Norma, ErrorCorpusDurable> {
    let mut r = Lector::new(bytes);
    let identificador = leer_str_u16(&mut r)?;
    let fuente = leer_str_u16(&mut r)?;
    let jurisdiccion = leer_str_u16(&mut r)?;
    let anio = r.u16()?;
    let mes = r.u8()?;
    let dia = r.u8()?;
    let entrada = Fecha::nueva(anio, mes, dia).map_err(ErrorCorpusDurable::Carga)?;
    let termino = match r.u8()? {
        0 => None,
        1 => {
            let a = r.u16()?;
            let m = r.u8()?;
            let d = r.u8()?;
            Some(Fecha::nueva(a, m, d).map_err(ErrorCorpusDurable::Carga)?)
        }
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let alcance = Alcance {
        caso_de_uso: leer_str_u16(&mut r)?,
        clase_riesgo: leer_str_u16(&mut r)?,
        rol_regulatorio: leer_str_u16(&mut r)?,
        sector: leer_str_u16(&mut r)?,
        categorias_datos: leer_str_u16(&mut r)?,
        autonomia: leer_str_u16(&mut r)?,
        destinatarios: leer_str_u16(&mut r)?,
    };
    let naturaleza = match r.u8()? {
        1 => Naturaleza::Prohibicion,
        2 => Naturaleza::Obligacion,
        3 => Naturaleza::Condicion,
        4 => Naturaleza::Definicion,
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let operacionalidad = match r.u8()? {
        1 => Operacionalidad::L1,
        2 => Operacionalidad::L2,
        3 => Operacionalidad::L3,
        4 => Operacionalidad::L4,
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let clase_de_efecto = clase_efecto(r.u8()?)?;
    let predicado = decode_predicado(&mut r)?;
    let n_ev = r.u32()? as usize;
    let mut evidencia_exigida = Vec::with_capacity(n_ev);
    for _ in 0..n_ev {
        let productor =
            IdProductor::nuevo(leer_str_u16(&mut r)?).map_err(|_| ErrorCorpusDurable::Corrupto)?;
        let antiguedad_maxima_segundos = r.u64()?;
        evidencia_exigida.push(RequisitoEvidencia {
            productor,
            antiguedad_maxima_segundos,
        });
    }
    let n_ac = r.u32()? as usize;
    let mut acciones_obligatorias = Vec::with_capacity(n_ac);
    for _ in 0..n_ac {
        acciones_obligatorias.push(leer_str_u16(&mut r)?);
    }
    let n_cd = r.u32()? as usize;
    let mut condiciones_de_denegacion = Vec::with_capacity(n_cd);
    for _ in 0..n_cd {
        condiciones_de_denegacion.push(leer_str_u16(&mut r)?);
    }
    let escalado = match r.u8()? {
        0 => None,
        1 => Some(Escalado {
            rol: leer_str_u16(&mut r)?,
            competencia: leer_str_u16(&mut r)?,
            quorum: r.u8()?,
            plazo_segundos: r.u64()?,
            exige_independencia: r.u8()? != 0,
        }),
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let monitorizacion = match r.u8()? {
        0 => None,
        1 => Some(Monitorizacion {
            que: leer_str_u16(&mut r)?,
            periodo_segundos: r.u64()?,
            umbral: leer_str_u16(&mut r)?,
        }),
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let interpretacion = Interpretacion {
        texto: leer_str_u16(&mut r)?,
        autor: leer_str_u16(&mut r)?,
        digest_aprobacion: r.arr48()?,
    };
    let ambigua = r.u8()? != 0;
    let rango = match r.u8()? {
        0 => Rango::P0,
        1 => Rango::P1,
        2 => Rango::P2,
        3 => Rango::P3,
        4 => Rango::P4,
        5 => Rango::P5,
        _ => return Err(ErrorCorpusDurable::Corrupto),
    };
    let n_mat = r.u32()? as usize;
    for _ in 0..n_mat {
        let _ = r.u8()?;
    }
    let borrador = crate::norma::BorradorNorma {
        identificador,
        fuente,
        jurisdiccion,
        vigencia: Vigencia { entrada, termino },
        alcance,
        naturaleza,
        operacionalidad,
        clase_de_efecto,
        predicado,
        evidencia_exigida,
        acciones_obligatorias,
        condiciones_de_denegacion,
        escalado,
        monitorizacion,
        interpretacion,
        ambigua,
        rango,
        pretende_resolver: vec![],
    };
    let n = Norma::cargar(borrador).map_err(ErrorCorpusDurable::Carga)?;
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    let dig = hasher.finalize();
    if dig.as_slice() != n.hash().bytes() {
        return Err(ErrorCorpusDurable::Corrupto);
    }
    Ok(n)
}

fn decode_blob(bytes: &[u8]) -> Result<(VersionCorpus, u64), ErrorCorpusDurable> {
    let mut r = Lector::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(ErrorCorpusDurable::Corrupto);
    }
    let hash = HashPaqueteNormativo::desde_bytes(r.arr48()?);
    let epoca = r.u64()?;
    let n_normas = r.u32()? as usize;
    let mut normas = Vec::with_capacity(n_normas);
    for _ in 0..n_normas {
        let texto = r.bytes()?.to_vec();
        normas.push(decode_norma_texto(&texto)?);
    }
    let canon_pkg = r.bytes()?.to_vec();
    let paquete = PaqueteNormativo::cargar(normas).map_err(ErrorCorpusDurable::Carga)?;
    if paquete.hash() != &hash {
        return Err(ErrorCorpusDurable::Corrupto);
    }
    if paquete.serializar_canonico() != canon_pkg {
        return Err(ErrorCorpusDurable::Corrupto);
    }
    let diff_bytes = r.bytes()?;
    let diff = if diff_bytes.is_empty() {
        None
    } else {
        Some(
            GobernanzaCorpus::deserializar_diff(diff_bytes)
                .map_err(|_| ErrorCorpusDurable::Corrupto)?,
        )
    };
    let n_firmas = r.u32()? as usize;
    let mut firmas = Vec::with_capacity(n_firmas);
    for _ in 0..n_firmas {
        let id = IdHumano::nuevo(r.str()?).map_err(|_| ErrorCorpusDurable::Corrupto)?;
        let rol = match r.u8()? {
            1 => RolFirmante::Juridico,
            2 => RolFirmante::Tecnico,
            _ => return Err(ErrorCorpusDurable::Corrupto),
        };
        let firma_mldsa = r.bytes()?.to_vec();
        firmas.push(FirmaPaquete {
            id,
            rol_declarado: rol,
            firma_mldsa,
        });
    }
    let n_acks = r.u32()? as usize;
    let mut reconocimientos = Vec::with_capacity(n_acks);
    for _ in 0..n_acks {
        let digest_cambio = r.arr48()?;
        let id_humano = IdHumano::nuevo(r.str()?).map_err(|_| ErrorCorpusDurable::Corrupto)?;
        let firma_mldsa = r.bytes()?.to_vec();
        reconocimientos.push(ReconocimientoCambio {
            digest_cambio,
            id_humano,
            firma_mldsa,
        });
    }
    let v = VersionCorpus {
        hash,
        paquete,
        estado: EstadoPropuesta::Activa { epoca },
        epoca_activacion: Some(epoca),
        diff,
        reconocimientos,
        firmas,
        activado_en: None,
        revocado_en: None,
    };
    Ok((v, epoca))
}

/// Conserva indefinidamente un paquete **Activa**. Falla si ya existe (no sobrescribe).
pub fn conservar_paquete_activado(
    almacen: &mut dyn AlmacenEvidencia,
    version: &VersionCorpus,
) -> Result<(), ErrorCorpusDurable> {
    if !matches!(version.estado, EstadoPropuesta::Activa { .. }) {
        return Err(ErrorCorpusDurable::EstadoNoActivado);
    }
    let clave = clave_pkg(&version.hash);
    if almacen.leer(&clave).is_some() {
        // Write-once: la ruta normal no sobrescribe el blob.
        return Err(ErrorCorpusDurable::YaExiste);
    }
    let blob = encode_version(version)?;
    almacen
        .escribir_durable(&clave, &blob)
        .map_err(|_| ErrorCorpusDurable::Codificacion)?;
    reafirmar_activo_en_historial(almacen, &version.hash, version.epoca_activacion.unwrap_or(0))?;
    Ok(())
}

/// Tras reactivación del mismo hash: actualiza puntero activo e historial sin tocar el blob.
pub fn reafirmar_activo_en_historial(
    almacen: &mut dyn AlmacenEvidencia,
    hash: &HashPaqueteNormativo,
    epoca: u64,
) -> Result<(), ErrorCorpusDurable> {
    // Exige que el paquete ya esté conservado e íntegro.
    let _ = resolver_cita_paquete(almacen, hash)?;
    almacen
        .escribir_durable(CLAVE_ACTIVO, hash.bytes())
        .map_err(|_| ErrorCorpusDurable::Codificacion)?;
    let mut hist = almacen.leer(CLAVE_HIST).unwrap_or_default();
    hist.extend_from_slice(hash.bytes());
    hist.extend_from_slice(&epoca.to_le_bytes());
    almacen
        .escribir_durable(CLAVE_HIST, &hist)
        .map_err(|_| ErrorCorpusDurable::Codificacion)?;
    Ok(())
}

/// Resuelve una cita de hash de paquete (INV-03). Err si falta o está corrupto.
pub fn resolver_cita_paquete(
    almacen: &dyn AlmacenEvidencia,
    hash: &HashPaqueteNormativo,
) -> Result<VersionCorpus, ErrorCorpusDurable> {
    let clave = clave_pkg(hash);
    let blob = almacen
        .leer(&clave)
        .ok_or(ErrorCorpusDurable::NoEncontrado)?;
    let (v, _) = decode_blob(&blob)?;
    if v.hash != *hash {
        return Err(ErrorCorpusDurable::Corrupto);
    }
    Ok(v)
}

/// Carga gobernanza desde paquetes conservados (reinicio de dominio).
pub fn cargar_gobernanza_desde_almacen(
    almacen: &dyn AlmacenEvidencia,
) -> Result<GobernanzaCorpus, ErrorCorpusDurable> {
    let mut gob = GobernanzaCorpus::nuevo();
    let hist = match almacen.leer(CLAVE_HIST) {
        Some(h) => h,
        None => return Ok(gob),
    };
    let mut i = 0;
    while i + LONGITUD_HASH_PAQUETE + 8 <= hist.len() {
        let mut hb = [0u8; LONGITUD_HASH_PAQUETE];
        hb.copy_from_slice(&hist[i..i + LONGITUD_HASH_PAQUETE]);
        i += LONGITUD_HASH_PAQUETE;
        let mut eb = [0u8; 8];
        eb.copy_from_slice(&hist[i..i + 8]);
        i += 8;
        let hash = HashPaqueteNormativo::desde_bytes(hb);
        let v = resolver_cita_paquete(almacen, &hash)?;
        gob.restaurar_version_activada(v);
        let _ = eb; // época ya en VersionCorpus
    }
    if let Some(ab) = almacen.leer(CLAVE_ACTIVO) {
        if ab.len() == LONGITUD_HASH_PAQUETE {
            let mut a = [0u8; LONGITUD_HASH_PAQUETE];
            a.copy_from_slice(&ab);
            gob.marcar_activo(HashPaqueteNormativo::desde_bytes(a));
        }
    }
    Ok(gob)
}

/// Si la cita no resuelve, suspende el dominio (INV-03).
pub fn exigir_cita_o_suspender<A: AlmacenEvidencia>(
    ledger: &mut LedgerEvidencia<A>,
    hash: &HashPaqueteNormativo,
) -> Result<(), ErrorEvidencia> {
    match resolver_cita_paquete(ledger.almacen(), hash) {
        Ok(_) => Ok(()),
        Err(_) => {
            ledger.suspender_por_cita_irresoluble();
            Err(ErrorEvidencia::CitaPaqueteIrresoluble)
        }
    }
}

/// Clave de almacén del paquete (pruebas de corrupción por FS; no es API de borrado).
pub fn clave_almacen_paquete(hash: &HashPaqueteNormativo) -> Vec<u8> {
    clave_pkg(hash)
}
