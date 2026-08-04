//! Persistencia durable de la CA y certificados emitidos (INV-05 / H.2).
//!
//! Perfil escritorio [VAL-EXT]: sin mTLS ni red.

use crate::evidencia::AlmacenEvidencia;
use crate::identidad::artefacto::{ArtefactoCliente, IdSistema};
use crate::identidad::ca::{AutoridadCertificacion, PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAGIC: &[u8] = b"SAKCA001";
const CLAVE_CA: &[u8] = b"identidad/v1/ca";
const CLAVE_PERFIL: &[u8] = b"identidad/v1/perfil";
const PREF_CERT: &[u8] = b"identidad/v1/cert/";
const CLAVE_REV: &[u8] = b"identidad/v1/revocados";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCaDurable {
    Corrupto,
    Codificacion,
    PerfilInvalido,
}

impl fmt::Display for ErrorCaDurable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCaDurable::Corrupto => f.write_str("estado de CA corrupto"),
            ErrorCaDurable::Codificacion => f.write_str("error de codificacion CA"),
            ErrorCaDurable::PerfilInvalido => {
                f.write_str("perfil de identidad no es ESCRITORIO-VAL-EXT")
            }
        }
    }
}

impl std::error::Error for ErrorCaDurable {}

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
    fn take(&mut self, n: usize) -> Result<&'a [u8], ErrorCaDurable> {
        if self.i + n > self.buf.len() {
            return Err(ErrorCaDurable::Corrupto);
        }
        let s = &self.buf[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, ErrorCaDurable> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    fn u64(&mut self) -> Result<u64, ErrorCaDurable> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ErrorCaDurable> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, ErrorCaDurable> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| ErrorCaDurable::Corrupto)
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.i)
    }
}

fn encode_cert(art: &ArtefactoCliente) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_str(&mut out, art.sistema_id.como_str());
    put_str(&mut out, &art.pasaporte_id);
    put_u32(&mut out, art.pasaporte_version);
    put_bytes(&mut out, &art.pk_workload);
    put_u32(&mut out, art.vigente_desde_dias);
    put_u32(&mut out, art.vigente_hasta_dias);
    put_u64(&mut out, art.serial);
    put_bytes(&mut out, &art.firma_ca);
    out
}

fn decode_cert(bytes: &[u8]) -> Result<ArtefactoCliente, ErrorCaDurable> {
    let mut r = Lector::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(ErrorCaDurable::Corrupto);
    }
    let sistema_id = IdSistema::nuevo(r.str()?).map_err(|_| ErrorCaDurable::Corrupto)?;
    Ok(ArtefactoCliente {
        sistema_id,
        pasaporte_id: r.str()?,
        pasaporte_version: r.u32()?,
        pk_workload: r.bytes()?.to_vec(),
        vigente_desde_dias: r.u32()?,
        vigente_hasta_dias: r.u32()?,
        serial: r.u64()?,
        firma_ca: r.bytes()?.to_vec(),
    })
}

fn clave_cert(serial: u64) -> Vec<u8> {
    let mut k = PREF_CERT.to_vec();
    k.extend_from_slice(&serial.to_le_bytes());
    k
}

/// Persiste CA + certificados emitidos + revocaciones. Sobrescribe el estado CA
/// (no el de un certificado individual ya sellado en firma).
pub fn conservar_ca(
    almacen: &mut dyn AlmacenEvidencia,
    ca: &AutoridadCertificacion,
) -> Result<(), ErrorCaDurable> {
    almacen
        .escribir_durable(CLAVE_PERFIL, PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT.as_bytes())
        .map_err(|_| ErrorCaDurable::Codificacion)?;
    let mut blob = Vec::new();
    blob.extend_from_slice(MAGIC);
    put_bytes(&mut blob, ca.pk_bytes());
    put_bytes(&mut blob, &ca.bytes_secreto());
    put_u64(&mut blob, ca.siguiente_serial());
    put_u32(&mut blob, ca.emitidos().len() as u32);
    for serial in ca.emitidos().keys() {
        put_u64(&mut blob, *serial);
    }
    almacen
        .escribir_durable(CLAVE_CA, &blob)
        .map_err(|_| ErrorCaDurable::Codificacion)?;
    for (serial, art) in ca.emitidos() {
        almacen
            .escribir_durable(&clave_cert(*serial), &encode_cert(art))
            .map_err(|_| ErrorCaDurable::Codificacion)?;
    }
    let mut rev = Vec::new();
    put_u32(&mut rev, ca.revocados().len() as u32);
    for s in ca.revocados() {
        put_u64(&mut rev, *s);
    }
    almacen
        .escribir_durable(CLAVE_REV, &rev)
        .map_err(|_| ErrorCaDurable::Codificacion)?;
    Ok(())
}

/// Carga la CA desde disco; exige el perfil escritorio VAL-EXT.
pub fn cargar_ca_desde_almacen(
    almacen: &dyn AlmacenEvidencia,
) -> Result<Option<AutoridadCertificacion>, ErrorCaDurable> {
    let perfil = match almacen.leer(CLAVE_PERFIL) {
        Some(p) => p,
        None => return Ok(None),
    };
    if perfil.as_slice() != PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT.as_bytes() {
        return Err(ErrorCaDurable::PerfilInvalido);
    }
    let blob = almacen
        .leer(CLAVE_CA)
        .ok_or(ErrorCaDurable::Corrupto)?;
    let mut r = Lector::new(&blob);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(ErrorCaDurable::Corrupto);
    }
    let public = r.bytes()?.to_vec();
    let secret = r.bytes()?.to_vec();
    let siguiente_serial = r.u64()?;
    let n = r.u32()? as usize;
    let mut emitidos = BTreeMap::new();
    for _ in 0..n {
        let serial = r.u64()?;
        let cert_blob = almacen
            .leer(&clave_cert(serial))
            .ok_or(ErrorCaDurable::Corrupto)?;
        let art = decode_cert(&cert_blob)?;
        if art.serial != serial {
            return Err(ErrorCaDurable::Corrupto);
        }
        emitidos.insert(serial, art);
    }
    let mut revocados = BTreeSet::new();
    if let Some(rev) = almacen.leer(CLAVE_REV) {
        let mut rr = Lector::new(&rev);
        let nr = rr.u32()? as usize;
        for _ in 0..nr {
            revocados.insert(rr.u64()?);
        }
        if rr.remaining() != 0 {
            return Err(ErrorCaDurable::Corrupto);
        }
    }
    let ca = AutoridadCertificacion::desde_estado(
        public,
        &secret,
        siguiente_serial,
        emitidos,
        revocados,
    )
    .map_err(|_| ErrorCaDurable::Corrupto)?;
    Ok(Some(ca))
}
