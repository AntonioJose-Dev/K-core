//! Persistencia durable de pasaportes (INV-04 / §E Registro soberano).
//!
//! Write-once por (id, versión): un pasaporte nuevo es versión nueva; no reescribe.

use crate::evidencia::AlmacenEvidencia;
use crate::identidad::artefacto::IdSistema;
use crate::identidad::pasaporte::{self, Pasaporte};
use crate::identidad::registro::{ErrorRegistro, RegistroSoberano};
use std::fmt;

const MAGIC: &[u8] = b"SAKPASS1";
const PREF: &[u8] = b"registro/v1/pass/";
const CLAVE_INDEX: &[u8] = b"registro/v1/index";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorRegistroDurable {
    YaExiste,
    NoEncontrado,
    Corrupto,
    Codificacion,
    Registro(ErrorRegistro),
}

impl fmt::Display for ErrorRegistroDurable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorRegistroDurable::YaExiste => {
                f.write_str("pasaporte/version ya conservado (no se reescribe)")
            }
            ErrorRegistroDurable::NoEncontrado => f.write_str("pasaporte no encontrado en almacen"),
            ErrorRegistroDurable::Corrupto => f.write_str("pasaporte corrupto o firma invalida"),
            ErrorRegistroDurable::Codificacion => f.write_str("error de codificacion"),
            ErrorRegistroDurable::Registro(e) => write!(f, "registro: {e}"),
        }
    }
}

impl std::error::Error for ErrorRegistroDurable {}

fn clave_pass(id: &str, version: u32) -> Vec<u8> {
    let mut k = PREF.to_vec();
    k.extend_from_slice(id.as_bytes());
    k.extend_from_slice(b"/v/");
    k.extend_from_slice(&version.to_le_bytes());
    k
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], ErrorRegistroDurable> {
        if self.i + n > self.buf.len() {
            return Err(ErrorRegistroDurable::Corrupto);
        }
        let s = &self.buf[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, ErrorRegistroDurable> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ErrorRegistroDurable> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, ErrorRegistroDurable> {
        let b = self.bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| ErrorRegistroDurable::Corrupto)
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.i)
    }
}

fn encode(p: &Pasaporte) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_str(&mut out, p.id());
    put_u32(&mut out, p.version());
    put_str(&mut out, p.sistema_id());
    put_str(&mut out, p.responsable());
    put_str(&mut out, p.finalidad());
    put_str(&mut out, p.modelos());
    put_str(&mut out, p.jurisdiccion());
    put_str(&mut out, p.datos());
    put_str(&mut out, p.autonomia_por_clase());
    put_str(&mut out, p.herramientas());
    put_str(&mut out, p.efectores());
    put_str(&mut out, p.clasificacion_riesgo());
    put_u32(&mut out, p.vigente_desde_dias());
    put_u32(&mut out, p.vigente_hasta_dias());
    put_bytes(&mut out, p.firma());
    put_bytes(&mut out, p.pk_registro());
    out
}

fn decode(bytes: &[u8]) -> Result<Pasaporte, ErrorRegistroDurable> {
    let mut r = Lector::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(ErrorRegistroDurable::Corrupto);
    }
    let id = r.str()?;
    let version = r.u32()?;
    let sistema_id = IdSistema::nuevo(r.str()?).map_err(|_| ErrorRegistroDurable::Corrupto)?;
    let responsable = r.str()?;
    let finalidad = r.str()?;
    let modelos = r.str()?;
    let jurisdiccion = r.str()?;
    let datos = r.str()?;
    let autonomia_por_clase = r.str()?;
    let herramientas = r.str()?;
    let efectores = r.str()?;
    let clasificacion_riesgo = r.str()?;
    let vigente_desde_dias = r.u32()?;
    let vigente_hasta_dias = r.u32()?;
    let firma = r.bytes()?.to_vec();
    let pk_registro = r.bytes()?.to_vec();
    let p = pasaporte::desde_almacen(
        id,
        version,
        sistema_id,
        responsable,
        finalidad,
        modelos,
        jurisdiccion,
        datos,
        autonomia_por_clase,
        herramientas,
        efectores,
        clasificacion_riesgo,
        vigente_desde_dias,
        vigente_hasta_dias,
        firma,
        pk_registro,
    );
    if !p.firma_valida() {
        return Err(ErrorRegistroDurable::Corrupto);
    }
    Ok(p)
}

/// Conserva un pasaporte sellado. Falla si (id, versión) ya existe.
pub fn conservar_pasaporte(
    almacen: &mut dyn AlmacenEvidencia,
    pasaporte: &Pasaporte,
) -> Result<(), ErrorRegistroDurable> {
    if pasaporte.version() == 0 || !pasaporte.firma_valida() {
        return Err(ErrorRegistroDurable::Corrupto);
    }
    let clave = clave_pass(pasaporte.id(), pasaporte.version());
    if almacen.leer(&clave).is_some() {
        return Err(ErrorRegistroDurable::YaExiste);
    }
    let blob = encode(pasaporte);
    almacen
        .escribir_durable(&clave, &blob)
        .map_err(|_| ErrorRegistroDurable::Codificacion)?;
    let mut idx = almacen.leer(CLAVE_INDEX).unwrap_or_default();
    put_str(&mut idx, pasaporte.id());
    put_u32(&mut idx, pasaporte.version());
    almacen
        .escribir_durable(CLAVE_INDEX, &idx)
        .map_err(|_| ErrorRegistroDurable::Codificacion)?;
    Ok(())
}

/// Registra en memoria y conserva en disco (write-once).
pub fn registrar_y_conservar(
    registro: &mut RegistroSoberano,
    almacen: &mut dyn AlmacenEvidencia,
    id: impl Into<String>,
    version: u32,
    sistema_id: IdSistema,
    responsable: impl Into<String>,
    finalidad: impl Into<String>,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
) -> Result<Pasaporte, ErrorRegistroDurable> {
    let p = registro
        .registrar(
            id,
            version,
            sistema_id,
            responsable,
            finalidad,
            vigente_desde_dias,
            vigente_hasta_dias,
        )
        .map_err(ErrorRegistroDurable::Registro)?;
    match conservar_pasaporte(almacen, &p) {
        Ok(()) => Ok(p),
        Err(e) => Err(e),
    }
}

/// Desde declaración firmada del responsable + conservación durable.
pub fn registrar_desde_declaracion_y_conservar(
    registro: &mut RegistroSoberano,
    almacen: &mut dyn AlmacenEvidencia,
    id: impl Into<String>,
    version: u32,
    decl: &crate::identidad::pasaporte::DeclaracionResponsable,
) -> Result<Pasaporte, ErrorRegistroDurable> {
    let p = registro
        .registrar_desde_declaracion(id, version, decl)
        .map_err(ErrorRegistroDurable::Registro)?;
    conservar_pasaporte(almacen, &p)?;
    Ok(p)
}

pub fn resolver_pasaporte(
    almacen: &dyn AlmacenEvidencia,
    id: &str,
    version: u32,
) -> Result<Pasaporte, ErrorRegistroDurable> {
    let blob = almacen
        .leer(&clave_pass(id, version))
        .ok_or(ErrorRegistroDurable::NoEncontrado)?;
    decode(&blob)
}

/// Carga todas las versiones conservadas en un registro vacío (reinicio de dominio).
pub fn cargar_registro_desde_almacen(
    almacen: &dyn AlmacenEvidencia,
) -> Result<RegistroSoberano, ErrorRegistroDurable> {
    let mut reg = RegistroSoberano::nuevo().map_err(|_| ErrorRegistroDurable::Codificacion)?;
    let idx = match almacen.leer(CLAVE_INDEX) {
        Some(i) => i,
        None => return Ok(reg),
    };
    let mut r = Lector::new(&idx);
    while r.remaining() > 0 {
        let id = r.str()?;
        let version = r.u32()?;
        let p = resolver_pasaporte(almacen, &id, version)?;
        reg.restaurar(p)
            .map_err(ErrorRegistroDurable::Registro)?;
    }
    Ok(reg)
}

pub fn clave_almacen_pasaporte(id: &str, version: u32) -> Vec<u8> {
    clave_pass(id, version)
}
