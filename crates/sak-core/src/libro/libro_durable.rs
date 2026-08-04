//! Persistencia durable del Libro de Control (INV-09 / §D.3).
//!
//! Snapshot por dominio: hechos firmados, ALCANZABLES, techos, suspensiones
//! y historial. Sin productores, PEP, UI ni red.

use crate::contexto::ClaseEfecto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::AlmacenEvidencia;
use crate::identidad::IdSistema;
use crate::libro::hecho::{
    antigüedad_maxima, HechoFirmadoLibro, InventarioAlcanzables, ProductorHecho, TipoHecho,
};
use crate::libro::libro_ctrl::{LibroControl, ParSistemaClase};
use crate::libro::nivel::NivelControl;
use std::collections::{BTreeSet, HashMap};
use std::fmt;

const MAGIC: &[u8] = b"SAKLIB1";
const CLAVE_SNAPSHOT: &[u8] = b"libro/v1/snapshot";

/// Etiqueta al restaurar; no entra en el digest del hecho.
const NO_DEMUESTRA_RESTAURADO: &str = "hecho restaurado del almacen durable";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorLibroDurable {
    Corrupto,
    Codificacion,
}

impl fmt::Display for ErrorLibroDurable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorLibroDurable::Corrupto => f.write_str("libro durable corrupto o firma invalida"),
            ErrorLibroDurable::Codificacion => f.write_str("error de codificacion del libro"),
        }
    }
}

impl std::error::Error for ErrorLibroDurable {}

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
    fn take(&mut self, n: usize) -> Result<&'a [u8], ErrorLibroDurable> {
        if self.i + n > self.buf.len() {
            return Err(ErrorLibroDurable::Corrupto);
        }
        let s = &self.buf[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ErrorLibroDurable> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, ErrorLibroDurable> {
        let mut a = [0u8; 4];
        a.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(a))
    }
    fn u64(&mut self) -> Result<u64, ErrorLibroDurable> {
        let mut a = [0u8; 8];
        a.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(a))
    }
    fn bytes(&mut self) -> Result<&'a [u8], ErrorLibroDurable> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, ErrorLibroDurable> {
        let b = self.bytes()?;
        String::from_utf8(b.to_vec()).map_err(|_| ErrorLibroDurable::Corrupto)
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.i)
    }
}

fn encode_hecho(out: &mut Vec<u8>, h: &HechoFirmadoLibro) {
    put_str(out, h.tipo.token());
    put_str(out, h.sistema.como_str());
    match h.clase {
        Some(c) => {
            out.push(1);
            put_str(out, c.token());
        }
        None => out.push(0),
    }
    out.push(u8::from(h.valor));
    put_str(out, h.productor.token());
    put_u32(out, h.version);
    put_u64(out, h.epoca);
    put_u64(out, h.emitido_en);
    put_u64(out, h.antigüedad_max);
    put_bytes(out, &h.digest);
    put_bytes(out, &h.firma);
    put_bytes(out, &h.pk_firmante);
    put_str(out, h.no_demuestra);
}

fn decode_hecho(r: &mut Lector<'_>) -> Result<HechoFirmadoLibro, ErrorLibroDurable> {
    let tipo = TipoHecho::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?;
    let sistema = IdSistema::nuevo(r.str()?).map_err(|_| ErrorLibroDurable::Corrupto)?;
    let clase = if r.u8()? == 1 {
        Some(ClaseEfecto::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?)
    } else {
        None
    };
    let valor = r.u8()? != 0;
    let productor = ProductorHecho::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?;
    let version = r.u32()?;
    let epoca = r.u64()?;
    let emitido_en = r.u64()?;
    let antigüedad_max = r.u64()?;
    let dig_b = r.bytes()?;
    if dig_b.len() != LONGITUD_HASH_PAQUETE {
        return Err(ErrorLibroDurable::Corrupto);
    }
    let mut digest = [0u8; LONGITUD_HASH_PAQUETE];
    digest.copy_from_slice(dig_b);
    let firma = r.bytes()?.to_vec();
    let pk_firmante = r.bytes()?.to_vec();
    let _no = r.str()?;
    let _ = antigüedad_maxima(tipo); // coerencia de tipo conocida
    Ok(HechoFirmadoLibro {
        tipo,
        sistema,
        clase,
        valor,
        productor,
        version,
        epoca,
        emitido_en,
        antigüedad_max,
        digest,
        firma,
        pk_firmante,
        no_demuestra: NO_DEMUESTRA_RESTAURADO,
    })
}

fn encode_inv(out: &mut Vec<u8>, inv: &InventarioAlcanzables) {
    put_str(out, inv.sistema.como_str());
    put_str(out, &inv.instancia);
    put_u32(out, inv.efectores.len() as u32);
    for e in &inv.efectores {
        put_str(out, e.token());
    }
    put_u32(out, inv.rutas_red.len() as u32);
    for s in &inv.rutas_red {
        put_str(out, s);
    }
    put_u32(out, inv.credenciales_detectadas.len() as u32);
    for s in &inv.credenciales_detectadas {
        put_str(out, s);
    }
    put_u32(out, inv.almacenes.len() as u32);
    for s in &inv.almacenes {
        put_str(out, s);
    }
    put_u32(out, inv.puntos_servicio.len() as u32);
    for s in &inv.puntos_servicio {
        put_str(out, s);
    }
    put_u32(out, inv.canales_consumo.len() as u32);
    for s in &inv.canales_consumo {
        put_str(out, s);
    }
    out.push(u8::from(inv.incompleto_declarado));
    put_u32(out, inv.version);
    put_u64(out, inv.epoca);
    put_u64(out, inv.emitido_en);
    put_u64(out, inv.antigüedad_max);
    put_str(out, inv.productor.token());
    put_str(out, &inv.productor_id);
    put_bytes(out, &inv.digest);
    put_bytes(out, &inv.firma);
    put_bytes(out, &inv.pk_firmante);
}

fn decode_set_str(r: &mut Lector<'_>) -> Result<BTreeSet<String>, ErrorLibroDurable> {
    let n = r.u32()? as usize;
    let mut s = BTreeSet::new();
    for _ in 0..n {
        s.insert(r.str()?);
    }
    Ok(s)
}

fn decode_inv(r: &mut Lector<'_>) -> Result<InventarioAlcanzables, ErrorLibroDurable> {
    let sistema = IdSistema::nuevo(r.str()?).map_err(|_| ErrorLibroDurable::Corrupto)?;
    let instancia = r.str()?;
    let n_ef = r.u32()? as usize;
    let mut efectores = BTreeSet::new();
    for _ in 0..n_ef {
        efectores.insert(ClaseEfecto::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?);
    }
    let rutas_red = decode_set_str(r)?;
    let credenciales_detectadas = decode_set_str(r)?;
    let almacenes = decode_set_str(r)?;
    let puntos_servicio = decode_set_str(r)?;
    let canales_consumo = decode_set_str(r)?;
    let incompleto_declarado = r.u8()? != 0;
    let version = r.u32()?;
    let epoca = r.u64()?;
    let emitido_en = r.u64()?;
    let antigüedad_max = r.u64()?;
    let productor = ProductorHecho::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?;
    let productor_id = r.str()?;
    let dig_b = r.bytes()?;
    if dig_b.len() != LONGITUD_HASH_PAQUETE {
        return Err(ErrorLibroDurable::Corrupto);
    }
    let mut digest = [0u8; LONGITUD_HASH_PAQUETE];
    digest.copy_from_slice(dig_b);
    let firma = r.bytes()?.to_vec();
    let pk_firmante = r.bytes()?.to_vec();
    Ok(InventarioAlcanzables {
        sistema,
        instancia,
        efectores,
        rutas_red,
        credenciales_detectadas,
        almacenes,
        puntos_servicio,
        canales_consumo,
        incompleto_declarado,
        version,
        epoca,
        emitido_en,
        antigüedad_max,
        productor,
        productor_id,
        digest,
        firma,
        pk_firmante,
        no_demuestra: InventarioAlcanzables::NO_DEMUESTRA,
    })
}

fn encode_par(out: &mut Vec<u8>, p: &ParSistemaClase) {
    put_str(out, p.sistema.como_str());
    put_str(out, p.clase.token());
}

fn decode_par(r: &mut Lector<'_>) -> Result<ParSistemaClase, ErrorLibroDurable> {
    Ok(ParSistemaClase {
        sistema: IdSistema::nuevo(r.str()?).map_err(|_| ErrorLibroDurable::Corrupto)?,
        clase: ClaseEfecto::desde_token(&r.str()?).ok_or(ErrorLibroDurable::Corrupto)?,
    })
}

fn encode_libro(libro: &LibroControl) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    put_u32(&mut out, libro.hechos().len() as u32);
    for h in libro.hechos() {
        encode_hecho(&mut out, h);
    }
    put_u32(&mut out, libro.alcanzables_map().len() as u32);
    for inv in libro.alcanzables_map().values() {
        encode_inv(&mut out, inv);
    }
    put_u32(&mut out, libro.techos().len() as u32);
    for (p, n) in libro.techos() {
        encode_par(&mut out, p);
        out.push(*n as u8);
    }
    put_u32(&mut out, libro.suspendidas().len() as u32);
    for p in libro.suspendidas() {
        encode_par(&mut out, p);
    }
    put_u32(&mut out, libro.forzar_c0_set().len() as u32);
    for p in libro.forzar_c0_set() {
        encode_par(&mut out, p);
    }
    put_u32(&mut out, libro.historial().len() as u32);
    for (p, n, causa, epoca) in libro.historial() {
        encode_par(&mut out, p);
        out.push(*n as u8);
        put_str(&mut out, causa);
        put_u64(&mut out, *epoca);
    }
    out
}

fn decode_libro(bytes: &[u8]) -> Result<LibroControl, ErrorLibroDurable> {
    let mut r = Lector::new(bytes);
    if r.take(MAGIC.len())? != MAGIC {
        return Err(ErrorLibroDurable::Corrupto);
    }
    let n_h = r.u32()? as usize;
    let mut hechos = Vec::with_capacity(n_h);
    for _ in 0..n_h {
        let h = decode_hecho(&mut r)?;
        if h.integridad_ok() {
            hechos.push(h);
        }
    }
    let n_a = r.u32()? as usize;
    let mut alcanzables = HashMap::new();
    for _ in 0..n_a {
        let inv = decode_inv(&mut r)?;
        if inv.integridad_ok() {
            alcanzables.insert(inv.sistema.como_str().to_string(), inv);
        }
    }
    let n_t = r.u32()? as usize;
    let mut techos = HashMap::new();
    for _ in 0..n_t {
        let p = decode_par(&mut r)?;
        let n = NivelControl::desde_u8(r.u8()?).ok_or(ErrorLibroDurable::Corrupto)?;
        techos.insert(p, n);
    }
    let n_s = r.u32()? as usize;
    let mut suspendidas = BTreeSet::new();
    for _ in 0..n_s {
        suspendidas.insert(decode_par(&mut r)?);
    }
    let n_f = r.u32()? as usize;
    let mut forzar_c0 = BTreeSet::new();
    for _ in 0..n_f {
        forzar_c0.insert(decode_par(&mut r)?);
    }
    let n_hist = r.u32()? as usize;
    let mut historial = Vec::with_capacity(n_hist);
    for _ in 0..n_hist {
        let p = decode_par(&mut r)?;
        let n = NivelControl::desde_u8(r.u8()?).ok_or(ErrorLibroDurable::Corrupto)?;
        let causa = r.str()?;
        let epoca = r.u64()?;
        historial.push((p, n, causa, epoca));
    }
    if r.remaining() != 0 {
        return Err(ErrorLibroDurable::Corrupto);
    }
    let mut libro = LibroControl::nuevo();
    libro.restaurar_estado(hechos, alcanzables, techos, suspendidas, forzar_c0, historial);
    Ok(libro)
}

/// Persiste el snapshot completo del Libro (sobrescribible).
pub fn conservar_libro(
    almacen: &mut dyn AlmacenEvidencia,
    libro: &LibroControl,
) -> Result<(), ErrorLibroDurable> {
    let blob = encode_libro(libro);
    almacen
        .escribir_durable(CLAVE_SNAPSHOT, &blob)
        .map_err(|_| ErrorLibroDurable::Codificacion)
}

/// Carga el Libro; si no hay snapshot, devuelve Libro vacío (C0).
pub fn cargar_libro_desde_almacen(
    almacen: &dyn AlmacenEvidencia,
) -> Result<LibroControl, ErrorLibroDurable> {
    match almacen.leer(CLAVE_SNAPSHOT) {
        None => Ok(LibroControl::nuevo()),
        Some(b) => decode_libro(&b),
    }
}

pub fn clave_almacen_libro() -> &'static [u8] {
    CLAVE_SNAPSHOT
}
