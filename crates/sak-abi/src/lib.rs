//! Frontera externa cerrada: exactamente los 8 símbolos de `SYMBOLS.lock`.
//!
//! Fuente canónica: Matriz Maestra v1.1 — INV-01, INV-06, E.1 y L-01.
//!
//! Convención de memoria: buffers del llamador o salida de tamaño fijo.
//! No existe símbolo de liberación. El `unsafe` queda confinado a la lectura
//! y escritura de esos buffers.

use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::decision::{
    CodigoRazon, Decision, HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE,
};
use sak_core::motor::decidir;
use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
use std::ptr;
use std::slice;

/// Código de éxito.
pub const SAK_OK: i32 = 0;
/// Buffer nulo o tamaño insuficiente.
pub const SAK_ERR_BUFFER: i32 = -1;
/// Entrada mal formada.
pub const SAK_ERR_ENTRADA: i32 = -2;
/// Operación no disponible en este bloque (superficie presente, cuerpo diferido).
pub const SAK_ERR_NO_DISPONIBLE: i32 = -3;

/// Salida fija de `sak_decidir` (48 bytes de hash + campos escalares).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SakDecisionFija {
    /// 0=DENY, 1=SUSPEND, 2=ESCALATE, 3=ALLOW.
    pub veredicto: u8,
    /// 255 = sin código; en otro caso discriminante de `CodigoRazon`.
    pub codigo: u8,
    pub _pad: [u8; 2],
    pub pasos_consumidos: u32,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

/// Entrada fija mínima de `sak_decidir` para el Bloque 1.
///
/// `clase`: 1..=12. `predicado_veredicto`: 0..=3 como `Veredicto`.
/// Si `tiene_norma` es 0, el perfil no aporta normas ⇒ `SIN_NORMA_APLICABLE`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SakDecisionEntrada {
    pub clase: u8,
    pub tiene_norma: u8,
    pub predicado_veredicto: u8,
    pub ambigua: u8,
    pub pasos_predicado: u32,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
}

fn escribir_buf(dest: *mut u8, dest_len: usize, src: &[u8]) -> i32 {
    if dest.is_null() || dest_len < src.len() {
        return SAK_ERR_BUFFER;
    }
    unsafe {
        ptr::copy_nonoverlapping(src.as_ptr(), dest, src.len());
    }
    src.len() as i32
}

fn veredicto_a_u8(v: Veredicto) -> u8 {
    match v {
        Veredicto::Deny => 0,
        Veredicto::Suspend => 1,
        Veredicto::Escalate => 2,
        Veredicto::Allow => 3,
    }
}

fn codigo_a_u8(c: Option<CodigoRazon>) -> u8 {
    match c {
        None => 255,
        Some(CodigoRazon::SinNormaAplicable) => 0,
        Some(CodigoRazon::PrecedenciaAplicada) => 1,
        Some(CodigoRazon::ConflictoJurisdiccion) => 2,
        Some(CodigoRazon::EvidenciaAusente) => 3,
        Some(CodigoRazon::NormaNoEvaluable) => 4,
        Some(CodigoRazon::AmbiguedadDeclarada) => 5,
        Some(CodigoRazon::FueraDeAlcanceTecnico) => 6,
        Some(CodigoRazon::ControlInsuficiente) => 7,
        Some(CodigoRazon::PerfilObsoleto) => 8,
        Some(CodigoRazon::QuorumSupervision) => 9,
    }
}

fn u8_a_veredicto(v: u8) -> Option<Veredicto> {
    match v {
        0 => Some(Veredicto::Deny),
        1 => Some(Veredicto::Suspend),
        2 => Some(Veredicto::Escalate),
        3 => Some(Veredicto::Allow),
        _ => None,
    }
}

fn u8_a_clase(c: u8) -> Option<ClaseEfecto> {
    match c {
        1 => Some(ClaseEfecto::Ef1),
        2 => Some(ClaseEfecto::Ef2),
        3 => Some(ClaseEfecto::Ef3),
        4 => Some(ClaseEfecto::Ef4),
        5 => Some(ClaseEfecto::Ef5),
        6 => Some(ClaseEfecto::Ef6),
        7 => Some(ClaseEfecto::Ef7),
        8 => Some(ClaseEfecto::Ef8),
        9 => Some(ClaseEfecto::Ef9),
        10 => Some(ClaseEfecto::Ef10),
        11 => Some(ClaseEfecto::Ef11),
        12 => Some(ClaseEfecto::Ef12),
        _ => None,
    }
}

fn decision_a_fija(d: &Decision) -> SakDecisionFija {
    SakDecisionFija {
        veredicto: veredicto_a_u8(d.veredicto()),
        codigo: codigo_a_u8(d.codigo()),
        _pad: [0, 0],
        pasos_consumidos: d.traza().pasos_consumidos(),
        hash_paquete: *d.hash_paquete().bytes(),
    }
}

/// Pedir decisión. Escribe una [`SakDecisionFija`] en `salida` (tamaño fijo).
#[no_mangle]
pub extern "C" fn sak_decidir(
    entrada: *const SakDecisionEntrada,
    salida: *mut SakDecisionFija,
) -> i32 {
    if entrada.is_null() || salida.is_null() {
        return SAK_ERR_BUFFER;
    }
    let ent = unsafe { *entrada };
    let Some(clase) = u8_a_clase(ent.clase) else {
        return SAK_ERR_ENTRADA;
    };
    let efecto = EfectoTipado::nuevo(clase, ent.digest_parametros);
    let ctx = Contexto::nuevo(efecto, vec![]);
    let hash = HashPaqueteNormativo::desde_bytes(ent.hash_paquete);

    let perfil = if ent.tiene_norma == 0 {
        PerfilNormativo::nuevo(hash, vec![], false)
    } else {
        let Some(veredicto) = u8_a_veredicto(ent.predicado_veredicto) else {
            return SAK_ERR_ENTRADA;
        };
        let predicado = if ent.pasos_predicado <= 1 {
            PredicadoMinimo::Constante(veredicto)
        } else {
            PredicadoMinimo::ConsumirPasos {
                pasos: ent.pasos_predicado,
                veredicto,
            }
        };
        let Ok(id) = IdNorma::nueva("ABI-N1") else {
            return SAK_ERR_ENTRADA;
        };
        let norma = NormaMinima::nueva(id, Rango::P2, clase, predicado, ent.ambigua != 0);
        PerfilNormativo::nuevo(hash, vec![norma], false)
    };

    let decision = decidir(&ctx, &perfil);
    unsafe {
        *salida = decision_a_fija(&decision);
    }
    SAK_OK
}

/// Ejercer capacidad. En el Bloque 1 la verificación de vigencia/época/unicidad
/// es del Bloque 5: la superficie existe; el cuerpo no concede autoridad.
#[no_mangle]
pub extern "C" fn sak_ejercer(
    _capacidad: *const u8,
    _capacidad_len: usize,
    _salida: *mut u8,
    _salida_len: usize,
) -> i32 {
    SAK_ERR_NO_DISPONIBLE
}

/// Observar estado del dominio. Escribe un token ASCII fijo en el buffer.
#[no_mangle]
pub extern "C" fn sak_estado(buf: *mut u8, buf_len: usize) -> i32 {
    escribir_buf(buf, buf_len, b"OPERATIVE")
}

/// Observar salud. Escribe un token ASCII fijo.
#[no_mangle]
pub extern "C" fn sak_salud(buf: *mut u8, buf_len: usize) -> i32 {
    escribir_buf(buf, buf_len, b"OK")
}

/// Exportar evidencia. Cuerpo diferido al Bloque 3; superficie presente.
#[no_mangle]
pub extern "C" fn sak_exportar_evidencia(
    _buf: *mut u8,
    _buf_len: usize,
) -> i32 {
    SAK_ERR_NO_DISPONIBLE
}

/// Verificar un paquete de evidencia. Cuerpo diferido al Bloque 3.
#[no_mangle]
pub extern "C" fn sak_verificar(
    _paquete: *const u8,
    _paquete_len: usize,
    _informe: *mut u8,
    _informe_len: usize,
) -> i32 {
    SAK_ERR_NO_DISPONIBLE
}

/// Versión del binario autoritativo.
#[no_mangle]
pub extern "C" fn sak_version(buf: *mut u8, buf_len: usize) -> i32 {
    escribir_buf(buf, buf_len, env!("CARGO_PKG_VERSION").as_bytes())
}

/// Describe la ABI: versión, esquema, capacidades públicas. Sin autoridad.
///
/// Formato ASCII fijo de una línea, terminado sin NUL obligatorio (el valor
/// de retorno es la longitud escrita).
#[no_mangle]
pub extern "C" fn sak_describir_abi(buf: *mut u8, buf_len: usize) -> i32 {
    // Hash de SYMBOLS.lock se sustituye por el token estable del Bloque 1;
    // el chequeo de coincidencia exacta de símbolos lo hace ci/check_symbols.ps1.
    let desc = b"sak-abi/0.1.0;esquema=fijo-v1;simbolos=8;symbols_lock=SYMBOLS.lock";
    escribir_buf(buf, buf_len, desc)
}

/// Lectura defensiva de un buffer del llamador (única zona `unsafe` documentada).
#[allow(dead_code)]
unsafe fn leer_buf<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if ptr.is_null() && len != 0 {
        return Err(SAK_ERR_BUFFER);
    }
    if len == 0 {
        return Ok(&[]);
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}
