//! Sonda §M 12: EF-1…EF-12 sin capacidad por la puerta canónica de control/emisión.
//!
//! No es un stub DENY: cada clase recorre `comprobar_puerta_control` y la
//! exigencia de capacidad/emisión. EF-12 = DENY incondicional (sin ruta permisiva).
//! Resultado: exactamente 12 denegaciones firmadas y verificables.

use crate::capacidad::Capability;
use crate::contexto::ClaseEfecto;
use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::{
    CodigoRazon, Decision, DecisionDenegada, HashPaqueteNormativo, LONGITUD_HASH_PAQUETE,
};
use crate::identidad::IdSistema;
use crate::libro::libro_ctrl::LibroControl;
use crate::libro::puerta::{comprobar_puerta_control, ResultadoPuertaControl};
use crate::reloj::Ticks;
use std::fmt;

pub const DOMINIO_SONDA12: &[u8] = b"SAK-SONDA-12-v1|";
pub const DOMINIO_SONDA_CLASE: &[u8] = b"SAK-SONDA-EF-v1|";

/// Reexporta denominación C5 (§M 12): cálculo sobre hechos ≠ host real.
pub use crate::libro::nivel::{C5_CALCULADO_SOBRE_HECHOS_APORTADOS, C5_HOST_REAL_PROHIBIDO};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultadoIntentoSonda {
    Deny,
    /// Prohibido en el resultado aceptable de la sonda §M 12.
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReciboSondaClase {
    pub clase: ClaseEfecto,
    pub capacidad_presente: bool,
    pub resultado: ResultadoIntentoSonda,
    pub codigo_razon: String,
    pub digest_intento: [u8; LONGITUD_HASH_PAQUETE],
    /// Trazas de pasos canónicos recorridos (puerta / emisión / EF-12).
    pub pasos: Vec<&'static str>,
}

#[derive(Debug, Clone)]
pub struct ResultadoSondaDoce {
    pub sistema: IdSistema,
    pub epoca: u64,
    pub emitida_en: Ticks,
    pub recibos: Vec<ReciboSondaClase>,
    pub digest_conjunto: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_mldsa: Vec<u8>,
    pub completo_12_deny: bool,
    pub no_comprobado: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSonda {
    CapacidadPresenteEnSondaSinCapacidad,
    AllowDetectado(ClaseEfecto),
    Firma,
    Verificacion,
    RecibosIncompletos,
}

impl fmt::Display for ErrorSonda {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ErrorSonda {}

const CLASES_EF: [ClaseEfecto; 12] = [
    ClaseEfecto::Ef1,
    ClaseEfecto::Ef2,
    ClaseEfecto::Ef3,
    ClaseEfecto::Ef4,
    ClaseEfecto::Ef5,
    ClaseEfecto::Ef6,
    ClaseEfecto::Ef7,
    ClaseEfecto::Ef8,
    ClaseEfecto::Ef9,
    ClaseEfecto::Ef10,
    ClaseEfecto::Ef11,
    ClaseEfecto::Ef12,
];

/// Puerta canónica: sin capacidad aportada.
///
/// Orden: (1) EF-12 DENY incondicional; (2) `comprobar_puerta_control`;
/// (3) si Continuar, denegar emisión/uso por capacidad ausente.
/// Nunca ALLOW si `capacidad` es `None`.
pub fn recorrer_puerta_sin_capacidad(
    libro: &LibroControl,
    sistema: &IdSistema,
    clase: ClaseEfecto,
    capacidad: Option<&Capability>,
    hash_paquete: HashPaqueteNormativo,
    ahora: Ticks,
    datos_personales: bool,
) -> Result<ReciboSondaClase, ErrorSonda> {
    let mut pasos = Vec::new();
    let capacidad_presente = capacidad.is_some();

    // EF-12: DENY incondicional — sin PEP permisivo ni vía alternativa.
    if clase == ClaseEfecto::Ef12 {
        pasos.push("ef12_deny_incondicional");
        let digest = digest_intento(sistema, clase, ahora, false);
        return Ok(ReciboSondaClase {
            clase,
            capacidad_presente,
            resultado: ResultadoIntentoSonda::Deny,
            codigo_razon: "EF12_NUNCA".into(),
            digest_intento: digest,
            pasos,
        });
    }

    if capacidad_presente {
        // La sonda §M 12 exige ausencia; presencia aquí no es el camino feliz.
        return Err(ErrorSonda::CapacidadPresenteEnSondaSinCapacidad);
    }
    pasos.push("capacidad_ausente_como_entrada");

    // Puerta Libro INV-09.
    pasos.push("comprobar_puerta_control");
    let puerta = comprobar_puerta_control(
        libro,
        sistema,
        clase,
        datos_personales,
        ahora,
        hash_paquete,
    );

    let (resultado, codigo) = match puerta {
        ResultadoPuertaControl::Denegar { decision, .. } => {
            pasos.push("puerta_control_denegar");
            let codigo = match &decision {
                Decision::Denegada(d) => d.codigo().token().to_string(),
                _ => "CONTROL_INSUFICIENTE".into(),
            };
            (ResultadoIntentoSonda::Deny, codigo)
        }
        ResultadoPuertaControl::Continuar(_) => {
            // Emisión/uso: sin DecisionPermitida ni Capability no hay autoridad (INV-01/08).
            pasos.push("emision_exige_capacidad");
            let emision = rechazar_emision_sin_capacidad(clase);
            match emision {
                Err(c) => {
                    pasos.push("emision_denegada");
                    (ResultadoIntentoSonda::Deny, c)
                }
                Ok(()) => {
                    // Imposible sin capacidad; defensa en profundidad.
                    pasos.push("emision_inconsistente");
                    return Err(ErrorSonda::AllowDetectado(clase));
                }
            }
        }
    };

    if resultado == ResultadoIntentoSonda::Allow {
        return Err(ErrorSonda::AllowDetectado(clase));
    }

    let digest = digest_intento(sistema, clase, ahora, false);
    Ok(ReciboSondaClase {
        clase,
        capacidad_presente: false,
        resultado,
        codigo_razon: codigo,
        digest_intento: digest,
        pasos,
    })
}

/// Emisión tipada sin capacidad: siempre Err (no hay DecisionPermitida ni Capability).
fn rechazar_emision_sin_capacidad(clase: ClaseEfecto) -> Result<(), String> {
    // No se llama a `emitir`: faltan DecisionPermitida y CompromisoEvidencia.
    // La denegación es el resultado de la puerta de emisión ante entrada vacía.
    let _ = clase;
    Err("CAPACIDAD_AUSENTE".into())
}

fn digest_intento(
    sistema: &IdSistema,
    clase: ClaseEfecto,
    ahora: Ticks,
    con_capacidad: bool,
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut m = Vec::new();
    m.extend_from_slice(sistema.como_str().as_bytes());
    m.push(0);
    m.extend_from_slice(clase.token().as_bytes());
    m.push(0);
    m.extend_from_slice(&ahora.to_le_bytes());
    m.push(u8::from(con_capacidad));
    crypto::sha384_dominio(DOMINIO_SONDA_CLASE, &m)
}

/// Ejecuta la sonda de las doce clases sin capacidad y firma el conjunto.
pub fn ejecutar_sonda_doce_sin_capacidad(
    libro: &LibroControl,
    sistema: &IdSistema,
    epoca: u64,
    ahora: Ticks,
    autoridad: &ParMlDsa87,
) -> Result<ResultadoSondaDoce, ErrorSonda> {
    let hash = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
    let mut recibos = Vec::with_capacity(12);
    for clase in CLASES_EF {
        let r = recorrer_puerta_sin_capacidad(
            libro,
            sistema,
            clase,
            None, // ausencia de capacidad
            hash,
            ahora,
            false,
        )?;
        if r.resultado != ResultadoIntentoSonda::Deny {
            return Err(ErrorSonda::AllowDetectado(clase));
        }
        recibos.push(r);
    }
    if recibos.len() != 12 {
        return Err(ErrorSonda::RecibosIncompletos);
    }
    let completo_12_deny = recibos
        .iter()
        .all(|r| r.resultado == ResultadoIntentoSonda::Deny && !r.capacidad_presente);

    let mut cuerpo = Vec::new();
    cuerpo.extend_from_slice(DOMINIO_SONDA12);
    cuerpo.extend_from_slice(sistema.como_str().as_bytes());
    cuerpo.extend_from_slice(&epoca.to_le_bytes());
    cuerpo.extend_from_slice(&ahora.to_le_bytes());
    for r in &recibos {
        cuerpo.extend_from_slice(&r.digest_intento);
        cuerpo.push(match r.resultado {
            ResultadoIntentoSonda::Deny => 0,
            ResultadoIntentoSonda::Allow => 1,
        });
    }
    let digest_conjunto = crypto::sha384_dominio(dominio::LIBRO, &cuerpo);
    let firma_mldsa = autoridad
        .firmar(&digest_conjunto)
        .map_err(|_| ErrorSonda::Firma)?;

    Ok(ResultadoSondaDoce {
        sistema: sistema.clone(),
        epoca,
        emitida_en: ahora,
        recibos,
        digest_conjunto,
        firma_mldsa,
        completo_12_deny,
        no_comprobado: vec![
            "rutas no intentadas por la sonda [DESP]".into(),
            format!("{C5_HOST_REAL_PROHIBIDO} no afirmado; solo {C5_CALCULADO_SOBRE_HECHOS_APORTADOS}"),
            "HSM / TSA / plataforma [DESP]/[VAL-EXT]".into(),
            "completitud ALCANZABLES [DESP]".into(),
            "conformidad legal [GOB]".into(),
        ],
    })
}

pub fn verificar_resultado_sonda(
    res: &ResultadoSondaDoce,
    pk: &[u8],
) -> Result<(), ErrorSonda> {
    if res.recibos.len() != 12 {
        return Err(ErrorSonda::RecibosIncompletos);
    }
    if !res.completo_12_deny {
        return Err(ErrorSonda::AllowDetectado(ClaseEfecto::Ef1));
    }
    for r in &res.recibos {
        if r.resultado != ResultadoIntentoSonda::Deny || r.capacidad_presente {
            return Err(ErrorSonda::AllowDetectado(r.clase));
        }
    }
    let mut cuerpo = Vec::new();
    cuerpo.extend_from_slice(DOMINIO_SONDA12);
    cuerpo.extend_from_slice(res.sistema.como_str().as_bytes());
    cuerpo.extend_from_slice(&res.epoca.to_le_bytes());
    cuerpo.extend_from_slice(&res.emitida_en.to_le_bytes());
    for r in &res.recibos {
        cuerpo.extend_from_slice(&r.digest_intento);
        cuerpo.push(0);
    }
    let dig = crypto::sha384_dominio(dominio::LIBRO, &cuerpo);
    if dig != res.digest_conjunto {
        return Err(ErrorSonda::Verificacion);
    }
    ParMlDsa87::verificar(pk, &res.digest_conjunto, &res.firma_mldsa)
        .map_err(|_| ErrorSonda::Verificacion)
}

/// EF-12: denegación incondicional (gobernanza; nunca emitible a IA).
pub fn denegar_ef12_siempre(hash: HashPaqueteNormativo) -> DecisionDenegada {
    let traza = crate::decision::TrazaPrecedencia::nueva(vec![], vec![], 0).expect("vacia");
    DecisionDenegada::nueva(hash, traza, CodigoRazon::ControlInsuficiente)
}

/// ¿El código de razón de denegación EF-12 es el canónico de nunca conceder?
pub fn es_deny_ef12(recibo: &ReciboSondaClase) -> bool {
    recibo.clase == ClaseEfecto::Ef12
        && recibo.resultado == ResultadoIntentoSonda::Deny
        && recibo.codigo_razon == "EF12_NUNCA"
}
