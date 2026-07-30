//! Atestación de confinamiento §M 12 / I.10 — ocho predicados por época.
//!
//! Emite el hecho `CONFINADO(s)` (antigüedad máx. 300 s). **No** afirma
//! corrección del anfitrión, HSM, TSA, C5 de host, exclusividad de red real
//! ni completitud de `ALCANZABLES` (`no_comprobado` / [DESP] / [VAL-EXT]).

use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::IdSistema;
use crate::libro::hecho::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use crate::libro::libro_ctrl::LibroControl;
use crate::reloj::Ticks;
use std::fmt;

/// Antigüedad máxima del hecho CONFINADO (D.3): 300 s.
pub const ANTIGUEDAD_CONFINADO_TICKS: Ticks = 300_000;

pub const DOMINIO_ATESTACION: &[u8] = b"SAK-CONFINADO-ATEST-v1|";

/// Identificador de la decisión de implementación del predicado 6 (10/10),
/// distinto de la sonda §M de doce clases EF.
pub const PREDICADO6_SONDA_DIEZ_V1: &str = "SAK-I10-SONDA-10-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdPredicadoI10 {
    AmbienteVacio = 1,
    HashSuperficieBlanca = 2,
    SinFuncionesFuera = 3,
    EnlazadoEstatico = 4,
    PepLatido = 5,
    SondaDiezDeDiez = 6,
    SondaEgreso = 7,
    AutotestCripto = 8,
}

impl IdPredicadoI10 {
    pub fn token(self) -> &'static str {
        match self {
            IdPredicadoI10::AmbienteVacio => "P1_ambiente_vacio",
            IdPredicadoI10::HashSuperficieBlanca => "P2_hash_superficie",
            IdPredicadoI10::SinFuncionesFuera => "P3_sin_funciones_fuera",
            IdPredicadoI10::EnlazadoEstatico => "P4_enlazado_estatico",
            IdPredicadoI10::PepLatido => "P5_pep_latido",
            IdPredicadoI10::SondaDiezDeDiez => "P6_sonda_10_10",
            IdPredicadoI10::SondaEgreso => "P7_sonda_egreso",
            IdPredicadoI10::AutotestCripto => "P8_autotest_cripto",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PredicadoEvaluado {
    pub id: IdPredicadoI10,
    pub ok: bool,
    pub digest_evidencia: [u8; LONGITUD_HASH_PAQUETE],
}

/// Entrada de evaluación de los ocho predicados (harness / runtime simulado).
#[derive(Debug, Clone)]
pub struct EntradaPredicadosI10 {
    pub ambiente_vacio: bool,
    pub superficie_blanca_canonica: Vec<u8>,
    pub funciones_expuestas: Vec<u8>,
    pub sin_carga_dinamica: bool,
    pub pep_latido_ok: bool,
    /// Exactamente 10 denegaciones de sonda de superficie I.10.
    pub denegaciones_sonda_diez: u8,
    pub egreso_sin_ruta_alternativa: bool,
    pub autotest_cripto_ok: bool,
}

impl EntradaPredicadosI10 {
    pub fn evaluar(&self) -> [PredicadoEvaluado; 8] {
        let hash_sup = crypto::sha384_dominio(DOMINIO_ATESTACION, &self.superficie_blanca_canonica);
        let dig = |tag: &[u8], ok: bool| {
            let mut m = Vec::new();
            m.extend_from_slice(tag);
            m.push(u8::from(ok));
            crypto::sha384_dominio(DOMINIO_ATESTACION, &m)
        };
        let p2_ok = !self.superficie_blanca_canonica.is_empty();
        let p3_ok = self.funciones_expuestas == self.superficie_blanca_canonica;
        let p6_ok = self.denegaciones_sonda_diez == 10;
        [
            PredicadoEvaluado {
                id: IdPredicadoI10::AmbienteVacio,
                ok: self.ambiente_vacio,
                digest_evidencia: dig(b"P1", self.ambiente_vacio),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::HashSuperficieBlanca,
                ok: p2_ok,
                digest_evidencia: hash_sup,
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::SinFuncionesFuera,
                ok: p3_ok,
                digest_evidencia: dig(b"P3", p3_ok),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::EnlazadoEstatico,
                ok: self.sin_carga_dinamica,
                digest_evidencia: dig(b"P4", self.sin_carga_dinamica),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::PepLatido,
                ok: self.pep_latido_ok,
                digest_evidencia: dig(b"P5", self.pep_latido_ok),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::SondaDiezDeDiez,
                ok: p6_ok,
                digest_evidencia: dig(PREDICADO6_SONDA_DIEZ_V1.as_bytes(), p6_ok),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::SondaEgreso,
                ok: self.egreso_sin_ruta_alternativa,
                digest_evidencia: dig(b"P7", self.egreso_sin_ruta_alternativa),
            },
            PredicadoEvaluado {
                id: IdPredicadoI10::AutotestCripto,
                ok: self.autotest_cripto_ok,
                digest_evidencia: dig(b"P8", self.autotest_cripto_ok),
            },
        ]
    }

    pub fn todos_ok(&self) -> bool {
        self.evaluar().iter().all(|p| p.ok)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorConfinamiento {
    PredicadoFallo(IdPredicadoI10),
    Firma,
    Caducada,
    SistemaVacio,
}

impl fmt::Display for ErrorConfinamiento {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ErrorConfinamiento {}

#[derive(Debug, Clone)]
pub struct AtestacionConfinamiento {
    pub sistema: IdSistema,
    pub epoca: u64,
    pub emitida_en: Ticks,
    pub predicados: [PredicadoEvaluado; 8],
    pub hash_superficie_blanca: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_mldsa: Vec<u8>,
    pub no_comprobado: Vec<String>,
}

impl AtestacionConfinamiento {
    pub fn limites_declarados() -> Vec<String> {
        vec![
            "correccion del anfitrion / TCB [DESP]".into(),
            "HSM / titularidad real de claves [DESP]".into(),
            "TSA [VAL-EXT]".into(),
            "atestacion de plataforma hardware [VAL-EXT]".into(),
            "C5_HOST_REAL — no afirmado; solo C5_CALCULADO_SOBRE_HECHOS_APORTADOS".into(),
            "exclusividad real de red [DESP]".into(),
            "completitud ALCANZABLES [DESP]".into(),
            "conformidad legal [GOB]".into(),
            "testigo honesto [DESP]".into(),
        ]
    }

    pub fn canonico_sin_firma(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(DOMINIO_ATESTACION);
        v.extend_from_slice(self.sistema.como_str().as_bytes());
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.emitida_en.to_le_bytes());
        v.extend_from_slice(&self.hash_superficie_blanca);
        for p in &self.predicados {
            v.extend_from_slice(p.id.token().as_bytes());
            v.push(u8::from(p.ok));
            v.extend_from_slice(&p.digest_evidencia);
        }
        v
    }

    pub fn emitir(
        sistema: IdSistema,
        epoca: u64,
        ahora: Ticks,
        entrada: &EntradaPredicadosI10,
        autoridad: &ParMlDsa87,
    ) -> Result<Self, ErrorConfinamiento> {
        if sistema.como_str().is_empty() {
            return Err(ErrorConfinamiento::SistemaVacio);
        }
        let predicados = entrada.evaluar();
        for p in &predicados {
            if !p.ok {
                return Err(ErrorConfinamiento::PredicadoFallo(p.id));
            }
        }
        let hash_superficie_blanca =
            crypto::sha384_dominio(DOMINIO_ATESTACION, &entrada.superficie_blanca_canonica);
        let mut at = AtestacionConfinamiento {
            sistema,
            epoca,
            emitida_en: ahora,
            predicados,
            hash_superficie_blanca,
            digest_paquete: [0u8; LONGITUD_HASH_PAQUETE],
            firma_mldsa: Vec::new(),
            no_comprobado: Self::limites_declarados(),
        };
        let cuerpo = at.canonico_sin_firma();
        at.digest_paquete = crypto::sha384_dominio(dominio::LIBRO, &cuerpo);
        at.firma_mldsa = autoridad
            .firmar(&at.digest_paquete)
            .map_err(|_| ErrorConfinamiento::Firma)?;
        Ok(at)
    }

    pub fn verificar(&self, pk: &[u8], ahora: Ticks) -> Result<(), ErrorConfinamiento> {
        if ahora.saturating_sub(self.emitida_en) > ANTIGUEDAD_CONFINADO_TICKS {
            return Err(ErrorConfinamiento::Caducada);
        }
        if !self.predicados.iter().all(|p| p.ok) {
            if let Some(p) = self.predicados.iter().find(|p| !p.ok) {
                return Err(ErrorConfinamiento::PredicadoFallo(p.id));
            }
        }
        let cuerpo = self.canonico_sin_firma();
        let dig = crypto::sha384_dominio(dominio::LIBRO, &cuerpo);
        if dig != self.digest_paquete {
            return Err(ErrorConfinamiento::Firma);
        }
        ParMlDsa87::verificar(pk, &self.digest_paquete, &self.firma_mldsa)
            .map_err(|_| ErrorConfinamiento::Firma)
    }

    /// Registra hecho CONFINADO=true en el Libro (productor atestación).
    pub fn registrar_hecho_en_libro(
        &self,
        libro: &mut LibroControl,
        firmante: &ParMlDsa87,
    ) -> Result<(), crate::crypto::ErrorCrypto> {
        let hecho = HechoFirmadoLibro::firmar(
            TipoHecho::Confinado,
            self.sistema.clone(),
            None,
            true,
            1,
            self.epoca,
            self.emitida_en,
            InventarioAlcanzables::NO_DEMUESTRA,
            firmante,
        )?;
        libro.registrar_hecho(hecho);
        Ok(())
    }
}
