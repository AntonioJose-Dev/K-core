//! Pruebas de bypass de la sección I (I.1–I.8). Cada una firma un resultado
//! con caducidad y declara explícitamente qué **no** demuestra.
//!
//! I.9 (atestación de plataforma) e I.10 (confinamiento real) quedan fuera
//! del Bloque 8 por mandato: no se afirma CONFINADO ni anti-host.

use crate::contexto::ClaseEfecto;
use crate::crypto::ParMlDsa87;
use crate::identidad::IdSistema;
use crate::libro::hecho::{HechoFirmadoLibro, TipoHecho};
use crate::reloj::Ticks;
use std::fmt;

/// Límites canónicos «qué no demuestra» (Matriz I).
pub mod limite_no_demuestra {
    pub const INVENTARIO: &str =
        "No demuestra ausencia de credenciales fuera de los ambitos inspeccionados";
    pub const ROTACION: &str =
        "No demuestra que no exista otro secreto de otra cuenta del mismo proveedor";
    pub const RECONCILIACION: &str =
        "No identifica por si sola que sistema produjo el consumo, ni detecta bajo umbral [VAL-EXT]";
    pub const EGRESO: &str =
        "No detecta tuneles sobre protocolo permitido ni canales encubiertos por DNS";
    pub const PEP: &str = "No demuestra que el PEP sea el unico camino al efector";
    pub const ESCANEO: &str =
        "No alcanza el interior de un binario, secreto en memoria ni proveedor no inventariado";
    pub const TRAMPA: &str =
        "Que no se usen no prueba que no exista otra ruta; solo atribuye si alguna se usa";
    pub const SONDA: &str =
        "No demuestra que esten cerradas las rutas que la sonda no intenta (limite fundamental)";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoPruebaBypass {
    InventarioCredenciales = 1,
    RotacionSecretosHeredados = 2,
    ReconciliacionProveedor = 3,
    ObservacionEgreso = 4,
    VerificacionPep = 5,
    EscaneoConfiguraciones = 6,
    CredencialesTrampa = 7,
    SondaAdversarial = 8,
}

impl TipoPruebaBypass {
    pub fn token(self) -> &'static str {
        match self {
            TipoPruebaBypass::InventarioCredenciales => "I1_INVENTARIO",
            TipoPruebaBypass::RotacionSecretosHeredados => "I2_ROTACION",
            TipoPruebaBypass::ReconciliacionProveedor => "I3_RECONCILIACION",
            TipoPruebaBypass::ObservacionEgreso => "I4_EGRESO",
            TipoPruebaBypass::VerificacionPep => "I5_PEP",
            TipoPruebaBypass::EscaneoConfiguraciones => "I6_ESCANEO",
            TipoPruebaBypass::CredencialesTrampa => "I7_TRAMPA",
            TipoPruebaBypass::SondaAdversarial => "I8_SONDA",
        }
    }

    pub fn no_demuestra(self) -> &'static str {
        match self {
            TipoPruebaBypass::InventarioCredenciales => limite_no_demuestra::INVENTARIO,
            TipoPruebaBypass::RotacionSecretosHeredados => limite_no_demuestra::ROTACION,
            TipoPruebaBypass::ReconciliacionProveedor => limite_no_demuestra::RECONCILIACION,
            TipoPruebaBypass::ObservacionEgreso => limite_no_demuestra::EGRESO,
            TipoPruebaBypass::VerificacionPep => limite_no_demuestra::PEP,
            TipoPruebaBypass::EscaneoConfiguraciones => limite_no_demuestra::ESCANEO,
            TipoPruebaBypass::CredencialesTrampa => limite_no_demuestra::TRAMPA,
            TipoPruebaBypass::SondaAdversarial => limite_no_demuestra::SONDA,
        }
    }
}

impl fmt::Display for TipoPruebaBypass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

#[derive(Debug, Clone)]
pub struct ResultadoPruebaBypass {
    pub prueba: TipoPruebaBypass,
    pub hechos: Vec<HechoFirmadoLibro>,
    pub ok: bool,
    pub no_demuestra: &'static str,
    /// Metadatos (p.ej. divergencia %, trampa usada).
    pub detalle: String,
}

/// Entrada mínima tipada para ejecutar una prueba en el entorno instrumentado.
#[derive(Debug, Clone)]
pub struct EntradaPrueba {
    pub sistema: IdSistema,
    pub clase: Option<ClaseEfecto>,
    pub epoca: u64,
    pub ahora: Ticks,
    pub version: u32,
    /// Semántica por prueba (ver `ejecutar_prueba`).
    pub senal_positiva: bool,
    /// Solo I.3: divergencia percentual (0–100+).
    pub divergencia_pct: u32,
    /// Solo I.7: la trampa fue usada.
    pub trampa_usada: bool,
}

pub fn ejecutar_prueba(
    tipo: TipoPruebaBypass,
    entrada: &EntradaPrueba,
    firmante: &ParMlDsa87,
) -> Result<ResultadoPruebaBypass, crate::crypto::ErrorCrypto> {
    let no_demuestra = tipo.no_demuestra();
    let clase = entrada.clase;
    let mut hechos = Vec::new();
    let (ok, detalle, tipos_valor) = match tipo {
        TipoPruebaBypass::InventarioCredenciales => {
            // Diferencia nula ⇒ contribuye a EXCLUSIVIDAD.
            (
                entrada.senal_positiva,
                if entrada.senal_positiva {
                    "diferencia de inventario nula en ambitos inspeccionados".into()
                } else {
                    "diferencia de inventario no nula".into()
                },
                vec![(TipoHecho::Exclusividad, entrada.senal_positiva)],
            )
        }
        TipoPruebaBypass::RotacionSecretosHeredados => (
            entrada.senal_positiva,
            "rotacion forzada de secretos heredados".into(),
            vec![(TipoHecho::Custodia, entrada.senal_positiva)],
        ),
        TipoPruebaBypass::ReconciliacionProveedor => {
            let ok = entrada.divergencia_pct <= 1;
            let det = format!(
                "divergencia {}% (incidente si >1; suspension si >5)",
                entrada.divergencia_pct
            );
            (
                ok,
                det,
                vec![(TipoHecho::Exclusividad, ok)],
            )
        }
        TipoPruebaBypass::ObservacionEgreso => (
            entrada.senal_positiva,
            if entrada.senal_positiva {
                "sin destinos no autorizados observados".into()
            } else {
                "destino no autorizado observado".into()
            },
            vec![(TipoHecho::Exclusividad, entrada.senal_positiva)],
        ),
        TipoPruebaBypass::VerificacionPep => (
            entrada.senal_positiva,
            "latido PEP y ausencia de credencial de efector".into(),
            vec![(TipoHecho::PepAtestado, entrada.senal_positiva)],
        ),
        TipoPruebaBypass::EscaneoConfiguraciones => {
            // senal_positiva = no se halló EF-9 abierto / secretos residuales.
            let ef9 = !entrada.senal_positiva;
            (
                entrada.senal_positiva,
                format!("EF9_ABIERTO={}", ef9),
                vec![
                    (TipoHecho::Ef9Abierto, ef9),
                    (TipoHecho::Exclusividad, entrada.senal_positiva),
                ],
            )
        }
        TipoPruebaBypass::CredencialesTrampa => {
            let exclusividad = !entrada.trampa_usada;
            (
                !entrada.trampa_usada,
                format!("trampa_usada={}", entrada.trampa_usada),
                vec![(TipoHecho::Exclusividad, exclusividad)],
            )
        }
        TipoPruebaBypass::SondaAdversarial => (
            entrada.senal_positiva,
            if entrada.senal_positiva {
                "efecto sin capacidad denegado en la ruta sondada".into()
            } else {
                "sonda produjo efecto — ruta abierta".into()
            },
            vec![(TipoHecho::SondaOk, entrada.senal_positiva)],
        ),
    };

    for (tipo_h, valor) in tipos_valor {
        let clase_h = match tipo_h {
            TipoHecho::Ef9Abierto | TipoHecho::Confinado => None,
            _ => clase,
        };
        hechos.push(HechoFirmadoLibro::firmar(
            tipo_h,
            entrada.sistema.clone(),
            clase_h,
            valor,
            entrada.version,
            entrada.epoca,
            entrada.ahora,
            no_demuestra,
            firmante,
        )?);
    }

    Ok(ResultadoPruebaBypass {
        prueba: tipo,
        hechos,
        ok,
        no_demuestra,
        detalle,
    })
}
