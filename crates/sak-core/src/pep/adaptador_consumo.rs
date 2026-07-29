//! Adaptador de consumo de decisión (instrumentado). Artefacto de autoridad en custodia.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_consumo::SolicitudConsumoDecisionPersona;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptadorConsumo {
    NoAutorizado,
    DivergenciaConsumo,
    AccionNoAutorizada,
    NoPuedeDemostrarExactitud,
    FalloInterno,
}

impl fmt::Display for ErrorAdaptadorConsumo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptadorConsumo::NoAutorizado => write!(f, "adaptador consumo no autorizado"),
            ErrorAdaptadorConsumo::DivergenciaConsumo => write!(f, "divergencia de consumo"),
            ErrorAdaptadorConsumo::AccionNoAutorizada => write!(f, "accion material distinta"),
            ErrorAdaptadorConsumo::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar consumo exacto autorizado")
            }
            ErrorAdaptadorConsumo::FalloInterno => write!(f, "fallo interno del adaptador"),
        }
    }
}

impl std::error::Error for ErrorAdaptadorConsumo {}

/// Artefacto de autoridad del canal de consumo (no necesariamente secreto criptográfico).
/// Nunca se entrega al sujeto ni al SDK.
pub struct ArtefactoConsumo {
    material: [u8; 32],
    canal: String,
}

impl ArtefactoConsumo {
    pub fn desde_semilla(canal: impl Into<String>, semilla: [u8; 32]) -> Self {
        ArtefactoConsumo {
            material: semilla,
            canal: canal.into(),
        }
    }

    pub fn canal(&self) -> &str {
        &self.canal
    }

    pub(crate) fn firmar_consumo(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for ArtefactoConsumo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArtefactoConsumo(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstadoConsumo {
    Entregado = 1,
    Registrado = 2,
    Presentado = 3,
    Indeterminado = 4,
}

impl EstadoConsumo {
    pub fn token(self) -> &'static str {
        match self {
            EstadoConsumo::Entregado => "entregado",
            EstadoConsumo::Registrado => "registrado",
            EstadoConsumo::Presentado => "presentado",
            EstadoConsumo::Indeterminado => "indeterminado",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoConsumo {
    pub digest_resultado_consumido: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_recibo_interno: [u8; LONGITUD_HASH_PAQUETE],
    pub canal_efectivo: String,
    pub destinatario_efectivo: String,
    pub accion_efectiva: String,
    pub sujeto_efectivo: String,
    pub clase_efectiva: String,
    pub finalidad_efectiva: String,
    pub version_efectiva: String,
    pub id_externo: String,
    pub estado: EstadoConsumo,
}

pub trait AdaptadorConsumoDecision {
    fn consumir_delegado(
        &mut self,
        solicitud: &SolicitudConsumoDecisionPersona,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoConsumo, ErrorAdaptadorConsumo>;
}

pub struct AdaptadorConsumoSimulado {
    artefacto: ArtefactoConsumo,
    pub consumos_delegados: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_accion_distinta: bool,
    pub forzar_sin_prueba: bool,
}

impl AdaptadorConsumoSimulado {
    pub fn nuevo(artefacto: ArtefactoConsumo) -> Self {
        AdaptadorConsumoSimulado {
            artefacto,
            consumos_delegados: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_accion_distinta: false,
            forzar_sin_prueba: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudConsumoDecisionPersona,
    ) -> Result<ResultadoConsumo, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.artefacto;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn artefacto_expuesto(&self) -> bool {
        false
    }
}

impl AdaptadorConsumoDecision for AdaptadorConsumoSimulado {
    fn consumir_delegado(
        &mut self,
        solicitud: &SolicitudConsumoDecisionPersona,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoConsumo, ErrorAdaptadorConsumo> {
        let digest = crate::pep::solicitud_consumo::digest_solicitud_consumo(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptadorConsumo::DivergenciaConsumo);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptadorConsumo::NoPuedeDemostrarExactitud);
        }
        if self.forzar_accion_distinta {
            return Err(ErrorAdaptadorConsumo::AccionNoAutorizada);
        }

        let sello = self.artefacto.firmar_consumo(&solicitud.canonico());
        self.consumos_delegados += 1;

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.digest_resultado);
        let digest_recibo = crypto::sha384_dominio(b"SAK-EF8-OUT-v1|", &payload);

        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };
        let (suj, canal, dest, accion, res, fin, ver, clase) = if self.forzar_divergencia {
            (
                "otro".to_string(),
                "canal-alt".to_string(),
                "humano-x".to_string(),
                "denegar".to_string(),
                {
                    let mut d = solicitud.digest_resultado;
                    d[0] ^= 0xaa;
                    d
                },
                "otra".to_string(),
                "0.0".to_string(),
                "seleccion".to_string(),
            )
        } else {
            (
                solicitud.id_sujeto_afectado.clone(),
                solicitud.sistema_canal.clone(),
                solicitud.destinatario.clone(),
                solicitud.accion_habilitada.clone(),
                solicitud.digest_resultado,
                solicitud.finalidad.clone(),
                solicitud.version_resultado.clone(),
                solicitud.clase.token().to_string(),
            )
        };

        Ok(ResultadoConsumo {
            digest_resultado_consumido: res,
            digest_solicitud_ejecutada,
            digest_recibo_interno: digest_recibo,
            canal_efectivo: canal,
            destinatario_efectivo: dest,
            accion_efectiva: accion,
            sujeto_efectivo: suj,
            clase_efectiva: clase,
            finalidad_efectiva: fin,
            version_efectiva: ver,
            id_externo: format!("ef8-{}", encode(&sello[..4])),
            estado: EstadoConsumo::Entregado,
        })
    }
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
