//! Adaptador de sistema de negocio (instrumentado). Credencial en custodia.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_negocio::SolicitudOperacionNegocio;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptadorNegocio {
    NoAutorizado,
    DivergenciaOperacion,
    IdempotenciaDuplicada,
    IdempotenciaIncompatible,
    ConflictoPrecondicion,
    ResultadoIndeterminado,
    NoPuedeDemostrarExactitud,
    FalloInterno,
}

impl fmt::Display for ErrorAdaptadorNegocio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptadorNegocio::NoAutorizado => write!(f, "adaptador negocio no autorizado"),
            ErrorAdaptadorNegocio::DivergenciaOperacion => write!(f, "divergencia de operacion"),
            ErrorAdaptadorNegocio::IdempotenciaDuplicada => write!(f, "idempotencia duplicada"),
            ErrorAdaptadorNegocio::IdempotenciaIncompatible => {
                write!(f, "idempotency key incompatible")
            }
            ErrorAdaptadorNegocio::ConflictoPrecondicion => write!(f, "conflicto de precondicion"),
            ErrorAdaptadorNegocio::ResultadoIndeterminado => {
                write!(f, "resultado externo indeterminado")
            }
            ErrorAdaptadorNegocio::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar operacion exacta autorizada")
            }
            ErrorAdaptadorNegocio::FalloInterno => write!(f, "fallo interno del adaptador"),
        }
    }
}

impl std::error::Error for ErrorAdaptadorNegocio {}

/// Credencial raíz de negocio. Nunca se entrega al sujeto ni al adaptador como
/// material reutilizable exportable; Debug siempre REDACTED.
pub struct CredencialNegocio {
    material: [u8; 32],
    sistema: String,
}

impl CredencialNegocio {
    pub fn desde_semilla(sistema: impl Into<String>, semilla: [u8; 32]) -> Self {
        CredencialNegocio {
            material: semilla,
            sistema: sistema.into(),
        }
    }

    pub fn sistema(&self) -> &str {
        &self.sistema
    }

    pub(crate) fn firmar_operacion(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialNegocio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialNegocio(REDACTED)")
    }
}

/// Estado de liquidación/conformación reportado por el efector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstadoLiquidacion {
    Confirmada = 1,
    Pendiente = 2,
    Rechazada = 3,
    Indeterminada = 4,
}

impl EstadoLiquidacion {
    pub fn token(self) -> &'static str {
        match self {
            EstadoLiquidacion::Confirmada => "confirmada",
            EstadoLiquidacion::Pendiente => "pendiente",
            EstadoLiquidacion::Rechazada => "rechazada",
            EstadoLiquidacion::Indeterminada => "indeterminada",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoNegocio {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_operacion_enviada: [u8; LONGITUD_HASH_PAQUETE],
    pub id_externo: String,
    pub estado_liquidacion: EstadoLiquidacion,
    pub tipo_efectivo: String,
    pub contraparte_efectiva: String,
    pub moneda_efectiva: String,
    pub importe_efectivo: u64,
    pub efector_efectivo: String,
}

pub trait AdaptadorNegocio {
    fn ejecutar_delegado(
        &mut self,
        solicitud: &SolicitudOperacionNegocio,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoNegocio, ErrorAdaptadorNegocio>;
}

/// Adaptador simulado: custodia, egreso forzado, idempotencia, ruta directa bloqueada.
pub struct AdaptadorNegocioSimulado {
    credencial: CredencialNegocio,
    /// idempotency_key → digest de solicitud ya ejecutada.
    idempotencia: BTreeMap<[u8; 32], [u8; LONGITUD_HASH_PAQUETE]>,
    pub operaciones_delegadas: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_indeterminado: bool,
    pub forzar_sin_prueba: bool,
    pub forzar_conflicto_precondicion: bool,
}

impl AdaptadorNegocioSimulado {
    pub fn nuevo(credencial: CredencialNegocio) -> Self {
        AdaptadorNegocioSimulado {
            credencial,
            idempotencia: BTreeMap::new(),
            operaciones_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_indeterminado: false,
            forzar_sin_prueba: false,
            forzar_conflicto_precondicion: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudOperacionNegocio,
    ) -> Result<ResultadoNegocio, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }

    pub fn clave_idempotente_fijada(&self, key: &[u8; 32]) -> bool {
        self.idempotencia.contains_key(key)
    }
}

impl AdaptadorNegocio for AdaptadorNegocioSimulado {
    fn ejecutar_delegado(
        &mut self,
        solicitud: &SolicitudOperacionNegocio,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoNegocio, ErrorAdaptadorNegocio> {
        let digest = crate::pep::solicitud_negocio::digest_solicitud_negocio(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptadorNegocio::DivergenciaOperacion);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptadorNegocio::NoPuedeDemostrarExactitud);
        }
        if self.forzar_conflicto_precondicion {
            return Err(ErrorAdaptadorNegocio::ConflictoPrecondicion);
        }
        if self.forzar_indeterminado {
            return Err(ErrorAdaptadorNegocio::ResultadoIndeterminado);
        }

        if let Some(prev) = self.idempotencia.get(&solicitud.idempotency_key) {
            if prev == &digest {
                return Err(ErrorAdaptadorNegocio::IdempotenciaDuplicada);
            }
            return Err(ErrorAdaptadorNegocio::IdempotenciaIncompatible);
        }

        let sello = self.credencial.firmar_operacion(&solicitud.canonico());
        self.operaciones_delegadas += 1;
        self.idempotencia
            .insert(solicitud.idempotency_key, digest);

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.idempotency_key);
        payload.extend_from_slice(&solicitud.importe.unidades_menores.to_le_bytes());

        let digest_resultado = crypto::sha384_dominio(b"SAK-BIZ-OUT-v1|", &payload);
        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };
        let (importe_ef, moneda_ef, contra_ef) = if self.forzar_divergencia {
            (
                solicitud.importe.unidades_menores.wrapping_add(1),
                "XXX".to_string(),
                "evil".to_string(),
            )
        } else {
            (
                solicitud.importe.unidades_menores,
                solicitud.moneda.clone(),
                solicitud.contraparte.clone(),
            )
        };

        Ok(ResultadoNegocio {
            digest_resultado,
            digest_solicitud_ejecutada,
            digest_operacion_enviada: digest_solicitud_ejecutada,
            id_externo: format!("ext-{}", hex::encode(&sello[..8])),
            estado_liquidacion: EstadoLiquidacion::Confirmada,
            tipo_efectivo: solicitud.tipo.token().to_string(),
            contraparte_efectiva: contra_ef,
            moneda_efectiva: moneda_ef,
            importe_efectivo: importe_ef,
            efector_efectivo: solicitud.sistema_efector.clone(),
        })
    }
}

// hex crate may not be a dependency — use manual encoding instead.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
