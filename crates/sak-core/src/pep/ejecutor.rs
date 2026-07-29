//! Custodia de credencial de escritura y ejecutor de negocio/datos (EF-3).

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_escritura::SolicitudEscritura;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEjecutor {
    NoAutorizado,
    DivergenciaMutacion,
    ConflictoCas,
    FalloInterno,
    NoPuedeDemostrarExactitud,
}

impl fmt::Display for ErrorEjecutor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorEjecutor::NoAutorizado => write!(f, "ejecutor no autorizado"),
            ErrorEjecutor::DivergenciaMutacion => write!(f, "divergencia de mutacion"),
            ErrorEjecutor::ConflictoCas => write!(f, "conflicto CAS / version"),
            ErrorEjecutor::FalloInterno => write!(f, "fallo interno del ejecutor"),
            ErrorEjecutor::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar mutacion exacta autorizada")
            }
        }
    }
}

impl std::error::Error for ErrorEjecutor {}

/// Credencial raíz de escritura. Sin exportación; no llega al sujeto ni al PEP.
pub struct CredencialEscritura {
    material: [u8; 32],
}

impl CredencialEscritura {
    pub fn desde_semilla(semilla: [u8; 32]) -> Self {
        CredencialEscritura { material: semilla }
    }

    pub(crate) fn firmar_mutacion(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialEscritura {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialEscritura(REDACTED)")
    }
}

/// Resultado de mutación delegada con prueba de exactitud.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoEscritura {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_cambio_autorizado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_cambio_aplicado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub version_previa: Option<u64>,
    pub version_posterior: Option<u64>,
    pub filas_afectadas: u32,
    pub referencia_minima: String,
}

pub trait EjecutorEscritura {
    fn mutar_delegado(
        &mut self,
        solicitud: &SolicitudEscritura,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoEscritura, ErrorEjecutor>;
}

/// Ejecutor instrumentado: egreso forzado; CAS por recurso; ruta directa denegada.
pub struct EjecutorSimulado {
    credencial: CredencialEscritura,
    /// recurso → versión actual.
    versiones: BTreeMap<String, u64>,
    pub mutaciones_delegadas: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_sin_prueba: bool,
    pub fallar_evidencia_simulada: bool,
}

impl EjecutorSimulado {
    pub fn nuevo(credencial: CredencialEscritura) -> Self {
        let mut versiones = BTreeMap::new();
        versiones.insert("tabla-estado".into(), 1);
        versiones.insert("config/app".into(), 3);
        versiones.insert("fichero/out.txt".into(), 0);
        EjecutorSimulado {
            credencial,
            versiones,
            mutaciones_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_sin_prueba: false,
            fallar_evidencia_simulada: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudEscritura,
    ) -> Result<ResultadoEscritura, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }

    pub fn version_de(&self, recurso: &str) -> Option<u64> {
        self.versiones.get(recurso).copied()
    }
}

impl EjecutorEscritura for EjecutorSimulado {
    fn mutar_delegado(
        &mut self,
        solicitud: &SolicitudEscritura,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoEscritura, ErrorEjecutor> {
        let digest = crate::pep::solicitud_escritura::digest_solicitud_escritura(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorEjecutor::DivergenciaMutacion);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorEjecutor::NoPuedeDemostrarExactitud);
        }

        let version_previa = self.versiones.get(&solicitud.recurso).copied();
        if let Some(esperada) = solicitud.version_precondicion {
            match version_previa {
                Some(actual) if actual == esperada => {}
                _ => return Err(ErrorEjecutor::ConflictoCas),
            }
        }

        let sello = self.credencial.firmar_mutacion(&solicitud.canonico());
        self.mutaciones_delegadas += 1;

        let version_posterior = Some(version_previa.unwrap_or(0).saturating_add(1));
        if let Some(v) = version_posterior {
            self.versiones.insert(solicitud.recurso.clone(), v);
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.digest_selector);
        payload.extend_from_slice(&solicitud.digest_valores);
        for c in &solicitud.campos {
            payload.extend_from_slice(c.as_bytes());
            payload.push(b'|');
        }
        if let Some(vp) = version_previa {
            payload.extend_from_slice(&vp.to_le_bytes());
        }
        if let Some(vn) = version_posterior {
            payload.extend_from_slice(&vn.to_le_bytes());
        }

        let digest_cambio = crypto::sha384_dominio(b"SAK-WRITE-CHANGE-v1|", &payload);
        let digest_cambio_aplicado = if self.forzar_divergencia {
            let mut d = digest_cambio;
            d[0] ^= 0xff;
            d
        } else {
            digest_cambio
        };

        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xaa;
            d
        } else {
            digest
        };

        let digest_resultado = crypto::sha384_dominio(b"SAK-WRITE-OUT-v1|", &payload);

        Ok(ResultadoEscritura {
            digest_resultado,
            digest_cambio_autorizado: digest_cambio,
            digest_cambio_aplicado,
            digest_solicitud_ejecutada,
            version_previa,
            version_posterior,
            filas_afectadas: 1.min(solicitud.limite_filas),
            referencia_minima: format!("write:{}", hex_corto(&digest_resultado)),
        })
    }
}

fn hex_corto(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
