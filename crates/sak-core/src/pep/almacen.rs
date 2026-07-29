//! Custodia de credencial de datos y almacén con egreso forzado (EF-2).

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_datos::SolicitudDatos;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAlmacen {
    NoAutorizado,
    DivergenciaConsulta,
    FalloInterno,
}

impl fmt::Display for ErrorAlmacen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAlmacen::NoAutorizado => write!(f, "almacen no autorizado"),
            ErrorAlmacen::DivergenciaConsulta => write!(f, "divergencia de consulta"),
            ErrorAlmacen::FalloInterno => write!(f, "fallo interno del almacen"),
        }
    }
}

impl std::error::Error for ErrorAlmacen {}

/// Credencial raíz de datos. Sin exportación de material.
pub struct CredencialDatos {
    material: [u8; 32],
}

impl CredencialDatos {
    pub fn desde_semilla(semilla: [u8; 32]) -> Self {
        CredencialDatos { material: semilla }
    }

    pub(crate) fn firmar_consulta(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialDatos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialDatos(REDACTED)")
    }
}

/// Resultado minimizado: solo campos/volumen autorizados + digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoDatos {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    pub digest_consulta_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub campos_devueltos: Vec<String>,
    pub volumen_devuelto: u32,
}

pub trait AlmacenDatos {
    fn consultar_delegado(
        &mut self,
        solicitud: &SolicitudDatos,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoDatos, ErrorAlmacen>;
}

/// Almacén de prueba: egreso forzado; ruta directa siempre denegada.
pub struct AlmacenSimulado {
    credencial: CredencialDatos,
    /// Filas ficticias por recurso: campo → valor.
    filas: BTreeMap<String, BTreeMap<String, String>>,
    pub consultas_delegadas: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
}

impl AlmacenSimulado {
    pub fn nuevo(credencial: CredencialDatos) -> Self {
        let mut filas = BTreeMap::new();
        let mut exp = BTreeMap::new();
        exp.insert("id".into(), "E-1".into());
        exp.insert("nombre".into(), "Ada".into());
        exp.insert("secreto".into(), "NO".into());
        filas.insert("expedientes".into(), exp);
        AlmacenSimulado {
            credencial,
            filas,
            consultas_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudDatos,
    ) -> Result<ResultadoDatos, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }
}

impl AlmacenDatos for AlmacenSimulado {
    fn consultar_delegado(
        &mut self,
        solicitud: &SolicitudDatos,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoDatos, ErrorAlmacen> {
        let digest = crate::pep::solicitud_datos::digest_solicitud_datos(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAlmacen::DivergenciaConsulta);
        }
        let sello = self.credencial.firmar_consulta(&solicitud.canonico());
        self.consultas_delegadas += 1;

        let fila = self
            .filas
            .get(&solicitud.recurso)
            .cloned()
            .unwrap_or_default();

        let mut campos_devueltos = Vec::new();
        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        let mut volumen = 0u32;
        for c in &solicitud.campos {
            if volumen >= solicitud.limite_volumen {
                break;
            }
            if let Some(val) = fila.get(c) {
                campos_devueltos.push(c.clone());
                payload.extend_from_slice(c.as_bytes());
                payload.push(b'=');
                payload.extend_from_slice(val.as_bytes());
                payload.push(b'|');
                volumen += 1;
            }
        }

        let digest_consulta = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };

        let digest_resultado = crypto::sha384_dominio(b"SAK-DATA-OUT-v1|", &payload);
        Ok(ResultadoDatos {
            digest_resultado,
            referencia_minima: format!("data:{}", hex_corto(&digest_resultado)),
            digest_consulta_ejecutada: digest_consulta,
            campos_devueltos,
            volumen_devuelto: volumen,
        })
    }
}

fn hex_corto(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
