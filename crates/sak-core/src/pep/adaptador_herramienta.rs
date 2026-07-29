//! Custodia de credenciales de herramienta y adaptador MCP/API (EF-4).

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_herramienta::SolicitudHerramienta;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptador {
    NoAutorizado,
    DivergenciaInvocacion,
    DestinoNoPermitido,
    FalloInterno,
    NoPuedeDemostrarExactitud,
}

impl fmt::Display for ErrorAdaptador {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptador::NoAutorizado => write!(f, "adaptador no autorizado"),
            ErrorAdaptador::DivergenciaInvocacion => write!(f, "divergencia de invocacion"),
            ErrorAdaptador::DestinoNoPermitido => write!(f, "destino no permitido"),
            ErrorAdaptador::FalloInterno => write!(f, "fallo interno del adaptador"),
            ErrorAdaptador::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar invocacion exacta autorizada")
            }
        }
    }
}

impl std::error::Error for ErrorAdaptador {}

/// Credencial por herramienta. Nunca se expone a sujetos ni adaptadores externos.
pub struct CredencialHerramienta {
    material: [u8; 32],
    id_herramienta: String,
}

impl CredencialHerramienta {
    pub fn desde_semilla(id_herramienta: impl Into<String>, semilla: [u8; 32]) -> Self {
        CredencialHerramienta {
            material: semilla,
            id_herramienta: id_herramienta.into(),
        }
    }

    pub(crate) fn firmar_llamada(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }

    pub fn id_herramienta(&self) -> &str {
        &self.id_herramienta
    }
}

impl fmt::Debug for CredencialHerramienta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CredencialHerramienta(id={}, REDACTED)",
            self.id_herramienta
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoHerramienta {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_argumentos_usados: [u8; LONGITUD_HASH_PAQUETE],
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub destino_efectivo: String,
    /// Digests de efectos secundarios declarados (vacío si ninguno).
    pub efectos_secundarios: Vec<[u8; LONGITUD_HASH_PAQUETE]>,
    pub referencia_minima: String,
}

pub trait AdaptadorHerramientas {
    fn invocar_delegado(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoHerramienta, ErrorAdaptador>;
}

/// Adaptador instrumentado: egreso forzado; ruta MCP directa denegada.
pub struct AdaptadorSimulado {
    credenciales: BTreeMap<String, CredencialHerramienta>,
    pub invocaciones_delegadas: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_sin_prueba: bool,
}

impl AdaptadorSimulado {
    pub fn nuevo() -> Self {
        AdaptadorSimulado {
            credenciales: BTreeMap::new(),
            invocaciones_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_sin_prueba: false,
        }
    }

    pub fn custodiar(&mut self, cred: CredencialHerramienta) {
        self.credenciales
            .insert(cred.id_herramienta().to_string(), cred);
    }

    pub fn llamar_mcp_directo(
        &mut self,
        _solicitud: &SolicitudHerramienta,
    ) -> Result<ResultadoHerramienta, ErrorEgreso> {
        self.intentos_directos += 1;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }
}

impl AdaptadorHerramientas for AdaptadorSimulado {
    fn invocar_delegado(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoHerramienta, ErrorAdaptador> {
        let digest = crate::pep::solicitud_herramienta::digest_solicitud_herramienta(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptador::DivergenciaInvocacion);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptador::NoPuedeDemostrarExactitud);
        }
        let cred = self
            .credenciales
            .get(&solicitud.id_herramienta)
            .ok_or(ErrorAdaptador::NoAutorizado)?;
        let sello = cred.firmar_llamada(&solicitud.canonico());
        self.invocaciones_delegadas += 1;

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.digest_argumentos);
        payload.extend_from_slice(solicitud.destino.as_bytes());

        let digest_resultado = crypto::sha384_dominio(dominio_out(), &payload);
        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };
        let digest_argumentos_usados = if self.forzar_divergencia {
            let mut d = solicitud.digest_argumentos;
            d[0] ^= 0xaa;
            d
        } else {
            solicitud.digest_argumentos
        };

        Ok(ResultadoHerramienta {
            digest_resultado,
            digest_solicitud_ejecutada,
            digest_argumentos_usados,
            id_herramienta: solicitud.id_herramienta.clone(),
            version: solicitud.version.clone(),
            servidor: solicitud.servidor.clone(),
            destino_efectivo: solicitud.destino.clone(),
            efectos_secundarios: vec![],
            referencia_minima: format!("tool:{}", hex_corto(&digest_resultado)),
        })
    }
}

fn dominio_out() -> &'static [u8] {
    b"SAK-TOOL-OUT-v1|"
}

fn hex_corto(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
