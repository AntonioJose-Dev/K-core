//! Adaptador de publicación (instrumentado). Credencial y cuenta en custodia.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_publicacion::{OperacionPublicacion, SolicitudPublicacion};
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptadorPublicacion {
    NoAutorizado,
    DivergenciaPublicacion,
    ConfirmacionParcial,
    ResultadoIndeterminado,
    RetiradaFueraAlcance,
    NoPuedeDemostrarExactitud,
    FalloInterno,
}

impl fmt::Display for ErrorAdaptadorPublicacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptadorPublicacion::NoAutorizado => write!(f, "adaptador publicacion no autorizado"),
            ErrorAdaptadorPublicacion::DivergenciaPublicacion => write!(f, "divergencia de publicacion"),
            ErrorAdaptadorPublicacion::ConfirmacionParcial => write!(f, "confirmacion parcial"),
            ErrorAdaptadorPublicacion::ResultadoIndeterminado => {
                write!(f, "resultado externo indeterminado")
            }
            ErrorAdaptadorPublicacion::RetiradaFueraAlcance => write!(f, "retirada fuera de alcance"),
            ErrorAdaptadorPublicacion::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar contenido exacto autorizado")
            }
            ErrorAdaptadorPublicacion::FalloInterno => write!(f, "fallo interno del adaptador"),
        }
    }
}

impl std::error::Error for ErrorAdaptadorPublicacion {}

/// Credencial de publicación + identidad/cuenta. Nunca exportable al sujeto.
pub struct CredencialPublicacion {
    material: [u8; 32],
    cuenta: String,
}

impl CredencialPublicacion {
    pub fn desde_semilla(cuenta: impl Into<String>, semilla: [u8; 32]) -> Self {
        CredencialPublicacion {
            material: semilla,
            cuenta: cuenta.into(),
        }
    }

    pub fn cuenta(&self) -> &str {
        &self.cuenta
    }

    pub(crate) fn firmar_publicacion(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialPublicacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialPublicacion(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstadoPublicacion {
    Publicado = 1,
    Actualizado = 2,
    Retirado = 3,
    Indeterminado = 4,
}

impl EstadoPublicacion {
    pub fn token(self) -> &'static str {
        match self {
            EstadoPublicacion::Publicado => "publicado",
            EstadoPublicacion::Actualizado => "actualizado",
            EstadoPublicacion::Retirado => "retirado",
            EstadoPublicacion::Indeterminado => "indeterminado",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoPublicacion {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_contenido_publicado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_medios_publicados: [u8; LONGITUD_HASH_PAQUETE],
    pub canal_efectivo: String,
    pub cuenta_efectiva: String,
    pub destino_efectivo: String,
    pub operacion_efectiva: String,
    pub audiencia_efectiva: String,
    pub visibilidad_efectiva: String,
    pub idioma_efectivo: String,
    pub etiquetas_efectivas: String,
    pub id_externo: String,
    pub estado: EstadoPublicacion,
}

pub trait AdaptadorPublicacion {
    fn publicar_delegado(
        &mut self,
        solicitud: &SolicitudPublicacion,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoPublicacion, ErrorAdaptadorPublicacion>;
}

pub struct AdaptadorPublicacionSimulado {
    credencial: CredencialPublicacion,
    /// Destinos con publicación activa (para retirada en alcance).
    publicados: BTreeSet<String>,
    pub publicaciones_delegadas: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_parcial: bool,
    pub forzar_indeterminado: bool,
    pub forzar_sin_prueba: bool,
    pub forzar_retirada_fuera: bool,
}

impl AdaptadorPublicacionSimulado {
    pub fn nuevo(credencial: CredencialPublicacion) -> Self {
        AdaptadorPublicacionSimulado {
            credencial,
            publicados: BTreeSet::new(),
            publicaciones_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_parcial: false,
            forzar_indeterminado: false,
            forzar_sin_prueba: false,
            forzar_retirada_fuera: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudPublicacion,
    ) -> Result<ResultadoPublicacion, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }
}

impl AdaptadorPublicacion for AdaptadorPublicacionSimulado {
    fn publicar_delegado(
        &mut self,
        solicitud: &SolicitudPublicacion,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoPublicacion, ErrorAdaptadorPublicacion> {
        let digest = crate::pep::solicitud_publicacion::digest_solicitud_publicacion(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptadorPublicacion::DivergenciaPublicacion);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptadorPublicacion::NoPuedeDemostrarExactitud);
        }
        if self.forzar_indeterminado {
            return Err(ErrorAdaptadorPublicacion::ResultadoIndeterminado);
        }
        if self.forzar_parcial {
            return Err(ErrorAdaptadorPublicacion::ConfirmacionParcial);
        }
        if self.forzar_retirada_fuera && solicitud.operacion == OperacionPublicacion::Retirar {
            return Err(ErrorAdaptadorPublicacion::RetiradaFueraAlcance);
        }
        if solicitud.operacion == OperacionPublicacion::Retirar
            && !self.publicados.contains(&solicitud.destino)
        {
            return Err(ErrorAdaptadorPublicacion::RetiradaFueraAlcance);
        }

        let sello = self.credencial.firmar_publicacion(&solicitud.canonico());
        self.publicaciones_delegadas += 1;
        match solicitud.operacion {
            OperacionPublicacion::Crear | OperacionPublicacion::Actualizar => {
                self.publicados.insert(solicitud.destino.clone());
            }
            OperacionPublicacion::Retirar => {
                self.publicados.remove(&solicitud.destino);
            }
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.digest_contenido);
        payload.extend_from_slice(solicitud.destino.as_bytes());
        let digest_resultado = crypto::sha384_dominio(b"SAK-PUB-OUT-v1|", &payload);

        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };

        let (
            cuenta,
            canal,
            dest,
            op,
            body,
            media,
            aud,
            vis,
            lang,
            tags,
        ) = if self.forzar_divergencia {
            (
                "evil".to_string(),
                "redes".to_string(),
                "https://evil".to_string(),
                "crear".to_string(),
                {
                    let mut d = solicitud.digest_contenido;
                    d[0] ^= 0xaa;
                    d
                },
                {
                    let mut d = solicitud.digest_medios;
                    d[0] ^= 0xbb;
                    d
                },
                "abierta".to_string(),
                "publica".to_string(),
                "en".to_string(),
                "spam".to_string(),
            )
        } else {
            (
                solicitud.cuenta_publicadora.clone(),
                solicitud.canal.token().to_string(),
                solicitud.destino.clone(),
                solicitud.operacion.token().to_string(),
                solicitud.digest_contenido,
                solicitud.digest_medios,
                solicitud.audiencia.clone(),
                solicitud.visibilidad.clone(),
                solicitud.idioma.clone(),
                solicitud.etiquetas.clone(),
            )
        };

        let estado = match solicitud.operacion {
            OperacionPublicacion::Crear => EstadoPublicacion::Publicado,
            OperacionPublicacion::Actualizar => EstadoPublicacion::Actualizado,
            OperacionPublicacion::Retirar => EstadoPublicacion::Retirado,
        };

        Ok(ResultadoPublicacion {
            digest_resultado,
            digest_solicitud_ejecutada,
            digest_contenido_publicado: body,
            digest_medios_publicados: media,
            canal_efectivo: canal,
            cuenta_efectiva: cuenta,
            destino_efectivo: dest,
            operacion_efectiva: op,
            audiencia_efectiva: aud,
            visibilidad_efectiva: vis,
            idioma_efectivo: lang,
            etiquetas_efectivas: tags,
            id_externo: format!("pub-{}", encode(&sello[..4])),
            estado,
        })
    }
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
