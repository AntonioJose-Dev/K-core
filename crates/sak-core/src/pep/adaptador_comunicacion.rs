//! Adaptador de comunicaciones (instrumentado). Credencial e identidad en custodia.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_comunicacion::SolicitudComunicacion;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptadorComunicacion {
    NoAutorizado,
    DivergenciaEntrega,
    EntregaParcial,
    ResultadoIndeterminado,
    NoPuedeDemostrarExactitud,
    FalloInterno,
}

impl fmt::Display for ErrorAdaptadorComunicacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptadorComunicacion::NoAutorizado => write!(f, "adaptador comunicacion no autorizado"),
            ErrorAdaptadorComunicacion::DivergenciaEntrega => write!(f, "divergencia de entrega"),
            ErrorAdaptadorComunicacion::EntregaParcial => write!(f, "entrega parcial"),
            ErrorAdaptadorComunicacion::ResultadoIndeterminado => {
                write!(f, "resultado externo indeterminado")
            }
            ErrorAdaptadorComunicacion::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar mensaje exacto autorizado")
            }
            ErrorAdaptadorComunicacion::FalloInterno => write!(f, "fallo interno del adaptador"),
        }
    }
}

impl std::error::Error for ErrorAdaptadorComunicacion {}

/// Credencial de envío + identidad de remitente. Nunca exportable al sujeto.
pub struct CredencialEnvio {
    material: [u8; 32],
    identidad_remitente: String,
}

impl CredencialEnvio {
    pub fn desde_semilla(identidad: impl Into<String>, semilla: [u8; 32]) -> Self {
        CredencialEnvio {
            material: semilla,
            identidad_remitente: identidad.into(),
        }
    }

    pub fn identidad_remitente(&self) -> &str {
        &self.identidad_remitente
    }

    pub(crate) fn firmar_envio(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialEnvio {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialEnvio(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstadoDestinatario {
    Entregado = 1,
    Rechazado = 2,
    Indeterminado = 3,
    Omitido = 4,
}

impl EstadoDestinatario {
    pub fn token(self) -> &'static str {
        match self {
            EstadoDestinatario::Entregado => "entregado",
            EstadoDestinatario::Rechazado => "rechazado",
            EstadoDestinatario::Indeterminado => "indeterminado",
            EstadoDestinatario::Omitido => "omitido",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoPorDestinatario {
    pub destinatario: String,
    pub estado: EstadoDestinatario,
    pub id_externo: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoComunicacion {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_contenido_entregado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_destinatarios_efectivos: [u8; LONGITUD_HASH_PAQUETE],
    pub canal_efectivo: String,
    pub remitente_efectivo: String,
    pub plantilla_efectiva: String,
    pub idioma_efectivo: String,
    pub por_destinatario: Vec<ResultadoPorDestinatario>,
}

pub trait AdaptadorComunicacion {
    fn enviar_delegado(
        &mut self,
        solicitud: &SolicitudComunicacion,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoComunicacion, ErrorAdaptadorComunicacion>;
}

pub struct AdaptadorComunicacionSimulado {
    credencial: CredencialEnvio,
    pub envios_delegados: u32,
    pub intentos_directos: u32,
    pub forzar_divergencia: bool,
    pub forzar_parcial: bool,
    pub forzar_indeterminado: bool,
    pub forzar_sin_prueba: bool,
}

impl AdaptadorComunicacionSimulado {
    pub fn nuevo(credencial: CredencialEnvio) -> Self {
        AdaptadorComunicacionSimulado {
            credencial,
            envios_delegados: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
            forzar_parcial: false,
            forzar_indeterminado: false,
            forzar_sin_prueba: false,
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudComunicacion,
    ) -> Result<ResultadoComunicacion, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }
}

impl AdaptadorComunicacion for AdaptadorComunicacionSimulado {
    fn enviar_delegado(
        &mut self,
        solicitud: &SolicitudComunicacion,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoComunicacion, ErrorAdaptadorComunicacion> {
        let digest = crate::pep::solicitud_comunicacion::digest_solicitud_comunicacion(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptadorComunicacion::DivergenciaEntrega);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptadorComunicacion::NoPuedeDemostrarExactitud);
        }
        if self.forzar_indeterminado {
            return Err(ErrorAdaptadorComunicacion::ResultadoIndeterminado);
        }
        if self.forzar_parcial {
            return Err(ErrorAdaptadorComunicacion::EntregaParcial);
        }

        let sello = self.credencial.firmar_envio(&solicitud.canonico());
        self.envios_delegados += 1;

        let mut por = Vec::new();
        for d in &solicitud.destinatarios.destinatarios {
            por.push(ResultadoPorDestinatario {
                destinatario: d.clone(),
                estado: EstadoDestinatario::Entregado,
                id_externo: format!("msg-{}", encode(&sello[..4])),
            });
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.destinatarios.digest);
        payload.extend_from_slice(&solicitud.digest_cuerpo);

        let digest_resultado = crypto::sha384_dominio(b"SAK-COMM-OUT-v1|", &payload);
        let digest_solicitud_ejecutada = if self.forzar_divergencia {
            let mut d = digest;
            d[0] ^= 0xff;
            d
        } else {
            digest
        };
        let (remitente, canal, plantilla, idioma, dest_dig, body) = if self.forzar_divergencia {
            (
                "evil@x".to_string(),
                "sms".to_string(),
                "otra".to_string(),
                "en".to_string(),
                {
                    let mut d = solicitud.destinatarios.digest;
                    d[0] ^= 0xaa;
                    d
                },
                {
                    let mut d = solicitud.digest_cuerpo;
                    d[0] ^= 0xbb;
                    d
                },
            )
        } else {
            (
                solicitud.identidad_remitente.clone(),
                solicitud.canal.token().to_string(),
                solicitud.id_plantilla.clone(),
                solicitud.idioma.clone(),
                solicitud.destinatarios.digest,
                solicitud.digest_cuerpo,
            )
        };

        Ok(ResultadoComunicacion {
            digest_resultado,
            digest_solicitud_ejecutada,
            digest_contenido_entregado: body,
            digest_destinatarios_efectivos: dest_dig,
            canal_efectivo: canal,
            remitente_efectivo: remitente,
            plantilla_efectiva: plantilla,
            idioma_efectivo: idioma,
            por_destinatario: por,
        })
    }
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
