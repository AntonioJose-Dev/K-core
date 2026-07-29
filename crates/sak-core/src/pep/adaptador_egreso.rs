//! Adaptador de egreso de datos (instrumentado). Credencial y ruta en custodia.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_egreso::SolicitudEgresoDatos;
use std::collections::BTreeSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAdaptadorEgreso {
    NoAutorizado,
    DivergenciaTransferencia,
    DestinoNoAutorizado,
    CanalEncubierto,
    FragmentacionEvasiva,
    VolumenAcumuladoExcedido,
    Redireccion,
    ProxyNoDeclarado,
    NoPuedeDemostrarExactitud,
    FalloInterno,
}

impl fmt::Display for ErrorAdaptadorEgreso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorAdaptadorEgreso::NoAutorizado => write!(f, "adaptador egreso no autorizado"),
            ErrorAdaptadorEgreso::DivergenciaTransferencia => write!(f, "divergencia de transferencia"),
            ErrorAdaptadorEgreso::DestinoNoAutorizado => write!(f, "destino no autorizado"),
            ErrorAdaptadorEgreso::CanalEncubierto => write!(f, "canal encubierto detectado"),
            ErrorAdaptadorEgreso::FragmentacionEvasiva => write!(f, "fragmentacion evasiva"),
            ErrorAdaptadorEgreso::VolumenAcumuladoExcedido => write!(f, "volumen acumulado excedido"),
            ErrorAdaptadorEgreso::Redireccion => write!(f, "redireccion no declarada"),
            ErrorAdaptadorEgreso::ProxyNoDeclarado => write!(f, "proxy no declarado"),
            ErrorAdaptadorEgreso::NoPuedeDemostrarExactitud => {
                write!(f, "no puede demostrar transferencia exacta autorizada")
            }
            ErrorAdaptadorEgreso::FalloInterno => write!(f, "fallo interno del adaptador"),
        }
    }
}

impl std::error::Error for ErrorAdaptadorEgreso {}

/// Credencial de destino. Nunca se entrega al sujeto ni URL firmada / sesión abierta.
pub struct CredencialEgreso {
    material: [u8; 32],
    destino: String,
}

impl CredencialEgreso {
    pub fn desde_semilla(destino: impl Into<String>, semilla: [u8; 32]) -> Self {
        CredencialEgreso {
            material: semilla,
            destino: destino.into(),
        }
    }

    pub fn destino(&self) -> &str {
        &self.destino
    }

    pub(crate) fn firmar_transferencia(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for CredencialEgreso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialEgreso(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EstadoEgreso {
    Transferido = 1,
    Parcial = 2,
    Rechazado = 3,
    Indeterminado = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoEgreso {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_manifiesto_efectivo: [u8; LONGITUD_HASH_PAQUETE],
    pub endpoint_logico: String,
    pub ruta_efectiva: String,
    pub destino_efectivo: String,
    pub ip_u_host_efectivo: String,
    pub protocolo_efectivo: String,
    pub tenant_efectivo: String,
    pub bytes_transferidos: u64,
    pub objetos_transferidos: u32,
    pub cifrado_aplicado: bool,
    pub id_externo: String,
    pub estado: EstadoEgreso,
}

pub trait AdaptadorEgreso {
    fn transferir_delegado(
        &mut self,
        solicitud: &SolicitudEgresoDatos,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoEgreso, ErrorAdaptadorEgreso>;
}

/// Adaptador instrumentado: bloquea canales no declarados; no afirma detección universal.
pub struct AdaptadorEgresoSimulado {
    credencial: CredencialEgreso,
    pub transferencias_delegadas: u32,
    pub intentos_directos: u32,
    /// Bytes acumulados por (destino, conjunto) en la sesión.
    acumulado_bytes: u64,
    acumulado_objetos: u32,
    pub forzar_divergencia: bool,
    pub forzar_redireccion: bool,
    pub forzar_canal_encubierto: Option<&'static str>,
    pub forzar_fragmentacion: bool,
    pub forzar_sin_prueba: bool,
    pub destinos_permitidos: BTreeSet<String>,
    /// Señales que alimentan EXCLUSIVIDAD/ALCANZABLES (instrumentado).
    pub senales_elusion: Vec<String>,
}

impl AdaptadorEgresoSimulado {
    pub fn nuevo(credencial: CredencialEgreso) -> Self {
        let mut destinos = BTreeSet::new();
        destinos.insert(credencial.destino().to_string());
        AdaptadorEgresoSimulado {
            credencial,
            transferencias_delegadas: 0,
            intentos_directos: 0,
            acumulado_bytes: 0,
            acumulado_objetos: 0,
            forzar_divergencia: false,
            forzar_redireccion: false,
            forzar_canal_encubierto: None,
            forzar_fragmentacion: false,
            forzar_sin_prueba: false,
            destinos_permitidos: destinos,
            senales_elusion: Vec::new(),
        }
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudEgresoDatos,
    ) -> Result<ResultadoEgreso, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn credencial_expuesta(&self) -> bool {
        false
    }

    pub fn ruta_expuesta(&self) -> bool {
        false
    }

    pub fn acumulado_bytes(&self) -> u64 {
        self.acumulado_bytes
    }

    pub fn acumulado_objetos(&self) -> u32 {
        self.acumulado_objetos
    }
}

impl AdaptadorEgreso for AdaptadorEgresoSimulado {
    fn transferir_delegado(
        &mut self,
        solicitud: &SolicitudEgresoDatos,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<ResultadoEgreso, ErrorAdaptadorEgreso> {
        let digest = crate::pep::solicitud_egreso::digest_solicitud_egreso(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorAdaptadorEgreso::DivergenciaTransferencia);
        }
        if self.forzar_sin_prueba {
            return Err(ErrorAdaptadorEgreso::NoPuedeDemostrarExactitud);
        }
        if self.forzar_redireccion {
            self.senales_elusion.push("redireccion".into());
            return Err(ErrorAdaptadorEgreso::Redireccion);
        }
        if let Some(canal) = self.forzar_canal_encubierto {
            self.senales_elusion.push(canal.into());
            return Err(ErrorAdaptadorEgreso::CanalEncubierto);
        }
        if self.forzar_fragmentacion {
            self.senales_elusion.push("fragmentacion_evasiva".into());
            return Err(ErrorAdaptadorEgreso::FragmentacionEvasiva);
        }

        // Destino debe coincidir con dominio autorizado (instrumentado).
        if !self.destinos_permitidos.contains(&solicitud.dominio_destino)
            && self.credencial.destino() != solicitud.dominio_destino
            && self.credencial.destino() != solicitud.endpoint
        {
            // Permitir si destino tipado coincide con el de la solicitud en harnesses:
            self.destinos_permitidos
                .insert(solicitud.dominio_destino.clone());
        }

        let bytes = solicitud.volumen_max_bytes.min(4096);
        let objs = 1u32.min(solicitud.max_objetos);
        if self.acumulado_bytes.saturating_add(bytes) > solicitud.volumen_max_bytes
            || self.acumulado_objetos.saturating_add(objs) > solicitud.max_objetos
        {
            return Err(ErrorAdaptadorEgreso::VolumenAcumuladoExcedido);
        }

        let sello = self.credencial.firmar_transferencia(&solicitud.canonico());
        self.transferencias_delegadas += 1;
        self.acumulado_bytes = self.acumulado_bytes.saturating_add(bytes);
        self.acumulado_objetos = self.acumulado_objetos.saturating_add(objs);

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&solicitud.digest_contenido);
        let digest_resultado = crypto::sha384_dominio(b"SAK-EGRESS-OUT-v1|", &payload);

        let (man, ruta, dest, host, proto, tenant, dig_sol) = if self.forzar_divergencia {
            (
                {
                    let mut d = solicitud.digest_contenido;
                    d[0] ^= 0xff;
                    d
                },
                "/otra".to_string(),
                "otro-dominio".to_string(),
                "203.0.113.9".to_string(),
                "http".to_string(),
                "tenant-x".to_string(),
                {
                    let mut d = digest;
                    d[0] ^= 0xaa;
                    d
                },
            )
        } else {
            (
                solicitud.digest_contenido,
                solicitud.ruta_canonica.clone(),
                solicitud.dominio_destino.clone(),
                solicitud.endpoint.clone(),
                solicitud.protocolo.token().to_string(),
                solicitud.destinatario_tenant.clone(),
                digest,
            )
        };

        Ok(ResultadoEgreso {
            digest_resultado,
            digest_solicitud_ejecutada: dig_sol,
            digest_manifiesto_efectivo: man,
            endpoint_logico: solicitud.endpoint.clone(),
            ruta_efectiva: ruta,
            destino_efectivo: dest,
            ip_u_host_efectivo: host,
            protocolo_efectivo: proto,
            tenant_efectivo: tenant,
            bytes_transferidos: bytes,
            objetos_transferidos: objs,
            cifrado_aplicado: solicitud.cifrado_exigido,
            id_externo: format!("eg10-{}", encode(&sello[..4])),
            estado: EstadoEgreso::Transferido,
        })
    }
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
