//! Custodia de credencial de proveedor y superficie de egreso (EF-1).
//!
//! La credencial **no** vive en el PEP: vive en [`ProveedorSimulado`] /
//! custodia. El PEP solo pide ejecución delegada. No hay getter público del
//! material (INV-06, L-02).

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::SolicitudInferencia;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorProveedor {
    NoAutorizado,
    DivergenciaParametros,
    FalloInterno,
}

impl fmt::Display for ErrorProveedor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorProveedor::NoAutorizado => write!(f, "proveedor no autorizado"),
            ErrorProveedor::DivergenciaParametros => write!(f, "divergencia de parametros"),
            ErrorProveedor::FalloInterno => write!(f, "fallo interno del proveedor"),
        }
    }
}

impl std::error::Error for ErrorProveedor {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEgreso {
    /// Ruta directa bloqueada: el proveedor no es alcanzable sin PEP (entorno de prueba).
    BloqueadoSinPep,
}

impl fmt::Display for ErrorEgreso {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorEgreso::BloqueadoSinPep => {
                write!(f, "egreso forzado: proveedor inalcanzable sin PEP")
            }
        }
    }
}

impl std::error::Error for ErrorEgreso {}

/// Credencial de proveedor encapsulada. Sin exportación de material.
pub struct CredencialProveedor {
    material: [u8; 32],
}

impl CredencialProveedor {
    pub fn desde_semilla(semilla: [u8; 32]) -> Self {
        CredencialProveedor { material: semilla }
    }

    pub(crate) fn firmar_llamada(&self, canon_solicitud: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon_solicitud)
    }
}

impl fmt::Debug for CredencialProveedor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredencialProveedor(REDACTED)")
    }
}

/// Respuesta minimizada del modelo (referencia + digest, sin volcar contenido completo).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaModelo {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    /// Digest de los parámetros que el proveedor declara haber ejecutado.
    pub digest_parametros_ejecutados: [u8; LONGITUD_HASH_PAQUETE],
}

/// Contrato de ejecución delegada. Solo el Kernel/gateway invoca esto.
///
/// Contexto de capacidad (2C): el Gateway instala datos de `cap` verificada
/// antes de `inferir_delegado`. Default no-op (p.ej. [`ProveedorSimulado`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextoEjercicioEf1 {
    pub cap_id: [u8; LONGITUD_HASH_PAQUETE],
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub vive_hasta: u64,
    pub ahora: u64,
}

thread_local! {
    static CTX_EJERCICIO_EF1: std::cell::RefCell<Option<ContextoEjercicioEf1>> =
        const { std::cell::RefCell::new(None) };
}

/// Instala contexto para la siguiente llamada delegada (Gateway → proveedor).
pub fn instalar_contexto_ejercicio_ef1(ctx: ContextoEjercicioEf1) {
    CTX_EJERCICIO_EF1.with(|c| {
        *c.borrow_mut() = Some(ctx);
    });
}

/// Toma el contexto instalado (una vez).
pub fn tomar_contexto_ejercicio_ef1() -> Option<ContextoEjercicioEf1> {
    CTX_EJERCICIO_EF1.with(|c| c.borrow_mut().take())
}

pub fn limpiar_contexto_ejercicio_ef1() {
    CTX_EJERCICIO_EF1.with(|c| {
        *c.borrow_mut() = None;
    });
}

pub trait ProveedorModelo {
    /// Hook 2C: recibe cap.id / época / TTL tras verificación del Gateway.
    /// Default: no-op (ProveedorSimulado idéntico).
    fn preparar_contexto_ejercicio(&mut self, _ctx: &ContextoEjercicioEf1) {}

    fn inferir_delegado(
        &mut self,
        solicitud: &SolicitudInferencia,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<RespuestaModelo, ErrorProveedor>;
}

/// Proveedor de prueba: egreso forzado; ruta directa siempre denegada.
pub struct ProveedorSimulado {
    credencial: CredencialProveedor,
    pub llamadas_delegadas: u32,
    pub intentos_directos: u32,
    /// Si true, la siguiente llamada delegada reporta digest distinto (incidente).
    pub forzar_divergencia: bool,
}

impl ProveedorSimulado {
    pub fn nuevo(credencial: CredencialProveedor) -> Self {
        ProveedorSimulado {
            credencial,
            llamadas_delegadas: 0,
            intentos_directos: 0,
            forzar_divergencia: false,
        }
    }

    /// Intento del sujeto de alcanzar el proveedor sin PEP.
    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudInferencia,
    ) -> Result<RespuestaModelo, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.credencial; // la credencial existe pero no se usa fuera del PEP
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    /// El sujeto/agente no puede leer la credencial.
    pub fn credencial_expuesta(&self) -> bool {
        false
    }
}

impl ProveedorModelo for ProveedorSimulado {
    fn inferir_delegado(
        &mut self,
        solicitud: &SolicitudInferencia,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<RespuestaModelo, ErrorProveedor> {
        let digest_params = crate::pep::solicitud::digest_solicitud_inferencia(solicitud);
        if digest_params != *digest_autorizado {
            return Err(ErrorProveedor::DivergenciaParametros);
        }
        // Uso interno de la credencial: firma de llamada; nunca se devuelve.
        let sello = self.credencial.firmar_llamada(&solicitud.canonico());
        self.llamadas_delegadas += 1;

        let digest_ejecutados = if self.forzar_divergencia {
            let mut d = digest_params;
            d[0] ^= 0xff;
            d
        } else {
            digest_params
        };

        let mut ref_msg = Vec::new();
        ref_msg.extend_from_slice(b"ok|");
        ref_msg.extend_from_slice(&sello);
        let digest_resultado = crypto::sha384_dominio(b"SAK-MODEL-OUT-v1|", &ref_msg);

        Ok(RespuestaModelo {
            digest_resultado,
            referencia_minima: format!("ref:{}", hex_corto(&digest_resultado)),
            digest_parametros_ejecutados: digest_ejecutados,
        })
    }
}

fn hex_corto(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
