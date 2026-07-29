//! Códigos y puerta de las fases H.2 / H.3.

use crate::contexto::EfectoTipado;
use crate::identidad::artefacto::{ArtefactoCliente, PruebaPosesion};
use crate::identidad::authn::{autenticar_mutua, IdentidadResuelta};
use crate::identidad::ca::AutoridadCertificacion;
use crate::identidad::pasaporte::PasaporteVigente;
use crate::identidad::registro::RegistroSoberano;
use std::fmt;

/// Códigos de denegación de las fases 2 y 3 de H (no son códigos de G.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodigoPuerta {
    /// H.2: artefacto no verificable ⇒ `DENY(IDENTIDAD)`.
    Identidad,
    /// H.3: sin pasaporte vigente/firmado/versionado ⇒ `DENY(SIN_REGISTRO)`.
    SinRegistro,
}

impl CodigoPuerta {
    pub const fn token(self) -> &'static str {
        match self {
            CodigoPuerta::Identidad => "IDENTIDAD",
            CodigoPuerta::SinRegistro => "SIN_REGISTRO",
        }
    }
}

impl fmt::Display for CodigoPuerta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Hallazgo de sistema no registrado (H.3 / INV-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HallazgoSistemaNoRegistrado {
    pub identidad_resuelta: Option<String>,
    pub motivo: String,
}

/// Petición de entrada a la cadena H.
///
/// `identidad_autodeclarada` existe para demostrar INV-05: **siempre se ignora**.
#[derive(Debug, Clone)]
pub struct PeticionIdentidad {
    pub artefacto: ArtefactoCliente,
    pub prueba_cliente: PruebaPosesion,
    /// Respuesta del servidor (CA) al mismo digest: autenticación mutua.
    pub prueba_servidor: PruebaPosesion,
    /// Campo autodeclarado. Se ignora; no participa en la identidad efectiva.
    pub identidad_autodeclarada: Option<String>,
    pub efecto: EfectoTipado,
    /// Instante inyectado (días epoch) para vigencia de artefacto y pasaporte.
    pub instante_epoch_dias: u32,
}

#[derive(Debug, Clone)]
pub struct ContextoAutorizado {
    pub identidad: IdentidadResuelta,
    pub pasaporte: PasaporteVigente,
    pub efecto: EfectoTipado,
}

#[derive(Debug, Clone)]
pub enum ResultadoPuerta {
    Permitido(ContextoAutorizado),
    Denegado {
        codigo: CodigoPuerta,
        hallazgo: Option<HallazgoSistemaNoRegistrado>,
    },
}

impl ResultadoPuerta {
    pub fn codigo(&self) -> Option<CodigoPuerta> {
        match self {
            ResultadoPuerta::Denegado { codigo, .. } => Some(*codigo),
            ResultadoPuerta::Permitido(_) => None,
        }
    }

    pub fn permitido(&self) -> Option<&ContextoAutorizado> {
        match self {
            ResultadoPuerta::Permitido(c) => Some(c),
            ResultadoPuerta::Denegado { .. } => None,
        }
    }
}

/// Fases H.2 y H.3: autenticación mutua, ignorar autodeclaración, exigir pasaporte.
pub fn resolver_puerta_h2_h3(
    ca: &AutoridadCertificacion,
    registro: &RegistroSoberano,
    peticion: &PeticionIdentidad,
) -> ResultadoPuerta {
    // H.2 — el campo autodeclarado se ignora deliberadamente (INV-05).
    let _ignorada = &peticion.identidad_autodeclarada;

    let identidad = match autenticar_mutua(
        ca,
        &peticion.artefacto,
        &peticion.prueba_cliente,
        &peticion.prueba_servidor,
        peticion.instante_epoch_dias,
    ) {
        Ok(id) => id,
        Err(_) => {
            return ResultadoPuerta::Denegado {
                codigo: CodigoPuerta::Identidad,
                hallazgo: None,
            };
        }
    };

    // H.3 — pasaporte vigente, firmado y versionado.
    match registro.cargar_pasaporte_vigente(&identidad, peticion.instante_epoch_dias) {
        Ok(pasaporte) => ResultadoPuerta::Permitido(ContextoAutorizado {
            identidad,
            pasaporte,
            efecto: peticion.efecto.clone(),
        }),
        Err(motivo) => ResultadoPuerta::Denegado {
            codigo: CodigoPuerta::SinRegistro,
            hallazgo: Some(HallazgoSistemaNoRegistrado {
                identidad_resuelta: Some(identidad.sistema_id().to_string()),
                motivo,
            }),
        },
    }
}
