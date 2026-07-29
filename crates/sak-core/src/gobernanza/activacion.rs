//! Sombra de siete días, activación en límite de época, revocación (G.5 5–7).

use crate::capacidad::VerificadorCapacidades;
use crate::decision::HashPaqueteNormativo;
use crate::evidencia::AlmacenEvidencia;
use crate::monitor::EpocaMonotonica;
use crate::reloj::Ticks;
use crate::gobernanza::corpus::{EstadoPropuesta, GobernanzaCorpus};
use crate::gobernanza::firmantes::{verificar_doble_firma, FirmaPaquete, RegistroFirmantesGob};
use std::fmt;

/// Ventana de sombra: siete días en ticks (1 tick ≡ 1 ms).
pub const VENTANA_SOMBRA_MS: Ticks = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorActivacion {
    NoEnSombra,
    SombraIncompleta { faltan_ms: Ticks },
    FueraDeLimiteEpoca,
    Firmas(crate::gobernanza::firmantes::ErrorFirmas),
    Epoca(crate::monitor::ErrorEpoca),
    EstadoInvalido,
    PaqueteNoEncontrado,
}

impl fmt::Display for ErrorActivacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorActivacion::NoEnSombra => f.write_str("paquete no esta en sombra"),
            ErrorActivacion::SombraIncompleta { faltan_ms } => {
                write!(f, "sombra incompleta; faltan {faltan_ms} ms")
            }
            ErrorActivacion::FueraDeLimiteEpoca => {
                f.write_str("activacion fuera de limite de epoca")
            }
            ErrorActivacion::Firmas(e) => write!(f, "firmas: {e}"),
            ErrorActivacion::Epoca(e) => write!(f, "epoca: {e}"),
            ErrorActivacion::EstadoInvalido => f.write_str("estado de propuesta invalido"),
            ErrorActivacion::PaqueteNoEncontrado => f.write_str("paquete no encontrado"),
        }
    }
}

impl std::error::Error for ErrorActivacion {}

/// Entra en sombra tras doble firma válida (sin aplicar aún).
pub fn entrar_en_sombra(
    gob: &mut GobernanzaCorpus,
    hash: &HashPaqueteNormativo,
    firmas: &[FirmaPaquete],
    registro: &RegistroFirmantesGob,
    ahora: Ticks,
) -> Result<(), ErrorActivacion> {
    let mensaje = {
        let p = gob
            .propuesta(hash)
            .ok_or(ErrorActivacion::PaqueteNoEncontrado)?;
        p.paquete.mensaje_firma()
    };
    verificar_doble_firma(&mensaje, firmas, registro).map_err(ErrorActivacion::Firmas)?;
    match gob.estado(hash) {
        Some(EstadoPropuesta::ConformidadOk) | Some(EstadoPropuesta::Firmada) => {}
        _ => return Err(ErrorActivacion::EstadoInvalido),
    }
    gob.transicionar(hash, EstadoPropuesta::Firmada, ahora)?;
    gob.transicionar(
        hash,
        EstadoPropuesta::EnSombra { desde: ahora },
        ahora,
    )?;
    gob.registrar_firmas(hash, firmas.to_vec());
    Ok(())
}

/// Activación solo en límite de época, tras ventana de sombra completa.
pub fn activar_en_limite_epoca(
    gob: &mut GobernanzaCorpus,
    hash: &HashPaqueteNormativo,
    epoca: &mut EpocaMonotonica,
    almacen: &mut dyn AlmacenEvidencia,
    ahora: Ticks,
    en_limite_epoca: bool,
) -> Result<u64, ErrorActivacion> {
    if !en_limite_epoca {
        return Err(ErrorActivacion::FueraDeLimiteEpoca);
    }
    let desde = match gob.estado(hash) {
        Some(EstadoPropuesta::EnSombra { desde }) => *desde,
        _ => return Err(ErrorActivacion::NoEnSombra),
    };
    let elapsed = ahora.saturating_sub(desde);
    if elapsed < VENTANA_SOMBRA_MS {
        return Err(ErrorActivacion::SombraIncompleta {
            faltan_ms: VENTANA_SOMBRA_MS - elapsed,
        });
    }
    let nuevo = epoca.avanzar(almacen).map_err(ErrorActivacion::Epoca)?;
    gob.activar(hash, nuevo, ahora)?;
    Ok(nuevo)
}

/// Revoca un paquete: no borra historia; invalida capacidades vivas bajo su hash.
pub fn revocar_paquete(
    gob: &mut GobernanzaCorpus,
    hash: &HashPaqueteNormativo,
    verificador: &mut VerificadorCapacidades,
    ahora: Ticks,
) -> Result<usize, ErrorActivacion> {
    gob.revocar(hash, ahora)?;
    Ok(verificador.revocar_por_paquete(hash))
}
