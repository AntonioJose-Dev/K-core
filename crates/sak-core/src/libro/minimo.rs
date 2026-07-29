//! Mínimos de garantía por clase (sección C) para INV-09.

use crate::contexto::ClaseEfecto;
use crate::libro::nivel::NivelControl;

/// Mínimo exigido para autorizar la clase. Por debajo ⇒ `DENY(CONTROL_INSUFICIENTE)`.
///
/// Simplificación operativa del Bloque 8 (sin Libro de riesgo por pasaporte):
/// EF-1 sin datos personales admite C2; con datos personales exige C3.
/// EF-5/6/7/11 exigen C4 (delegado). EF-9 exige C5 o queda denegada. EF-12 nunca.
pub fn minimo_exigido(clase: ClaseEfecto, datos_personales: bool) -> NivelControl {
    match clase {
        ClaseEfecto::Ef1 => {
            if datos_personales {
                NivelControl::C3
            } else {
                NivelControl::C2
            }
        }
        ClaseEfecto::Ef2 | ClaseEfecto::Ef3 | ClaseEfecto::Ef4 | ClaseEfecto::Ef8 => {
            NivelControl::C3
        }
        ClaseEfecto::Ef5 | ClaseEfecto::Ef6 | ClaseEfecto::Ef7 | ClaseEfecto::Ef11 => {
            NivelControl::C4
        }
        ClaseEfecto::Ef10 => {
            if datos_personales {
                NivelControl::C4
            } else {
                NivelControl::C3
            }
        }
        ClaseEfecto::Ef9 => NivelControl::C5,
        ClaseEfecto::Ef12 => NivelControl::C5, // inalcanzable en la práctica ⇒ siempre deny
    }
}
