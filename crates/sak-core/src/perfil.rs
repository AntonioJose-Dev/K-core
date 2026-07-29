//! Perfil normativo como dato — costura hacia el Bloque 2.
//!
//! Fuente canónica: Matriz Maestra v1.1 — sección E (motor de decisión: «contexto
//! tipado, perfil normativo, hechos firmados»), G.2 (precedencia) y Bloque 2
//! (objeto de norma completo y lenguaje de predicados).
//!
//! **Límite declarado del Bloque 1.** Este perfil es un dato mínimo de prueba
//! tras una interfaz de datos. El objeto de norma completo, el lenguaje de
//! predicados total y terminante y las ocho reglas de precedencia son del
//! Bloque 2. El motor del Bloque 1 evalúa sobre esta representación mínima
//! para que el Bloque 2 no obligue a rehacerlo.

use crate::contexto::ClaseEfecto;
use crate::decision::{HashPaqueteNormativo, IdNorma, Veredicto};
use std::fmt;

/// Rango de precedencia P0–P5 (G.2). El orden de declaración es el de la Matriz.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Rango {
    P0 = 0,
    P1 = 1,
    P2 = 2,
    P3 = 3,
    P4 = 4,
    P5 = 5,
}

impl Rango {
    pub const fn token(self) -> &'static str {
        match self {
            Rango::P0 => "P0",
            Rango::P1 => "P1",
            Rango::P2 => "P2",
            Rango::P3 => "P3",
            Rango::P4 => "P4",
            Rango::P5 => "P5",
        }
    }
}

impl fmt::Display for Rango {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Predicado mínimo de prueba del Bloque 1.
///
/// El lenguaje total y terminante llega en el Bloque 2. Aquí solo existen dos
/// formas deterministas, suficientes para demostrar cierre conservador,
/// presupuesto e ínfimo R2:
/// - `Constante(veredicto)`: aporta ese veredicto, consume un paso.
/// - `ConsumirPasos { pasos, veredicto }`: consume exactamente `pasos` del
///   presupuesto y, si alcanza, aporta `veredicto`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PredicadoMinimo {
    Constante(Veredicto),
    ConsumirPasos { pasos: u32, veredicto: Veredicto },
}

/// Norma mínima aplicable a una clase de efecto. Dato, no lógica jurídica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormaMinima {
    id: IdNorma,
    rango: Rango,
    clase: ClaseEfecto,
    predicado: PredicadoMinimo,
    /// Si es `true`, la norma fuerza escalado (R8 / G.3 `AMBIGUEDAD_DECLARADA`).
    ambigua: bool,
}

impl NormaMinima {
    pub fn nueva(
        id: IdNorma,
        rango: Rango,
        clase: ClaseEfecto,
        predicado: PredicadoMinimo,
        ambigua: bool,
    ) -> Self {
        NormaMinima {
            id,
            rango,
            clase,
            predicado,
            ambigua,
        }
    }

    pub fn id(&self) -> &IdNorma {
        &self.id
    }

    pub fn rango(&self) -> Rango {
        self.rango
    }

    pub fn clase(&self) -> ClaseEfecto {
        self.clase
    }

    pub fn predicado(&self) -> &PredicadoMinimo {
        &self.predicado
    }

    pub fn ambigua(&self) -> bool {
        self.ambigua
    }
}

/// Perfil normativo firmado y versionado como dato.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PerfilNormativo {
    hash_paquete: HashPaqueteNormativo,
    normas: Vec<NormaMinima>,
    /// Si es `true`, el perfil no se ha recalculado tras un cambio de corpus
    /// (G.3 `PERFIL_OBSOLETO`: solo efectos reversibles). En el Bloque 1 se
    /// modela como denegación de efectos no cubiertos por una norma que ya
    /// autorice explícitamente; el tratamiento completo es del Bloque 2.
    obsoleto: bool,
}

impl PerfilNormativo {
    pub fn nuevo(
        hash_paquete: HashPaqueteNormativo,
        normas: Vec<NormaMinima>,
        obsoleto: bool,
    ) -> Self {
        PerfilNormativo {
            hash_paquete,
            normas,
            obsoleto,
        }
    }

    pub fn hash_paquete(&self) -> &HashPaqueteNormativo {
        &self.hash_paquete
    }

    pub fn normas(&self) -> &[NormaMinima] {
        &self.normas
    }

    pub fn obsoleto(&self) -> bool {
        self.obsoleto
    }

    /// Normas del perfil cuya clase coincide con la solicitada.
    pub fn aplicables_a(&self, clase: ClaseEfecto) -> impl Iterator<Item = &NormaMinima> {
        self.normas.iter().filter(move |n| n.clase() == clase)
    }
}
