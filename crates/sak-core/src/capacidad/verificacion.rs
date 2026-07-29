//! Verificación de uso de capacidades (H.13, INV-08).

use super::tipos::{Alcance, Capability, IdCapacidad};
use crate::decision::{HashPaqueteNormativo, LONGITUD_HASH_PAQUETE};
use crate::identidad::IdSistema;
use crate::reloj::{RelojMonotonico, Ticks, MAX_ANTIGUEDAD_VISTA_REVOCACION_MS};
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CausaDenegacion {
    DigestDistinto,
    AlcanceDistinto,
    SistemaDistinto,
    EpocaInferior,
    EpocaInvalida,
    Expirada,
    Revocada,
    Repetida,
    VistaRevocacionObsoleta,
    SilencioRevocacion,
    VistaNoVerificable,
}

impl fmt::Display for CausaDenegacion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            CausaDenegacion::DigestDistinto => "DIGEST_DISTINTO",
            CausaDenegacion::AlcanceDistinto => "ALCANCE_DISTINTO",
            CausaDenegacion::SistemaDistinto => "SISTEMA_DISTINTO",
            CausaDenegacion::EpocaInferior => "EPOCA_INFERIOR",
            CausaDenegacion::EpocaInvalida => "EPOCA_INVALIDA",
            CausaDenegacion::Expirada => "EXPIRADA",
            CausaDenegacion::Revocada => "REVOCADA",
            CausaDenegacion::Repetida => "REPETIDA",
            CausaDenegacion::VistaRevocacionObsoleta => "VISTA_REVOCACION_OBSOLETA",
            CausaDenegacion::SilencioRevocacion => "SILENCIO_REVOCACION",
            CausaDenegacion::VistaNoVerificable => "VISTA_NO_VERIFICABLE",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroDenegacionUso {
    pub causa: CausaDenegacion,
    pub id_capacidad: IdCapacidad,
    pub ticks: Ticks,
}

/// Intento de ejercer una capacidad en un punto de aplicación.
#[derive(Debug, Clone)]
pub struct IntentoUso {
    pub sistema: IdSistema,
    pub digest_efecto: [u8; LONGITUD_HASH_PAQUETE],
    pub alcance: Alcance,
    pub epoca_actual: u64,
}

/// Vista de revocación presentada al verificador.
#[derive(Debug, Clone)]
pub enum VistaRevocacion {
    /// Consulta síncrona (latencia nula): obligatoria en efectos irreversibles.
    Sincrona {
        revocadas: HashSet<IdCapacidad>,
        /// Debe coincidir con `reloj.ahora()` (antigüedad 0).
        obtenida_en: Ticks,
    },
    /// Vista cacheada: solo admisible si el efecto es reversible y antigüedad ≤ 5 s.
    Cacheada {
        revocadas: HashSet<IdCapacidad>,
        obtenida_en: Ticks,
    },
    /// Silencio del motor ⇒ denegar.
    Silencio,
    /// Vista presente pero no verificable ⇒ denegar.
    NoVerificable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoVerificacion {
    Permitido { antiguedad_vista_ms: Ticks },
    Denegado { causa: CausaDenegacion },
}

/// Estado persistente de nonces, revocaciones y denegaciones (INV-08).
#[derive(Debug, Default)]
pub struct VerificadorCapacidades {
    /// Nonces consumidos por época.
    nonces_por_epoca: HashMap<u64, HashSet<IdCapacidad>>,
    revocadas: HashSet<IdCapacidad>,
    /// Capacidades indexadas por hash del paquete normativo (G.5 revocación).
    por_paquete: HashMap<[u8; LONGITUD_HASH_PAQUETE], HashSet<IdCapacidad>>,
    /// Suelo monótono de época: capacidades con época < suelo se rechazan.
    suelo_epoca: u64,
    denegaciones: Vec<RegistroDenegacionUso>,
}

impl VerificadorCapacidades {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        VerificadorCapacidades {
            nonces_por_epoca: HashMap::new(),
            revocadas: HashSet::new(),
            por_paquete: HashMap::new(),
            suelo_epoca,
            denegaciones: Vec::new(),
        }
    }

    /// Indexa una capacidad emitida bajo el hash de su paquete normativo.
    pub fn indexar_capacidad(&mut self, capacidad: &Capability) {
        let h = *capacidad.decision().hash_paquete().bytes();
        self.por_paquete
            .entry(h)
            .or_default()
            .insert(*capacidad.id());
    }

    /// Revoca todas las capacidades vivas emitidas bajo el hash del paquete (G.5).
    pub fn revocar_por_paquete(&mut self, hash: &HashPaqueteNormativo) -> usize {
        let mut n = 0;
        if let Some(ids) = self.por_paquete.get(hash.bytes()) {
            for id in ids {
                if self.revocadas.insert(*id) {
                    n += 1;
                }
            }
        }
        n
    }

    pub fn suelo_epoca(&self) -> u64 {
        self.suelo_epoca
    }

    /// Avanza el suelo de época (anti-rollback). No retrocede.
    pub fn avanzar_suelo_epoca(&mut self, nuevo: u64) -> Result<(), CausaDenegacion> {
        if nuevo < self.suelo_epoca {
            return Err(CausaDenegacion::EpocaInferior);
        }
        self.suelo_epoca = nuevo;
        Ok(())
    }

    pub fn revocar(&mut self, id: IdCapacidad) {
        self.revocadas.insert(id);
    }

    pub fn vista_sincrona(&self, reloj: &impl RelojMonotonico) -> VistaRevocacion {
        VistaRevocacion::Sincrona {
            revocadas: self.revocadas.clone(),
            obtenida_en: reloj.ahora(),
        }
    }

    pub fn snapshot_revocacion(&self) -> HashSet<IdCapacidad> {
        self.revocadas.clone()
    }

    pub fn denegaciones(&self) -> &[RegistroDenegacionUso] {
        &self.denegaciones
    }

    pub fn nonce_consumido(&self, epoca: u64, id: &IdCapacidad) -> bool {
        self.nonces_por_epoca
            .get(&epoca)
            .map(|s| s.contains(id))
            .unwrap_or(false)
    }

    /// Verifica vigencia, alcance, época, no revocación y unicidad (H.13).
    ///
    /// No hay caché permisiva: cada uso se evalúa de nuevo.
    pub fn verificar_uso(
        &mut self,
        capacidad: &Capability,
        intento: &IntentoUso,
        vista: &VistaRevocacion,
        reloj: &impl RelojMonotonico,
    ) -> ResultadoVerificacion {
        let ahora = reloj.ahora();
        let denegar = |this: &mut Self, causa: CausaDenegacion| {
            this.denegaciones.push(RegistroDenegacionUso {
                causa: causa.clone(),
                id_capacidad: *capacidad.id(),
                ticks: ahora,
            });
            ResultadoVerificacion::Denegado { causa }
        };

        if capacidad.epoca() == 0 || intento.epoca_actual == 0 {
            return denegar(self, CausaDenegacion::EpocaInvalida);
        }
        if capacidad.epoca() < self.suelo_epoca || intento.epoca_actual < self.suelo_epoca {
            return denegar(self, CausaDenegacion::EpocaInferior);
        }
        if intento.epoca_actual != capacidad.epoca() {
            // Época presentada distinta / inferior respecto de la ligada.
            if intento.epoca_actual < capacidad.epoca() {
                return denegar(self, CausaDenegacion::EpocaInferior);
            }
            return denegar(self, CausaDenegacion::EpocaInvalida);
        }
        if intento.sistema != *capacidad.sistema() {
            return denegar(self, CausaDenegacion::SistemaDistinto);
        }
        if intento.digest_efecto != *capacidad.digest_efecto() {
            return denegar(self, CausaDenegacion::DigestDistinto);
        }
        if !capacidad.alcance().cubre(&intento.alcance) {
            return denegar(self, CausaDenegacion::AlcanceDistinto);
        }
        if ahora > capacidad.vive_hasta() {
            return denegar(self, CausaDenegacion::Expirada);
        }

        let (revocadas, antiguedad) = match vista {
            VistaRevocacion::Silencio => {
                return denegar(self, CausaDenegacion::SilencioRevocacion);
            }
            VistaRevocacion::NoVerificable => {
                return denegar(self, CausaDenegacion::VistaNoVerificable);
            }
            VistaRevocacion::Sincrona {
                revocadas,
                obtenida_en,
            } => {
                if *obtenida_en != ahora {
                    // Latencia nula incumplida.
                    return denegar(self, CausaDenegacion::VistaRevocacionObsoleta);
                }
                (revocadas, 0)
            }
            VistaRevocacion::Cacheada {
                revocadas,
                obtenida_en,
            } => {
                if capacidad.irreversible() {
                    // Irreversible exige consulta síncrona; cache ⇒ no verificable / silencio de sync.
                    return denegar(self, CausaDenegacion::VistaNoVerificable);
                }
                let ant = ahora.saturating_sub(*obtenida_en);
                if ant > MAX_ANTIGUEDAD_VISTA_REVOCACION_MS {
                    return denegar(self, CausaDenegacion::VistaRevocacionObsoleta);
                }
                (revocadas, ant)
            }
        };

        if revocadas.contains(capacidad.id()) || self.revocadas.contains(capacidad.id()) {
            return denegar(self, CausaDenegacion::Revocada);
        }

        if capacidad.un_solo_uso() {
            let set = self
                .nonces_por_epoca
                .entry(capacidad.epoca())
                .or_default();
            if !set.insert(*capacidad.id()) {
                return denegar(self, CausaDenegacion::Repetida);
            }
        }

        ResultadoVerificacion::Permitido {
            antiguedad_vista_ms: antiguedad,
        }
    }
}
