//! Corpus activo, historial permanente y reconstrucción (G.5).

use crate::decision::HashPaqueteNormativo;
use crate::gobernanza::activacion::ErrorActivacion;
use crate::gobernanza::conformidad::{DiffDecisiones, ReconocimientoCambio};
use crate::gobernanza::firmantes::FirmaPaquete;
use crate::gobernanza::propuesta::PropuestaNormativa;
use crate::norma::PaqueteNormativo;
use crate::reloj::Ticks;
use std::collections::BTreeMap;
use std::fmt;

/// Etiqueta de dependencia de gobernanza / validación externa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EtiquetaGob {
    /// Procedimiento de gobernanza humana (GOB).
    Gob = 1,
    /// Validación externa (VAL-EXT).
    ValExt = 2,
}

impl EtiquetaGob {
    pub const fn token(self) -> &'static str {
        match self {
            EtiquetaGob::Gob => "GOB",
            EtiquetaGob::ValExt => "VAL-EXT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoPropuesta {
    Borrador,
    Revisada,
    ConformidadOk,
    Firmada,
    EnSombra { desde: Ticks },
    Activa { epoca: u64 },
    Revocada { en: Ticks },
}

impl fmt::Display for EstadoPropuesta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EstadoPropuesta::Borrador => f.write_str("BORRADOR"),
            EstadoPropuesta::Revisada => f.write_str("REVISADA"),
            EstadoPropuesta::ConformidadOk => f.write_str("CONFORMIDAD_OK"),
            EstadoPropuesta::Firmada => f.write_str("FIRMADA"),
            EstadoPropuesta::EnSombra { .. } => f.write_str("EN_SOMBRA"),
            EstadoPropuesta::Activa { .. } => f.write_str("ACTIVA"),
            EstadoPropuesta::Revocada { .. } => f.write_str("REVOCADA"),
        }
    }
}

/// Versión conservada indefinidamente (nunca se borra).
#[derive(Debug, Clone)]
pub struct VersionCorpus {
    pub hash: HashPaqueteNormativo,
    pub paquete: PaqueteNormativo,
    pub estado: EstadoPropuesta,
    pub epoca_activacion: Option<u64>,
    pub diff: Option<DiffDecisiones>,
    pub reconocimientos: Vec<ReconocimientoCambio>,
    pub firmas: Vec<FirmaPaquete>,
    pub activado_en: Option<Ticks>,
    pub revocado_en: Option<Ticks>,
}

/// Custodia del ciclo G.5 y del historial.
#[derive(Debug, Default)]
pub struct GobernanzaCorpus {
    versiones: BTreeMap<[u8; 48], VersionCorpus>,
    /// Orden de activación (histórico, nunca truncado): (hash, época de activación).
    historial_activaciones: Vec<(HashPaqueteNormativo, u64)>,
    activo: Option<HashPaqueteNormativo>,
}

impl GobernanzaCorpus {
    pub fn nuevo() -> Self {
        Self::default()
    }

    pub fn proponer(&mut self, propuesta: PropuestaNormativa) -> HashPaqueteNormativo {
        let hash = *propuesta.paquete.hash();
        let estado = if propuesta.revision_ok {
            EstadoPropuesta::Revisada
        } else {
            EstadoPropuesta::Borrador
        };
        if let Some(v) = self.versiones.get_mut(hash.bytes()) {
            // Reversión / repropuesta: no se borra la entrada histórica; se reinicia el ciclo.
            v.paquete = propuesta.paquete;
            v.estado = estado;
            v.diff = None;
            v.reconocimientos = Vec::new();
            v.firmas = Vec::new();
            // Se conservan epoca_activacion previa y revocado_en como rastro.
            return hash;
        }
        self.versiones.insert(
            *hash.bytes(),
            VersionCorpus {
                hash,
                paquete: propuesta.paquete,
                estado,
                epoca_activacion: None,
                diff: None,
                reconocimientos: Vec::new(),
                firmas: Vec::new(),
                activado_en: None,
                revocado_en: None,
            },
        );
        hash
    }

    pub fn propuesta(&self, hash: &HashPaqueteNormativo) -> Option<&VersionCorpus> {
        self.versiones.get(hash.bytes())
    }

    pub fn estado(&self, hash: &HashPaqueteNormativo) -> Option<&EstadoPropuesta> {
        self.versiones.get(hash.bytes()).map(|v| &v.estado)
    }

    pub fn activo(&self) -> Option<&PaqueteNormativo> {
        self.activo
            .as_ref()
            .and_then(|h| self.versiones.get(h.bytes()).map(|v| &v.paquete))
    }

    pub fn hash_activo(&self) -> Option<&HashPaqueteNormativo> {
        self.activo.as_ref()
    }

    pub fn historial(&self) -> &[(HashPaqueteNormativo, u64)] {
        &self.historial_activaciones
    }

    pub fn version(&self, hash: &HashPaqueteNormativo) -> Option<&VersionCorpus> {
        self.versiones.get(hash.bytes())
    }

    /// Reconstrucción: último paquete activado con época ≤ la pedida (historia intacta).
    pub fn reconstruir_en_epoca(&self, epoca: u64) -> Option<&PaqueteNormativo> {
        let mut chosen = None;
        for (h, ea) in &self.historial_activaciones {
            if *ea <= epoca {
                chosen = self.versiones.get(h.bytes()).map(|v| &v.paquete);
            }
        }
        chosen
    }

    /// Todas las versiones conservadas (incluye revocadas y sombras).
    pub fn todas_las_versiones(&self) -> impl Iterator<Item = &VersionCorpus> {
        self.versiones.values()
    }

    pub fn registrar_diff(
        &mut self,
        hash: &HashPaqueteNormativo,
        diff: DiffDecisiones,
        reconocimientos: Vec<ReconocimientoCambio>,
    ) -> Result<(), ErrorActivacion> {
        let v = self
            .versiones
            .get_mut(hash.bytes())
            .ok_or(ErrorActivacion::PaqueteNoEncontrado)?;
        if !matches!(
            v.estado,
            EstadoPropuesta::Revisada | EstadoPropuesta::ConformidadOk | EstadoPropuesta::Borrador
        ) {
            return Err(ErrorActivacion::EstadoInvalido);
        }
        v.diff = Some(diff);
        v.reconocimientos = reconocimientos;
        v.estado = EstadoPropuesta::ConformidadOk;
        Ok(())
    }

    pub fn registrar_firmas(&mut self, hash: &HashPaqueteNormativo, firmas: Vec<FirmaPaquete>) {
        if let Some(v) = self.versiones.get_mut(hash.bytes()) {
            v.firmas = firmas;
        }
    }

    pub fn transicionar(
        &mut self,
        hash: &HashPaqueteNormativo,
        nuevo: EstadoPropuesta,
        _ahora: Ticks,
    ) -> Result<(), ErrorActivacion> {
        let v = self
            .versiones
            .get_mut(hash.bytes())
            .ok_or(ErrorActivacion::PaqueteNoEncontrado)?;
        v.estado = nuevo;
        Ok(())
    }

    pub fn activar(
        &mut self,
        hash: &HashPaqueteNormativo,
        epoca: u64,
        ahora: Ticks,
    ) -> Result<(), ErrorActivacion> {
        // El anterior permanece en historial; solo deja de ser el activo.
        if let Some(prev) = self.activo {
            if let Some(v) = self.versiones.get_mut(prev.bytes()) {
                if matches!(v.estado, EstadoPropuesta::Activa { .. }) {
                    // Conservado: no se borra; deja de marcarse como único activo.
                    // Estado histórico: se mantiene Activa con su época (reconstrucción).
                    let _ = v;
                }
            }
        }
        let v = self
            .versiones
            .get_mut(hash.bytes())
            .ok_or(ErrorActivacion::PaqueteNoEncontrado)?;
        if !matches!(v.estado, EstadoPropuesta::EnSombra { .. }) {
            return Err(ErrorActivacion::NoEnSombra);
        }
        v.estado = EstadoPropuesta::Activa { epoca };
        v.epoca_activacion = Some(epoca);
        v.activado_en = Some(ahora);
        self.activo = Some(*hash);
        self.historial_activaciones.push((*hash, epoca));
        Ok(())
    }

    pub fn revocar(
        &mut self,
        hash: &HashPaqueteNormativo,
        ahora: Ticks,
    ) -> Result<(), ErrorActivacion> {
        let v = self
            .versiones
            .get_mut(hash.bytes())
            .ok_or(ErrorActivacion::PaqueteNoEncontrado)?;
        if !matches!(v.estado, EstadoPropuesta::Activa { .. }) {
            return Err(ErrorActivacion::EstadoInvalido);
        }
        v.estado = EstadoPropuesta::Revocada { en: ahora };
        v.revocado_en = Some(ahora);
        if self.activo.as_ref() == Some(hash) {
            self.activo = None;
        }
        // Historia intacta: el hash sigue en historial_activaciones y versiones.
        Ok(())
    }

    /// Reversión = reactivar versión anterior por el mismo procedimiento (nueva propuesta).
    /// Nunca borra. Devuelve el paquete histórico para reproponerlo.
    pub fn paquete_historico(
        &self,
        hash: &HashPaqueteNormativo,
    ) -> Option<&PaqueteNormativo> {
        self.versiones.get(hash.bytes()).map(|v| &v.paquete)
    }

    pub fn serializar_evento_activacion(
        hash: &HashPaqueteNormativo,
        epoca: u64,
    ) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // ACTIVACION
        v.extend_from_slice(hash.bytes());
        v.extend_from_slice(&epoca.to_le_bytes());
        v
    }

    pub fn serializar_evento_revocacion(hash: &HashPaqueteNormativo) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(2); // REVOCACION
        v.extend_from_slice(hash.bytes());
        v
    }

    pub fn serializar_evento_sombra(hash: &HashPaqueteNormativo, desde: Ticks) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(3); // SOMBRA
        v.extend_from_slice(hash.bytes());
        v.extend_from_slice(&desde.to_le_bytes());
        v
    }

    pub fn serializar_diff(diff: &DiffDecisiones) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(4); // DIFF
        v.extend_from_slice(&(diff.cambios.len() as u32).to_le_bytes());
        for c in &diff.cambios {
            let id = c.id_caso.as_bytes();
            v.extend_from_slice(&(id.len() as u16).to_le_bytes());
            v.extend_from_slice(id);
            v.extend_from_slice(&c.digest_cambio);
            v.push(c.anterior as u8);
            v.push(c.nuevo as u8);
        }
        v
    }
}
