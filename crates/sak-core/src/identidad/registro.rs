//! Registro soberano de sistemas de IA y pasaportes.

use crate::crypto::{ParMlDsa87, ErrorCrypto};
use crate::identidad::authn::IdentidadResuelta;
use crate::identidad::pasaporte::{self, Pasaporte, PasaporteVigente};
use crate::identidad::artefacto::IdSistema;
use std::collections::BTreeMap;

/// Registro soberano: emite y custodia pasaportes firmados y versionados.
pub struct RegistroSoberano {
    firmante: ParMlDsa87,
    /// pasaporte_id → versiones ordenadas (la máxima es la vigente registrada).
    por_id: BTreeMap<String, Vec<Pasaporte>>,
}

impl RegistroSoberano {
    pub fn nuevo() -> Result<Self, ErrorCrypto> {
        Ok(RegistroSoberano {
            firmante: ParMlDsa87::generar()?,
            por_id: BTreeMap::new(),
        })
    }

    pub fn pk_bytes(&self) -> &[u8] {
        &self.firmante.public
    }

    /// Registra un pasaporte nuevo. `version` debe ser ≥ 1.
    pub fn registrar(
        &mut self,
        id: impl Into<String>,
        version: u32,
        sistema_id: IdSistema,
        responsable: impl Into<String>,
        finalidad: impl Into<String>,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
    ) -> Result<Pasaporte, ErrorRegistro> {
        if version == 0 {
            return Err(ErrorRegistro::VersionObligatoria);
        }
        let id = id.into();
        let p = pasaporte::sellar_pasaporte(
            id.clone(),
            version,
            sistema_id,
            responsable.into(),
            finalidad.into(),
            vigente_desde_dias,
            vigente_hasta_dias,
            &self.firmante,
        )
        .map_err(|_| ErrorRegistro::Firma)?;
        self.por_id.entry(id).or_default().push(p.clone());
        Ok(p)
    }

    /// H.3: carga el pasaporte ligado a la identidad, exige firma, versión y vigencia.
    pub fn cargar_pasaporte_vigente(
        &self,
        identidad: &IdentidadResuelta,
        instante_epoch_dias: u32,
    ) -> Result<PasaporteVigente, String> {
        let versions = self
            .por_id
            .get(identidad.pasaporte_id())
            .ok_or_else(|| "pasaporte inexistente en registro".to_string())?;

        let p = versions
            .iter()
            .find(|p| p.version() == identidad.pasaporte_version())
            .ok_or_else(|| "version de pasaporte no encontrada".to_string())?;

        if p.sistema_id() != identidad.sistema_id() {
            return Err("pasaporte no ligado a la identidad del artefacto".into());
        }
        if p.version() == 0 {
            return Err("pasaporte sin version".into());
        }
        if !p.firma_valida() {
            return Err("firma de pasaporte invalida".into());
        }
        if !p.vigente_en(instante_epoch_dias) {
            return Err("pasaporte vencido o no vigente aun".into());
        }
        Ok(pasaporte::como_vigente(p.clone()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorRegistro {
    VersionObligatoria,
    Firma,
}

impl std::fmt::Display for ErrorRegistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRegistro::VersionObligatoria => f.write_str("version de pasaporte obligatoria (>=1)"),
            ErrorRegistro::Firma => f.write_str("fallo al firmar pasaporte"),
        }
    }
}

impl std::error::Error for ErrorRegistro {}
