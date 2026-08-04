//! Registro soberano de sistemas de IA y pasaportes (INV-04 / §E).

use crate::crypto::{ParMlDsa87, ErrorCrypto};
use crate::identidad::artefacto::IdSistema;
use crate::identidad::authn::IdentidadResuelta;
use crate::identidad::pasaporte::{self, DeclaracionResponsable, Pasaporte, PasaporteVigente};
use std::collections::BTreeMap;

/// Registro soberano: emite y custodia pasaportes firmados y versionados.
pub struct RegistroSoberano {
    firmante: ParMlDsa87,
    /// pasaporte_id → versiones (histórico; no se reescribe una versión).
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

    /// Número de versiones conservadas (todas las ids).
    pub fn n_versiones(&self) -> usize {
        self.por_id.values().map(|v| v.len()).sum()
    }

    /// Registra un pasaporte nuevo. `version` debe ser ≥ 1 y no reutilizar una ya emitida.
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
        self.sellar_y_guardar(
            id.into(),
            version,
            sistema_id,
            responsable.into(),
            finalidad.into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            vigente_desde_dias,
            vigente_hasta_dias,
        )
    }

    /// Crea el pasaporte desde la declaración firmada del responsable (§E).
    pub fn registrar_desde_declaracion(
        &mut self,
        id: impl Into<String>,
        version: u32,
        decl: &DeclaracionResponsable,
    ) -> Result<Pasaporte, ErrorRegistro> {
        if !decl.firma_valida() {
            return Err(ErrorRegistro::DeclaracionInvalida);
        }
        self.sellar_y_guardar(
            id.into(),
            version,
            decl.sistema_id().clone(),
            decl.responsable().to_string(),
            decl.finalidad().to_string(),
            decl.modelos().to_string(),
            decl.jurisdiccion().to_string(),
            decl.datos().to_string(),
            decl.autonomia_por_clase().to_string(),
            decl.herramientas().to_string(),
            decl.efectores().to_string(),
            decl.clasificacion_riesgo().to_string(),
            decl.vigente_desde_dias(),
            decl.vigente_hasta_dias(),
        )
    }

    fn sellar_y_guardar(
        &mut self,
        id: String,
        version: u32,
        sistema_id: IdSistema,
        responsable: String,
        finalidad: String,
        modelos: String,
        jurisdiccion: String,
        datos: String,
        autonomia_por_clase: String,
        herramientas: String,
        efectores: String,
        clasificacion_riesgo: String,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
    ) -> Result<Pasaporte, ErrorRegistro> {
        if version == 0 {
            return Err(ErrorRegistro::VersionObligatoria);
        }
        if let Some(vs) = self.por_id.get(&id) {
            if vs.iter().any(|p| p.version() == version) {
                return Err(ErrorRegistro::VersionYaExiste);
            }
        }
        let p = pasaporte::sellar_pasaporte(
            id.clone(),
            version,
            sistema_id,
            responsable,
            finalidad,
            modelos,
            jurisdiccion,
            datos,
            autonomia_por_clase,
            herramientas,
            efectores,
            clasificacion_riesgo,
            vigente_desde_dias,
            vigente_hasta_dias,
            &self.firmante,
        )
        .map_err(|_| ErrorRegistro::Firma)?;
        self.por_id.entry(id).or_default().push(p.clone());
        Ok(p)
    }

    /// Inserta un pasaporte ya sellado (carga durable). No sobrescribe la misma versión.
    pub fn restaurar(&mut self, p: Pasaporte) -> Result<(), ErrorRegistro> {
        if p.version() == 0 || !p.firma_valida() {
            return Err(ErrorRegistro::Firma);
        }
        let id = p.id().to_string();
        if let Some(vs) = self.por_id.get(&id) {
            if vs.iter().any(|x| x.version() == p.version()) {
                return Err(ErrorRegistro::VersionYaExiste);
            }
        }
        self.por_id.entry(id).or_default().push(p);
        Ok(())
    }

    pub fn obtener(&self, id: &str, version: u32) -> Option<&Pasaporte> {
        self.por_id
            .get(id)?
            .iter()
            .find(|p| p.version() == version)
    }

    pub fn version_activa(&self, id: &str) -> Option<u32> {
        self.por_id.get(id)?.iter().map(|p| p.version()).max()
    }

    /// Lista (pasaporte_id, version, sistema_id, finalidad, clasificacion_riesgo).
    pub fn listar(&self) -> Vec<(String, u32, String, String, String)> {
        let mut out = Vec::new();
        for (id, vs) in &self.por_id {
            for p in vs {
                out.push((
                    id.clone(),
                    p.version(),
                    p.sistema_id().to_string(),
                    p.finalidad().to_string(),
                    p.clasificacion_riesgo().to_string(),
                ));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        out
    }

    /// H.3: carga el pasaporte ligado a la identidad; exige firma, versión, vigencia y no sustituido.
    pub fn cargar_pasaporte_vigente(
        &self,
        identidad: &IdentidadResuelta,
        instante_epoch_dias: u32,
    ) -> Result<PasaporteVigente, String> {
        self.exigir_pasaporte_vigente(
            identidad.sistema_id(),
            identidad.pasaporte_id(),
            identidad.pasaporte_version(),
            instante_epoch_dias,
        )
    }

    /// INV-04: el pasaporte debe ser del sistema, firmado, vigente y no sustituido.
    pub fn exigir_pasaporte_vigente(
        &self,
        sistema_id: &str,
        pasaporte_id: &str,
        version: u32,
        instante_epoch_dias: u32,
    ) -> Result<PasaporteVigente, String> {
        let versions = self
            .por_id
            .get(pasaporte_id)
            .ok_or_else(|| "pasaporte inexistente en registro".to_string())?;

        let p = versions
            .iter()
            .find(|p| p.version() == version)
            .ok_or_else(|| "version de pasaporte no encontrada".to_string())?;

        if p.sistema_id() != sistema_id {
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
        let max_v = versions.iter().map(|x| x.version()).max().unwrap_or(0);
        if p.version() != max_v {
            return Err("pasaporte sustituido por version posterior".into());
        }
        Ok(pasaporte::como_vigente(p.clone()))
    }

    pub fn todas_las_versiones(&self) -> impl Iterator<Item = &Pasaporte> {
        self.por_id.values().flat_map(|v| v.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorRegistro {
    VersionObligatoria,
    VersionYaExiste,
    Firma,
    DeclaracionInvalida,
}

impl std::fmt::Display for ErrorRegistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorRegistro::VersionObligatoria => {
                f.write_str("version de pasaporte obligatoria (>=1)")
            }
            ErrorRegistro::VersionYaExiste => {
                f.write_str("version de pasaporte ya existe (no se reescribe)")
            }
            ErrorRegistro::Firma => f.write_str("fallo al firmar pasaporte"),
            ErrorRegistro::DeclaracionInvalida => {
                f.write_str("declaracion del responsable invalida o sin firma")
            }
        }
    }
}

impl std::error::Error for ErrorRegistro {}
