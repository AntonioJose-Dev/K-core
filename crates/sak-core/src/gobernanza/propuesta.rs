//! Propuesta no firmada y validación gobernada del paquete (G.5 etapas 1–2).

use crate::crypto::ParMlDsa87;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::norma::{ErrorCarga, Norma, PaqueteNormativo, ESQUEMA_NORMA_VERSION};
use crate::supervision::IdHumano;
use std::collections::BTreeMap;
use std::fmt;

pub const ESQUEMA_REQUERIDO: u32 = ESQUEMA_NORMA_VERSION;

/// Etiqueta de dependencia externa (reexportada vía corpus).
pub use crate::gobernanza::corpus::EtiquetaGob;

/// Cita jurídica resoluble (calidad `GOB` / `VAL-EXT`; el Kernel no la certifica).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntradaCita {
    pub fuente: String,
    pub digest_cita: [u8; LONGITUD_HASH_PAQUETE],
    pub etiqueta: EtiquetaGob,
}

#[derive(Debug, Default, Clone)]
pub struct RegistroCitas {
    por_fuente: BTreeMap<String, EntradaCita>,
}

impl RegistroCitas {
    pub fn nuevo() -> Self {
        Self::default()
    }

    pub fn registrar(&mut self, e: EntradaCita) -> Result<(), &'static str> {
        if e.fuente.trim().is_empty() {
            return Err("fuente vacia");
        }
        self.por_fuente.insert(e.fuente.clone(), e);
        Ok(())
    }

    pub fn resuelve(&self, fuente: &str) -> bool {
        self.por_fuente.contains_key(fuente)
    }
}

/// Aprobación firmada de interpretación operativa (INV-16). Etiqueta GOB/VAL-EXT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AprobacionInterpretacion {
    pub id_aprobador: IdHumano,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_mldsa: Vec<u8>,
    pub pk_aprobador: Vec<u8>,
    pub etiqueta: EtiquetaGob,
}

impl AprobacionInterpretacion {
    pub fn firmar(
        par: &ParMlDsa87,
        id: IdHumano,
        digest: [u8; LONGITUD_HASH_PAQUETE],
        etiqueta: EtiquetaGob,
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"interp-aprob|");
        msg.extend_from_slice(&digest);
        let firma = par.firmar(&msg)?;
        Ok(AprobacionInterpretacion {
            id_aprobador: id,
            digest,
            firma_mldsa: firma,
            pk_aprobador: par.public.clone(),
            etiqueta,
        })
    }

    pub fn verificar(&self) -> bool {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"interp-aprob|");
        msg.extend_from_slice(&self.digest);
        ParMlDsa87::verificar(&self.pk_aprobador, &msg, &self.firma_mldsa).is_ok()
    }
}

#[derive(Debug, Default, Clone)]
pub struct RegistroAprobacionesInterp {
    por_digest: BTreeMap<[u8; LONGITUD_HASH_PAQUETE], AprobacionInterpretacion>,
}

impl RegistroAprobacionesInterp {
    pub fn nuevo() -> Self {
        Self::default()
    }

    pub fn registrar(&mut self, a: AprobacionInterpretacion) -> Result<(), ErrorCarga> {
        if !a.verificar() {
            return Err(ErrorCarga::InterpretacionSinAprobacion);
        }
        if a.digest == [0u8; LONGITUD_HASH_PAQUETE] {
            return Err(ErrorCarga::InterpretacionSinAprobacion);
        }
        self.por_digest.insert(a.digest, a);
        Ok(())
    }

    pub fn aprobada(&self, digest: &[u8; LONGITUD_HASH_PAQUETE]) -> bool {
        self.por_digest
            .get(digest)
            .map(|a| a.verificar())
            .unwrap_or(false)
    }
}

/// Propuesta borrador sin firmar (G.5 etapa 1).
#[derive(Debug, Clone)]
pub struct PropuestaNormativa {
    pub esquema: u32,
    pub paquete: PaqueteNormativo,
    pub revisor_id: Option<IdHumano>,
    pub revision_ok: bool,
}

impl PropuestaNormativa {
    pub fn nueva_borrador(paquete: PaqueteNormativo) -> Self {
        PropuestaNormativa {
            esquema: ESQUEMA_REQUERIDO,
            paquete,
            revisor_id: None,
            revision_ok: false,
        }
    }

    /// Revisión jurídica por identidad con competencia registrada (etapa 2).
    pub fn marcar_revision_juridica(
        &mut self,
        revisor: IdHumano,
        competencia_registrada: bool,
    ) -> Result<(), ErrorPropuesta> {
        if !competencia_registrada {
            return Err(ErrorPropuesta::CompetenciaNoRegistrada);
        }
        self.revisor_id = Some(revisor);
        self.revision_ok = true;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorPropuesta {
    CompetenciaNoRegistrada,
    SinRevision,
}

impl fmt::Display for ErrorPropuesta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorPropuesta::CompetenciaNoRegistrada => {
                f.write_str("revisor sin competencia registrada")
            }
            ErrorPropuesta::SinRevision => f.write_str("falta revision juridica"),
        }
    }
}

impl std::error::Error for ErrorPropuesta {}

/// Validación gobernada: esquema, citas resolubles, interpretaciones aprobadas.
pub fn validar_paquete_gobernado(
    esquema: u32,
    paquete: &PaqueteNormativo,
    citas: &RegistroCitas,
    aprobaciones: &RegistroAprobacionesInterp,
) -> Result<(), ErrorCarga> {
    if esquema != ESQUEMA_REQUERIDO {
        return Err(ErrorCarga::EsquemaDesconocido(esquema));
    }
    for n in paquete.normas() {
        if !citas.resuelve(n.fuente()) {
            return Err(ErrorCarga::CitaNoResoluble);
        }
        let dig = n.interpretacion().digest_aprobacion;
        if dig == [0u8; LONGITUD_HASH_PAQUETE] || !aprobaciones.aprobada(&dig) {
            return Err(ErrorCarga::InterpretacionSinAprobacion);
        }
    }
    let _ = Norma::cargar; // ancla: normas ya cargadas vía G.1
    Ok(())
}
