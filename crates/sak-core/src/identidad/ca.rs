//! Autoridad de certificación del Kernel — perfil escritorio degradado [VAL-EXT].
//!
//! §E Identidad de workload: en escritorio degrada a verificación local del
//! certificado presentado al proceso. **No afirma mTLS ni identidad fuerte de red.**

use crate::crypto::{ParMlDsa87, ErrorCrypto};
use crate::identidad::artefacto::{ArtefactoCliente, IdSistema};
use crate::identidad::pasaporte::Pasaporte;
use std::collections::{BTreeMap, BTreeSet};

/// Etiqueta obligatoria del perfil local (Matriz §E [VAL-EXT]).
pub const PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT: &str =
    "ESCRITORIO-VAL-EXT: verificacion local de certificado; sin mTLS; sin identidad fuerte de red";

/// CA del dominio: emite certificados de cliente ligados a un pasaporte vigente (INV-05 / H.2).
pub struct AutoridadCertificacion {
    par: ParMlDsa87,
    siguiente_serial: u64,
    /// Certificados emitidos (serial → artefacto). Desconocido ⇒ fuera de este mapa.
    emitidos: BTreeMap<u64, ArtefactoCliente>,
    revocados: BTreeSet<u64>,
    /// Constancia del perfil de escritorio degradado [VAL-EXT].
    perfil: &'static str,
}

impl AutoridadCertificacion {
    pub fn generar() -> Result<Self, ErrorCrypto> {
        Ok(AutoridadCertificacion {
            par: ParMlDsa87::generar()?,
            siguiente_serial: 1,
            emitidos: BTreeMap::new(),
            revocados: BTreeSet::new(),
            perfil: PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT,
        })
    }

    /// Reconstitución durable (misma PK/SK, seriales, revocaciones, emitidos).
    pub fn desde_estado(
        public: Vec<u8>,
        secret: &[u8],
        siguiente_serial: u64,
        emitidos: BTreeMap<u64, ArtefactoCliente>,
        revocados: BTreeSet<u64>,
    ) -> Result<Self, ErrorCrypto> {
        Ok(AutoridadCertificacion {
            par: ParMlDsa87::desde_bytes(public, secret)?,
            siguiente_serial,
            emitidos,
            revocados,
            perfil: PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT,
        })
    }

    pub fn perfil(&self) -> &'static str {
        self.perfil
    }

    pub fn pk_bytes(&self) -> &[u8] {
        &self.par.public
    }

    pub fn bytes_secreto(&self) -> Vec<u8> {
        self.par.bytes_secreto()
    }

    pub fn siguiente_serial(&self) -> u64 {
        self.siguiente_serial
    }

    pub fn emitidos(&self) -> &BTreeMap<u64, ArtefactoCliente> {
        &self.emitidos
    }

    pub fn revocados(&self) -> &BTreeSet<u64> {
        &self.revocados
    }

    pub fn n_emitidos(&self) -> usize {
        self.emitidos.len()
    }

    /// Emite un certificado de cliente ligado a **un** pasaporte firmado, versionado y vigente.
    pub fn emitir_artefacto(
        &mut self,
        pasaporte: &Pasaporte,
        sistema_id: IdSistema,
        pk_workload: Vec<u8>,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
        instante_epoch_dias: u32,
    ) -> Result<ArtefactoCliente, ErrorEmisionCert> {
        if pasaporte.version() == 0 {
            return Err(ErrorEmisionCert::PasaporteSinVersion);
        }
        if !pasaporte.firma_valida() {
            return Err(ErrorEmisionCert::PasaporteNoFirmado);
        }
        if !pasaporte.vigente_en(instante_epoch_dias) {
            return Err(ErrorEmisionCert::PasaporteNoVigente);
        }
        if pasaporte.sistema_id() != sistema_id.como_str() {
            return Err(ErrorEmisionCert::SistemaNoCoincide);
        }
        if vigente_hasta_dias < vigente_desde_dias {
            return Err(ErrorEmisionCert::VigenciaInvalida);
        }
        let serial = self.siguiente_serial;
        self.siguiente_serial += 1;
        let mut art = ArtefactoCliente {
            sistema_id,
            pasaporte_id: pasaporte.id().to_string(),
            pasaporte_version: pasaporte.version(),
            pk_workload,
            vigente_desde_dias,
            vigente_hasta_dias,
            serial,
            firma_ca: vec![],
        };
        let cuerpo = art.cuerpo_canonico();
        art.firma_ca = self
            .par
            .firmar(&cuerpo)
            .map_err(|_| ErrorEmisionCert::Firma)?;
        self.emitidos.insert(serial, art.clone());
        Ok(art)
    }

    pub fn revocar(&mut self, serial: u64) -> Result<(), ErrorEmisionCert> {
        if !self.emitidos.contains_key(&serial) {
            return Err(ErrorEmisionCert::Desconocido);
        }
        self.revocados.insert(serial);
        Ok(())
    }

    pub fn firmar_como_servidor(
        &self,
        digest_peticion: [u8; crate::decision::LONGITUD_HASH_PAQUETE],
    ) -> Result<crate::identidad::artefacto::PruebaPosesion, ErrorCrypto> {
        crate::identidad::artefacto::PruebaPosesion::firmar(&self.par, digest_peticion)
    }

    pub fn verificar_firma_artefacto(&self, art: &ArtefactoCliente) -> bool {
        ParMlDsa87::verificar(self.pk_bytes(), &art.cuerpo_canonico(), &art.firma_ca).is_ok()
    }

    /// H.2 local: firma CA, vigencia, conocido, no revocado, vínculo con el pasaporte dado.
    pub fn verificar_certificado(
        &self,
        art: &ArtefactoCliente,
        pasaporte: &Pasaporte,
        instante_epoch_dias: u32,
    ) -> Result<(), ErrorVerificacionCert> {
        if !self.emitidos.contains_key(&art.serial) {
            return Err(ErrorVerificacionCert::Desconocido);
        }
        if self.revocados.contains(&art.serial) {
            return Err(ErrorVerificacionCert::Revocado);
        }
        if !self.verificar_firma_artefacto(art) {
            return Err(ErrorVerificacionCert::Alterado);
        }
        // El blob emitido debe coincidir (detecta alteración de campos con firma reciclada).
        if let Some(orig) = self.emitidos.get(&art.serial) {
            if orig != art {
                return Err(ErrorVerificacionCert::Alterado);
            }
        }
        if instante_epoch_dias < art.vigente_desde_dias
            || instante_epoch_dias > art.vigente_hasta_dias
        {
            return Err(ErrorVerificacionCert::Caducado);
        }
        if art.pasaporte_id != pasaporte.id()
            || art.pasaporte_version != pasaporte.version()
            || art.sistema_id.como_str() != pasaporte.sistema_id()
        {
            return Err(ErrorVerificacionCert::PasaporteAjeno);
        }
        if !pasaporte.firma_valida() || !pasaporte.vigente_en(instante_epoch_dias) {
            return Err(ErrorVerificacionCert::PasaporteAjeno);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEmisionCert {
    PasaporteSinVersion,
    PasaporteNoFirmado,
    PasaporteNoVigente,
    SistemaNoCoincide,
    VigenciaInvalida,
    Firma,
    Desconocido,
}

impl std::fmt::Display for ErrorEmisionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorEmisionCert::PasaporteSinVersion => f.write_str("pasaporte sin version"),
            ErrorEmisionCert::PasaporteNoFirmado => f.write_str("pasaporte no firmado"),
            ErrorEmisionCert::PasaporteNoVigente => f.write_str("pasaporte no vigente"),
            ErrorEmisionCert::SistemaNoCoincide => {
                f.write_str("sistema_id no coincide con pasaporte")
            }
            ErrorEmisionCert::VigenciaInvalida => f.write_str("vigencia invalida"),
            ErrorEmisionCert::Firma => f.write_str("fallo al firmar certificado"),
            ErrorEmisionCert::Desconocido => f.write_str("certificado desconocido"),
        }
    }
}

impl std::error::Error for ErrorEmisionCert {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorVerificacionCert {
    Desconocido,
    Revocado,
    Alterado,
    Caducado,
    PasaporteAjeno,
}

impl std::fmt::Display for ErrorVerificacionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorVerificacionCert::Desconocido => f.write_str("certificado desconocido"),
            ErrorVerificacionCert::Revocado => f.write_str("certificado revocado"),
            ErrorVerificacionCert::Alterado => f.write_str("certificado alterado"),
            ErrorVerificacionCert::Caducado => f.write_str("certificado caducado"),
            ErrorVerificacionCert::PasaporteAjeno => {
                f.write_str("certificado ligado a otro pasaporte")
            }
        }
    }
}

impl std::error::Error for ErrorVerificacionCert {}
