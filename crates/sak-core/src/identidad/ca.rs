//! Autoridad de certificación propia del Kernel (mTLS lógico).

use crate::crypto::{ParMlDsa87, ErrorCrypto};
use crate::identidad::artefacto::{ArtefactoCliente, IdSistema};
use crate::identidad::pasaporte::Pasaporte;

/// CA del dominio: emite artefactos de cliente ligados a pasaporte (INV-04).
pub struct AutoridadCertificacion {
    par: ParMlDsa87,
    siguiente_serial: u64,
}

impl AutoridadCertificacion {
    pub fn generar() -> Result<Self, ErrorCrypto> {
        Ok(AutoridadCertificacion {
            par: ParMlDsa87::generar()?,
            siguiente_serial: 1,
        })
    }

    pub fn pk_bytes(&self) -> &[u8] {
        &self.par.public
    }

    /// Emite un certificado de cliente **solo** si el pasaporte está firmado y
    /// tiene versión ≥ 1. No entrega secretos raíz ni credenciales de efector
    /// (Bloque 5).
    pub fn emitir_artefacto(
        &mut self,
        pasaporte: &Pasaporte,
        sistema_id: IdSistema,
        pk_workload: Vec<u8>,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
    ) -> Result<ArtefactoCliente, ErrorEmisionCert> {
        if pasaporte.version() == 0 {
            return Err(ErrorEmisionCert::PasaporteSinVersion);
        }
        if !pasaporte.firma_valida() {
            return Err(ErrorEmisionCert::PasaporteNoFirmado);
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
        Ok(art)
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEmisionCert {
    PasaporteSinVersion,
    PasaporteNoFirmado,
    SistemaNoCoincide,
    VigenciaInvalida,
    Firma,
}

impl std::fmt::Display for ErrorEmisionCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorEmisionCert::PasaporteSinVersion => f.write_str("pasaporte sin version"),
            ErrorEmisionCert::PasaporteNoFirmado => f.write_str("pasaporte no firmado"),
            ErrorEmisionCert::SistemaNoCoincide => f.write_str("sistema_id no coincide con pasaporte"),
            ErrorEmisionCert::VigenciaInvalida => f.write_str("vigencia invalida"),
            ErrorEmisionCert::Firma => f.write_str("fallo al firmar certificado"),
        }
    }
}

impl std::error::Error for ErrorEmisionCert {}
