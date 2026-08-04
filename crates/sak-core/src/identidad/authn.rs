//! Autenticación de identidad a partir del artefacto (INV-05 / H.2).
//! Autenticación mutua: el servidor (CA) también firma el digest de petición.

use crate::crypto::ParMlDsa87;
use crate::identidad::artefacto::{ArtefactoCliente, PruebaPosesion};
use crate::identidad::ca::AutoridadCertificacion;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentidadResuelta {
    sistema_id: String,
    pasaporte_id: String,
    pasaporte_version: u32,
    serial_artefacto: u64,
}

impl IdentidadResuelta {
    pub fn sistema_id(&self) -> &str {
        &self.sistema_id
    }
    pub fn pasaporte_id(&self) -> &str {
        &self.pasaporte_id
    }
    pub fn pasaporte_version(&self) -> u32 {
        self.pasaporte_version
    }
    pub fn serial_artefacto(&self) -> u64 {
        self.serial_artefacto
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorAuthn {
    FirmaCaInvalida,
    ArtefactoNoVigente,
    ArtefactoRevocado,
    ArtefactoDesconocido,
    PruebaClienteInvalida,
    PruebaServidorInvalida,
    DigestsDistintos,
}

/// Autenticación local H.2 (perfil escritorio [VAL-EXT]; sin mTLS).
///
/// 1. Verifica que el certificado es conocido, no revocado, firmado por la CA y vigente.
/// 2. Verifica que el cliente posee la clave del artefacto.
/// 3. Verifica que el servidor (CA) firmó el **mismo** digest de petición (local).
///
/// **No** consulta ningún campo autodeclarado.
pub fn autenticar_mutua(
    ca: &AutoridadCertificacion,
    artefacto: &ArtefactoCliente,
    prueba_cliente: &PruebaPosesion,
    prueba_servidor: &PruebaPosesion,
    instante_epoch_dias: u32,
) -> Result<IdentidadResuelta, ErrorAuthn> {
    if prueba_cliente.digest_peticion != prueba_servidor.digest_peticion {
        return Err(ErrorAuthn::DigestsDistintos);
    }
    if !ca.emitidos().contains_key(&artefacto.serial) {
        return Err(ErrorAuthn::ArtefactoDesconocido);
    }
    if ca.revocados().contains(&artefacto.serial) {
        return Err(ErrorAuthn::ArtefactoRevocado);
    }
    if let Some(orig) = ca.emitidos().get(&artefacto.serial) {
        if orig != artefacto {
            return Err(ErrorAuthn::FirmaCaInvalida);
        }
    }
    if !ca.verificar_firma_artefacto(artefacto) {
        return Err(ErrorAuthn::FirmaCaInvalida);
    }
    if instante_epoch_dias < artefacto.vigente_desde_dias
        || instante_epoch_dias > artefacto.vigente_hasta_dias
    {
        return Err(ErrorAuthn::ArtefactoNoVigente);
    }
    if ParMlDsa87::verificar(
        &artefacto.pk_workload,
        &prueba_cliente.digest_peticion,
        &prueba_cliente.firma_workload,
    )
    .is_err()
    {
        return Err(ErrorAuthn::PruebaClienteInvalida);
    }
    if ParMlDsa87::verificar(
        ca.pk_bytes(),
        &prueba_servidor.digest_peticion,
        &prueba_servidor.firma_workload,
    )
    .is_err()
    {
        return Err(ErrorAuthn::PruebaServidorInvalida);
    }
    Ok(IdentidadResuelta {
        sistema_id: artefacto.sistema_id.como_str().to_string(),
        pasaporte_id: artefacto.pasaporte_id.clone(),
        pasaporte_version: artefacto.pasaporte_version,
        serial_artefacto: artefacto.serial,
    })
}

/// Atajo: solo artefacto+cliente (sin prueba de servidor).
pub fn autenticar_artefacto(
    ca: &AutoridadCertificacion,
    artefacto: &ArtefactoCliente,
    prueba: &PruebaPosesion,
    instante_epoch_dias: u32,
) -> Result<IdentidadResuelta, ErrorAuthn> {
    if !ca.emitidos().contains_key(&artefacto.serial) {
        return Err(ErrorAuthn::ArtefactoDesconocido);
    }
    if ca.revocados().contains(&artefacto.serial) {
        return Err(ErrorAuthn::ArtefactoRevocado);
    }
    if let Some(orig) = ca.emitidos().get(&artefacto.serial) {
        if orig != artefacto {
            return Err(ErrorAuthn::FirmaCaInvalida);
        }
    }
    if !ca.verificar_firma_artefacto(artefacto) {
        return Err(ErrorAuthn::FirmaCaInvalida);
    }
    if instante_epoch_dias < artefacto.vigente_desde_dias
        || instante_epoch_dias > artefacto.vigente_hasta_dias
    {
        return Err(ErrorAuthn::ArtefactoNoVigente);
    }
    if ParMlDsa87::verificar(
        &artefacto.pk_workload,
        &prueba.digest_peticion,
        &prueba.firma_workload,
    )
    .is_err()
    {
        return Err(ErrorAuthn::PruebaClienteInvalida);
    }
    Ok(IdentidadResuelta {
        sistema_id: artefacto.sistema_id.como_str().to_string(),
        pasaporte_id: artefacto.pasaporte_id.clone(),
        pasaporte_version: artefacto.pasaporte_version,
        serial_artefacto: artefacto.serial,
    })
}
