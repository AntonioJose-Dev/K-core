//! Firmantes jurídicos/técnicos y umbral 2-de-N (G.5 etapa 4).

use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::supervision::IdHumano;
use std::collections::BTreeMap;
use std::fmt;

/// Rol del firmante en la doble firma normativa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RolFirmante {
    Juridico = 1,
    Tecnico = 2,
}

impl RolFirmante {
    pub const fn token(self) -> &'static str {
        match self {
            RolFirmante::Juridico => "JURIDICO",
            RolFirmante::Tecnico => "TECNICO",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmanteGobernanza {
    pub id: IdHumano,
    pub rol: RolFirmante,
    pub pk_mldsa: Vec<u8>,
    /// Competencia registrada: `GOB` o `VAL-EXT` (el Kernel no la certifica).
    pub etiqueta: crate::gobernanza::corpus::EtiquetaGob,
}

#[derive(Debug, Default, Clone)]
pub struct RegistroFirmantesGob {
    por_id: BTreeMap<String, FirmanteGobernanza>,
}

impl RegistroFirmantesGob {
    pub fn nuevo() -> Self {
        Self::default()
    }

    pub fn registrar(&mut self, f: FirmanteGobernanza) -> Result<(), &'static str> {
        if f.pk_mldsa.is_empty() {
            return Err("pk firmante vacia");
        }
        self.por_id.insert(f.id.como_str().to_string(), f);
        Ok(())
    }

    pub fn obtener(&self, id: &IdHumano) -> Option<&FirmanteGobernanza> {
        self.por_id.get(id.como_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmaPaquete {
    pub id: IdHumano,
    pub rol_declarado: RolFirmante,
    pub firma_mldsa: Vec<u8>,
}

impl FirmaPaquete {
    pub fn firmar(
        par: &ParMlDsa87,
        id: IdHumano,
        rol: RolFirmante,
        mensaje_paquete: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"paquete|");
        msg.extend_from_slice(mensaje_paquete);
        msg.push(rol as u8);
        let firma = par.firmar(&msg)?;
        Ok(FirmaPaquete {
            id,
            rol_declarado: rol,
            firma_mldsa: firma,
        })
    }

    pub fn mensaje(mensaje_paquete: &[u8; LONGITUD_HASH_PAQUETE], rol: RolFirmante) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"paquete|");
        msg.extend_from_slice(mensaje_paquete);
        msg.push(rol as u8);
        msg
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorFirmas {
    Insuficientes,
    IdentidadRepetida,
    SinDiversidadJuridicoTecnico,
    FirmanteNoRegistrado,
    RolNoCoincide,
    FirmaInvalida,
}

impl fmt::Display for ErrorFirmas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorFirmas::Insuficientes => f.write_str("firmas insuficientes (umbral 2-de-N)"),
            ErrorFirmas::IdentidadRepetida => f.write_str("identidad de firmante repetida"),
            ErrorFirmas::SinDiversidadJuridicoTecnico => {
                f.write_str("faltan firmante juridico y tecnico distintos")
            }
            ErrorFirmas::FirmanteNoRegistrado => f.write_str("firmante no registrado"),
            ErrorFirmas::RolNoCoincide => f.write_str("rol declarado no coincide con registro"),
            ErrorFirmas::FirmaInvalida => f.write_str("firma de paquete invalida"),
        }
    }
}

impl std::error::Error for ErrorFirmas {}

/// Umbral 2-de-N con ≥1 jurídico y ≥1 técnico, identidades distintas.
pub fn verificar_doble_firma(
    mensaje_paquete: &[u8; LONGITUD_HASH_PAQUETE],
    firmas: &[FirmaPaquete],
    registro: &RegistroFirmantesGob,
) -> Result<(), ErrorFirmas> {
    if firmas.len() < 2 {
        return Err(ErrorFirmas::Insuficientes);
    }
    let mut vistos = BTreeMap::new();
    let mut hay_j = false;
    let mut hay_t = false;
    for f in firmas {
        if vistos.insert(f.id.como_str().to_string(), ()).is_some() {
            return Err(ErrorFirmas::IdentidadRepetida);
        }
        let reg = registro
            .obtener(&f.id)
            .ok_or(ErrorFirmas::FirmanteNoRegistrado)?;
        if reg.rol != f.rol_declarado {
            return Err(ErrorFirmas::RolNoCoincide);
        }
        let msg = FirmaPaquete::mensaje(mensaje_paquete, f.rol_declarado);
        if ParMlDsa87::verificar(&reg.pk_mldsa, &msg, &f.firma_mldsa).is_err() {
            return Err(ErrorFirmas::FirmaInvalida);
        }
        match f.rol_declarado {
            RolFirmante::Juridico => hay_j = true,
            RolFirmante::Tecnico => hay_t = true,
        }
    }
    if !(hay_j && hay_t) {
        return Err(ErrorFirmas::SinDiversidadJuridicoTecnico);
    }
    let _ = crypto::sha384_dominio(dominio::GOBERNANZA, mensaje_paquete);
    Ok(())
}
