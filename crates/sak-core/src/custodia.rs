//! Custodia de secreto raíz y broker de credenciales efímeras (Bloque 5).
//!
//! El material raíz no se exporta por ninguna API pública. Las credenciales
//! derivadas caducan y su reutilización se deniega y registra (criterio M§5).

use crate::capacidad::{Alcance, Capability, IdCapacidad};
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::IdSistema;
use crate::reloj::{RelojMonotonico, Ticks};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// Secreto raíz de titularidad del proceso autoritativo. Sin getters de material.
pub struct SecretoRaiz {
    material: [u8; 32],
}

impl SecretoRaiz {
    /// Semilla inyectada (tests / arranque). El material no es recuperable después.
    pub fn desde_semilla(semilla: [u8; 32]) -> Self {
        SecretoRaiz { material: semilla }
    }

    /// Deriva un token opaco; el raíz permanece encapsulado.
    pub(crate) fn derivar(&self, etiqueta: &[u8], contexto: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        let mut msg = Vec::with_capacity(etiqueta.len() + 1 + contexto.len());
        msg.extend_from_slice(etiqueta);
        msg.push(0);
        msg.extend_from_slice(contexto);
        crypto::hmac_sha384(&self.material, &msg)
    }
}

impl fmt::Debug for SecretoRaiz {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretoRaiz(REDACTED)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCustodia {
    CapacidadNoAutoriza,
    CredencialExpirada,
    CredencialReutilizada,
    CredencialDesconocida,
}

impl fmt::Display for ErrorCustodia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCustodia::CapacidadNoAutoriza => write!(f, "capacidad no autoriza credencial"),
            ErrorCustodia::CredencialExpirada => write!(f, "credencial expirada"),
            ErrorCustodia::CredencialReutilizada => write!(f, "credencial reutilizada"),
            ErrorCustodia::CredencialDesconocida => write!(f, "credencial desconocida"),
        }
    }
}

impl std::error::Error for ErrorCustodia {}

/// Credencial efímera de alcance mínimo y vida útil limitada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredencialEfimera {
    id: [u8; LONGITUD_HASH_PAQUETE],
    sistema: IdSistema,
    alcance: Alcance,
    id_capacidad: IdCapacidad,
    vive_hasta: Ticks,
}

impl CredencialEfimera {
    pub fn id(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.id
    }

    pub fn sistema(&self) -> &IdSistema {
        &self.sistema
    }

    pub fn alcance(&self) -> &Alcance {
        &self.alcance
    }

    pub fn vive_hasta(&self) -> Ticks {
        self.vive_hasta
    }
}

#[derive(Debug, Default)]
pub struct BrokerCredenciales {
    raiz: Option<SecretoRaiz>,
    consumidas: HashSet<[u8; LONGITUD_HASH_PAQUETE]>,
    denegaciones: Vec<ErrorCustodia>,
    /// Metadatos por id para comprobar caducidad sin re-derivar el raíz en claro.
    meta: HashMap<[u8; LONGITUD_HASH_PAQUETE], (Ticks, IdSistema)>,
}

impl BrokerCredenciales {
    pub fn nuevo(raiz: SecretoRaiz) -> Self {
        BrokerCredenciales {
            raiz: Some(raiz),
            consumidas: HashSet::new(),
            denegaciones: Vec::new(),
            meta: HashMap::new(),
        }
    }

    /// Emite credencial derivada tras capacidad ya materializada (H.12).
    pub fn emitir_desde_capacidad(
        &mut self,
        capacidad: &Capability,
        reloj: &impl RelojMonotonico,
    ) -> Result<CredencialEfimera, ErrorCustodia> {
        let raiz = self.raiz.as_ref().ok_or(ErrorCustodia::CapacidadNoAutoriza)?;
        let ahora = reloj.ahora();
        if ahora > capacidad.vive_hasta() {
            self.denegaciones.push(ErrorCustodia::CredencialExpirada);
            return Err(ErrorCustodia::CredencialExpirada);
        }
        let mut ctx = Vec::new();
        ctx.extend_from_slice(capacidad.id().as_bytes());
        ctx.extend_from_slice(capacidad.sistema().como_str().as_bytes());
        ctx.extend_from_slice(capacidad.digest_efecto());
        ctx.extend_from_slice(&capacidad.vive_hasta().to_le_bytes());
        let id = raiz.derivar(b"SAK-CRED-v1", &ctx);
        let cred = CredencialEfimera {
            id,
            sistema: capacidad.sistema().clone(),
            alcance: capacidad.alcance().clone(),
            id_capacidad: *capacidad.id(),
            vive_hasta: capacidad.vive_hasta(),
        };
        self.meta
            .insert(cred.id, (cred.vive_hasta, cred.sistema.clone()));
        Ok(cred)
    }

    /// Uso de un solo tiro: caducidad o repetición ⇒ denegación registrada.
    pub fn ejercer(
        &mut self,
        credencial: &CredencialEfimera,
        reloj: &impl RelojMonotonico,
    ) -> Result<(), ErrorCustodia> {
        if !self.meta.contains_key(&credencial.id) {
            self.denegaciones.push(ErrorCustodia::CredencialDesconocida);
            return Err(ErrorCustodia::CredencialDesconocida);
        }
        if reloj.ahora() > credencial.vive_hasta {
            self.denegaciones.push(ErrorCustodia::CredencialExpirada);
            return Err(ErrorCustodia::CredencialExpirada);
        }
        if !self.consumidas.insert(credencial.id) {
            self.denegaciones.push(ErrorCustodia::CredencialReutilizada);
            return Err(ErrorCustodia::CredencialReutilizada);
        }
        Ok(())
    }

    pub fn n_denegaciones(&self) -> usize {
        self.denegaciones.len()
    }

    /// Confirma que no hay API de exportación: el raíz solo existe encapsulado.
    pub fn tiene_raiz_encapsulada(&self) -> bool {
        self.raiz.is_some()
    }
}
