//! Pasaporte soberano firmado y versionado.

use crate::crypto::{self, dominio, ParMlDsa87, ErrorCrypto};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::artefacto::IdSistema;

/// Pasaporte de un sistema de IA (INV-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pasaporte {
    id: String,
    version: u32,
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    /// Firma del registro soberano sobre el cuerpo canónico.
    firma: Vec<u8>,
    /// PK del registro que firmó (para verificación offline del propio objeto).
    pk_registro: Vec<u8>,
}

impl Pasaporte {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn sistema_id(&self) -> &str {
        self.sistema_id.como_str()
    }
    pub fn responsable(&self) -> &str {
        &self.responsable
    }
    pub fn finalidad(&self) -> &str {
        &self.finalidad
    }
    pub fn vigente_desde_dias(&self) -> u32 {
        self.vigente_desde_dias
    }
    pub fn vigente_hasta_dias(&self) -> u32 {
        self.vigente_hasta_dias
    }

    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-PASSPORT-v1|");
        v.extend_from_slice(self.id.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(self.sistema_id.como_str().as_bytes());
        v.push(0);
        v.extend_from_slice(self.responsable.as_bytes());
        v.push(0);
        v.extend_from_slice(self.finalidad.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.vigente_desde_dias.to_le_bytes());
        v.extend_from_slice(&self.vigente_hasta_dias.to_le_bytes());
        v
    }

    pub fn digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, &self.cuerpo_canonico())
    }

    pub fn firma_valida(&self) -> bool {
        if self.version == 0 || self.firma.is_empty() || self.pk_registro.is_empty() {
            return false;
        }
        ParMlDsa87::verificar(&self.pk_registro, &self.cuerpo_canonico(), &self.firma).is_ok()
    }

    pub fn vigente_en(&self, instante_epoch_dias: u32) -> bool {
        instante_epoch_dias >= self.vigente_desde_dias
            && instante_epoch_dias <= self.vigente_hasta_dias
    }
}

/// Pasaporte ya verificado como vigente, firmado y versionado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasaporteVigente {
    inner: Pasaporte,
}

impl PasaporteVigente {
    pub fn pasaporte(&self) -> &Pasaporte {
        &self.inner
    }
    pub fn id(&self) -> &str {
        self.inner.id()
    }
    pub fn version(&self) -> u32 {
        self.inner.version()
    }
    pub fn sistema_id(&self) -> &str {
        self.inner.sistema_id()
    }
}

/// Construcción interna por el registro (firma incluida).
pub(super) fn sellar_pasaporte(
    id: String,
    version: u32,
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    firmante: &ParMlDsa87,
) -> Result<Pasaporte, ErrorCrypto> {
    let mut p = Pasaporte {
        id,
        version,
        sistema_id,
        responsable,
        finalidad,
        vigente_desde_dias,
        vigente_hasta_dias,
        firma: vec![],
        pk_registro: firmante.public.clone(),
    };
    p.firma = firmante.firmar(&p.cuerpo_canonico())?;
    Ok(p)
}

pub(super) fn como_vigente(p: Pasaporte) -> PasaporteVigente {
    PasaporteVigente { inner: p }
}
