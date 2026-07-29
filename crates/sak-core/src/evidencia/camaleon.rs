//! Hash camaleón con trampilla bajo umbral 2-de-3 (J.6 / L-08 / §M 11).
//!
//! Compromiso = HMAC-SHA-384(material_trampilla, ciphertext || nonce || aleatoriedad).
//!
//! **Decisión de implementación (no mandato literal Matriz sobre primitiva/KEK):**
//! - Cifrado de contenido PII retenido: AES-256-GCM (`aes-gcm`).
//! - KEK de 32 bytes: primeros 32 de HMAC-SHA-384(material_trampilla, `SAK-PII-KEK-v1|`).
//! - Nonce: 12 bytes tomados de aleatoriedad[0..12] (determinista por hoja).
//! No afirma HSM, KEK de titularidad cliente, ni resistencia a host [DESP].

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use std::fmt;

const DOMINIO_CAMALEON: &[u8] = b"SAK-CHAMELEON-v1|";
/// Dominio de derivación KEK PII — decisión de implementación documentada.
pub const DOMINIO_PII_KEK_V1: &[u8] = b"SAK-PII-KEK-v1|";
/// Identificador comprobable de la decisión cripto PII.
pub const DECISION_CRIPTO_PII_V1: &str = "AES-256-GCM + HMAC-SHA-384(KEK via SAK-PII-KEK-v1)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdTitular(pub u8);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitularTrampilla {
    pub id: IdTitular,
    pub ajeno_al_operador: bool,
}

#[derive(Debug, Clone)]
pub struct CustodiaTrampilla {
    titulares: [TitularTrampilla; 3],
    /// Material de trampilla; no se exporta por API pública.
    material: [u8; 32],
}

impl CustodiaTrampilla {
    /// `ajeno_*`: al menos uno debe ser true (titular ajeno al operador).
    pub fn instalar(
        semilla0: [u8; 32],
        ajeno0: bool,
        semilla1: [u8; 32],
        ajeno1: bool,
        semilla2: [u8; 32],
        ajeno2: bool,
    ) -> Result<Self, ErrorCamaleon> {
        if !ajeno0 && !ajeno1 && !ajeno2 {
            return Err(ErrorCamaleon::SinTitularAjeno);
        }
        let mut concat = [0u8; 96];
        concat[..32].copy_from_slice(&semilla0);
        concat[32..64].copy_from_slice(&semilla1);
        concat[64..].copy_from_slice(&semilla2);
        let dig = crypto::hmac_sha384(&concat, DOMINIO_CAMALEON);
        let mut material = [0u8; 32];
        material.copy_from_slice(&dig[..32]);
        Ok(CustodiaTrampilla {
            titulares: [
                TitularTrampilla {
                    id: IdTitular(0),
                    ajeno_al_operador: ajeno0,
                },
                TitularTrampilla {
                    id: IdTitular(1),
                    ajeno_al_operador: ajeno1,
                },
                TitularTrampilla {
                    id: IdTitular(2),
                    ajeno_al_operador: ajeno2,
                },
            ],
            material,
        })
    }

    fn autorizar(&self, a: IdTitular, b: IdTitular) -> Result<(), ErrorCamaleon> {
        if a.0 == b.0 || a.0 > 2 || b.0 > 2 {
            return Err(ErrorCamaleon::QuorumInsuficiente);
        }
        let ta = &self.titulares[a.0 as usize];
        let tb = &self.titulares[b.0 as usize];
        if !ta.ajeno_al_operador && !tb.ajeno_al_operador {
            return Err(ErrorCamaleon::OperadorSolo);
        }
        Ok(())
    }

    pub fn material_si_autorizado(
        &self,
        a: IdTitular,
        b: IdTitular,
    ) -> Result<&[u8; 32], ErrorCamaleon> {
        self.autorizar(a, b)?;
        Ok(&self.material)
    }

    /// KEK de implementación para PII (no HSM). Requiere quórum.
    pub fn kek_pii(&self, a: IdTitular, b: IdTitular) -> Result<[u8; 32], ErrorCamaleon> {
        let material = self.material_si_autorizado(a, b)?;
        Ok(derivar_kek_pii(material))
    }
}

pub fn derivar_kek_pii(material_trampilla: &[u8; 32]) -> [u8; 32] {
    let dig = crypto::hmac_sha384(material_trampilla, DOMINIO_PII_KEK_V1);
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&dig[..32]);
    kek
}

fn cifrar_aes256_gcm(kek: &[u8; 32], nonce12: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, ErrorCamaleon> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| ErrorCamaleon::Cifrado)?;
    let nonce = Nonce::from_slice(nonce12);
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ErrorCamaleon::Cifrado)
}

fn descifrar_aes256_gcm(kek: &[u8; 32], nonce12: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, ErrorCamaleon> {
    let cipher = Aes256Gcm::new_from_slice(kek).map_err(|_| ErrorCamaleon::Cifrado)?;
    let nonce = Nonce::from_slice(nonce12);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ErrorCamaleon::Cifrado)
}

/// Hoja PII: contenido retenido solo cifrado; compromiso camaleón sobre ciphertext||nonce||aleatoriedad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HojaCamaleon {
    pub compromiso: [u8; LONGITUD_HASH_PAQUETE],
    pub aleatoriedad: [u8; LONGITUD_HASH_PAQUETE],
    pub nonce: [u8; 12],
    /// Ciphertext AES-256-GCM; vacío si redactada.
    pub ciphertext: Vec<u8>,
    pub redactada: bool,
    /// Retención J.6 clase datos personales: 90 días.
    pub retencion_dias: u64,
    /// Debe ser true mientras haya contenido retenido (no redactado).
    pub contenido_cifrado: bool,
    /// Etiqueta de la decisión cripto (comprobable en tests).
    pub decision_cripto: &'static str,
}

impl HojaCamaleon {
    /// Compromete y cifra plaintext. No almacena claro.
    pub fn comprometer_cifrado(
        material: &[u8; 32],
        plaintext: &[u8],
        aleatoriedad: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, ErrorCamaleon> {
        let kek = derivar_kek_pii(material);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&aleatoriedad[..12]);
        let ciphertext = cifrar_aes256_gcm(&kek, &nonce, plaintext)?;
        let compromiso = compromiso_camaleon(material, &ciphertext, &nonce, &aleatoriedad);
        Ok(HojaCamaleon {
            compromiso,
            aleatoriedad,
            nonce,
            ciphertext,
            redactada: false,
            retencion_dias: 90,
            contenido_cifrado: true,
            decision_cripto: DECISION_CRIPTO_PII_V1,
        })
    }

    pub fn verificar_compromiso(&self, material: &[u8; 32]) -> bool {
        if self.redactada {
            return true;
        }
        if !self.contenido_cifrado || self.ciphertext.is_empty() {
            return false;
        }
        compromiso_camaleon(material, &self.ciphertext, &self.nonce, &self.aleatoriedad)
            == self.compromiso
    }

    /// Descifrado solo con material autorizado (prueba de cifrado; no HSM).
    pub fn descifrar_para_auditoria(&self, material: &[u8; 32]) -> Result<Vec<u8>, ErrorCamaleon> {
        if self.redactada {
            return Err(ErrorCamaleon::YaRedactada);
        }
        let kek = derivar_kek_pii(material);
        descifrar_aes256_gcm(&kek, &self.nonce, &self.ciphertext)
    }

    /// Rechaza hoja PII retenida en claro o sin marca de cifrado.
    pub fn validar_retencion_cifrada(&self) -> Result<(), ErrorCamaleon> {
        if self.retencion_dias != 90 {
            return Err(ErrorCamaleon::RetencionInvalida);
        }
        if self.redactada {
            return Ok(());
        }
        if !self.contenido_cifrado || self.ciphertext.is_empty() {
            return Err(ErrorCamaleon::ContenidoEnClaro);
        }
        Ok(())
    }
}

pub fn compromiso_camaleon(
    material: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    aleatoriedad: &[u8; LONGITUD_HASH_PAQUETE],
) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut msg = Vec::with_capacity(ciphertext.len() + 12 + aleatoriedad.len());
    msg.extend_from_slice(ciphertext);
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(aleatoriedad);
    crypto::hmac_sha384(material, &msg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroRedaccion {
    pub id_hoja: String,
    pub autorizante_a: IdTitular,
    pub autorizante_b: IdTitular,
    pub base_juridica: String,
    pub fecha_epoch_dias: u64,
    pub digest_previo_contenido: [u8; LONGITUD_HASH_PAQUETE],
    pub compromiso_preservado: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCamaleon {
    SinTitularAjeno,
    QuorumInsuficiente,
    OperadorSolo,
    CompromisoInvalido,
    YaRedactada,
    BaseJuridicaVacia,
    Cifrado,
    ContenidoEnClaro,
    RetencionInvalida,
}

impl fmt::Display for ErrorCamaleon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCamaleon::SinTitularAjeno => write!(f, "trampilla sin titular ajeno al operador"),
            ErrorCamaleon::QuorumInsuficiente => write!(f, "quorum 2-de-3 insuficiente"),
            ErrorCamaleon::OperadorSolo => write!(f, "redaccion por operador en solitario"),
            ErrorCamaleon::CompromisoInvalido => write!(f, "compromiso camaleon invalido"),
            ErrorCamaleon::YaRedactada => write!(f, "hoja ya redactada"),
            ErrorCamaleon::BaseJuridicaVacia => write!(f, "base juridica vacia"),
            ErrorCamaleon::Cifrado => write!(f, "fallo cifrado/descifrado PII"),
            ErrorCamaleon::ContenidoEnClaro => write!(f, "contenido PII retenido sin cifrado"),
            ErrorCamaleon::RetencionInvalida => write!(f, "retencion PII distinta de 90 dias"),
        }
    }
}

impl std::error::Error for ErrorCamaleon {}

pub fn redactar_hoja(
    custodia: &CustodiaTrampilla,
    hoja: &mut HojaCamaleon,
    id_hoja: impl Into<String>,
    autorizante_a: IdTitular,
    autorizante_b: IdTitular,
    base_juridica: impl Into<String>,
    fecha_epoch_dias: u64,
) -> Result<RegistroRedaccion, ErrorCamaleon> {
    let base_juridica = base_juridica.into();
    if base_juridica.trim().is_empty() {
        return Err(ErrorCamaleon::BaseJuridicaVacia);
    }
    if hoja.redactada {
        return Err(ErrorCamaleon::YaRedactada);
    }
    let material = custodia.material_si_autorizado(autorizante_a, autorizante_b)?;
    if !hoja.verificar_compromiso(material) {
        return Err(ErrorCamaleon::CompromisoInvalido);
    }
    let digest_previo = crypto::sha384_dominio(DOMINIO_CAMALEON, &hoja.ciphertext);
    let compromiso = hoja.compromiso;
    hoja.ciphertext.clear();
    hoja.redactada = true;
    hoja.contenido_cifrado = true; // política: nunca se retiene claro
    Ok(RegistroRedaccion {
        id_hoja: id_hoja.into(),
        autorizante_a,
        autorizante_b,
        base_juridica,
        fecha_epoch_dias,
        digest_previo_contenido: digest_previo,
        compromiso_preservado: compromiso,
    })
}
