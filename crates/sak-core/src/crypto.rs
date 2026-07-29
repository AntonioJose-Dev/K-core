//! Suite criptográfica J.6 / L-07 (fragmento del Bloque 3).
//!
//! - SHA-384 con separación de dominio
//! - ML-DSA-87: autoridad, evidencia y paquetes
//! - SLH-DSA-SHA2-128s: cofirma de checkpoints (base hash; J.6)
//!
//! Parámetro SLH elegido: SHA2-128s (hash-based). Suficiente para cofirma de
//! archivo en Bloque 3; un perfil de categoría 5 (p.ej. SHA2-256s) puede
//! sustituirse sin cambiar el protocolo de cofirma.
use crate::decision::LONGITUD_HASH_PAQUETE;
use fips204::ml_dsa_87;
use fips204::traits::{SerDes as MlSerDes, Signer as MlSigner, Verifier as MlVerifier};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes as SlhSerDes, Signer as SlhSigner, Verifier as SlhVerifier};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha384};
use std::fmt;

type HmacSha384 = Hmac<Sha384>;

/// Etiquetas de separación de dominio (J.6).
pub mod dominio {
    pub const REGISTRO: &[u8] = b"SAK-EVIDENCE-v1|registro|";
    pub const ENLACE: &[u8] = b"SAK-EVIDENCE-v1|enlace|";
    pub const MERKLE_HOJA: &[u8] = b"SAK-EVIDENCE-v1|merkle-leaf|";
    pub const MERKLE_NODO: &[u8] = b"SAK-EVIDENCE-v1|merkle-node|";
    pub const CHECKPOINT: &[u8] = b"SAK-EVIDENCE-v1|checkpoint|";
    pub const DECISION: &[u8] = b"SAK-EVIDENCE-v1|decision|";
    pub const RECIBO: &[u8] = b"SAK-EVIDENCE-v1|recibo|";
    pub const LIBRO: &[u8] = b"SAK-LIBRO-v1|hecho|";
    pub const BYPASS: &[u8] = b"SAK-BYPASS-v1|prueba|";
    pub const SUPERVISION: &[u8] = b"SAK-SUPERVISION-v1|";
    pub const CONTEXTO: &[u8] = b"SAK-CONTEXT-v1|";
    pub const GOBERNANZA: &[u8] = b"SAK-GOBERNANZA-v1|";
    pub const PAQUETE_NORMA: &[u8] = b"SAK-NORMA-PKG-v1|";
    pub const CATALOGO_HERR: &[u8] = b"SAK-TOOL-CATALOG-v1|";
    pub const HERRAMIENTA: &[u8] = b"SAK-TOOL-v1|";
    pub const NEGOCIO: &[u8] = b"SAK-BIZ-v1|";
    pub const COMUNICACION: &[u8] = b"SAK-COMM-v1|";
    pub const PUBLICACION: &[u8] = b"SAK-PUB-v1|";
    pub const DECISION_PERSONA: &[u8] = b"SAK-EF8-v1|";
    pub const EF9: &[u8] = b"SAK-EF9-v1|";
    pub const EGRESO: &[u8] = b"SAK-EGRESS-v1|";
    pub const FISICO: &[u8] = b"SAK-PHYS-v1|";
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCrypto {
    Firma,
    Verificacion,
    Clave,
}

impl fmt::Display for ErrorCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCrypto::Firma => f.write_str("fallo al firmar"),
            ErrorCrypto::Verificacion => f.write_str("firma invalida"),
            ErrorCrypto::Clave => f.write_str("clave invalida"),
        }
    }
}

impl std::error::Error for ErrorCrypto {}

/// SHA-384 con separación de dominio: H(domain || msg).
pub fn sha384_dominio(domain: &[u8], msg: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut h = Sha384::new();
    h.update(domain);
    h.update(msg);
    let out = h.finalize();
    let mut arr = [0u8; LONGITUD_HASH_PAQUETE];
    arr.copy_from_slice(&out);
    arr
}

/// HMAC-SHA-384 (J.6 derivación).
pub fn hmac_sha384(key: &[u8], msg: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut mac = HmacSha384::new_from_slice(key).expect("HMAC acepta clave de cualquier longitud");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; LONGITUD_HASH_PAQUETE];
    arr.copy_from_slice(&out);
    arr
}

#[derive(Clone)]
pub struct ParMlDsa87 {
    pub public: Vec<u8>,
    secret: ml_dsa_87::PrivateKey,
}

impl ParMlDsa87 {
    pub fn generar() -> Result<Self, ErrorCrypto> {
        let (pk, sk) = ml_dsa_87::try_keygen().map_err(|_| ErrorCrypto::Clave)?;
        Ok(ParMlDsa87 {
            public: pk.into_bytes().to_vec(),
            secret: sk,
        })
    }

    pub fn firmar(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorCrypto> {
        let sig = self
            .secret
            .try_sign(msg, &[])
            .map_err(|_| ErrorCrypto::Firma)?;
        Ok(sig.to_vec())
    }

    pub fn verificar(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ErrorCrypto> {
        let pk_arr: [u8; ml_dsa_87::PK_LEN] = public
            .try_into()
            .map_err(|_| ErrorCrypto::Clave)?;
        let pk = ml_dsa_87::PublicKey::try_from_bytes(pk_arr).map_err(|_| ErrorCrypto::Clave)?;
        let sig_arr: [u8; ml_dsa_87::SIG_LEN] =
            sig.try_into().map_err(|_| ErrorCrypto::Verificacion)?;
        if pk.verify(msg, &sig_arr, &[]) {
            Ok(())
        } else {
            Err(ErrorCrypto::Verificacion)
        }
    }
}

#[derive(Clone)]
pub struct ParSlhDsa {
    pub public: Vec<u8>,
    secret: slh_dsa_sha2_128s::PrivateKey,
}

impl ParSlhDsa {
    pub fn generar() -> Result<Self, ErrorCrypto> {
        let (pk, sk) = slh_dsa_sha2_128s::try_keygen().map_err(|_| ErrorCrypto::Clave)?;
        Ok(ParSlhDsa {
            public: pk.into_bytes().to_vec(),
            secret: sk,
        })
    }

    pub fn firmar(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorCrypto> {
        // ctx vacío; firmado «hedged» (true) según API fips205.
        let sig = self
            .secret
            .try_sign(msg, &[], true)
            .map_err(|_| ErrorCrypto::Firma)?;
        Ok(sig.to_vec())
    }

    pub fn verificar(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ErrorCrypto> {
        let pk_arr: [u8; slh_dsa_sha2_128s::PK_LEN] =
            public.try_into().map_err(|_| ErrorCrypto::Clave)?;
        let pk =
            slh_dsa_sha2_128s::PublicKey::try_from_bytes(&pk_arr).map_err(|_| ErrorCrypto::Clave)?;
        let sig_arr: [u8; slh_dsa_sha2_128s::SIG_LEN] =
            sig.try_into().map_err(|_| ErrorCrypto::Verificacion)?;
        if pk.verify(msg, &sig_arr, &[]) {
            Ok(())
        } else {
            Err(ErrorCrypto::Verificacion)
        }
    }
}
