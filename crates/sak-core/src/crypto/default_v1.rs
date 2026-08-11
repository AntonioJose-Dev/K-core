//! Perfil criptográfico default v1 (J.6 / L-07 / B-01).
//!
//! Primitivas base (siempre disponibles):
//! - SHA-256 con separación de dominio
//! - HMAC-SHA-256
//! - AES-256-GCM
//! - HKDF-SHA-256 (implementación manual sobre HMAC-SHA-256 / RFC 5869)
//!
//! Primitiva condicional (`default-v1-ed25519` feature):
//! - Ed25519 (vía `ed25519-dalek` v2)
//!
//! Este perfil coexiste con el perfil declarable SHA-384 / ML-DSA-87 / SLH-DSA
//! definido en `crypto.rs`. La selección es por módulo; no hay mezcla
//! de primitivas de ambos perfiles en una misma operación.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;

type HmacSha256 = Hmac<Sha256>;

pub const SHA256_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDefaultV1 {
    Hkdf,
    Hmac,
    AesGcm,
    Firma,
    Verificacion,
    Clave,
}

impl fmt::Display for ErrorDefaultV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorDefaultV1::Hkdf => f.write_str("fallo HKDF-SHA-256"),
            ErrorDefaultV1::Hmac => f.write_str("fallo HMAC-SHA-256"),
            ErrorDefaultV1::AesGcm => f.write_str("fallo AES-256-GCM"),
            ErrorDefaultV1::Firma => f.write_str("fallo al firmar"),
            ErrorDefaultV1::Verificacion => f.write_str("firma invalida"),
            ErrorDefaultV1::Clave => f.write_str("clave invalida"),
        }
    }
}

impl std::error::Error for ErrorDefaultV1 {}

/// SHA-256 con separación de dominio: H(domain || msg).
pub fn sha256_dominio(domain: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(msg);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// HMAC-SHA-256.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC acepta clave de cualquier longitud");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

/// AES-256-GCM encriptar (nonce 12 bytes, AAD opcional).
pub fn aes256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ErrorDefaultV1> {
    let k = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let n = Nonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };
    cipher
        .encrypt(n, payload)
        .map_err(|_| ErrorDefaultV1::AesGcm)
}

/// AES-256-GCM desencriptar (nonce 12 bytes, AAD opcional).
pub fn aes256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ErrorDefaultV1> {
    let k = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(k);
    let n = Nonce::from_slice(nonce);
    let payload = Payload { msg: ciphertext, aad };
    cipher
        .decrypt(n, payload)
        .map_err(|_| ErrorDefaultV1::AesGcm)
}

/// HKDF-SHA-256 (RFC 5869).
///
/// Implementado manualmente sobre HMAC-SHA-256 para evitar dependencia en `hkdf` crate.
///
/// * `ikm`: entrada keying material.
/// * `salt`: sal opcional (si es `None` se usa array de ceros de longitud de hash).
/// * `info`: contexto/información de dominio.
/// * `len`: longitud de salida en bytes.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, ErrorDefaultV1> {
    let hash_len = SHA256_DIGEST_LEN;

    // Paso 1: Extract — PRK = HMAC-Hash(salt, IKM)
    let salt_final: Vec<u8> = match salt {
        Some(s) => s.to_vec(),
        None => vec![0u8; hash_len],
    };
    let prk = hmac_sha256(&salt_final, ikm);

    // Paso 2: Expand — generar bloques T(1) .. T(N)
    let n = (len + hash_len - 1) / hash_len;
    if n > 255 {
        return Err(ErrorDefaultV1::Hkdf);
    }

    let mut okm = Vec::with_capacity(len);
    let mut t_prev: Option<[u8; 32]> = None;

    for i in 1..=n {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&prk)
            .map_err(|_| ErrorDefaultV1::Hmac)?;
        if let Some(ref prev) = t_prev {
            mac.update(prev);
        }
        mac.update(info);
        mac.update(&[i as u8]);
        let t = mac.finalize().into_bytes();
        let mut block = [0u8; 32];
        block.copy_from_slice(&t);
        let take = std::cmp::min(hash_len, len - okm.len());
        okm.extend_from_slice(&block[..take]);
        t_prev = Some(block);
    }

    Ok(okm)
}

/// Derivación ejemplo `TK_tenant` (B-01.7 default v1).
///
/// `TK_tenant = HKDF-SHA-256(MK, "SK-TENANT-v1" || tenant_id || epoch_counter)`
pub fn derivar_tk_tenant(
    mk: &[u8],
    tenant_id: &str,
    epoch_counter: u64,
) -> Result<[u8; 32], ErrorDefaultV1> {
    let info = format!("SK-TENANT-v1|{}|{}", tenant_id, epoch_counter);
    let mut tk = hkdf_sha256(mk, None, info.as_bytes(), 32)?;
    tk.resize(32, 0);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&tk);
    Ok(arr)
}

/// HKDF-SHA-256 con salt explícita (wrapper).
pub fn hkdf_sha256_with_salt(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, ErrorDefaultV1> {
    hkdf_sha256(ikm, Some(salt), info, len)
}

#[cfg(feature = "default-v1-ed25519")]
pub mod ed25519 {
    //! Ed25519 (vía `ed25519-dalek` v2).
    //!
    //! Requiere la feature `default-v1-ed25519` activada en `sak-core`.
    //! Se puede usar `cargo test -p sak-core --test gate1_crypto_default_v1 --features default-v1-ed25519`.

    use super::ErrorDefaultV1;
    use ed25519_dalek::{Signature, SigningKey, Signer, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    pub const PUBLIC_KEY_LEN: usize = 32;
    pub const SECRET_KEY_LEN: usize = 32;
    pub const SIGNATURE_LEN: usize = 64;

    #[derive(Clone)]
    pub struct ParEd25519 {
        pub public: [u8; PUBLIC_KEY_LEN],
        signing: SigningKey,
        verifying: VerifyingKey,
    }

    impl ParEd25519 {
        pub fn generar() -> Result<Self, ErrorDefaultV1> {
            let signing = SigningKey::generate(&mut OsRng);
            let verifying = VerifyingKey::from(&signing);
            Ok(ParEd25519 {
                public: verifying.to_bytes(),
                signing,
                verifying,
            })
        }

        pub fn bytes_secreto(&self) -> Vec<u8> {
            self.signing.to_bytes().to_vec()
        }

        pub fn desde_bytes(
            public: [u8; PUBLIC_KEY_LEN],
            secret: &[u8],
        ) -> Result<Self, ErrorDefaultV1> {
            let secret_arr: [u8; SECRET_KEY_LEN] =
                secret.try_into().map_err(|_| ErrorDefaultV1::Clave)?;
            let signing = SigningKey::from_bytes(&secret_arr);
            let verifying = VerifyingKey::from(&signing);
            if verifying.to_bytes() != public {
                return Err(ErrorDefaultV1::Clave);
            }
            Ok(ParEd25519 {
                public,
                signing,
                verifying,
            })
        }

        pub fn firmar(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorDefaultV1> {
            let sig = self.signing.sign(msg);
            Ok(sig.to_bytes().to_vec())
        }

        pub fn verificar(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), ErrorDefaultV1> {
            let vk_arr: [u8; PUBLIC_KEY_LEN] =
                public.try_into().map_err(|_| ErrorDefaultV1::Clave)?;
            let vk = VerifyingKey::from_bytes(&vk_arr).map_err(|_| ErrorDefaultV1::Clave)?;
            let sig_arr: [u8; SIGNATURE_LEN] =
                sig.try_into().map_err(|_| ErrorDefaultV1::Verificacion)?;
            let signature = Signature::from_bytes(&sig_arr);
            vk.verify(msg, &signature)
                .map_err(|_| ErrorDefaultV1::Verificacion)
        }
    }
}
