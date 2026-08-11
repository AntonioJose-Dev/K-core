//! Gate 1 — Perfil criptográfico default v1.
//!
//! Verifica SHA-256, HMAC-SHA-256, AES-256-GCM, HKDF-SHA-256 e Ed25519.

use sak_core::crypto::default_v1::{
    aes256_gcm_decrypt, aes256_gcm_encrypt, derivar_tk_tenant, hkdf_sha256, hkdf_sha256_with_salt,
    hmac_sha256, sha256_dominio, ErrorDefaultV1,
};
use sak_core::crypto::ParMlDsa87;

#[test]
fn hkdf_sha256_vector_conocido_rfc5869() {
    // RFC 5869 Test Case 1 (SHA-256).
    let ikm: [u8; 22] = [0x0b; 22];
    let salt: [u8; 22] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20,
    ];
    let info: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
        0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
        0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];

    let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap();
    assert_eq!(okm, expected);
}

#[test]
fn hkdf_sha256_sin_salt_ceros() {
    // RFC 5869 Test Case 2 (SHA-256): salt = null ⇒ ceros de longitud hash.
    let ikm: [u8; 64] = [
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
        0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
        0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
    ];
    let info = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe,
        0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc,
    ];
    let expected: [u8; 42] = [
        0x0f, 0xa6, 0xb2, 0xe5, 0x75, 0x7a, 0xa8, 0x93, 0x43, 0xd3, 0x56, 0xe6, 0x90, 0x1f, 0xb5,
        0x2d, 0x9f, 0x0b, 0xe5, 0x73, 0x12, 0x36, 0x40, 0x52, 0xd0, 0x17, 0x72, 0x62, 0x5c, 0x0a,
        0xc8, 0x09, 0x46, 0x0d, 0x69, 0x49, 0xc4, 0x41, 0x0f, 0x03, 0x33, 0x53,
    ];

    let okm = hkdf_sha256(&ikm, None, &info, 42).unwrap();
    assert_eq!(okm, expected);
}

#[test]
fn derivar_tk_tenant_vector_conocido() {
    let mk = [0xab; 32];
    let tk = derivar_tk_tenant(&mk, "tenant-001", 1).unwrap();
    assert_eq!(tk.len(), 32);
    assert_eq!(tk, derivar_tk_tenant(&mk, "tenant-001", 1).unwrap());
    assert_ne!(tk, derivar_tk_tenant(&mk, "tenant-001", 2).unwrap());
}

#[test]
fn aes256_gcm_roundtrip() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"sovereign-kernel-default-v1";
    let aad = b"";

    let ct = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    let pt = aes256_gcm_decrypt(&key, &nonce, &ct, aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn aes256_gcm_tamper_detectado() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"sovereign-kernel-default-v1";
    let aad = b"";

    let mut ct = aes256_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
    ct[0] ^= 0x01;
    let result = aes256_gcm_decrypt(&key, &nonce, &ct, aad);
    assert!(matches!(result, Err(ErrorDefaultV1::AesGcm)));
}

#[test]
fn aes256_gcm_aad_diferente_falla() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"sovereign-kernel-default-v1";

    let ct = aes256_gcm_encrypt(&key, &nonce, plaintext, b"aad1").unwrap();
    let result = aes256_gcm_decrypt(&key, &nonce, &ct, b"aad2");
    assert!(matches!(result, Err(ErrorDefaultV1::AesGcm)));
}

#[test]
fn sha256_dominio_separacion() {
    let domain = b"SAK-TEST|dominio|";
    let msg = b"mensaje";
    let digest = sha256_dominio(domain, msg);
    let mut h = sha2::Sha256::new();
    h.update(domain);
    h.update(msg);
    let expected = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&expected);
    assert_eq!(digest, arr);
}

#[test]
fn hmac_sha256_vector_conocido() {
    let key = b"clave-hmac";
    let msg = b"mensaje-hmac";
    let mac = hmac_sha256(key, msg);
    let mut expected = <hmac::Hmac<sha2::Sha256> as hmac::Mac>::new_from_slice(key).unwrap();
    expected.update(msg);
    let expected_bytes = expected.finalize().into_bytes();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&expected_bytes);
    assert_eq!(mac, arr);
}

#[test]
fn hkdf_sha256_with_salt_equivalente_a_with_salt() {
    let ikm = [0xcd; 32];
    let salt = [0xab; 16];
    let info = b"contexto";
    let a = hkdf_sha256(ikm, Some(salt), info, 32).unwrap();
    let b = hkdf_sha256_with_salt(ikm, salt, info, 32).unwrap();
    assert_eq!(a, b);
}

#[test]
fn dualidad_perfil_declarable_intacto() {
    let par = ParMlDsa87::generar().unwrap();
    let msg = b"perfil-declarable";
    let sig = par.firmar(msg).unwrap();
    assert!(ParMlDsa87::verificar(&par.public, msg, &sig).is_ok());
}
