//! Perfil de autoridad multiparte §M 12 / K — quórum 2/3+1 y certificado de vista.
//!
//! Distinto del Kernel uniparte (sin consenso en ruta de decisión ordinaria).
//! Umbral: q = ⌊2N/3⌋ + 1; **nunca** mayoría simple ⌈N/2⌉.

use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use std::collections::BTreeSet;
use std::fmt;

pub const DOMINIO_VISTA: &[u8] = b"SAK-VISTA-MULTIPARTE-v1|";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdNodo(pub String);

impl IdNodo {
    pub fn nuevo(s: impl Into<String>) -> Result<Self, ErrorVista> {
        let s = s.into();
        if s.trim().is_empty() {
            return Err(ErrorVista::NodoVacio);
        }
        Ok(IdNodo(s))
    }
}

/// q = floor(2N/3) + 1
pub fn quorum_dos_tercios_mas_uno(n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    (2 * n) / 3 + 1
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorVista {
    NodoVacio,
    QuorumInsuficiente { firmas: usize, requerido: usize },
    FirmaInvalida,
    DigestAlterado,
    NodoNoMiembro,
    FirmaDuplicada,
    ConjuntoVacio,
    VistaConflictiva,
}

impl fmt::Display for ErrorVista {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ErrorVista {}

#[derive(Debug, Clone)]
pub struct CertificadoCambioVista {
    pub vista_id: String,
    pub epoca_nueva: u64,
    pub suelo_epoca: u64,
    pub nodos: Vec<IdNodo>,
    pub umbral: usize,
    pub digest_vista: [u8; LONGITUD_HASH_PAQUETE],
    pub firmas: Vec<(IdNodo, Vec<u8>)>,
}

impl CertificadoCambioVista {
    pub fn digest_de(
        vista_id: &str,
        epoca_nueva: u64,
        suelo_epoca: u64,
        nodos: &[IdNodo],
    ) -> [u8; LONGITUD_HASH_PAQUETE] {
        let mut v = Vec::new();
        v.extend_from_slice(DOMINIO_VISTA);
        v.extend_from_slice(vista_id.as_bytes());
        v.extend_from_slice(&epoca_nueva.to_le_bytes());
        v.extend_from_slice(&suelo_epoca.to_le_bytes());
        for n in nodos {
            v.extend_from_slice(n.0.as_bytes());
            v.push(0);
        }
        crypto::sha384_dominio(dominio::CHECKPOINT, &v)
    }
}

/// Construye certificado firmado por el subconjunto aportado (debe alcanzar umbral).
pub fn emitir_certificado_vista(
    vista_id: impl Into<String>,
    epoca_nueva: u64,
    suelo_epoca: u64,
    nodos: Vec<IdNodo>,
    firmantes: &[(IdNodo, &ParMlDsa87)],
) -> Result<CertificadoCambioVista, ErrorVista> {
    let vista_id = vista_id.into();
    if nodos.is_empty() {
        return Err(ErrorVista::ConjuntoVacio);
    }
    let miembros: BTreeSet<_> = nodos.iter().cloned().collect();
    let umbral = quorum_dos_tercios_mas_uno(nodos.len());
    let digest_vista =
        CertificadoCambioVista::digest_de(&vista_id, epoca_nueva, suelo_epoca, &nodos);

    let mut firmas = Vec::new();
    let mut vistos = BTreeSet::new();
    for (id, sk) in firmantes {
        if !miembros.contains(id) {
            return Err(ErrorVista::NodoNoMiembro);
        }
        if !vistos.insert(id.clone()) {
            return Err(ErrorVista::FirmaDuplicada);
        }
        let sig = sk.firmar(&digest_vista).map_err(|_| ErrorVista::FirmaInvalida)?;
        firmas.push((id.clone(), sig));
    }
    if firmas.len() < umbral {
        return Err(ErrorVista::QuorumInsuficiente {
            firmas: firmas.len(),
            requerido: umbral,
        });
    }
    Ok(CertificadoCambioVista {
        vista_id,
        epoca_nueva,
        suelo_epoca,
        nodos,
        umbral,
        digest_vista,
        firmas,
    })
}

/// Verifica certificado: umbral 2/3+1, firmas válidas, sin mayoría simple como regla.
pub fn aceptar_certificado(
    cert: &CertificadoCambioVista,
    pks: &[(IdNodo, &[u8])],
) -> Result<(), ErrorVista> {
    let esperado = quorum_dos_tercios_mas_uno(cert.nodos.len());
    if cert.umbral != esperado {
        return Err(ErrorVista::QuorumInsuficiente {
            firmas: cert.umbral,
            requerido: esperado,
        });
    }
    let dig = CertificadoCambioVista::digest_de(
        &cert.vista_id,
        cert.epoca_nueva,
        cert.suelo_epoca,
        &cert.nodos,
    );
    if dig != cert.digest_vista {
        return Err(ErrorVista::DigestAlterado);
    }
    let miembros: BTreeSet<_> = cert.nodos.iter().cloned().collect();
    let mut validas = 0usize;
    let mut vistos = BTreeSet::new();
    for (id, sig) in &cert.firmas {
        if !miembros.contains(id) {
            return Err(ErrorVista::NodoNoMiembro);
        }
        if !vistos.insert(id.clone()) {
            return Err(ErrorVista::FirmaDuplicada);
        }
        let pk = pks
            .iter()
            .find(|(n, _)| n == id)
            .map(|(_, pk)| *pk)
            .ok_or(ErrorVista::FirmaInvalida)?;
        ParMlDsa87::verificar(pk, &cert.digest_vista, sig)
            .map_err(|_| ErrorVista::FirmaInvalida)?;
        validas += 1;
    }
    if validas < cert.umbral {
        return Err(ErrorVista::QuorumInsuficiente {
            firmas: validas,
            requerido: cert.umbral,
        });
    }
    Ok(())
}

/// Invariante: no aceptar un segundo certificado conflictivo para la misma época
/// si ya hay uno aceptado (suelo monótono).
pub fn registrar_vista_si_compatible(
    aceptada: &Option<CertificadoCambioVista>,
    nueva: &CertificadoCambioVista,
    pks: &[(IdNodo, &[u8])],
) -> Result<CertificadoCambioVista, ErrorVista> {
    aceptar_certificado(nueva, pks)?;
    if let Some(prev) = aceptada {
        if prev.epoca_nueva == nueva.epoca_nueva && prev.digest_vista != nueva.digest_vista {
            return Err(ErrorVista::VistaConflictiva);
        }
        if nueva.suelo_epoca < prev.suelo_epoca {
            return Err(ErrorVista::VistaConflictiva);
        }
    }
    Ok(nueva.clone())
}
