//! Almacén durable en disco local — INV-07 («el almacenamiento no miente»).
//!
//! Backend de [`AlmacenEvidencia`] para el proceso autoritativo por dominio (§E).
//! No añade requisitos: solo hace verdadera la escritura que el ledger ya exige.

use crate::evidencia::ledger::AlmacenEvidencia;
use std::fs;
use std::path::{Path, PathBuf};

/// Prefijo de archivo para claves del almacén (evita colisiones con nombres reservados).
const PREFIJO: &str = "k_";

/// Almacén clave→valor en un directorio. Cada clave se codifica a un nombre de archivo.
#[derive(Debug)]
pub struct AlmacenDiscoLocal {
    root: PathBuf,
    /// Inyectable en pruebas: simula disco no escribible (INV-07).
    pub fallar_escritura: bool,
}

impl AlmacenDiscoLocal {
    /// Abre o crea el directorio raíz del almacén.
    pub fn abrir(root: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        Ok(AlmacenDiscoLocal {
            root,
            fallar_escritura: false,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_de_clave(&self, clave: &[u8]) -> PathBuf {
        // Hex de la clave: portable en Windows; las claves del ledger usan ASCII (`reg/...`).
        let mut nombre = String::from(PREFIJO);
        for b in clave {
            nombre.push_str(&format!("{b:02x}"));
        }
        self.root.join(nombre)
    }
}

impl AlmacenEvidencia for AlmacenDiscoLocal {
    fn escribir_durable(&mut self, clave: &[u8], valor: &[u8]) -> Result<(), ()> {
        if self.fallar_escritura {
            return Err(());
        }
        let path = self.path_de_clave(clave);
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, valor).map_err(|_| ())?;
        // Renombrado atómico en el mismo volumen: confirmación material de durabilidad.
        fs::rename(&tmp, &path).map_err(|_| ())?;
        Ok(())
    }

    fn leer(&self, clave: &[u8]) -> Option<Vec<u8>> {
        fs::read(self.path_de_clave(clave)).ok()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dir_tmp(tag: &str) -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sak-almacen-{tag}-{n}"))
    }

    #[test]
    fn persiste_tras_reabrir() {
        let dir = dir_tmp("persist");
        let clave = b"reg/sujeto-a/1/0";
        let valor = b"blob-evidencia-v1";
        {
            let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
            a.escribir_durable(clave, valor).unwrap();
        }
        let a2 = AlmacenDiscoLocal::abrir(&dir).unwrap();
        assert_eq!(a2.leer(clave).as_deref(), Some(valor.as_slice()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fallo_escritura_no_persiste() {
        let dir = dir_tmp("fail");
        let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
        a.fallar_escritura = true;
        assert!(a.escribir_durable(b"k", b"v").is_err());
        a.fallar_escritura = false;
        assert!(a.leer(b"k").is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
