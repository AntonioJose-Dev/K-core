//! Catálogo de herramientas firmado y ligado a pasaporte/corpus (EF-4 / F.5).

use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use std::collections::BTreeMap;
use std::fmt;

/// Entrada tipada del catálogo. Sin herramientas dinámicas ni extensiones en ejecución.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntradaHerramienta {
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub operacion: String,
    /// Digest del esquema de argumentos declarado.
    pub digest_esquema_args: [u8; LONGITUD_HASH_PAQUETE],
    /// Destinos/URL permitidos (vacío = sin redirección externa).
    pub destinos_permitidos: Vec<String>,
    /// Clase de efecto subyacente que la herramienta puede producir.
    pub efecto_subyacente: ClaseEfecto,
    pub reversible: bool,
    pub datos_personales: bool,
    pub cuota_maxima: u32,
    pub timeout_ms: u64,
}

impl EntradaHerramienta {
    pub fn clave(&self) -> String {
        format!("{}@{}|{}|{}", self.id_herramienta, self.version, self.servidor, self.operacion)
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        escribir(&mut v, &self.id_herramienta);
        escribir(&mut v, &self.version);
        escribir(&mut v, &self.servidor);
        escribir(&mut v, &self.operacion);
        v.extend_from_slice(&self.digest_esquema_args);
        v.extend_from_slice(&(self.destinos_permitidos.len() as u32).to_le_bytes());
        for d in &self.destinos_permitidos {
            escribir(&mut v, d);
        }
        v.push(self.efecto_subyacente as u8);
        v.push(u8::from(self.reversible));
        v.push(u8::from(self.datos_personales));
        v.extend_from_slice(&self.cuota_maxima.to_le_bytes());
        v.extend_from_slice(&self.timeout_ms.to_le_bytes());
        v
    }
}

fn escribir(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

/// Catálogo firmado, ligado a digest de pasaporte y hash de corpus.
#[derive(Debug, Clone)]
pub struct CatalogoHerramientas {
    entradas: BTreeMap<String, EntradaHerramienta>,
    digest_pasaporte: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete_normativo: [u8; LONGITUD_HASH_PAQUETE],
    digest_catalogo: [u8; LONGITUD_HASH_PAQUETE],
    firma_mldsa: Vec<u8>,
    pk_autoridad: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCatalogo {
    FirmaInvalida,
    EntradaInvalida(&'static str),
    NoFirmado,
}

impl fmt::Display for ErrorCatalogo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCatalogo::FirmaInvalida => f.write_str("firma de catalogo invalida"),
            ErrorCatalogo::EntradaInvalida(c) => write!(f, "entrada invalida: {c}"),
            ErrorCatalogo::NoFirmado => f.write_str("catalogo no firmado"),
        }
    }
}

impl std::error::Error for ErrorCatalogo {}

impl CatalogoHerramientas {
    pub fn construir(
        entradas: Vec<EntradaHerramienta>,
        digest_pasaporte: [u8; LONGITUD_HASH_PAQUETE],
        hash_paquete_normativo: [u8; LONGITUD_HASH_PAQUETE],
        autoridad: &ParMlDsa87,
    ) -> Result<Self, ErrorCatalogo> {
        let mut map = BTreeMap::new();
        for e in entradas {
            if e.id_herramienta.trim().is_empty()
                || e.version.trim().is_empty()
                || e.servidor.trim().is_empty()
                || e.operacion.trim().is_empty()
            {
                return Err(ErrorCatalogo::EntradaInvalida("campo vacio"));
            }
            let k = e.clave();
            if map.insert(k, e).is_some() {
                return Err(ErrorCatalogo::EntradaInvalida("duplicada"));
            }
        }
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&digest_pasaporte);
        cuerpo.extend_from_slice(&hash_paquete_normativo);
        cuerpo.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for e in map.values() {
            let c = e.canonico();
            cuerpo.extend_from_slice(&(c.len() as u32).to_le_bytes());
            cuerpo.extend_from_slice(&c);
        }
        let digest = crypto::sha384_dominio(dominio::CATALOGO_HERR, &cuerpo);
        let firma = autoridad
            .firmar(&digest)
            .map_err(|_| ErrorCatalogo::FirmaInvalida)?;
        Ok(CatalogoHerramientas {
            entradas: map,
            digest_pasaporte,
            hash_paquete_normativo,
            digest_catalogo: digest,
            firma_mldsa: firma,
            pk_autoridad: autoridad.public.clone(),
        })
    }

    pub fn verificar_firma(&self) -> Result<(), ErrorCatalogo> {
        ParMlDsa87::verificar(&self.pk_autoridad, &self.digest_catalogo, &self.firma_mldsa)
            .map_err(|_| ErrorCatalogo::FirmaInvalida)
    }

    pub fn obtener(
        &self,
        id: &str,
        version: &str,
        servidor: &str,
        operacion: &str,
    ) -> Option<&EntradaHerramienta> {
        let k = format!("{id}@{version}|{servidor}|{operacion}");
        self.entradas.get(&k)
    }

    pub fn expuesto(&self, id: &str) -> bool {
        self.entradas.keys().any(|k| k.starts_with(&format!("{id}@")))
    }

    pub fn digest_catalogo(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_catalogo
    }

    pub fn digest_pasaporte(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.digest_pasaporte
    }

    pub fn hash_paquete_normativo(&self) -> &[u8; LONGITUD_HASH_PAQUETE] {
        &self.hash_paquete_normativo
    }

    pub fn serializar_payload(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // alta/snapshot
        v.extend_from_slice(&self.digest_pasaporte);
        v.extend_from_slice(&self.hash_paquete_normativo);
        v.extend_from_slice(&self.digest_catalogo);
        v.extend_from_slice(&(self.firma_mldsa.len() as u32).to_le_bytes());
        v.extend_from_slice(&self.firma_mldsa);
        v.extend_from_slice(&(self.entradas.len() as u32).to_le_bytes());
        for e in self.entradas.values() {
            let c = e.canonico();
            v.extend_from_slice(&(c.len() as u32).to_le_bytes());
            v.extend_from_slice(&c);
        }
        v
    }

    pub fn entradas(&self) -> impl Iterator<Item = &EntradaHerramienta> {
        self.entradas.values()
    }
}
