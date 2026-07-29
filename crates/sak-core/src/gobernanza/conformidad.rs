//! Prueba de conformidad y diff determinista de decisiones (G.5 etapa 3).

use crate::contexto::Contexto;
use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::{Decision, LONGITUD_HASH_PAQUETE, Veredicto};
use crate::norma::PaqueteNormativo;
use crate::precedencia::decidir_paquete;
use crate::supervision::IdHumano;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CasoConformidad {
    pub id: String,
    pub contexto: Contexto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CambioDecision {
    pub id_caso: String,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub anterior: Veredicto,
    pub nuevo: Veredicto,
    pub digest_cambio: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDecisiones {
    pub cambios: Vec<CambioDecision>,
}

impl DiffDecisiones {
    pub fn vacio(&self) -> bool {
        self.cambios.is_empty()
    }
}

/// Diff determinista: mismas entradas ⇒ mismo conjunto ordenado de cambios.
pub fn resultado_diff(
    casos: &[CasoConformidad],
    anterior: &PaqueteNormativo,
    propuesto: &PaqueteNormativo,
) -> DiffDecisiones {
    let mut cambios = Vec::new();
    for c in casos {
        let d_ant = decidir_paquete(&c.contexto, anterior);
        let d_nue = decidir_paquete(&c.contexto, propuesto);
        let v_ant = d_ant.veredicto();
        let v_nue = d_nue.veredicto();
        if v_ant != v_nue {
            let digest_ctx = crate::supervision::digest_contexto(&c.contexto);
            let mut msg = Vec::new();
            msg.extend_from_slice(c.id.as_bytes());
            msg.push(0);
            msg.extend_from_slice(&digest_ctx);
            msg.push(v_ant as u8);
            msg.push(v_nue as u8);
            let digest_cambio = crypto::sha384_dominio(dominio::GOBERNANZA, &msg);
            cambios.push(CambioDecision {
                id_caso: c.id.clone(),
                digest_contexto: digest_ctx,
                anterior: v_ant,
                nuevo: v_nue,
                digest_cambio,
            });
        }
    }
    cambios.sort_by(|a, b| a.id_caso.cmp(&b.id_caso));
    DiffDecisiones { cambios }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconocimientoCambio {
    pub digest_cambio: [u8; LONGITUD_HASH_PAQUETE],
    pub id_humano: IdHumano,
    pub firma_mldsa: Vec<u8>,
}

impl ReconocimientoCambio {
    pub fn firmar(
        par: &ParMlDsa87,
        id: IdHumano,
        digest_cambio: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"diff-ack|");
        msg.extend_from_slice(&digest_cambio);
        let firma = par.firmar(&msg)?;
        Ok(ReconocimientoCambio {
            digest_cambio,
            id_humano: id,
            firma_mldsa: firma,
        })
    }

    pub fn verificar(&self, pk: &[u8]) -> bool {
        let mut msg = Vec::new();
        msg.extend_from_slice(b"diff-ack|");
        msg.extend_from_slice(&self.digest_cambio);
        ParMlDsa87::verificar(pk, &msg, &self.firma_mldsa).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorDiff {
    DiffNoReconocido,
    ReconocimientoInvalido,
}

impl fmt::Display for ErrorDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorDiff::DiffNoReconocido => f.write_str("diff de decisiones no reconocido"),
            ErrorDiff::ReconocimientoInvalido => f.write_str("reconocimiento de cambio invalido"),
        }
    }
}

impl std::error::Error for ErrorDiff {}

/// Todo cambio debe tener reconocimiento firmado; un diff no reconocido bloquea.
pub fn exigir_diff_reconocido(
    diff: &DiffDecisiones,
    reconocimientos: &[ReconocimientoCambio],
    pks: &[(IdHumano, Vec<u8>)],
) -> Result<(), ErrorDiff> {
    for cambio in &diff.cambios {
        let ack = reconocimientos
            .iter()
            .find(|r| r.digest_cambio == cambio.digest_cambio)
            .ok_or(ErrorDiff::DiffNoReconocido)?;
        let pk = pks
            .iter()
            .find(|(id, _)| id == &ack.id_humano)
            .map(|(_, pk)| pk.as_slice())
            .ok_or(ErrorDiff::ReconocimientoInvalido)?;
        if !ack.verificar(pk) {
            return Err(ErrorDiff::ReconocimientoInvalido);
        }
    }
    Ok(())
}

/// Serializa veredicto de decisión para evidencia (INV-03: hash + ids ya en Decision).
pub fn decision_cita_construible(d: &Decision) -> bool {
    // Hash siempre presente por tipo; ALLOW exige normas citadas.
    match d {
        Decision::Permitida(p) => !p.normas_citadas().is_empty(),
        _ => true,
    }
}
