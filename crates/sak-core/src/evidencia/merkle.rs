//! Árbol de Merkle por época, checkpoint cofirmado y pruebas de inclusión (§M 11 / J.6).

use crate::crypto::{self, dominio, ErrorCrypto, ParMlDsa87, ParSlhDsa};
use crate::decision::LONGITUD_HASH_PAQUETE;

/// Raíz de Merkle sobre digests de registros (SHA-384 con dominio).
pub fn merkle_raiz(hojas: &[[u8; LONGITUD_HASH_PAQUETE]]) -> [u8; LONGITUD_HASH_PAQUETE] {
    if hojas.is_empty() {
        return crypto::sha384_dominio(dominio::MERKLE_HOJA, b"");
    }
    let mut nivel: Vec<[u8; LONGITUD_HASH_PAQUETE]> = hojas
        .iter()
        .map(|h| crypto::sha384_dominio(dominio::MERKLE_HOJA, h))
        .collect();
    while nivel.len() > 1 {
        let mut next = Vec::new();
        for chunk in nivel.chunks(2) {
            let mut cat = Vec::with_capacity(96);
            cat.extend_from_slice(&chunk[0]);
            if chunk.len() == 2 {
                cat.extend_from_slice(&chunk[1]);
            } else {
                cat.extend_from_slice(&chunk[0]); // duplicar última
            }
            next.push(crypto::sha384_dominio(dominio::MERKLE_NODO, &cat));
        }
        nivel = next;
    }
    nivel[0]
}

/// Prueba de inclusión Merkle verificable (J.1-12 / J.6): hermano por nivel + lado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruebaInclusion {
    pub indice: u32,
    pub hoja: [u8; LONGITUD_HASH_PAQUETE],
    /// Por nivel desde la hoja hacia la raíz: (hermano, lado_hermano).
    /// `lado_hermano == 0` ⇒ el hermano va a la izquierda; `1` ⇒ a la derecha.
    pub camino: Vec<([u8; LONGITUD_HASH_PAQUETE], u8)>,
}

/// Emite prueba de inclusión para `indice` sobre el mismo árbol que `merkle_raiz`.
pub fn emitir_prueba_inclusion(
    hojas: &[[u8; LONGITUD_HASH_PAQUETE]],
    indice: usize,
) -> Option<PruebaInclusion> {
    if hojas.is_empty() || indice >= hojas.len() {
        return None;
    }
    let mut nivel: Vec<[u8; LONGITUD_HASH_PAQUETE]> = hojas
        .iter()
        .map(|h| crypto::sha384_dominio(dominio::MERKLE_HOJA, h))
        .collect();
    let mut idx = indice;
    let mut camino = Vec::new();
    while nivel.len() > 1 {
        let par = idx / 2;
        let es_izq = idx % 2 == 0;
        let herm_idx = if es_izq {
            if idx + 1 < nivel.len() {
                idx + 1
            } else {
                idx // duplicado
            }
        } else {
            idx - 1
        };
        let hermano = nivel[herm_idx];
        let lado_hermano = if es_izq { 1u8 } else { 0u8 };
        camino.push((hermano, lado_hermano));

        let mut next = Vec::new();
        for chunk in nivel.chunks(2) {
            let mut cat = Vec::with_capacity(96);
            cat.extend_from_slice(&chunk[0]);
            if chunk.len() == 2 {
                cat.extend_from_slice(&chunk[1]);
            } else {
                cat.extend_from_slice(&chunk[0]);
            }
            next.push(crypto::sha384_dominio(dominio::MERKLE_NODO, &cat));
        }
        nivel = next;
        idx = par;
    }
    Some(PruebaInclusion {
        indice: indice as u32,
        hoja: hojas[indice],
        camino,
    })
}

/// Verifica que la prueba reconstruye `raiz` (misma función de dominio que `merkle_raiz`).
pub fn verificar_inclusion(
    prueba: &PruebaInclusion,
    raiz: &[u8; LONGITUD_HASH_PAQUETE],
) -> bool {
    let mut acc = crypto::sha384_dominio(dominio::MERKLE_HOJA, &prueba.hoja);
    for (hermano, lado) in &prueba.camino {
        let mut cat = Vec::with_capacity(96);
        if *lado == 0 {
            cat.extend_from_slice(hermano);
            cat.extend_from_slice(&acc);
        } else {
            cat.extend_from_slice(&acc);
            cat.extend_from_slice(hermano);
        }
        acc = crypto::sha384_dominio(dominio::MERKLE_NODO, &cat);
    }
    &acc == raiz
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointEpoca {
    pub epoca: u64,
    pub suelo_epoca: u64,
    pub merkle_root: [u8; LONGITUD_HASH_PAQUETE],
    pub n_registros: u64,
    pub firma_autoridad_mldsa: Vec<u8>,
    pub cofirma_testigo_1_slh: Vec<u8>,
    pub cofirma_testigo_2_slh: Vec<u8>,
}

impl CheckpointEpoca {
    pub fn mensaje_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.suelo_epoca.to_le_bytes());
        v.extend_from_slice(&self.merkle_root);
        v.extend_from_slice(&self.n_registros.to_le_bytes());
        crypto::sha384_dominio(dominio::CHECKPOINT, &v).to_vec()
    }

    pub fn crear(
        epoca: u64,
        suelo_epoca: u64,
        merkle_root: [u8; LONGITUD_HASH_PAQUETE],
        n_registros: u64,
        autoridad: &ParMlDsa87,
        testigo1: &ParSlhDsa,
        testigo2: &ParSlhDsa,
    ) -> Result<Self, ErrorCrypto> {
        let mut cp = CheckpointEpoca {
            epoca,
            suelo_epoca,
            merkle_root,
            n_registros,
            firma_autoridad_mldsa: vec![],
            cofirma_testigo_1_slh: vec![],
            cofirma_testigo_2_slh: vec![],
        };
        let msg = cp.mensaje_canonico();
        cp.firma_autoridad_mldsa = autoridad.firmar(&msg)?;
        cp.cofirma_testigo_1_slh = testigo1.firmar(&msg)?;
        cp.cofirma_testigo_2_slh = testigo2.firmar(&msg)?;
        Ok(cp)
    }
}
