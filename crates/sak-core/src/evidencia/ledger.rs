//! Ledger: escritura durable, cadena por sujeto, emisión tras compromiso.

use crate::capacidad::{emitir, Capability, CompromisoEvidencia, ParametrosEmision};
use crate::crypto::{self, dominio, ParMlDsa87, ParSlhDsa};
use crate::decision::{Decision, DecisionPermitida, LONGITUD_HASH_PAQUETE};
use crate::evidencia::estado::{ErrorEvidencia, EstadoDominio};
use crate::evidencia::merkle::{merkle_raiz, CheckpointEpoca};
use crate::evidencia::registro::{
    digest_decision_permitida, serializar_decision, serializar_recibo, IdSujeto, PaqueteEvidencia,
    ReciboEfecto, RegistroFirmado, TipoRegistro,
};
use crate::reloj::RelojMonotonico;
use std::collections::{BTreeMap, BTreeSet};

/// Almacén durable. La confirmación de escritura es el cierre material de INV-07.
pub trait AlmacenEvidencia {
    /// Persiste bytes. `Err` ⇒ evidencia no escribible.
    fn escribir_durable(&mut self, clave: &[u8], valor: &[u8]) -> Result<(), ()>;
    fn leer(&self, clave: &[u8]) -> Option<Vec<u8>>;
}

/// Almacén en memoria con fallo inyectable (tests).
#[derive(Default)]
pub struct MemoriaDurable {
    map: BTreeMap<Vec<u8>, Vec<u8>>,
    pub fallar_escritura: bool,
}

impl AlmacenEvidencia for MemoriaDurable {
    fn escribir_durable(&mut self, clave: &[u8], valor: &[u8]) -> Result<(), ()> {
        if self.fallar_escritura {
            return Err(());
        }
        self.map.insert(clave.to_vec(), valor.to_vec());
        Ok(())
    }

    fn leer(&self, clave: &[u8]) -> Option<Vec<u8>> {
        self.map.get(clave).cloned()
    }
}

struct CadenaSujeto {
    siguiente_seq: u64,
    ultimo_hash: [u8; LONGITUD_HASH_PAQUETE],
    digests_epoca: Vec<[u8; LONGITUD_HASH_PAQUETE]>,
}

/// Ledger de evidencia del dominio.
pub struct LedgerEvidencia<A: AlmacenEvidencia> {
    almacen: A,
    estado: EstadoDominio,
    epoca: u64,
    suelo_epoca: u64,
    autoridad: ParMlDsa87,
    testigo_1: ParSlhDsa,
    testigo_2: ParSlhDsa,
    cadenas: BTreeMap<String, CadenaSujeto>,
    registros: Vec<RegistroFirmado>,
    checkpoints: Vec<CheckpointEpoca>,
    /// Digests de decisiones permisivas ya comprometidas (cardinalidad INV-07).
    decisiones_comprometidas: BTreeSet<[u8; LONGITUD_HASH_PAQUETE]>,
    /// Digests para los que ya se emitió capacidad.
    capacidades_emitidas: BTreeSet<[u8; LONGITUD_HASH_PAQUETE]>,
}

impl<A: AlmacenEvidencia> LedgerEvidencia<A> {
    pub fn nuevo(almacen: A) -> Result<Self, ErrorEvidencia> {
        Ok(LedgerEvidencia {
            almacen,
            estado: EstadoDominio::Operative,
            epoca: 1,
            suelo_epoca: 1,
            autoridad: ParMlDsa87::generar().map_err(|e| ErrorEvidencia::Firma(e.to_string()))?,
            testigo_1: ParSlhDsa::generar().map_err(|e| ErrorEvidencia::Firma(e.to_string()))?,
            testigo_2: ParSlhDsa::generar().map_err(|e| ErrorEvidencia::Firma(e.to_string()))?,
            cadenas: BTreeMap::new(),
            registros: Vec::new(),
            checkpoints: Vec::new(),
            decisiones_comprometidas: BTreeSet::new(),
            capacidades_emitidas: BTreeSet::new(),
        })
    }

    pub fn estado(&self) -> EstadoDominio {
        self.estado
    }

    pub fn epoca(&self) -> u64 {
        self.epoca
    }

    pub fn pk_autoridad(&self) -> &[u8] {
        &self.autoridad.public
    }

    /// Firma ML-DSA de autoridad del ledger (expediente §M 11 / exportes).
    pub fn firmar_autoridad(&self, msg: &[u8]) -> Result<Vec<u8>, ErrorEvidencia> {
        self.autoridad
            .firmar(msg)
            .map_err(|e| ErrorEvidencia::Firma(e.to_string()))
    }

    pub fn pk_testigos(&self) -> (&[u8], &[u8]) {
        (&self.testigo_1.public, &self.testigo_2.public)
    }

    fn suspender(&mut self) {
        self.estado = EstadoDominio::Suspended;
    }

    fn exigir_operative(&self) -> Result<(), ErrorEvidencia> {
        if self.estado != EstadoDominio::Operative {
            return Err(ErrorEvidencia::DominioSuspendido);
        }
        Ok(())
    }

    fn cadena_mut(&mut self, sujeto: &IdSujeto) -> &mut CadenaSujeto {
        self.cadenas
            .entry(sujeto.como_str().to_string())
            .or_insert_with(|| CadenaSujeto {
                siguiente_seq: 0,
                ultimo_hash: [0u8; LONGITUD_HASH_PAQUETE],
                digests_epoca: Vec::new(),
            })
    }

    fn anexar(
        &mut self,
        sujeto: &IdSujeto,
        tipo: TipoRegistro,
        payload: Vec<u8>,
    ) -> Result<RegistroFirmado, ErrorEvidencia> {
        // PERFECTO §6.2: la evidencia de transición se escribe también en SUSPENDED.
        match tipo {
            TipoRegistro::TransicionEstado => {
                if matches!(self.estado, EstadoDominio::Operative | EstadoDominio::Suspended) {
                    // ok
                } else {
                    return Err(ErrorEvidencia::DominioSuspendido);
                }
            }
            _ => self.exigir_operative()?,
        }
        let epoca = self.epoca;
        let (seq, prev) = {
            let c = self.cadena_mut(sujeto);
            let seq = c.siguiente_seq;
            let prev = c.ultimo_hash;
            (seq, prev)
        };

        let mut reg = RegistroFirmado {
            sujeto: sujeto.clone(),
            epoca,
            secuencia: seq,
            prev_hash: prev,
            tipo,
            payload,
            digest: [0u8; LONGITUD_HASH_PAQUETE],
            firma_mldsa: vec![],
        };
        let cuerpo = reg.cuerpo_para_hash();
        reg.digest = RegistroFirmado::calcular_digest(&cuerpo);
        let enlace = {
            let mut v = Vec::new();
            v.extend_from_slice(&prev);
            v.extend_from_slice(&reg.digest);
            crypto::sha384_dominio(dominio::ENLACE, &v)
        };
        reg.firma_mldsa = self
            .autoridad
            .firmar(&reg.digest)
            .map_err(|e| ErrorEvidencia::Firma(e.to_string()))?;

        // Escritura durable del registro completo (digest||firma||cuerpo).
        let mut blob = Vec::new();
        blob.extend_from_slice(&reg.digest);
        blob.extend_from_slice(&(reg.firma_mldsa.len() as u32).to_le_bytes());
        blob.extend_from_slice(&reg.firma_mldsa);
        blob.extend_from_slice(&cuerpo);
        let clave = format!(
            "reg/{}/{}/{}",
            sujeto.como_str(),
            epoca,
            seq
        );
        if self
            .almacen
            .escribir_durable(clave.as_bytes(), &blob)
            .is_err()
        {
            self.suspender();
            return Err(ErrorEvidencia::EscrituraFallida);
        }

        // Actualizar cadena tras confirmación.
        {
            let esperado = {
                let c = self.cadena_mut(sujeto);
                c.siguiente_seq
            };
            if esperado != seq {
                self.suspender();
                return Err(ErrorEvidencia::HuecoSecuencia {
                    esperado,
                    encontrado: seq,
                });
            }
            let c = self.cadena_mut(sujeto);
            c.siguiente_seq = seq + 1;
            c.ultimo_hash = enlace;
            c.digests_epoca.push(reg.digest);
        }

        self.registros.push(reg.clone());
        Ok(reg)
    }

    /// Compromete de forma durable la evidencia de una decisión permisiva.
    /// Única vía que construye [`CompromisoEvidencia`] tras confirmación real.
    pub fn comprometer_decision(
        &mut self,
        sujeto: &IdSujeto,
        decision: &DecisionPermitida,
    ) -> Result<CompromisoEvidencia, ErrorEvidencia> {
        self.exigir_operative()?;
        if decision.normas_citadas().is_empty() {
            return Err(ErrorEvidencia::DecisionSinCita);
        }
        let d_digest = digest_decision_permitida(decision);
        if self.decisiones_comprometidas.contains(&d_digest) {
            return Err(ErrorEvidencia::DecisionYaComprometida);
        }
        let dec: Decision = decision.clone().into();
        let payload = serializar_decision(&dec)?;
        let reg = self.anexar(sujeto, TipoRegistro::Decision, payload)?;
        self.decisiones_comprometidas.insert(d_digest);
        Ok(CompromisoEvidencia::tras_confirmacion_durable(reg.digest))
    }

    /// INV-07 + INV-08: primero compromiso durable, después capacidad ligada.
    pub fn emitir_tras_evidencia(
        &mut self,
        sujeto: &IdSujeto,
        decision: DecisionPermitida,
        params: ParametrosEmision,
        reloj: &impl RelojMonotonico,
    ) -> Result<Capability, ErrorEvidencia> {
        let d_digest = digest_decision_permitida(&decision);
        let compromiso = self.comprometer_decision(sujeto, &decision)?;
        if self.capacidades_emitidas.contains(&d_digest) {
            return Err(ErrorEvidencia::CapacidadYaEmitida);
        }
        let cap = emitir(decision, compromiso, params, reloj)
            .map_err(|_| ErrorEvidencia::EmisionCapacidadRechazada)?;
        self.capacidades_emitidas.insert(d_digest);
        Ok(cap)
    }

    /// Registra un recibo (H.14) encadenado. Hueco de secuencia ⇒ SUSPENDED.
    pub fn registrar_recibo(
        &mut self,
        sujeto: &IdSujeto,
        recibo: &ReciboEfecto,
    ) -> Result<RegistroFirmado, ErrorEvidencia> {
        let ok = self.registros.iter().any(|r| {
            r.tipo == TipoRegistro::Decision && r.digest == recibo.digest_decision
        });
        if !ok {
            return Err(ErrorEvidencia::ReciboSinDecision);
        }
        let payload = serializar_recibo(recibo);
        self.anexar(sujeto, TipoRegistro::Recibo, payload)
    }

    /// Evento de sistema (p.ej. transición de estado) encadenado en evidencia.
    pub fn registrar_evento_sistema(
        &mut self,
        sujeto: &IdSujeto,
        tipo: TipoRegistro,
        payload: Vec<u8>,
    ) -> Result<RegistroFirmado, ErrorEvidencia> {
        self.anexar(sujeto, tipo, payload)
    }

    /// Registra un evento de supervisión humana (solicitud, firmas, hecho, fallo).
    pub fn registrar_supervision(
        &mut self,
        sujeto: &IdSujeto,
        payload: Vec<u8>,
    ) -> Result<RegistroFirmado, ErrorEvidencia> {
        self.anexar(sujeto, TipoRegistro::Supervision, payload)
    }

    /// Registra un evento de gobernanza normativa (G.5).
    pub fn registrar_gobernanza(
        &mut self,
        sujeto: &IdSujeto,
        payload: Vec<u8>,
    ) -> Result<RegistroFirmado, ErrorEvidencia> {
        self.anexar(sujeto, TipoRegistro::Gobernanza, payload)
    }

    /// Detecta y aplica suspensión por hueco de secuencia inyectado (tests / monitor).
    pub fn reportar_hueco_secuencia(
        &mut self,
        esperado: u64,
        encontrado: u64,
    ) -> ErrorEvidencia {
        self.suspender();
        ErrorEvidencia::HuecoSecuencia {
            esperado,
            encontrado,
        }
    }

    /// Cierra la época: checkpoint Merkle + cofirmas de dos testigos SLH-DSA.
    pub fn cerrar_epoca(&mut self) -> Result<CheckpointEpoca, ErrorEvidencia> {
        self.exigir_operative()?;
        let mut hojas = Vec::new();
        for c in self.cadenas.values() {
            hojas.extend_from_slice(&c.digests_epoca);
        }
        let root = merkle_raiz(&hojas);
        let n = hojas.len() as u64;
        let cp = CheckpointEpoca::crear(
            self.epoca,
            self.suelo_epoca,
            root,
            n,
            &self.autoridad,
            &self.testigo_1,
            &self.testigo_2,
        )
        .map_err(|e| ErrorEvidencia::Firma(e.to_string()))?;

        let mut blob = Vec::new();
        blob.extend_from_slice(&cp.mensaje_canonico());
        blob.extend_from_slice(&cp.firma_autoridad_mldsa);
        blob.extend_from_slice(&cp.cofirma_testigo_1_slh);
        blob.extend_from_slice(&cp.cofirma_testigo_2_slh);
        let clave = format!("checkpoint/{}", self.epoca);
        if self
            .almacen
            .escribir_durable(clave.as_bytes(), &blob)
            .is_err()
        {
            self.suspender();
            return Err(ErrorEvidencia::EscrituraFallida);
        }

        for c in self.cadenas.values_mut() {
            c.digests_epoca.clear();
        }
        self.checkpoints.push(cp.clone());
        self.epoca += 1;
        self.suelo_epoca = self.epoca;
        Ok(cp)
    }

    pub fn exportar_paquete(&self) -> PaqueteEvidencia {
        PaqueteEvidencia {
            registros: self.registros.clone(),
            checkpoints: self.checkpoints.clone(),
            pk_autoridad_mldsa: self.autoridad.public.clone(),
            pk_testigo_1_slh: self.testigo_1.public.clone(),
            pk_testigo_2_slh: self.testigo_2.public.clone(),
        }
    }

    pub fn n_decisiones_comprometidas(&self) -> usize {
        self.decisiones_comprometidas.len()
    }

    pub fn n_capacidades_emitidas(&self) -> usize {
        self.capacidades_emitidas.len()
    }
}
