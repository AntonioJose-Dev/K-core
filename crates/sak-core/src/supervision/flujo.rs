//! Flujo: ESCALATE → solicitud → hecho humano → revalidación → ALLOW o DENY(QUORUM_SUPERVISION).

use crate::capacidad::Alcance;
use crate::contexto::Contexto;
use crate::decision::{
    CodigoRazon, Decision, DecisionDenegada, DecisionEscalada, DecisionPermitida,
};
use crate::identidad::IdSistema;
use crate::norma::PaqueteNormativo;
use crate::precedencia::decidir_paquete;
use crate::reloj::Ticks;
use crate::supervision::hecho::{FirmaAprobador, HechoSupervision, VeredictoHumano};
use crate::supervision::identidad::{IdHumano, RegistroHumanos};
use crate::supervision::solicitud::{
    digest_contexto, desde_decision, ErrorSolicitud, RequisitosEscalado, SolicitudSupervision,
};
use crate::supervision::verificar::{construir_hecho, verificar_hecho_completo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoSupervision {
    /// Aprobación íntegra: el motor puede emitir decisión permisiva.
    Continuar(DecisionPermitida),
    /// Fallo técnico o rechazo ⇒ DENY(QUORUM_SUPERVISION).
    Denegar(DecisionDenegada),
}

fn denegar_quorum(esc: &DecisionEscalada) -> DecisionDenegada {
    DecisionDenegada::nueva(
        esc.hash_paquete().clone(),
        esc.traza().clone(),
        CodigoRazon::QuorumSupervision,
    )
}

/// Crea la solicitud tipada solo desde una decisión `ESCALATE` del motor.
pub fn crear_solicitud_desde_escalada(
    decision: &Decision,
    contexto: &Contexto,
    id_solicitante: IdHumano,
    sistema: IdSistema,
    requisitos: RequisitosEscalado,
    instante: Ticks,
    epoca: u64,
    alcance_efecto: Alcance,
) -> Result<SolicitudSupervision, ErrorSolicitud> {
    desde_decision(
        decision,
        digest_contexto(contexto),
        id_solicitante,
        sistema,
        contexto.efecto().clase(),
        requisitos,
        instante,
        epoca,
        alcance_efecto,
    )
}

/// Silencio al vencimiento: nunca ALLOW tácito.
pub fn denegar_silencio(decision_escalada: &DecisionEscalada) -> DecisionDenegada {
    denegar_quorum(decision_escalada)
}

/// Plazo vencido con o sin firmas tardías.
pub fn denegar_vencimiento(decision_escalada: &DecisionEscalada) -> DecisionDenegada {
    denegar_quorum(decision_escalada)
}

/// Resuelve firmas humanas sobre una solicitud: produce hecho o DENY.
pub fn resolver_firmas(
    solicitud: &SolicitudSupervision,
    decision_escalada: &DecisionEscalada,
    veredicto: VeredictoHumano,
    firmas: Vec<FirmaAprobador>,
    registro: &RegistroHumanos,
    ahora: Ticks,
) -> Result<HechoSupervision, DecisionDenegada> {
    if !solicitud.integra() {
        return Err(denegar_quorum(decision_escalada));
    }
    if ahora > solicitud.plazo_hasta() {
        return Err(denegar_vencimiento(decision_escalada));
    }
    let hecho = construir_hecho(solicitud, veredicto, firmas, ahora);
    if veredicto == VeredictoHumano::Rechazado {
        // Registrar rechazo: el hecho existe pero el resultado es DENY.
        let _ = hecho;
        return Err(denegar_quorum(decision_escalada));
    }
    match verificar_hecho_completo(solicitud, &hecho, registro, ahora) {
        Ok(()) => Ok(hecho),
        Err(_) => Err(denegar_quorum(decision_escalada)),
    }
}

/// Tras el hecho humano: valida digest/decisión vigentes y solo entonces ALLOW.
///
/// - No aprueba un `DENY` del motor.
/// - Si el contexto cambió (digest distinto) ⇒ DENY(QUORUM_SUPERVISION).
/// - Recomputa el motor; si sigue en ESCALATE con el mismo hash, la supervisión
///   satisfecha desbloquea `DecisionPermitida` citando las mismas normas.
pub fn continuar_tras_supervision(
    solicitud: &SolicitudSupervision,
    hecho: &HechoSupervision,
    decision_previa: &Decision,
    contexto_actual: &Contexto,
    paquete: &PaqueteNormativo,
    registro: &RegistroHumanos,
    ahora: Ticks,
) -> ResultadoSupervision {
    let esc = match decision_previa {
        Decision::Escalada(e) => e,
        Decision::Denegada(d) => {
            return ResultadoSupervision::Denegar(DecisionDenegada::nueva(
                d.hash_paquete().clone(),
                d.traza().clone(),
                CodigoRazon::QuorumSupervision,
            ));
        }
        Decision::Permitida(_) | Decision::Suspendida(_) => {
            return ResultadoSupervision::Denegar(DecisionDenegada::nueva(
                solicitud.hash_paquete().clone(),
                decision_previa.traza().clone(),
                CodigoRazon::QuorumSupervision,
            ));
        }
    };

    if digest_contexto(contexto_actual) != *solicitud.digest_contexto() {
        return ResultadoSupervision::Denegar(denegar_quorum(esc));
    }

    if verificar_hecho_completo(solicitud, hecho, registro, ahora).is_err() {
        return ResultadoSupervision::Denegar(denegar_quorum(esc));
    }

    let recomputada = decidir_paquete(contexto_actual, paquete);
    if recomputada.hash_paquete() != solicitud.hash_paquete() {
        return ResultadoSupervision::Denegar(denegar_quorum(esc));
    }

    match &recomputada {
        Decision::Permitida(p) => ResultadoSupervision::Continuar(p.clone()),
        Decision::Escalada(e) => {
            if e.hash_paquete() != esc.hash_paquete() || e.codigo() != esc.codigo() {
                return ResultadoSupervision::Denegar(denegar_quorum(esc));
            }
            match DecisionPermitida::nueva(esc.hash_paquete().clone(), esc.traza().clone(), None) {
                Ok(p) => ResultadoSupervision::Continuar(p),
                Err(_) => ResultadoSupervision::Denegar(denegar_quorum(esc)),
            }
        }
        Decision::Denegada(d) => ResultadoSupervision::Denegar(DecisionDenegada::nueva(
            d.hash_paquete().clone(),
            d.traza().clone(),
            CodigoRazon::QuorumSupervision,
        )),
        Decision::Suspendida(_) => ResultadoSupervision::Denegar(denegar_quorum(esc)),
    }
}

/// Silencio: no hay hecho al llegar el plazo ⇒ DENY, nunca ALLOW.
pub fn resolver_silencio(decision_escalada: &DecisionEscalada) -> DecisionDenegada {
    denegar_silencio(decision_escalada)
}
