//! Puerta H.4: Libro de Control antes de evaluar normas (INV-09).

use crate::contexto::{ClaseEfecto, Contexto};
use crate::decision::{
    CodigoRazon, Decision, DecisionDenegada, HashPaqueteNormativo, TrazaPrecedencia,
};
use crate::identidad::IdSistema;
use crate::libro::calculo::EvaluacionNivel;
use crate::libro::libro_ctrl::LibroControl;
use crate::libro::minimo::minimo_exigido;
use crate::libro::nivel::NivelControl;
use crate::motor::{decidir, decidir_paquete};
use crate::norma::PaqueteNormativo;
use crate::perfil::PerfilNormativo;
use crate::reloj::Ticks;

#[derive(Debug, Clone)]
pub struct DecisionConControl {
    pub decision: Decision,
    pub nivel_en_instante: NivelControl,
    pub minimo_exigido: NivelControl,
    pub evaluacion: EvaluacionNivel,
    /// `true` si se evaluó el corpus; `false` si DENY por control insuficiente.
    pub corpus_evaluado: bool,
}

#[derive(Debug, Clone)]
pub enum ResultadoPuertaControl {
    /// Nivel suficiente: se puede evaluar el corpus.
    Continuar(EvaluacionNivel),
    /// `DENY(CONTROL_INSUFICIENTE)` sin evaluar normas.
    Denegar {
        decision: Decision,
        evaluacion: EvaluacionNivel,
        minimo: NivelControl,
    },
}

/// Comprueba el Libro. Si el nivel < mínimo de la clase ⇒ deniega sin corpus.
pub fn comprobar_puerta_control(
    libro: &LibroControl,
    sistema: &IdSistema,
    clase: ClaseEfecto,
    datos_personales: bool,
    ahora: Ticks,
    hash_paquete: HashPaqueteNormativo,
) -> ResultadoPuertaControl {
    if libro.clase_suspendida(sistema, clase) {
        let eval = libro.evaluar(sistema, clase, ahora);
        let traza = TrazaPrecedencia::nueva(vec![], vec![], 0).expect("vacia");
        return ResultadoPuertaControl::Denegar {
            decision: Decision::Denegada(DecisionDenegada::nueva(
                hash_paquete,
                traza,
                CodigoRazon::ControlInsuficiente,
            )),
            evaluacion: eval,
            minimo: minimo_exigido(clase, datos_personales),
        };
    }

    let eval = libro.evaluar(sistema, clase, ahora);
    let minimo = minimo_exigido(clase, datos_personales);
    if eval.nivel_vigente < minimo {
        let traza = TrazaPrecedencia::nueva(vec![], vec![], 0).expect("vacia");
        return ResultadoPuertaControl::Denegar {
            decision: Decision::Denegada(DecisionDenegada::nueva(
                hash_paquete,
                traza,
                CodigoRazon::ControlInsuficiente,
            )),
            evaluacion: eval,
            minimo,
        };
    }
    ResultadoPuertaControl::Continuar(eval)
}

/// Decisión completa: puerta de control y, solo si pasa, evaluación normativa.
pub fn decidir_con_libro(
    contexto: &Contexto,
    perfil: &PerfilNormativo,
    libro: &LibroControl,
    sistema: &IdSistema,
    datos_personales: bool,
    ahora: Ticks,
) -> DecisionConControl {
    let clase = contexto.efecto().clase();
    let hash = *perfil.hash_paquete();
    match comprobar_puerta_control(
        libro,
        sistema,
        clase,
        datos_personales,
        ahora,
        hash,
    ) {
        ResultadoPuertaControl::Denegar {
            decision,
            evaluacion,
            minimo,
        } => DecisionConControl {
            decision,
            nivel_en_instante: evaluacion.nivel_vigente,
            minimo_exigido: minimo,
            evaluacion,
            corpus_evaluado: false,
        },
        ResultadoPuertaControl::Continuar(evaluacion) => {
            let decision = decidir(contexto, perfil);
            DecisionConControl {
                decision,
                nivel_en_instante: evaluacion.nivel_vigente,
                minimo_exigido: minimo_exigido(clase, datos_personales),
                evaluacion,
                corpus_evaluado: true,
            }
        }
    }
}

/// Igual que [`decidir_con_libro`] sobre paquete G.1.
pub fn decidir_paquete_con_libro(
    contexto: &Contexto,
    paquete: &PaqueteNormativo,
    libro: &LibroControl,
    sistema: &IdSistema,
    datos_personales: bool,
    ahora: Ticks,
) -> DecisionConControl {
    let clase = contexto.efecto().clase();
    let hash = *paquete.hash();
    match comprobar_puerta_control(
        libro,
        sistema,
        clase,
        datos_personales,
        ahora,
        hash,
    ) {
        ResultadoPuertaControl::Denegar {
            decision,
            evaluacion,
            minimo,
        } => DecisionConControl {
            decision,
            nivel_en_instante: evaluacion.nivel_vigente,
            minimo_exigido: minimo,
            evaluacion,
            corpus_evaluado: false,
        },
        ResultadoPuertaControl::Continuar(evaluacion) => {
            let decision = decidir_paquete(contexto, paquete);
            DecisionConControl {
                decision,
                nivel_en_instante: evaluacion.nivel_vigente,
                minimo_exigido: minimo_exigido(clase, datos_personales),
                evaluacion,
                corpus_evaluado: true,
            }
        }
    }
}
