//! Motor de decisión: función pura `decidir` (Bloque 1) y puente al paquete
//! normativo completo (Bloque 2).
//!
//! `decidir` conserva los vectores del Bloque 1 sobre `PerfilNormativo` mínimo.
//! `decidir_paquete` aplica R1–R8 sobre el objeto de norma G.1.

use crate::contexto::Contexto;
use crate::decision::{
    CodigoRazon, Decision, DecisionDenegada, DecisionEscalada, DecisionPermitida,
    DecisionSuspendida, ErrorDecision, IdNorma, MotivoInercia, NormaInerte, TrazaPrecedencia,
    Veredicto,
};
use crate::norma::PaqueteNormativo;
use crate::perfil::{PerfilNormativo, PredicadoMinimo};
use crate::presupuesto::Presupuesto;

pub use crate::precedencia::decidir_paquete;

/// Evalúa el efecto del contexto contra el perfil normativo mínimo (Bloque 1).
///
/// Función pura: no consulta reloj, entropía, red ni disco.
pub fn decidir(contexto: &Contexto, perfil: &PerfilNormativo) -> Decision {
    let hash = *perfil.hash_paquete();
    let clase = contexto.efecto().clase();
    let mut presupuesto = Presupuesto::nuevo();
    let mut aplicadas: Vec<IdNorma> = Vec::new();
    let mut inertes: Vec<NormaInerte> = Vec::new();
    let mut veredicto_acumulado: Option<Veredicto> = None;
    let mut codigo: Option<CodigoRazon> = None;

    let aplicables: Vec<_> = perfil.aplicables_a(clase).collect();

    if aplicables.is_empty() {
        let traza = TrazaPrecedencia::nueva(vec![], vec![], presupuesto.consumidos())
            .expect("traza vacia valida");
        return Decision::Denegada(DecisionDenegada::nueva(
            hash,
            traza,
            CodigoRazon::SinNormaAplicable,
        ));
    }

    for norma in aplicables {
        presupuesto.comenzar_norma();

        if norma.ambigua() {
            aplicadas.push(norma.id().clone());
            veredicto_acumulado = Some(match veredicto_acumulado {
                Some(v) => v.infimo(Veredicto::Escalate),
                None => Veredicto::Escalate,
            });
            codigo = Some(CodigoRazon::AmbiguedadDeclarada);
            continue;
        }

        let resultado = evaluar_predicado(norma.predicado(), &mut presupuesto);
        match resultado {
            Err(()) => {
                aplicadas.push(norma.id().clone());
                let traza =
                    TrazaPrecedencia::nueva(aplicadas, inertes, presupuesto.consumidos())
                        .unwrap_or_else(traza_de_emergencia);
                return Decision::Denegada(DecisionDenegada::nueva(
                    hash,
                    traza,
                    CodigoRazon::NormaNoEvaluable,
                ));
            }
            Ok(veredicto) => {
                if let Some(acum) = veredicto_acumulado {
                    if veredicto > acum
                        && matches!(veredicto, Veredicto::Allow)
                        && !matches!(acum, Veredicto::Allow)
                    {
                        inertes.push(NormaInerte::nueva(
                            norma.id().clone(),
                            MotivoInercia::R1RestriccionMonotona,
                        ));
                        codigo = Some(CodigoRazon::PrecedenciaAplicada);
                        continue;
                    }
                    veredicto_acumulado = Some(acum.infimo(veredicto));
                } else {
                    veredicto_acumulado = Some(veredicto);
                }
                aplicadas.push(norma.id().clone());
            }
        }
    }

    let veredicto = veredicto_acumulado.unwrap_or(Veredicto::Deny);
    let traza = TrazaPrecedencia::nueva(aplicadas, inertes, presupuesto.consumidos())
        .unwrap_or_else(traza_de_emergencia);

    match veredicto {
        Veredicto::Deny => Decision::Denegada(DecisionDenegada::nueva(
            hash,
            traza,
            codigo.unwrap_or(CodigoRazon::SinNormaAplicable),
        )),
        Veredicto::Suspend => Decision::Suspendida(DecisionSuspendida::nueva(
            hash,
            traza,
            codigo.unwrap_or(CodigoRazon::ControlInsuficiente),
        )),
        Veredicto::Escalate => Decision::Escalada(DecisionEscalada::nueva(
            hash,
            traza,
            codigo.unwrap_or(CodigoRazon::AmbiguedadDeclarada),
        )),
        Veredicto::Allow => {
            let codigo_allow = if perfil.obsoleto() {
                Some(CodigoRazon::PerfilObsoleto)
            } else if codigo == Some(CodigoRazon::PrecedenciaAplicada) {
                Some(CodigoRazon::PrecedenciaAplicada)
            } else {
                None
            };
            match DecisionPermitida::nueva(hash, traza, codigo_allow) {
                Ok(p) => Decision::Permitida(p),
                Err(ErrorDecision::PermisoSinNormaCitada) => {
                    let traza_vacia =
                        TrazaPrecedencia::nueva(vec![], vec![], presupuesto.consumidos())
                            .expect("traza vacia");
                    Decision::Denegada(DecisionDenegada::nueva(
                        hash,
                        traza_vacia,
                        CodigoRazon::SinNormaAplicable,
                    ))
                }
                Err(_) => {
                    let traza_vacia =
                        TrazaPrecedencia::nueva(vec![], vec![], presupuesto.consumidos())
                            .expect("traza vacia");
                    Decision::Denegada(DecisionDenegada::nueva(
                        hash,
                        traza_vacia,
                        CodigoRazon::NormaNoEvaluable,
                    ))
                }
            }
        }
    }
}

/// Atajo: decidir sobre un paquete G.1 completo (Bloque 2).
pub fn decidir_sobre_paquete(contexto: &Contexto, paquete: &PaqueteNormativo) -> Decision {
    decidir_paquete(contexto, paquete)
}

fn evaluar_predicado(
    predicado: &PredicadoMinimo,
    presupuesto: &mut Presupuesto,
) -> Result<Veredicto, ()> {
    match predicado {
        PredicadoMinimo::Constante(v) => {
            presupuesto.consumir(1)?;
            Ok(*v)
        }
        PredicadoMinimo::ConsumirPasos { pasos, veredicto } => {
            presupuesto.consumir(*pasos)?;
            Ok(*veredicto)
        }
    }
}

fn traza_de_emergencia(_: ErrorDecision) -> TrazaPrecedencia {
    TrazaPrecedencia::nueva(vec![], vec![], 0).expect("traza vacia valida")
}

/// Harness `pureza_de_decision` (sección K): mismas entradas ⇒ misma salida.
///
/// ```
/// use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
/// use sak_core::decision::{HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE};
/// use sak_core::motor::decidir;
/// use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
///
/// let hash = HashPaqueteNormativo::desde_bytes([7u8; LONGITUD_HASH_PAQUETE]);
/// let efecto = EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]);
/// let ctx = Contexto::nuevo(efecto, vec![]);
/// let norma = NormaMinima::nueva(
///     IdNorma::nueva("N-ALLOW").unwrap(),
///     Rango::P2,
///     ClaseEfecto::Ef1,
///     PredicadoMinimo::Constante(Veredicto::Allow),
///     false,
/// );
/// let perfil = PerfilNormativo::nuevo(hash, vec![norma], false);
///
/// let a = decidir(&ctx, &perfil);
/// let b = decidir(&ctx, &perfil);
/// assert_eq!(a, b);
/// assert!(matches!(a, sak_core::decision::Decision::Permitida(_)));
/// ```
///
/// Cierre conservador: sin norma aplicable ⇒ `DENY(SIN_NORMA_APLICABLE)`.
///
/// ```
/// use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
/// use sak_core::decision::{CodigoRazon, Decision, HashPaqueteNormativo, LONGITUD_HASH_PAQUETE};
/// use sak_core::motor::decidir;
/// use sak_core::perfil::PerfilNormativo;
///
/// let hash = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
/// let efecto = EfectoTipado::nuevo(ClaseEfecto::Ef3, [2u8; LONGITUD_HASH_PAQUETE]);
/// let ctx = Contexto::nuevo(efecto, vec![]);
/// let perfil = PerfilNormativo::nuevo(hash, vec![], false);
///
/// let d = decidir(&ctx, &perfil);
/// match d {
///     Decision::Denegada(den) => assert_eq!(den.codigo(), CodigoRazon::SinNormaAplicable),
///     _ => panic!("se esperaba DENY"),
/// }
/// ```
///
/// Presupuesto agotado ⇒ `DENY(NORMA_NO_EVALUABLE)`, siempre en el mismo paso.
///
/// ```
/// use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
/// use sak_core::decision::{
///     CodigoRazon, Decision, HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE,
/// };
/// use sak_core::motor::decidir;
/// use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
/// use sak_core::presupuesto::PASOS_POR_NORMA;
///
/// let hash = HashPaqueteNormativo::desde_bytes([3u8; LONGITUD_HASH_PAQUETE]);
/// let efecto = EfectoTipado::nuevo(ClaseEfecto::Ef1, [3u8; LONGITUD_HASH_PAQUETE]);
/// let ctx = Contexto::nuevo(efecto, vec![]);
/// let norma = NormaMinima::nueva(
///     IdNorma::nueva("N-HEAVY").unwrap(),
///     Rango::P0,
///     ClaseEfecto::Ef1,
///     PredicadoMinimo::ConsumirPasos {
///         pasos: PASOS_POR_NORMA + 1,
///         veredicto: Veredicto::Allow,
///     },
///     false,
/// );
/// let perfil = PerfilNormativo::nuevo(hash, vec![norma], false);
///
/// let a = decidir(&ctx, &perfil);
/// let b = decidir(&ctx, &perfil);
/// assert_eq!(a, b);
/// match a {
///     Decision::Denegada(den) => {
///         assert_eq!(den.codigo(), CodigoRazon::NormaNoEvaluable);
///         assert_eq!(den.traza().pasos_consumidos(), 0);
///     }
///     _ => panic!("se esperaba DENY por presupuesto"),
/// }
/// ```
#[allow(dead_code)]
fn _doc_harness_pureza() {}
