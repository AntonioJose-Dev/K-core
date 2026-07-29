//! Precedencia determinista R1–R8 (Matriz G.2).
//!
//! Ninguna anomalía termina en ALLOW. Cierre conservador.

use crate::contexto::Contexto;
use crate::decision::{
    CodigoRazon, Decision, DecisionDenegada, DecisionEscalada, DecisionPermitida,
    DecisionSuspendida, IdNorma, MotivoInercia, NormaInerte, TrazaPrecedencia, Veredicto,
};
use crate::norma::{Norma, Operacionalidad, PaqueteNormativo};
use crate::predicado::{self, ErrorPredicado};
use crate::presupuesto::Presupuesto;
use std::collections::BTreeMap;

/// Evalúa el efecto del contexto contra un paquete normativo completo (Bloque 2).
pub fn decidir_paquete(contexto: &Contexto, paquete: &PaqueteNormativo) -> Decision {
    let hash = *paquete.hash();
    let clase = contexto.efecto().clase();
    let mut presupuesto = Presupuesto::nuevo();
    let mut aplicadas: Vec<IdNorma> = Vec::new();
    let mut inertes: Vec<NormaInerte> = Vec::new();
    let mut codigo: Option<CodigoRazon> = None;

    let candidatas: Vec<&Norma> = paquete.aplicables_a(clase).collect();
    if candidatas.is_empty() {
        return denegar(
            hash,
            vec![],
            vec![],
            0,
            CodigoRazon::SinNormaAplicable,
        );
    }

    // Clasificar por vigencia (R4 / R5) respecto al instante inyectado.
    let instante = contexto.instante_epoch_dias();
    let mut vigentes: Vec<&Norma> = Vec::new();
    for n in &candidatas {
        let entrada = n.vigencia().entrada.a_epoch_dias();
        let termino = n.vigencia().termino.map(|t| t.a_epoch_dias());
        if instante < entrada {
            // R5: no vigente aún — sombra.
            presupuesto.comenzar_norma();
            let sombra = evaluar_norma_sombra(n, contexto, &mut presupuesto);
            inertes.push(match sombra {
                Ok(v) => NormaInerte::con_sombra(n.id().clone(), v),
                Err(_) => NormaInerte::nueva(n.id().clone(), MotivoInercia::R5FuenteNoVigenteAun),
            });
            continue;
        }
        if let Some(fin) = termino {
            if instante > fin {
                // R4: vencida.
                inertes.push(NormaInerte::nueva(
                    n.id().clone(),
                    MotivoInercia::R4FuenteVencida,
                ));
                continue;
            }
        }
        vigentes.push(n);
    }

    if vigentes.is_empty() {
        return denegar(
            hash,
            aplicadas,
            inertes,
            presupuesto.consumidos(),
            CodigoRazon::SinNormaAplicable,
        );
    }

    // R3: conflicto mismo rango, jurisdicciones distintas, veredictos incompatibles.
    // Usa presupuesto de sonda aislado para no alterar el contador de la decisión.
    if let Some(decision_r3) = {
        let mut sonda = Presupuesto::nuevo();
        detectar_conflicto_jurisdiccion(
            &vigentes,
            contexto,
            &mut sonda,
            hash,
            &aplicadas,
            &inertes,
        )
    } {
        return decision_r3;
    }

    // Evaluar vigentes en orden de rango (P0 primero = más restrictivo).
    let mut vigentes_ordenadas = vigentes;
    vigentes_ordenadas.sort_by_key(|n| n.rango());

    // Por cada rango, el veredicto más restrictivo de ese rango; luego R1 entre rangos.
    let mut veredicto_por_rango: BTreeMap<u8, (Veredicto, IdNorma, Option<CodigoRazon>)> =
        BTreeMap::new();

    for n in &vigentes_ordenadas {
        presupuesto.comenzar_norma();

        // R8
        if n.ambigua() {
            aplicadas.push(n.id().clone());
            insertar_rango(
                &mut veredicto_por_rango,
                n,
                Veredicto::Escalate,
                Some(CodigoRazon::AmbiguedadDeclarada),
            );
            codigo = Some(CodigoRazon::AmbiguedadDeclarada);
            continue;
        }

        // L4 como precondición (G.3)
        if n.operacionalidad() == Operacionalidad::L4 {
            aplicadas.push(n.id().clone());
            insertar_rango(
                &mut veredicto_por_rango,
                n,
                Veredicto::Deny,
                Some(CodigoRazon::FueraDeAlcanceTecnico),
            );
            codigo = Some(CodigoRazon::FueraDeAlcanceTecnico);
            continue;
        }

        // R7: evidencia exigida
        if let Some(r7) = comprobar_evidencia(n, contexto) {
            aplicadas.push(n.id().clone());
            insertar_rango(&mut veredicto_por_rango, n, r7.0, Some(r7.1));
            codigo = Some(r7.1);
            continue;
        }

        // Predicado (R6 si falla)
        match predicado::evaluar(n.predicado(), contexto, &mut presupuesto) {
            Err(ErrorPredicado::PresupuestoAgotado)
            | Err(ErrorPredicado::CampoAusente)
            | Err(ErrorPredicado::TipoIncompatible) => {
                aplicadas.push(n.id().clone());
                let traza = TrazaPrecedencia::nueva(
                    aplicadas,
                    inertes,
                    presupuesto.consumidos(),
                )
                .expect("traza");
                return Decision::Denegada(DecisionDenegada::nueva(
                    hash,
                    traza,
                    CodigoRazon::NormaNoEvaluable,
                ));
            }
            Ok(veredicto) => {
                aplicadas.push(n.id().clone());
                insertar_rango(&mut veredicto_por_rango, n, veredicto, None);
            }
        }
    }

    // R1 + R2: recorrer rangos de superior (P0) a inferior (P5).
    let mut acum: Option<Veredicto> = None;
    for (_rango, (veredicto, id, cod)) in veredicto_por_rango.iter() {
        if let Some(c) = cod {
            codigo = Some(*c);
        }
        match acum {
            None => acum = Some(*veredicto),
            Some(prev) => {
                // R1: rango inferior (ya ordenado BTreeMap P0..P5) solo restringe.
                // Si el nuevo ampliaría lo que el superior permite, queda inerte.
                if veredicto_amplia(prev, *veredicto) {
                    inertes.push(NormaInerte::nueva(
                        id.clone(),
                        MotivoInercia::R1RestriccionMonotona,
                    ));
                    // quitar de aplicadas si estaba
                    aplicadas.retain(|a| a != id);
                    codigo = Some(CodigoRazon::PrecedenciaAplicada);
                } else {
                    acum = Some(prev.infimo(*veredicto)); // R2
                }
            }
        }
    }

    let veredicto = acum.unwrap_or(Veredicto::Deny);
    emitir(hash, aplicadas, inertes, presupuesto.consumidos(), veredicto, codigo)
}

fn veredicto_amplia(superior: Veredicto, inferior: Veredicto) -> bool {
    // Ampliar = pasar a algo estrictamente menos restrictivo.
    (inferior as u8) > (superior as u8)
}

fn insertar_rango(
    map: &mut BTreeMap<u8, (Veredicto, IdNorma, Option<CodigoRazon>)>,
    n: &Norma,
    v: Veredicto,
    c: Option<CodigoRazon>,
) {
    let key = n.rango() as u8;
    match map.get(&key) {
        None => {
            map.insert(key, (v, n.id().clone(), c));
        }
        Some((prev, _, prev_c)) => {
            let inf = prev.infimo(v);
            let cod = c.or(*prev_c);
            map.insert(key, (inf, n.id().clone(), cod));
        }
    }
}

fn comprobar_evidencia(n: &Norma, ctx: &Contexto) -> Option<(Veredicto, CodigoRazon)> {
    for req in n.evidencia_exigida() {
        let ok = ctx.hechos().iter().any(|h| {
            h.productor() == &req.productor
                && !h.caducado()
                && h.antiguedad_segundos() <= req.antiguedad_maxima_segundos
        });
        if !ok {
            if n.escalado().is_some() {
                return Some((Veredicto::Escalate, CodigoRazon::EvidenciaAusente));
            }
            return Some((Veredicto::Deny, CodigoRazon::EvidenciaAusente));
        }
    }
    None
}

fn evaluar_norma_sombra(
    n: &Norma,
    ctx: &Contexto,
    presupuesto: &mut Presupuesto,
) -> Result<Veredicto, ErrorPredicado> {
    if n.ambigua() {
        return Ok(Veredicto::Escalate);
    }
    predicado::evaluar(n.predicado(), ctx, presupuesto)
}

fn detectar_conflicto_jurisdiccion(
    vigentes: &[&Norma],
    ctx: &Contexto,
    presupuesto: &mut Presupuesto,
    hash: crate::decision::HashPaqueteNormativo,
    aplicadas: &[IdNorma],
    inertes: &[NormaInerte],
) -> Option<Decision> {
    // Agrupar por rango.
    let mut por_rango: BTreeMap<u8, Vec<&Norma>> = BTreeMap::new();
    for n in vigentes {
        por_rango.entry(n.rango() as u8).or_default().push(n);
    }
    for (_r, grupo) in por_rango {
        if grupo.len() < 2 {
            continue;
        }
        // Evaluar veredictos tentativos; si jurisdicciones distintas e incompatibles → R3.
        let mut por_j: BTreeMap<String, Veredicto> = BTreeMap::new();
        for n in &grupo {
            presupuesto.comenzar_norma();
            let v = if n.ambigua() {
                Veredicto::Escalate
            } else {
                match predicado::evaluar(n.predicado(), ctx, presupuesto) {
                    Ok(v) => v,
                    Err(_) => Veredicto::Deny,
                }
            };
            let j = n.jurisdiccion().to_string();
            if let Some(prev) = por_j.get(&j) {
                por_j.insert(j, prev.infimo(v));
            } else {
                por_j.insert(j, v);
            }
        }
        if por_j.len() < 2 {
            continue;
        }
        let vals: Vec<Veredicto> = por_j.values().copied().collect();
        // Incompatibles: no todos iguales y el ínfimo no los unifica sin pérdida
        // de un ALLOW frente a DENY/ESCALATE de otra jurisdicción.
        let mut incompat = false;
        for i in 0..vals.len() {
            for j in (i + 1)..vals.len() {
                if vals[i] != vals[j] {
                    // Distinct jurisdictions with different verdicts.
                    incompat = true;
                }
            }
        }
        if incompat {
            let mut apps = aplicadas.to_vec();
            for n in grupo {
                apps.push(n.id().clone());
            }
            let traza =
                TrazaPrecedencia::nueva(apps, inertes.to_vec(), presupuesto.consumidos())
                    .ok()?;
            return Some(Decision::Escalada(DecisionEscalada::nueva(
                hash,
                traza,
                CodigoRazon::ConflictoJurisdiccion,
            )));
        }
    }
    None
}

fn denegar(
    hash: crate::decision::HashPaqueteNormativo,
    aplicadas: Vec<IdNorma>,
    inertes: Vec<NormaInerte>,
    pasos: u32,
    codigo: CodigoRazon,
) -> Decision {
    let traza = TrazaPrecedencia::nueva(aplicadas, inertes, pasos).expect("traza");
    Decision::Denegada(DecisionDenegada::nueva(hash, traza, codigo))
}

fn emitir(
    hash: crate::decision::HashPaqueteNormativo,
    aplicadas: Vec<IdNorma>,
    inertes: Vec<NormaInerte>,
    pasos: u32,
    veredicto: Veredicto,
    codigo: Option<CodigoRazon>,
) -> Decision {
    let traza = TrazaPrecedencia::nueva(aplicadas, inertes, pasos).expect("traza");
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
            let codigo_allow = match codigo {
                Some(CodigoRazon::PrecedenciaAplicada) => Some(CodigoRazon::PrecedenciaAplicada),
                Some(CodigoRazon::PerfilObsoleto) => Some(CodigoRazon::PerfilObsoleto),
                _ => None,
            };
            match DecisionPermitida::nueva(hash, traza, codigo_allow) {
                Ok(p) => Decision::Permitida(p),
                Err(_) => Decision::Denegada(DecisionDenegada::nueva(
                    hash,
                    TrazaPrecedencia::nueva(vec![], vec![], pasos).expect("traza"),
                    CodigoRazon::SinNormaAplicable,
                )),
            }
        }
    }
}
