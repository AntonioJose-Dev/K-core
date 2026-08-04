//! Algoritmo D.3: nivel base + degradación transitiva EF-9 / ALCANZABLES.
//!
//! Un resultado `NivelControl::C5` en este módulo es **solo**
//! `C5_CALCULADO_SOBRE_HECHOS_APORTADOS`. Queda prohibido inferir o declarar
//! `C5_HOST_REAL` (host / TCB / plataforma / atestación real / red /
//! completitud de inventario permanecen `no_comprobado` / [DESP] / [VAL-EXT]).

use crate::contexto::ClaseEfecto;
use crate::identidad::IdSistema;
use crate::libro::hecho::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use crate::libro::nivel::NivelControl;
use crate::reloj::Ticks;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluacionNivel {
    pub nivel_base: NivelControl,
    pub nivel_vigente: NivelControl,
    pub hechos_efectivos: Vec<TipoHecho>,
    pub hechos_caducados: Vec<TipoHecho>,
    pub bypass_residual: &'static str,
    pub causa_degradacion: Option<String>,
    pub techo_manual: Option<NivelControl>,
}

/// Vista de hechos para un par (s,e) en un instante.
#[derive(Debug, Clone, Copy, Default)]
pub struct VistaHechos {
    pub custodia: bool,
    pub exclusividad: bool,
    pub pep_atestado: bool,
    pub sonda_ok: bool,
    pub delegado: bool,
    pub confinado: bool,
    pub observable: bool,
    pub ef9_abierto: bool,
}

/// Matriz D.3 — primera regla que se satisface fija el nivel base.
///
/// C2 = `CUSTODIA ∧ ¬(EXCLUSIVIDAD ∧ SONDA_OK)` (literal D.3; no C3 incompleto).
/// Si el resultado es C5, la denominación normativa de prueba/auditoría es
/// [`denominacion_si_c5_calculado`] → `C5_CALCULADO_SOBRE_HECHOS_APORTADOS`.
pub fn calcular_nivel_base(v: VistaHechos) -> NivelControl {
    if v.confinado
        && v.delegado
        && v.custodia
        && v.exclusividad
        && v.pep_atestado
        && v.sonda_ok
    {
        return NivelControl::C5;
    }
    if v.delegado && v.custodia && v.exclusividad && v.pep_atestado && v.sonda_ok {
        return NivelControl::C4;
    }
    if v.custodia && v.exclusividad && v.pep_atestado && v.sonda_ok {
        return NivelControl::C3;
    }
    if v.custodia && !(v.exclusividad && v.sonda_ok) {
        return NivelControl::C2;
    }
    if v.observable {
        return NivelControl::C1;
    }
    NivelControl::C0
}

/// Denominación explícita cuando el cálculo sobre hechos aportados produce C5.
/// Nunca retorna ni implica `C5_HOST_REAL`.
pub fn denominacion_si_c5_calculado(nivel: NivelControl) -> Option<&'static str> {
    nivel.denominacion_c5_calculado()
}

pub fn bypass_residual_de(nivel: NivelControl) -> &'static str {
    match nivel {
        NivelControl::C0 => "total y no acotado: sujeto posee artefacto o alcanza efector sin interposicion",
        NivelControl::C1 => "total en prevencion: el efecto ya ocurrio; Kernel no estaba en la ruta",
        NivelControl::C2 => "ruta directa concreta que el sujeto conserva (credencial, URL, herramienta)",
        NivelControl::C3 => "exfiltracion de credencial efimera durante su vida util",
        NivelControl::C4 => "abuso dentro de la autorizacion (parametros veraces indebidos en el fondo)",
        NivelControl::C5 => "correccion del runtime/anfitrion (TCB); no resistencia a host/firmware comprometidos",
    }
}

/// Degradación INV-11 / H-3 tras el cálculo base.
pub fn aplicar_degradacion_ef9(
    nivel_base: NivelControl,
    clase: ClaseEfecto,
    ef9_abierto: bool,
    inventario: Option<&InventarioAlcanzables>,
    ahora: Ticks,
) -> (NivelControl, Option<String>) {
    if !ef9_abierto {
        return (nivel_base, None);
    }
    match inventario {
        Some(inv) if inv.vigente(ahora) => {
            if inv.efectores.contains(&clase) {
                let n = nivel_base.min(NivelControl::C2);
                (
                    n,
                    Some(format!(
                        "EF9_ABIERTO y {} ∈ ALCANZABLES ⇒ min(nivel, C2)",
                        clase.token()
                    )),
                )
            } else {
                (nivel_base, None)
            }
        }
        // Inventario ausente, caducado, incompleto o no verificable + EF9 ⇒ todas ≤ C2.
        Some(inv) if inv.incompleto_declarado => (
            nivel_base.min(NivelControl::C2),
            Some(
                "EF9_ABIERTO con ALCANZABLES incompleto_declarado ⇒ cierre conservador ≤ C2"
                    .into(),
            ),
        ),
        Some(inv) if !inv.no_caducado(ahora) => (
            nivel_base.min(NivelControl::C2),
            Some(
                "EF9_ABIERTO con ALCANZABLES caducado ⇒ cierre conservador ≤ C2".into(),
            ),
        ),
        _ => (
            nivel_base.min(NivelControl::C2),
            Some(
                "EF9_ABIERTO con ALCANZABLES ausente/caducado ⇒ cierre conservador ≤ C2"
                    .into(),
            ),
        ),
    }
}

pub fn vista_desde_hechos(
    hechos: &[HechoFirmadoLibro],
    sistema: &IdSistema,
    clase: ClaseEfecto,
    ahora: Ticks,
) -> (VistaHechos, Vec<TipoHecho>, Vec<TipoHecho>) {
    let mut v = VistaHechos::default();
    let mut efectivos = Vec::new();
    let mut caducados = Vec::new();

    for h in hechos {
        if !h.integridad_ok() {
            continue;
        }
        if h.sistema != *sistema {
            continue;
        }
        let aplica = match h.tipo {
            TipoHecho::Confinado | TipoHecho::Ef9Abierto => h.clase.is_none(),
            _ => h.clase == Some(clase),
        };
        if !aplica {
            continue;
        }
        if !h.vigente(ahora) {
            caducados.push(h.tipo);
            continue;
        }
        if !h.valor {
            continue;
        }
        efectivos.push(h.tipo);
        match h.tipo {
            TipoHecho::Custodia => v.custodia = true,
            TipoHecho::Exclusividad => v.exclusividad = true,
            TipoHecho::PepAtestado => v.pep_atestado = true,
            TipoHecho::SondaOk => v.sonda_ok = true,
            TipoHecho::Delegado => v.delegado = true,
            TipoHecho::Confinado => v.confinado = true,
            TipoHecho::Observable => v.observable = true,
            TipoHecho::Ef9Abierto => v.ef9_abierto = true,
            TipoHecho::Alcanzables => {}
        }
    }
    (v, efectivos, caducados)
}

/// Ninguna asignación CONFINADO ∧ ¬(CUSTODIA ∧ EXCLUSIVIDAD) produce C5 (H-2).
pub fn confinado_sin_custodia_exclusividad_no_es_c5(v: VistaHechos) -> bool {
    if v.confinado && !(v.custodia && v.exclusividad) {
        calcular_nivel_base(v) != NivelControl::C5
    } else {
        true
    }
}
