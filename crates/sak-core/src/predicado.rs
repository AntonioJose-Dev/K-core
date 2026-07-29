//! Lenguaje de predicados total y terminante (G.1 / L-36).
//!
//! Sin bucles, sin recursión del evaluador sobre sí mismo vía pila de llamadas
//! acotada por la profundidad del árbol, con presupuesto de pasos. No es
//! Turing-completo.

use crate::contexto::{ClaseEfecto, Contexto, IdProductor};
use crate::decision::Veredicto;
use crate::presupuesto::Presupuesto;
use std::fmt;

/// Campo tipado del contexto sobre el que puede predicarse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CampoContexto {
    ClaseEfecto = 1,
}

/// Valor comparable en un predicado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Valor {
    Clase(ClaseEfecto),
    Entero(u64),
}

/// Expresión evaluable. Toda variante termina; el evaluador cuenta pasos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Predicado {
    /// Veredicto literal (un paso).
    Fijo(Veredicto),
    /// Igualdad de un campo del contexto con un valor.
    Eq(CampoContexto, Valor),
    /// Existe un hecho no caducado del productor indicado.
    HechoVigente(IdProductor),
    /// Conjunción: todos deben ser verdaderos. Cortocircuito determinista.
    Y(Vec<Predicado>),
    /// Disyunción: el primero verdadero decide. Cortocircuito determinista.
    O(Vec<Predicado>),
    /// Negación booleana; no aplica a `Fijo(veredicto)` distinto de Allow/Deny.
    No(Box<Predicado>),
    /// Condicional total: si cond entonces a si no b.
    Si {
        cond: Box<Predicado>,
        entonces: Box<Predicado>,
        si_no: Box<Predicado>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorPredicado {
    PresupuestoAgotado,
    CampoAusente,
    TipoIncompatible,
}

impl fmt::Display for ErrorPredicado {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorPredicado::PresupuestoAgotado => f.write_str("presupuesto de pasos agotado"),
            ErrorPredicado::CampoAusente => f.write_str("campo de contexto ausente"),
            ErrorPredicado::TipoIncompatible => f.write_str("error de tipo en predicado"),
        }
    }
}

impl std::error::Error for ErrorPredicado {}

/// Evalúa a un veredicto. Los predicados booleanos se interpretan como
/// `Allow` (verdadero) o `Deny` (falso) cuando se usan como resultado final.
pub fn evaluar(
    pred: &Predicado,
    ctx: &Contexto,
    presupuesto: &mut Presupuesto,
) -> Result<Veredicto, ErrorPredicado> {
    match eval_bool_o_veredicto(pred, ctx, presupuesto)? {
        Salida::Veredicto(v) => Ok(v),
        Salida::Bool(true) => Ok(Veredicto::Allow),
        Salida::Bool(false) => Ok(Veredicto::Deny),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Salida {
    Bool(bool),
    Veredicto(Veredicto),
}

fn step(presupuesto: &mut Presupuesto) -> Result<(), ErrorPredicado> {
    presupuesto
        .consumir(1)
        .map_err(|_| ErrorPredicado::PresupuestoAgotado)
}

fn eval_bool_o_veredicto(
    pred: &Predicado,
    ctx: &Contexto,
    presupuesto: &mut Presupuesto,
) -> Result<Salida, ErrorPredicado> {
    step(presupuesto)?;
    match pred {
        Predicado::Fijo(v) => Ok(Salida::Veredicto(*v)),
        Predicado::Eq(campo, valor) => {
            let ok = match (campo, valor) {
                (CampoContexto::ClaseEfecto, Valor::Clase(c)) => ctx.efecto().clase() == *c,
                (CampoContexto::ClaseEfecto, _) => {
                    return Err(ErrorPredicado::TipoIncompatible);
                }
            };
            Ok(Salida::Bool(ok))
        }
        Predicado::HechoVigente(prod) => {
            let ok = ctx.hechos().iter().any(|h| {
                h.productor() == prod && !h.caducado()
            });
            Ok(Salida::Bool(ok))
        }
        Predicado::Y(xs) => {
            for x in xs {
                match eval_bool_o_veredicto(x, ctx, presupuesto)? {
                    Salida::Bool(false) => return Ok(Salida::Bool(false)),
                    Salida::Veredicto(Veredicto::Deny) => return Ok(Salida::Bool(false)),
                    Salida::Bool(true) | Salida::Veredicto(Veredicto::Allow) => {}
                    Salida::Veredicto(v) => return Ok(Salida::Veredicto(v)),
                }
            }
            Ok(Salida::Bool(true))
        }
        Predicado::O(xs) => {
            for x in xs {
                match eval_bool_o_veredicto(x, ctx, presupuesto)? {
                    Salida::Bool(true) => return Ok(Salida::Bool(true)),
                    Salida::Veredicto(Veredicto::Allow) => return Ok(Salida::Bool(true)),
                    Salida::Bool(false) | Salida::Veredicto(Veredicto::Deny) => {}
                    Salida::Veredicto(v) => return Ok(Salida::Veredicto(v)),
                }
            }
            Ok(Salida::Bool(false))
        }
        Predicado::No(x) => match eval_bool_o_veredicto(x, ctx, presupuesto)? {
            Salida::Bool(b) => Ok(Salida::Bool(!b)),
            Salida::Veredicto(Veredicto::Allow) => Ok(Salida::Bool(false)),
            Salida::Veredicto(Veredicto::Deny) => Ok(Salida::Bool(true)),
            Salida::Veredicto(_) => Err(ErrorPredicado::TipoIncompatible),
        },
        Predicado::Si {
            cond,
            entonces,
            si_no,
        } => {
            let c = match eval_bool_o_veredicto(cond, ctx, presupuesto)? {
                Salida::Bool(b) => b,
                Salida::Veredicto(Veredicto::Allow) => true,
                Salida::Veredicto(Veredicto::Deny) => false,
                Salida::Veredicto(_) => return Err(ErrorPredicado::TipoIncompatible),
            };
            if c {
                eval_bool_o_veredicto(entonces, ctx, presupuesto)
            } else {
                eval_bool_o_veredicto(si_no, ctx, presupuesto)
            }
        }
    }
}

/// Serialización canónica del predicado (para el hash de la norma).
pub fn serializar_canonico(pred: &Predicado, out: &mut Vec<u8>) {
    match pred {
        Predicado::Fijo(v) => {
            out.push(1);
            out.push(*v as u8);
        }
        Predicado::Eq(c, val) => {
            out.push(2);
            out.push(*c as u8);
            serializar_valor(val, out);
        }
        Predicado::HechoVigente(p) => {
            out.push(3);
            escribir_str(out, p.como_str());
        }
        Predicado::Y(xs) => {
            out.push(4);
            out.extend_from_slice(&(xs.len() as u32).to_le_bytes());
            for x in xs {
                serializar_canonico(x, out);
            }
        }
        Predicado::O(xs) => {
            out.push(5);
            out.extend_from_slice(&(xs.len() as u32).to_le_bytes());
            for x in xs {
                serializar_canonico(x, out);
            }
        }
        Predicado::No(x) => {
            out.push(6);
            serializar_canonico(x, out);
        }
        Predicado::Si {
            cond,
            entonces,
            si_no,
        } => {
            out.push(7);
            serializar_canonico(cond, out);
            serializar_canonico(entonces, out);
            serializar_canonico(si_no, out);
        }
    }
}

fn serializar_valor(v: &Valor, out: &mut Vec<u8>) {
    match v {
        Valor::Clase(c) => {
            out.push(1);
            out.push(*c as u8);
        }
        Valor::Entero(n) => {
            out.push(2);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

fn escribir_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}
