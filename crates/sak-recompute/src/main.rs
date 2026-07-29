//! Recomputación bit a bit del conjunto de conformidad del Bloque 1.
//!
//! Criterio de aceptación (Matriz M, fila 1): un proceso independiente
//! recompute un conjunto de decisiones y el resultado es idéntico byte a byte.

use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::decision::{
    CodigoRazon, Decision, HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE,
};
use sak_core::motor::decidir;
use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
use sak_core::presupuesto::PASOS_POR_NORMA;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

/// Serialización canónica de una decisión (sin dependencias externas).
/// Formato estable, little-endian, sin reloj ni aleatoriedad.
fn codificar_decision(d: &Decision) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(1u8); // versión del esquema de conformidad
    out.push(match d.veredicto() {
        Veredicto::Deny => 0,
        Veredicto::Suspend => 1,
        Veredicto::Escalate => 2,
        Veredicto::Allow => 3,
    });
    out.push(match d.codigo() {
        None => 255,
        Some(CodigoRazon::SinNormaAplicable) => 0,
        Some(CodigoRazon::PrecedenciaAplicada) => 1,
        Some(CodigoRazon::ConflictoJurisdiccion) => 2,
        Some(CodigoRazon::EvidenciaAusente) => 3,
        Some(CodigoRazon::NormaNoEvaluable) => 4,
        Some(CodigoRazon::AmbiguedadDeclarada) => 5,
        Some(CodigoRazon::FueraDeAlcanceTecnico) => 6,
        Some(CodigoRazon::ControlInsuficiente) => 7,
        Some(CodigoRazon::PerfilObsoleto) => 8,
        Some(CodigoRazon::QuorumSupervision) => 9,
    });
    out.extend_from_slice(&d.traza().pasos_consumidos().to_le_bytes());
    out.extend_from_slice(d.hash_paquete().bytes());
    let aplicadas = d.normas_citadas();
    out.extend_from_slice(&(aplicadas.len() as u32).to_le_bytes());
    for id in aplicadas {
        let b = id.como_str().as_bytes();
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
    }
    let inertes = d.traza().inertes();
    out.extend_from_slice(&(inertes.len() as u32).to_le_bytes());
    for n in inertes {
        let b = n.id().como_str().as_bytes();
        out.extend_from_slice(&(b.len() as u16).to_le_bytes());
        out.extend_from_slice(b);
        out.push(n.motivo() as u8);
    }
    out
}

struct Caso {
    id: &'static str,
    contexto: Contexto,
    perfil: PerfilNormativo,
}

fn casos() -> Vec<Caso> {
    let h = |x: u8| HashPaqueteNormativo::desde_bytes([x; LONGITUD_HASH_PAQUETE]);
    let dig = |x: u8| [x; LONGITUD_HASH_PAQUETE];

    vec![
        Caso {
            id: "01_sin_norma",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef1, dig(1)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(h(10), vec![], false),
        },
        Caso {
            id: "02_allow_constante",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef1, dig(2)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(
                h(20),
                vec![NormaMinima::nueva(
                    IdNorma::nueva("N-ALLOW").unwrap(),
                    Rango::P2,
                    ClaseEfecto::Ef1,
                    PredicadoMinimo::Constante(Veredicto::Allow),
                    false,
                )],
                false,
            ),
        },
        Caso {
            id: "03_deny_constante",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef5, dig(3)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(
                h(30),
                vec![NormaMinima::nueva(
                    IdNorma::nueva("N-DENY").unwrap(),
                    Rango::P0,
                    ClaseEfecto::Ef5,
                    PredicadoMinimo::Constante(Veredicto::Deny),
                    false,
                )],
                false,
            ),
        },
        Caso {
            id: "04_presupuesto_agotado",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef2, dig(4)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(
                h(40),
                vec![NormaMinima::nueva(
                    IdNorma::nueva("N-HEAVY").unwrap(),
                    Rango::P1,
                    ClaseEfecto::Ef2,
                    PredicadoMinimo::ConsumirPasos {
                        pasos: PASOS_POR_NORMA + 1,
                        veredicto: Veredicto::Allow,
                    },
                    false,
                )],
                false,
            ),
        },
        Caso {
            id: "05_ambigua_escala",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef6, dig(5)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(
                h(50),
                vec![NormaMinima::nueva(
                    IdNorma::nueva("N-AMB").unwrap(),
                    Rango::P3,
                    ClaseEfecto::Ef6,
                    PredicadoMinimo::Constante(Veredicto::Allow),
                    true,
                )],
                false,
            ),
        },
        Caso {
            id: "06_infimo_deny_gana",
            contexto: Contexto::nuevo(
                EfectoTipado::nuevo(ClaseEfecto::Ef3, dig(6)),
                vec![],
            ),
            perfil: PerfilNormativo::nuevo(
                h(60),
                vec![
                    NormaMinima::nueva(
                        IdNorma::nueva("N-A").unwrap(),
                        Rango::P2,
                        ClaseEfecto::Ef3,
                        PredicadoMinimo::Constante(Veredicto::Allow),
                        false,
                    ),
                    NormaMinima::nueva(
                        IdNorma::nueva("N-D").unwrap(),
                        Rango::P0,
                        ClaseEfecto::Ef3,
                        PredicadoMinimo::Constante(Veredicto::Deny),
                        false,
                    ),
                ],
                false,
            ),
        },
    ]
}

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("bloque1")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run_recompute(dir: &Path) -> i32 {
    let mut ok = true;
    for caso in casos() {
        let d1 = decidir(&caso.contexto, &caso.perfil);
        let d2 = decidir(&caso.contexto, &caso.perfil);
        let b1 = codificar_decision(&d1);
        let b2 = codificar_decision(&d2);
        if b1 != b2 {
            eprintln!("{}: fallo de pureza intramproceso", caso.id);
            ok = false;
            continue;
        }
        let expected_path = dir.join(format!("{}.expected.hex", caso.id));
        let actual_hex = hex_encode(&b1);
        if !expected_path.exists() {
            eprintln!(
                "{}: falta {}. Ejecute con --write-expected",
                caso.id,
                expected_path.display()
            );
            ok = false;
            continue;
        }
        let expected_hex = fs::read_to_string(&expected_path)
            .unwrap_or_default()
            .trim()
            .to_string();
        if expected_hex != actual_hex {
            eprintln!("{}: divergencia bit a bit", caso.id);
            eprintln!("  esperado: {expected_hex}");
            eprintln!("  actual:   {actual_hex}");
            ok = false;
        } else {
            println!("{}: OK ({} bytes)", caso.id, b1.len());
        }
    }
    if ok {
        println!("sak-recompute: todas las decisiones coinciden bit a bit");
        0
    } else {
        1
    }
}

fn write_expected(dir: &Path) -> i32 {
    fs::create_dir_all(dir).expect("crear conformance/bloque1");
    for caso in casos() {
        let d = decidir(&caso.contexto, &caso.perfil);
        let bytes = codificar_decision(&d);
        let path = dir.join(format!("{}.expected.hex", caso.id));
        fs::write(&path, hex_encode(&bytes) + "\n").expect("escribir expected");
        println!("escrito {}", path.display());
    }
    0
}

fn main() {
    let dir = conformance_dir();
    let args: Vec<String> = env::args().collect();
    let code = if args.iter().any(|a| a == "--write-expected") {
        write_expected(&dir)
    } else {
        run_recompute(&dir)
    };
    process::exit(code);
}
