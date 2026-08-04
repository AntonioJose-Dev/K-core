//! Test INV-14: serialización determinista de normas.
//!
//  Dos serializaciones del mismo input deben producir exactamente el mismo output,
//  repetidamente, sin depender de reloj, red ni estado externo.

use sak_core::contexto::IdProductor;
use sak_core::norma::{
    Alcance, BorradorNorma, Escalado, Fecha, Interpretacion, Monitorizacion, MateriaReservada,
    Norma, Operacionalidad, RequisitoEvidencia, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;

fn borrador_completo() -> BorradorNorma {
    BorradorNorma {
        identificador: "norma-test-inv14-001".into(),
        fuente: "https://example.com/norma/test".into(),
        jurisdiccion: "TestJurisdiction".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2025, 1, 15).unwrap(),
            termino: Some(Fecha::nueva(2030, 12, 31).unwrap()),
        },
        alcance: Alcance {
            caso_de_uso: "test-caso-uso".into(),
            clase_riesgo: "test-clase-riesgo".into(),
            rol_regulatorio: "test-rol".into(),
            sector: "test-sector".into(),
            categorias_datos: "test-cats".into(),
            autonomia: "test-autonomia".into(),
            destinatarios: "test-dest".into(),
        },
        naturaleza: sak_core::norma::Naturaleza::Obligacion,
        operacionalidad: Operacionalidad::L2,
        clase_de_efecto: sak_core::contexto::ClaseEfecto::Ef1,
        predicado: Predicado::Fijo(sak_core::decision::Veredicto::Allow),
        evidencia_exigida: vec![
            RequisitoEvidencia {
                productor: IdProductor::nuevo("prod-a").unwrap(),
                antiguedad_maxima_segundos: 86400,
            },
            RequisitoEvidencia {
                productor: IdProductor::nuevo("prod-b").unwrap(),
                antiguedad_maxima_segundos: 172800,
            },
        ],
        acciones_obligatorias: vec!["accion-1".into(), "accion-2".into()],
        condiciones_de_denegacion: vec!["cond-deneg-1".into()],
        escalado: Some(Escalado {
            rol: "escalonador".into(),
            competencia: "test-comp".into(),
            quorum: 3,
            plazo_segundos: 604800,
            exige_independencia: true,
        }),
        monitorizacion: Some(Monitorizacion {
            que: "test-monitor".into(),
            periodo_segundos: 3600,
            umbral: "test-umbral".into(),
        }),
        interpretacion: Interpretacion {
            texto: "Interpretación de prueba para INV-14".into(),
            autor: "test-author".into(),
            digest_aprobacion: [0xAB; 48],
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![MateriaReservada::ClasificacionOperacionalidad],
    }
}

fn borrador_simple() -> BorradorNorma {
    BorradorNorma {
        identificador: "norma-simple".into(),
        fuente: "fuente-simple".into(),
        jurisdiccion: "jur-simple".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2024, 6, 1).unwrap(),
            termino: None,
        },
        alcance: Alcance {
            caso_de_uso: "caso".into(),
            clase_riesgo: "riesgo".into(),
            rol_regulatorio: "rol".into(),
            sector: "sector".into(),
            categorias_datos: "cats".into(),
            autonomia: "auto".into(),
            destinatarios: "dest".into(),
        },
        naturaleza: sak_core::norma::Naturaleza::Prohibicion,
        operacionalidad: Operacionalidad::L1,
        clase_de_efecto: sak_core::contexto::ClaseEfecto::Ef3,
        predicado: Predicado::Fijo(sak_core::decision::Veredicto::Deny),
        evidencia_exigida: vec![],
        acciones_obligatorias: vec![],
        condiciones_de_denegacion: vec![],
        escalado: None,
        monitorizacion: None,
        interpretacion: Interpretacion {
            texto: "Texto simple".into(),
            autor: "autor-simple".into(),
            digest_aprobacion: [0x00; 48],
        },
        ambigua: true,
        rango: Rango::P0,
        pretende_resolver: vec![],
    }
}

#[test]
fn inv14_determinismo_serializacion_completa() {
    let norma = Norma::cargar(borrador_completo()).unwrap();
    let ref_bytes = norma.serializar_texto_canonico();

    for i in 0..100 {
        let bytes = norma.serializar_texto_canonico();
        assert_eq!(
            ref_bytes,
            bytes,
            "Serialización {i} difiere de la referencia ({} vs {} bytes)",
            ref_bytes.len(),
            bytes.len()
        );
    }
}

#[test]
fn inv14_determinismo_hash() {
    let norma = Norma::cargar(borrador_completo()).unwrap();
    let ref_hash = norma.hash();

    for i in 0..100 {
        let norma2 = Norma::cargar(borrador_completo()).unwrap();
        assert_eq!(
            ref_hash,
            norma2.hash(),
            "Hash {i} difiere de la referencia"
        );
    }
}

#[test]
fn inv14_determinismo_norma_simple() {
    let norma = Norma::cargar(borrador_simple()).unwrap();
    let ref_bytes = norma.serializar_texto_canonico();

    for i in 0..100 {
        let bytes = norma.serializar_texto_canonico();
        assert_eq!(
            ref_bytes,
            bytes,
            "Serialización simple {i} difiere"
        );
    }
}

#[test]
fn inv14_determinismo_dos_normas_distintas() {
    let n1 = Norma::cargar(borrador_completo()).unwrap();
    let n2 = Norma::cargar(borrador_simple()).unwrap();

    let s1 = n1.serializar_texto_canonico();
    let s2 = n2.serializar_texto_canonico();

    assert_ne!(s1, s2, "Dos normas distintas producen la misma serialización");

    for i in 0..50 {
        assert_eq!(s1, n1.serializar_texto_canonico(), "Norma 1 iteración {i} inestable");
        assert_eq!(s2, n2.serializar_texto_canonico(), "Norma 2 iteración {i} inestable");
    }
}

#[test]
fn inv14_determinismo_longitud_fija() {
    let norma = Norma::cargar(borrador_completo()).unwrap();
    let ref_len = norma.serializar_texto_canonico().len();

    for i in 0..100 {
        let len = norma.serializar_texto_canonico().len();
        assert_eq!(
            ref_len, len,
            "Longitud {i}: esperada {ref_len}, obtenida {len}"
        );
    }
}
