//! Validación de carga G.1: campos obligatorios, interpretación, materias reservadas.

use sak_core::contexto::ClaseEfecto;
use sak_core::decision::{HashPaqueteNormativo, Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::norma::{
    Alcance, BorradorNorma, ErrorCarga, Fecha, Interpretacion, MateriaReservada, Naturaleza, Norma,
    Operacionalidad, Vigencia, ESQUEMA_NORMA_V1,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;

fn base() -> BorradorNorma {
    BorradorNorma {
        identificador: "N-1".into(),
        fuente: "instrumento art. 1".into(),
        jurisdiccion: "EU".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2024, 6, 1).unwrap(),
            termino: None,
        },
        alcance: Alcance {
            caso_de_uso: "c".into(),
            clase_riesgo: "r".into(),
            rol_regulatorio: "rol".into(),
            sector: "s".into(),
            categorias_datos: "d".into(),
            autonomia: "a".into(),
            destinatarios: "dest".into(),
        },
        naturaleza: Naturaleza::Obligacion,
        operacionalidad: Operacionalidad::L2,
        clase_de_efecto: ClaseEfecto::Ef1,
        predicado: Predicado::Fijo(Veredicto::Allow),
        evidencia_exigida: vec![],
        acciones_obligatorias: vec![],
        condiciones_de_denegacion: vec![],
        escalado: None,
        monitorizacion: None,
        interpretacion: Interpretacion {
            texto: "texto interpretativo aprobado".into(),
            autor: "ana.revisor".into(),
            digest_aprobacion: [1u8; LONGITUD_HASH_PAQUETE],
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    }
}

#[test]
fn carga_ok_y_hash_estable() {
    let n1 = Norma::cargar(base()).unwrap();
    let n2 = Norma::cargar(base()).unwrap();
    assert_eq!(n1.hash(), n2.hash());
    assert!(!ESQUEMA_NORMA_V1.is_empty());
    assert!(ESQUEMA_NORMA_V1.contains("interpretacion"));
}

#[test]
fn rechazo_interpretacion_vacia() {
    let mut b = base();
    b.interpretacion.texto = "   ".into();
    assert_eq!(Norma::cargar(b).unwrap_err(), ErrorCarga::InterpretacionVacia);
}

#[test]
fn rechazo_autor_vacio() {
    let mut b = base();
    b.interpretacion.autor = "".into();
    assert_eq!(Norma::cargar(b).unwrap_err(), ErrorCarga::AutorNoIdentificado);
}

#[test]
fn rechazo_campo_obligatorio() {
    let mut b = base();
    b.fuente = "".into();
    assert!(matches!(
        Norma::cargar(b).unwrap_err(),
        ErrorCarga::CampoObligatorioAusente("fuente")
    ));
}

#[test]
fn rechazo_materia_reservada_como_l1() {
    let mut b = base();
    b.operacionalidad = Operacionalidad::L1;
    b.pretende_resolver = vec![MateriaReservada::ImpactoDerechosFundamentales];
    assert!(matches!(
        Norma::cargar(b).unwrap_err(),
        ErrorCarga::MateriaReservadaComoL1(_)
    ));
}

#[test]
fn rechazo_hash_declarado_incorrecto() {
    let b = base();
    let malo = HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]);
    assert_eq!(
        Norma::cargar_con_hash_declarado(b, malo).unwrap_err(),
        ErrorCarga::HashNoCoincide
    );
}

#[test]
fn hash_declarado_correcto() {
    let n = Norma::cargar(base()).unwrap();
    let hash = *n.hash();
    let n2 = Norma::cargar_con_hash_declarado(base(), hash).unwrap();
    assert_eq!(n2.hash(), n.hash());
}
