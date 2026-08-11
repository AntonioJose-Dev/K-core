//! INV-09 / §D.3 / §C / H.4 — Libro durable y puerta de control (D5).

use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    CodigoRazon, Decision, HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::AlmacenDiscoLocal;
use sak_core::identidad::IdSistema;
use sak_core::libro::{
    antigüedad_maxima, cargar_libro_desde_almacen, conservar_libro, decidir_con_libro,
    minimo_exigido, HechoFirmadoLibro, LibroControl, NivelControl, ProductorHecho, TipoHecho,
};
use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir_tmp(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sak-d5-{tag}-{n}"))
}

fn firmante() -> ParMlDsa87 {
    ParMlDsa87::generar().unwrap()
}

fn sistema() -> IdSistema {
    IdSistema::nuevo("sys-d5").unwrap()
}

fn perfil_allow(clase: ClaseEfecto) -> PerfilNormativo {
    let hash = HashPaqueteNormativo::desde_bytes([7u8; LONGITUD_HASH_PAQUETE]);
    let norma = NormaMinima::nueva(
        IdNorma::nueva("N-ALLOW").unwrap(),
        Rango::P2,
        clase,
        PredicadoMinimo::Constante(Veredicto::Allow),
        false,
    );
    PerfilNormativo::nuevo(hash, vec![norma], false)
}

fn ctx(clase: ClaseEfecto) -> Contexto {
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    Contexto::nuevo(
        EfectoTipado::nuevo(clase, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        hash_peticion,
    )
}

fn hecho(
    tipo: TipoHecho,
    clase: Option<ClaseEfecto>,
    valor: bool,
    ahora: u64,
    fk: &ParMlDsa87,
) -> HechoFirmadoLibro {
    HechoFirmadoLibro::firmar(tipo, sistema(), clase, valor, 1, 1, ahora, "d5", fk).unwrap()
}

#[test]
fn sin_hechos_c0_y_deny_antes_de_norma() {
    let libro = LibroControl::nuevo();
    let clase = ClaseEfecto::Ef2; // mínimo C3
    assert_eq!(
        libro.evaluar(&sistema(), clase, 0).nivel_vigente,
        NivelControl::C0
    );
    assert!(minimo_exigido(clase, false) > NivelControl::C0);
    let d = decidir_con_libro(&ctx(clase), &perfil_allow(clase), &libro, &sistema(), false, 0);
    assert!(!d.corpus_evaluado);
    assert_eq!(d.nivel_en_instante, NivelControl::C0);
    match &d.decision {
        Decision::Denegada(den) => {
            assert_eq!(den.codigo(), CodigoRazon::ControlInsuficiente);
        }
        _ => panic!("esperado DENY(CONTROL_INSUFICIENTE)"),
    }
}

#[test]
fn hechos_caducados_como_falsos() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk)).unwrap();
    }
    assert!(libro.evaluar(&sistema(), c, 0).nivel_vigente >= NivelControl::C3);
    let tarde = antigüedad_maxima(TipoHecho::PepAtestado) + 1;
    let eval = libro.evaluar(&sistema(), c, tarde);
    assert!(eval.hechos_caducados.contains(&TipoHecho::PepAtestado));
    assert!(eval.nivel_vigente < NivelControl::C3);
    let d = decidir_con_libro(&ctx(c), &perfil_allow(c), &libro, &sistema(), true, tarde);
    assert!(!d.corpus_evaluado);
    assert_eq!(d.minimo_exigido, NivelControl::C3);
}

#[test]
fn productor_firma_o_alcance_incorrecto_no_eleva() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    libro
        .registrar_hecho(hecho(TipoHecho::Observable, Some(c), true, 0, &fk))
        .unwrap();

    let mut malo_prod = hecho(TipoHecho::Custodia, Some(c), true, 0, &fk);
    malo_prod.productor = ProductorHecho::IngestaRegistros;
    assert!(libro.registrar_hecho(malo_prod).is_err());

    let mut malo_firma = hecho(TipoHecho::Custodia, Some(c), true, 0, &fk);
    malo_firma.firma[0] ^= 0xff;
    assert!(libro.registrar_hecho(malo_firma).is_err());

    assert!(HechoFirmadoLibro::firmar(
        TipoHecho::Custodia,
        sistema(),
        None,
        true,
        1,
        1,
        0,
        "d5",
        &fk,
    )
    .is_err());

    let mut malo_dig = hecho(TipoHecho::Custodia, Some(c), true, 0, &fk);
    malo_dig.digest[0] ^= 0xff;
    assert!(libro.registrar_hecho(malo_dig).is_err());

    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C1
    );
}

#[test]
fn libro_y_control_sobreviven_reinicio() {
    let dir = dir_tmp("persist");
    let fk = firmante();
    let c = ClaseEfecto::Ef1;
    let nivel_antes;
    {
        let mut almacen = AlmacenDiscoLocal::abrir(&dir).unwrap();
        let mut libro = LibroControl::nuevo();
        for t in [
            TipoHecho::Custodia,
            TipoHecho::Exclusividad,
            TipoHecho::PepAtestado,
            TipoHecho::SondaOk,
        ] {
            libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk)).unwrap();
        }
        nivel_antes = libro.evaluar(&sistema(), c, 0).nivel_vigente;
        assert!(nivel_antes >= NivelControl::C3);
        conservar_libro(&mut almacen, &libro).unwrap();
        let d = decidir_con_libro(&ctx(c), &perfil_allow(c), &libro, &sistema(), false, 0);
        assert!(d.corpus_evaluado);
        assert_eq!(d.nivel_en_instante, nivel_antes);
    }
    {
        let almacen = AlmacenDiscoLocal::abrir(&dir).unwrap();
        let libro = cargar_libro_desde_almacen(&almacen).unwrap();
        assert_eq!(libro.n_hechos(), 4);
        assert_eq!(libro.evaluar(&sistema(), c, 0).nivel_vigente, nivel_antes);
        let d = decidir_con_libro(&ctx(c), &perfil_allow(c), &libro, &sistema(), false, 0);
        assert_eq!(d.nivel_en_instante, nivel_antes);
        assert!(d.corpus_evaluado);
        match &d.decision {
            Decision::Permitida(_) => {}
            other => panic!("esperado ALLOW tras reinicio: {other:?}"),
        }
    }
    let _ = fs::remove_dir_all(&dir);
}
