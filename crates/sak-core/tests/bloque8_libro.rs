//! Harnesses Bloque 8: Libro de Control D.3, bypass §I, INV-09/10/11.

use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    CodigoRazon, Decision, HashPaqueteNormativo, LONGITUD_HASH_PAQUETE,
};
use sak_core::identidad::IdSistema;
use sak_core::libro::{
    antigüedad_maxima, calcular_nivel_base, confinado_sin_custodia_exclusividad_no_es_c5,
    decidir_con_libro, ejecutar_prueba, minimo_exigido, EntradaPrueba, ErrorLibro,
    HechoFirmadoLibro, InventarioAlcanzables, LibroControl, NivelControl, TipoHecho,
    TipoPruebaBypass, VistaHechos,
};
use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
use sak_core::reloj::RelojInyectado;
use std::collections::BTreeSet;

fn firmante() -> ParMlDsa87 {
    ParMlDsa87::generar().unwrap()
}

fn sistema() -> IdSistema {
    IdSistema::nuevo("sys-libro").unwrap()
}

fn hecho(
    tipo: TipoHecho,
    clase: Option<ClaseEfecto>,
    valor: bool,
    ahora: u64,
    fk: &ParMlDsa87,
) -> HechoFirmadoLibro {
    HechoFirmadoLibro::firmar(
        tipo,
        sistema(),
        clase,
        valor,
        1,
        1,
        ahora,
        "harness",
        fk,
    )
    .unwrap()
}

fn vista_c3() -> VistaHechos {
    VistaHechos {
        custodia: true,
        exclusividad: true,
        pep_atestado: true,
        sonda_ok: true,
        delegado: false,
        confinado: false,
        observable: false,
        ef9_abierto: false,
    }
}

#[test]
fn orden_c0_a_c5_matriz_d3() {
    assert_eq!(calcular_nivel_base(VistaHechos::default()), NivelControl::C0);
    assert_eq!(
        calcular_nivel_base(VistaHechos {
            observable: true,
            ..VistaHechos::default()
        }),
        NivelControl::C1
    );
    // C2: CUSTODIA ∧ ¬(EXCLUSIVIDAD ∧ SONDA_OK)
    assert_eq!(
        calcular_nivel_base(VistaHechos {
            custodia: true,
            exclusividad: false,
            sonda_ok: false,
            ..VistaHechos::default()
        }),
        NivelControl::C2
    );
    assert_eq!(
        calcular_nivel_base(VistaHechos {
            custodia: true,
            exclusividad: true,
            sonda_ok: false,
            ..VistaHechos::default()
        }),
        NivelControl::C2
    );
    assert_eq!(calcular_nivel_base(vista_c3()), NivelControl::C3);
    let mut c4 = vista_c3();
    c4.delegado = true;
    assert_eq!(calcular_nivel_base(c4), NivelControl::C4);
    let mut c5 = c4;
    c5.confinado = true;
    assert_eq!(calcular_nivel_base(c5), NivelControl::C5);

    // H-2: CONFINADO sin CUSTODIA∧EXCLUSIVIDAD no es C5
    let malo = VistaHechos {
        confinado: true,
        delegado: true,
        pep_atestado: true,
        sonda_ok: true,
        custodia: false,
        exclusividad: false,
        ..VistaHechos::default()
    };
    assert!(confinado_sin_custodia_exclusividad_no_es_c5(malo));
    assert_ne!(calcular_nivel_base(malo), NivelControl::C5);
}

#[test]
fn caducidad_conservadora_decae_solo() {
    let fk = firmante();
    let reloj = RelojInyectado::nuevo(0);
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C4
    );
    // Caduca PEP_ATESTADO (30s)
    let despues = antigüedad_maxima(TipoHecho::PepAtestado) + 1;
    reloj.fijar(despues).unwrap();
    let eval = libro.evaluar(&sistema(), c, despues);
    assert!(eval.hechos_caducados.contains(&TipoHecho::PepAtestado));
    assert!(eval.nivel_vigente < NivelControl::C4);
}

#[test]
fn ninguna_api_eleva_niveles() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef2;
    libro.registrar_hecho(hecho(TipoHecho::Observable, Some(c), true, 0, &fk));
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C1
    );
    let err = libro
        .rebajar(&sistema(), c, NivelControl::C3, 0, 1, "intento elevar")
        .unwrap_err();
    assert_eq!(err, ErrorLibro::ElevacionProhibida);
    // No existe LibroControl::elevar — comprobado por ausencia de API pública.
}

#[test]
fn rebaja_manual_permitida() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C3
    );
    libro
        .rebajar(
            &sistema(),
            c,
            NivelControl::C1,
            0,
            1,
            "ruta no detectada por el Kernel",
        )
        .unwrap();
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C1
    );
}

#[test]
fn degradacion_ef9_y_alcanzables() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    libro.registrar_hecho(hecho(TipoHecho::Ef9Abierto, None, true, 0, &fk));
    let mut set = BTreeSet::new();
    set.insert(ClaseEfecto::Ef1);
    libro.registrar_alcanzables(
        InventarioAlcanzables::firmar(sistema(), set, 1, 1, 0, &fk).unwrap(),
    );
    let eval = libro.evaluar(&sistema(), c, 0);
    assert_eq!(eval.nivel_vigente, NivelControl::C2);
    assert!(eval
        .causa_degradacion
        .as_ref()
        .unwrap()
        .contains("ALCANZABLES"));
}

#[test]
fn cierre_conservador_sin_inventario_alcanzables() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef2;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    libro.registrar_hecho(hecho(TipoHecho::Ef9Abierto, None, true, 0, &fk));
    // Sin inventario ALCANZABLES
    let eval = libro.evaluar(&sistema(), c, 0);
    assert_eq!(eval.nivel_vigente, NivelControl::C2);
    assert!(eval
        .causa_degradacion
        .as_ref()
        .unwrap()
        .contains("cierre conservador"));

    // Inventario caducado
    let inv = InventarioAlcanzables::firmar(
        sistema(),
        BTreeSet::new(),
        1,
        1,
        0,
        &fk,
    )
    .unwrap();
    libro.registrar_alcanzables(inv);
    let tarde = antigüedad_maxima(TipoHecho::Alcanzables) + 1;
    let eval2 = libro.evaluar(&sistema(), c, tarde);
    assert!(eval2.nivel_vigente <= NivelControl::C2);
}

#[test]
fn declarar_efector_degrada_clase() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    libro.registrar_hecho(hecho(TipoHecho::Ef9Abierto, None, true, 0, &fk));
    libro
        .declarar_efector_alcanzable(&sistema(), c, 0, 1, &fk)
        .unwrap();
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C2
    );
}

#[test]
fn deny_control_insuficiente_sin_evaluar_normas() {
    let _fk = firmante();
    let libro = LibroControl::nuevo(); // C0
    let efecto = EfectoTipado::nuevo(ClaseEfecto::Ef5, [1u8; LONGITUD_HASH_PAQUETE]);
    let ctx = Contexto::nuevo(efecto, vec![]);
    let hash = HashPaqueteNormativo::desde_bytes([9u8; LONGITUD_HASH_PAQUETE]);
    let norma = NormaMinima::nueva(
        sak_core::decision::IdNorma::nueva("N-ALLOW").unwrap(),
        Rango::P2,
        ClaseEfecto::Ef5,
        PredicadoMinimo::Constante(sak_core::decision::Veredicto::Allow),
        false,
    );
    let perfil = PerfilNormativo::nuevo(hash, vec![norma], false);
    // Sin puerta, ALLOW; con Libro C0 vs mínimo C4 ⇒ CONTROL_INSUFICIENTE
    let d = decidir_con_libro(&ctx, &perfil, &libro, &sistema(), false, 0);
    assert!(!d.corpus_evaluado);
    assert_eq!(d.minimo_exigido, minimo_exigido(ClaseEfecto::Ef5, false));
    match d.decision {
        Decision::Denegada(den) => {
            assert_eq!(den.codigo(), CodigoRazon::ControlInsuficiente);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn pep_ef1_ef2_solo_hechos_sostenibles() {
    let sostenibles = LibroControl::hechos_sostenibles_por_pep_ef1_ef2();
    assert!(sostenibles.contains(&TipoHecho::Custodia));
    assert!(sostenibles.contains(&TipoHecho::Delegado));
    assert!(sostenibles.contains(&TipoHecho::PepAtestado));
    assert!(sostenibles.contains(&TipoHecho::SondaOk));
    assert!(sostenibles.contains(&TipoHecho::Observable));
    assert!(!sostenibles.contains(&TipoHecho::Confinado));

    // En entorno instrumentado: PEPs generan CUSTODIA+DELEGADO+PEP+SONDA ⇒ C4, no C5.
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in sostenibles.iter().copied().filter(|t| {
        !matches!(t, TipoHecho::Exclusividad) // exclusividad viene de §I
    }) {
        let clase = if matches!(t, TipoHecho::Ef9Abierto | TipoHecho::Confinado) {
            None
        } else {
            Some(c)
        };
        libro.registrar_hecho(hecho(t, clase, true, 0, &fk));
    }
    // Añadir exclusividad vía prueba I (no el PEP solo)
    let r = ejecutar_prueba(
        TipoPruebaBypass::InventarioCredenciales,
        &EntradaPrueba {
            sistema: sistema(),
            clase: Some(c),
            epoca: 1,
            ahora: 0,
            version: 1,
            senal_positiva: true,
            divergencia_pct: 0,
            trampa_usada: false,
        },
        &fk,
    )
    .unwrap();
    for h in r.hechos {
        libro.registrar_hecho(h);
    }
    let eval = libro.evaluar(&sistema(), c, 0);
    assert_eq!(eval.nivel_vigente, NivelControl::C4);
    assert_ne!(eval.nivel_vigente, NivelControl::C5);
}

#[test]
fn pruebas_bypass_firman_y_declaran_limites() {
    let fk = firmante();
    let pruebas = [
        TipoPruebaBypass::InventarioCredenciales,
        TipoPruebaBypass::RotacionSecretosHeredados,
        TipoPruebaBypass::ReconciliacionProveedor,
        TipoPruebaBypass::ObservacionEgreso,
        TipoPruebaBypass::VerificacionPep,
        TipoPruebaBypass::EscaneoConfiguraciones,
        TipoPruebaBypass::CredencialesTrampa,
        TipoPruebaBypass::SondaAdversarial,
    ];
    for p in pruebas {
        let r = ejecutar_prueba(
            p,
            &EntradaPrueba {
                sistema: sistema(),
                clase: Some(ClaseEfecto::Ef2),
                epoca: 1,
                ahora: 0,
                version: 1,
                senal_positiva: true,
                divergencia_pct: 0,
                trampa_usada: false,
            },
            &fk,
        )
        .unwrap();
        assert!(!r.no_demuestra.is_empty());
        assert!(!r.hechos.is_empty());
        assert!(!r.hechos[0].firma.is_empty());
    }
}

#[test]
fn trampa_usada_fuerza_c0() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let c = ClaseEfecto::Ef1;
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
    ] {
        libro.registrar_hecho(hecho(t, Some(c), true, 0, &fk));
    }
    libro.credencial_trampa_usada(&sistema(), c, 1);
    assert_eq!(
        libro.evaluar(&sistema(), c, 0).nivel_vigente,
        NivelControl::C0
    );
    assert!(libro.clase_suspendida(&sistema(), c));
}
