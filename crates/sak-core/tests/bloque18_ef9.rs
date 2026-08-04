//! Harnesses rebanada repo EF-9 (tests/bloque18_*): prohibición/confinamiento; no mediación.
//! No es bloque §M. Matriz C EF-9 / INV-11. Atestación C5 → §M 12.
//! Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.
//!
//! Los tests prueban el uso correcto del inventario **instrumentado**, no su
//! completitud ante activos desconocidos ni un host privilegiado. C5 y
//! atestación de plataforma real no están implementados.

use sak_core::capacidad::{Alcance, ClasificacionEfecto, ParametrosEmision};
use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::libro::{
    antigüedad_maxima, control_alcanza_minimo, libro_suficiente_c3, libro_suficiente_c4,
    EvaluadorEf9, HechoFirmadoLibro, InventarioAlcanzables, LibroControl, NivelControl,
    ObservacionEntornoEf9, PerfilEf9, ResultadoEvaluacionEf9, SenalEf9, TipoHecho,
};
use sak_core::pep::{
    alcance_ef3, preparar_solicitud_escritura, CodigoPep, CredencialEscritura, EjecutorSimulado,
    GatewayEscritura, OperacionEscritura, PrecondicionesPepEf3, ResultadoPepEscritura,
    SolicitudEscritura, SolicitudEscrituraCruda,
};
use sak_core::reloj::RelojInyectado;
use std::collections::BTreeSet;

fn sistema() -> IdSistema {
    IdSistema::nuevo("sys-ef9").unwrap()
}

fn firmante() -> ParMlDsa87 {
    ParMlDsa87::generar().unwrap()
}

fn hechos_c4(libro: &mut LibroControl, clase: ClaseEfecto, fk: &ParMlDsa87) {
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro.registrar_hecho(
            HechoFirmadoLibro::firmar(t, sistema(), Some(clase), true, 1, 1, 0, "test", fk)
                .unwrap(),
        ).unwrap();
    }
}

fn inv_firmado(
    efectores: BTreeSet<ClaseEfecto>,
    fk: &ParMlDsa87,
    incompleto: bool,
    emitido: u64,
) -> InventarioAlcanzables {
    let mut rutas = BTreeSet::new();
    rutas.insert("10.0.0.5:443".into());
    let mut creds = BTreeSet::new();
    creds.insert("cred:digest:aabb".into());
    InventarioAlcanzables::firmar_completo(
        sistema(),
        "inst-1",
        efectores,
        rutas,
        creds,
        BTreeSet::from(["store-a".into()]),
        BTreeSet::from(["svc-api".into()]),
        BTreeSet::from(["canal-consumo".into()]),
        incompleto,
        1,
        1,
        emitido,
        "detector-instrumentado",
        fk,
    )
    .unwrap()
}

#[test]
fn senales_abren_ef9_salvo_demostracion() {
    let mut obs = ObservacionEntornoEf9::default();
    assert!(EvaluadorEf9::detectar_apertura(&obs)); // conservador por defecto

    obs.demostracion_codigo_ausente = true;
    assert!(!EvaluadorEf9::detectar_apertura(&obs));

    for s in [
        SenalEf9::InterpreteDisponible,
        SenalEf9::ShellOComandoRemoto,
        SenalEf9::NodoCodigoAutomatizacion,
        SenalEf9::EjecucionScript,
        SenalEf9::PluginOMacroCargable,
        SenalEf9::CargaDinamica,
        SenalEf9::RedSalidaNoForzada,
        SenalEf9::CredencialAccesibleDesdeProceso,
        SenalEf9::ContenedorPrivilegiadoOMontaje,
        SenalEf9::DespliegueOModificacionInfra,
        SenalEf9::AccesoDirectoEfector(ClaseEfecto::Ef3),
    ] {
        let mut o = ObservacionEntornoEf9 {
            demostracion_codigo_ausente: true,
            ..Default::default()
        };
        o.senales.insert(s);
        assert!(
            EvaluadorEf9::detectar_apertura(&o),
            "senal {:?} debe abrir EF-9",
            s
        );
    }
}

#[test]
fn inventario_firmado_valido_y_alterado() {
    let fk = firmante();
    let inv = inv_firmado(BTreeSet::from([ClaseEfecto::Ef4]), &fk, false, 0);
    assert!(inv.verificar_firma(&fk.public).is_ok());
    assert!(inv.vigente(0));

    let mut alterado = inv.clone();
    alterado.digest[0] ^= 0xff;
    assert!(alterado.verificar_firma(&fk.public).is_err());

    let mut sin_firma = inv.clone();
    sin_firma.firma.clear();
    assert!(sin_firma.verificar_firma(&fk.public).is_err());

    let vencido = inv_firmado(BTreeSet::new(), &fk, false, 0);
    let tarde = antigüedad_maxima(TipoHecho::Alcanzables) + 1;
    assert!(!vencido.vigente(tarde));

    let incompleto = inv_firmado(BTreeSet::new(), &fk, true, 0);
    assert!(!incompleto.vigente(0));
    assert!(incompleto.no_caducado(0));
}

#[test]
fn ef9_abierto_degrada_efectores_alcanzables_a_c2() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let mut eval = EvaluadorEf9::nuevo();
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-deg").unwrap();

    for c in [
        ClaseEfecto::Ef3,
        ClaseEfecto::Ef4,
        ClaseEfecto::Ef5,
        ClaseEfecto::Ef6,
        ClaseEfecto::Ef7,
        ClaseEfecto::Ef8,
    ] {
        hechos_c4(&mut libro, c, &fk);
    }

    let efectores = BTreeSet::from([
        ClaseEfecto::Ef3,
        ClaseEfecto::Ef4,
        ClaseEfecto::Ef5,
        ClaseEfecto::Ef6,
        ClaseEfecto::Ef7,
        ClaseEfecto::Ef8,
    ]);
    let inv = inv_firmado(efectores, &fk, false, 0);
    let mut obs = ObservacionEntornoEf9::default();
    obs.senales.insert(SenalEf9::InterpreteDisponible);

    eval.sincronizar_libro(
        &sistema(),
        PerfilEf9::CodigoProhibido,
        &obs,
        Some(&inv),
        &mut libro,
        &fk,
        1,
        0,
        Some(&sujeto),
        Some(&mut ledger),
    )
    .unwrap();

    for c in [
        ClaseEfecto::Ef3,
        ClaseEfecto::Ef4,
        ClaseEfecto::Ef5,
        ClaseEfecto::Ef6,
        ClaseEfecto::Ef7,
        ClaseEfecto::Ef8,
    ] {
        let e = libro.evaluar(&sistema(), c, 0);
        assert_eq!(e.nivel_vigente, NivelControl::C2, "{c:?}");
        assert!(!libro_suficiente_c3(&libro, &sistema(), c, 0));
        assert!(!libro_suficiente_c4(&libro, &sistema(), c, 0));
        assert!(!control_alcanza_minimo(
            &libro,
            &sistema(),
            c,
            true,
            0
        ));
    }
}

#[test]
fn inventario_caducado_sin_alcanzables_degrada_todas_las_clases() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    hechos_c4(&mut libro, ClaseEfecto::Ef2, &fk);
    hechos_c4(&mut libro, ClaseEfecto::Ef1, &fk);
    libro.registrar_hecho(
        HechoFirmadoLibro::firmar(
            TipoHecho::Ef9Abierto,
            sistema(),
            None,
            true,
            1,
            1,
            0,
            "test",
            &fk,
        )
        .unwrap(),
    ).unwrap();
    // Inventario vacío pero vigente: no degrada clases no listadas.
    let inv_vacio = InventarioAlcanzables::firmar(sistema(), BTreeSet::new(), 1, 1, 0, &fk).unwrap();
    libro.registrar_alcanzables(inv_vacio);
    assert_eq!(
        libro.evaluar(&sistema(), ClaseEfecto::Ef2, 0).nivel_vigente,
        NivelControl::C4
    );

    // Caducado ⇒ cierre conservador todas ≤ C2
    let inv_old = InventarioAlcanzables::firmar(sistema(), BTreeSet::new(), 2, 1, 0, &fk).unwrap();
    libro.registrar_alcanzables(inv_old);
    let tarde = antigüedad_maxima(TipoHecho::Alcanzables) + 1;
    // Hecho EF9 también caduca; re-registrar vigente en `tarde` no — usamos hecho largo.
    // Re-emitir EF9 en t=0 con antigüedad larga ya está; evaluar en `tarde` caduca hechos C4
    // y el EF9. Para aislar inventario: emitir EF9 fresco.
    let mut libro2 = LibroControl::nuevo();
    hechos_c4(&mut libro2, ClaseEfecto::Ef2, &fk);
    // Hechos con emitido_en = tarde para que sigan vigentes
    for t in [
        TipoHecho::Custodia,
        TipoHecho::Exclusividad,
        TipoHecho::PepAtestado,
        TipoHecho::SondaOk,
        TipoHecho::Delegado,
    ] {
        libro2.registrar_hecho(
            HechoFirmadoLibro::firmar(
                t,
                sistema(),
                Some(ClaseEfecto::Ef2),
                true,
                1,
                1,
                tarde,
                "test",
                &fk,
            )
            .unwrap(),
        ).unwrap();
    }
    libro2.registrar_hecho(
        HechoFirmadoLibro::firmar(
            TipoHecho::Ef9Abierto,
            sistema(),
            None,
            true,
            1,
            1,
            tarde,
            "test",
            &fk,
        )
        .unwrap(),
    ).unwrap();
    let inv_cad = InventarioAlcanzables::firmar(sistema(), BTreeSet::new(), 1, 1, 0, &fk).unwrap();
    libro2.registrar_alcanzables(inv_cad);
    let eval = libro2.evaluar(&sistema(), ClaseEfecto::Ef2, tarde);
    assert!(eval.nivel_vigente <= NivelControl::C2);
    assert!(eval
        .causa_degradacion
        .as_ref()
        .unwrap()
        .contains("caducado"));
}

#[test]
fn rechazo_capacidad_ef9() {
    assert!(!EvaluadorEf9::puede_emitir_capacidad());
    assert!(!EvaluadorEf9::c5_implementado());
    assert!(!PerfilEf9::CodigoProhibido.afirma_c5());
    assert!(!PerfilEf9::ConfinadoPendienteAtestacion.afirma_confinamiento_efectivo());

    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-cap").unwrap();
    let hash = HashPaqueteNormativo::desde_bytes([9u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF9").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let params = ParametrosEmision {
        sistema: sistema(),
        digest_efecto: [2u8; LONGITUD_HASH_PAQUETE],
        alcance: Alcance::minimo(["EF-9", "script"]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 1000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let err = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap_err();
    assert!(
        matches!(err, sak_core::evidencia::ErrorEvidencia::EmisionCapacidadRechazada)
            || err.to_string().contains("EF-9"),
        "{err}"
    );
}

#[test]
fn perfil_codigo_prohibido_deniega_solicitud() {
    let mut eval = EvaluadorEf9::nuevo();
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-proh").unwrap();
    eval.asignar_perfil(&sistema(), PerfilEf9::CodigoProhibido);
    let r = eval.evaluar_solicitud_ejecucion(&sistema(), &sujeto, &mut ledger, 10);
    assert!(matches!(
        r,
        ResultadoEvaluacionEf9::DenegadoProhibido {
            codigo: CodigoPep::Ef9Prohibido
        }
    ));
    assert!(ledger
        .exportar_paquete()
        .registros
        .iter()
        .any(|x| x.tipo == TipoRegistro::Ef9));
}

#[test]
fn perfil_confinado_pendiente_no_afirma_c5() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let mut eval = EvaluadorEf9::nuevo();
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-conf").unwrap();
    hechos_c4(&mut libro, ClaseEfecto::Ef1, &fk);

    let obs = ObservacionEntornoEf9 {
        runtime_minimo_declarado: true,
        salida_solo_mediada: true,
        demostracion_codigo_ausente: false,
        senales: BTreeSet::new(),
    };
    let r = eval
        .sincronizar_libro(
            &sistema(),
            PerfilEf9::ConfinadoPendienteAtestacion,
            &obs,
            None,
            &mut libro,
            &fk,
            1,
            0,
            Some(&sujeto),
            Some(&mut ledger),
        )
        .unwrap();
    match r {
        ResultadoEvaluacionEf9::EstadoSincronizado {
            ef9_abierto,
            perfil,
        } => {
            assert!(ef9_abierto);
            assert_eq!(perfil, PerfilEf9::ConfinadoPendienteAtestacion);
        }
        other => panic!("{other:?}"),
    }
    assert!(!PerfilEf9::ConfinadoPendienteAtestacion.afirma_c5());
    // Sin CONFINADO atestado ⇒ no C5
    assert_ne!(
        libro.evaluar(&sistema(), ClaseEfecto::Ef1, 0).nivel_vigente,
        NivelControl::C5
    );

    let den = eval.evaluar_solicitud_ejecucion(&sistema(), &sujeto, &mut ledger, 20);
    assert!(matches!(
        den,
        ResultadoEvaluacionEf9::DenegadoNoConfinado {
            codigo: CodigoPep::Ef9NoConfinado
        }
    ));
}

#[test]
fn gateway_ef3_bloqueado_por_control_insuficiente_tras_ef9() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    hechos_c4(&mut libro, ClaseEfecto::Ef3, &fk);
    libro.registrar_hecho(
        HechoFirmadoLibro::firmar(
            TipoHecho::Ef9Abierto,
            sistema(),
            None,
            true,
            1,
            1,
            0,
            "test",
            &fk,
        )
        .unwrap(),
    ).unwrap();
    let inv = inv_firmado(BTreeSet::from([ClaseEfecto::Ef3]), &fk, false, 0);
    libro.registrar_alcanzables(inv);
    assert!(!libro_suficiente_c3(
        &libro,
        &sistema(),
        ClaseEfecto::Ef3,
        0
    ));

    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-gw").unwrap();
    let sol = SolicitudEscritura::nueva(
        OperacionEscritura::Update,
        "tabla-estado",
        [0x11u8; LONGITUD_HASH_PAQUETE],
        Some(1),
        ["estado"],
        [0x22u8; LONGITUD_HASH_PAQUETE],
        1,
        "dest",
        true,
        false,
        [3u8; LONGITUD_HASH_PAQUETE],
    )
    .unwrap();
    let (s, digest) = preparar_solicitud_escritura(sol.clone());
    let hash = HashPaqueteNormativo::desde_bytes([3u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-3").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let params = ParametrosEmision {
        sistema: sistema(),
        digest_efecto: digest,
        alcance: alcance_ef3(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: false,
            afecta_personas: false,
            datos_personales: false,
        },
    };
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap();

    let mut pre = PrecondicionesPepEf3::todas_ok();
    pre.libro_suficiente = libro_suficiente_c3(&libro, &sistema(), ClaseEfecto::Ef3, 0);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([3u8; 32]));
    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema(),
        &sujeto,
        &pre,
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::ControlInsuficiente
        }
    ));
}

#[test]
fn acceso_directo_cada_efector_en_inventario() {
    let fk = firmante();
    let mut set = BTreeSet::new();
    for c in [
        ClaseEfecto::Ef1,
        ClaseEfecto::Ef2,
        ClaseEfecto::Ef3,
        ClaseEfecto::Ef4,
        ClaseEfecto::Ef5,
        ClaseEfecto::Ef6,
        ClaseEfecto::Ef7,
        ClaseEfecto::Ef8,
    ] {
        set.insert(c);
    }
    let inv = inv_firmado(set.clone(), &fk, false, 0);
    assert_eq!(inv.efectores, set);
    assert!(!inv.rutas_red.is_empty());
    assert!(!inv.credenciales_detectadas.is_empty());
}

#[test]
fn persistencia_historica_y_verificacion_offline() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    let mut eval = EvaluadorEf9::nuevo();
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    hechos_c4(&mut libro, ClaseEfecto::Ef3, &fk);
    let inv = inv_firmado(BTreeSet::from([ClaseEfecto::Ef3]), &fk, false, 0);
    let mut obs = ObservacionEntornoEf9::default();
    obs.senales.insert(SenalEf9::ShellOComandoRemoto);

    eval.sincronizar_libro(
        &sistema(),
        PerfilEf9::CodigoProhibido,
        &obs,
        Some(&inv),
        &mut libro,
        &fk,
        1,
        0,
        Some(&sujeto),
        Some(&mut ledger),
    )
    .unwrap();
    eval.evaluar_solicitud_ejecucion(&sistema(), &sujeto, &mut ledger, 5);

    assert!(!libro.historial().is_empty());
    assert!(libro.historial().iter().any(|(_, n, causa, _)| {
        *n <= NivelControl::C2 && causa.contains("ALCANZABLES")
    }));

    // Transición: recuperar (código prohibido demostrado) ⇒ EF9 cerrado
    let obs_cerrada = ObservacionEntornoEf9 {
        demostracion_codigo_ausente: true,
        senales: BTreeSet::new(),
        ..Default::default()
    };
    eval.sincronizar_libro(
        &sistema(),
        PerfilEf9::CodigoProhibido,
        &obs_cerrada,
        Some(&inv),
        &mut libro,
        &fk,
        2,
        100,
        Some(&sujeto),
        Some(&mut ledger),
    )
    .unwrap();
    // Tras cierre, sin EF9 efectivo reciente: el último hecho EF9_ABIERTO=false
    // (hechos previos true siguen vigentes si antigüedad lo permite — ambos vigentes;
    // vista usa todos los vigentes con valor true. Necesitamos que el false anule...
    // El diseño actual: solo hechos con valor=true activan. Un EF9_ABIERTO=false
    // vigente no pone ef9_abierto. Si sigue un true vigente, sigue abierto.
    // Para transición limpia usamos libro fresco o hecho true caducado.
    let mut libro3 = LibroControl::nuevo();
    hechos_c4(&mut libro3, ClaseEfecto::Ef3, &fk);
    eval.sincronizar_libro(
        &sistema(),
        PerfilEf9::CodigoProhibido,
        &obs_cerrada,
        Some(&inv),
        &mut libro3,
        &fk,
        3,
        0,
        Some(&sujeto),
        Some(&mut ledger),
    )
    .unwrap();
    assert_eq!(
        libro3.evaluar(&sistema(), ClaseEfecto::Ef3, 0).nivel_vigente,
        NivelControl::C4
    );

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Ef9));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}

#[test]
fn sin_interfaz_de_elevacion() {
    let fk = firmante();
    let mut libro = LibroControl::nuevo();
    hechos_c4(&mut libro, ClaseEfecto::Ef3, &fk);
    libro.registrar_hecho(
        HechoFirmadoLibro::firmar(
            TipoHecho::Ef9Abierto,
            sistema(),
            None,
            true,
            1,
            1,
            0,
            "test",
            &fk,
        )
        .unwrap(),
    ).unwrap();
    libro.registrar_alcanzables(inv_firmado(BTreeSet::from([ClaseEfecto::Ef3]), &fk, false, 0));
    assert_eq!(
        libro.evaluar(&sistema(), ClaseEfecto::Ef3, 0).nivel_vigente,
        NivelControl::C2
    );
    // rebajar a C1 ok; no hay elevar
    libro
        .rebajar(
            &sistema(),
            ClaseEfecto::Ef3,
            NivelControl::C1,
            0,
            1,
            "operador",
        )
        .unwrap();
    assert_eq!(
        libro.evaluar(&sistema(), ClaseEfecto::Ef3, 0).nivel_vigente,
        NivelControl::C1
    );
}
