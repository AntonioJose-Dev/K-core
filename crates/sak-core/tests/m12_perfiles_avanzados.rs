//! §M 12 — Perfiles avanzados: I.10, sonda 12 EF por puerta canónica, multiparte.
//!
//! C5 solo como `C5_CALCULADO_SOBRE_HECHOS_APORTADOS`. Prohibido `C5_HOST_REAL`.
//! No afirma HSM, TSA, TCB/plataforma, exclusividad de red, ALCANZABLES completo ni [GOB].

use sak_core::capacidad::{Alcance, ClasificacionEfecto, ParametrosEmision};
use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{IdSujeto, LedgerEvidencia, MemoriaDurable};
use sak_core::identidad::IdSistema;
use sak_core::libro::{
    aceptar_certificado, calcular_nivel_base, emitir_certificado_vista, es_deny_ef12,
    ejecutar_sonda_doce_sin_capacidad, quorum_dos_tercios_mas_uno, registrar_vista_si_compatible,
    verificar_resultado_sonda, AtestacionConfinamiento, EntradaPredicadosI10, ErrorConfinamiento,
    ErrorVista, EvaluadorEf9, HechoFirmadoLibro, IdNodo, IdPredicadoI10, LibroControl,
    NivelControl, ObservacionEntornoEf9, PerfilEf9, TipoHecho, VistaHechos,
    C5_CALCULADO_SOBRE_HECHOS_APORTADOS, C5_HOST_REAL_PROHIBIDO,
};
use sak_core::reloj::RelojInyectado;
use std::collections::BTreeSet;

fn fk() -> ParMlDsa87 {
    ParMlDsa87::generar().unwrap()
}

fn sys() -> IdSistema {
    IdSistema::nuevo("sys-m12").unwrap()
}

fn entrada_i10_ok() -> EntradaPredicadosI10 {
    let blanca = b"surface-v1".to_vec();
    EntradaPredicadosI10 {
        ambiente_vacio: true,
        superficie_blanca_canonica: blanca.clone(),
        funciones_expuestas: blanca,
        sin_carga_dinamica: true,
        pep_latido_ok: true,
        denegaciones_sonda_diez: 10,
        egreso_sin_ruta_alternativa: true,
        autotest_cripto_ok: true,
    }
}

#[test]
fn p1_ocho_predicados_emiten_confinado() {
    let autoridad = fk();
    let at = AtestacionConfinamiento::emitir(sys(), 1, 1_000, &entrada_i10_ok(), &autoridad)
        .unwrap();
    at.verificar(&autoridad.public, 1_000).unwrap();
    assert!(at.predicados.iter().all(|p| p.ok));
    assert!(!at.no_comprobado.is_empty());
    assert!(at
        .no_comprobado
        .iter()
        .any(|x| x.contains(C5_HOST_REAL_PROHIBIDO) || x.contains("C5_HOST_REAL")));

    let mut libro = LibroControl::nuevo();
    at.registrar_hecho_en_libro(&mut libro, &autoridad).unwrap();
    let eval = libro.evaluar(&sys(), ClaseEfecto::Ef1, 1_000);
    // Solo CONFINADO no basta para C5
    assert_ne!(eval.nivel_vigente, NivelControl::C5);
}

#[test]
fn n1_predicado_fallo_no_atestacion() {
    let mut e = entrada_i10_ok();
    e.denegaciones_sonda_diez = 9;
    let err = AtestacionConfinamiento::emitir(sys(), 1, 1, &e, &fk()).unwrap_err();
    assert!(matches!(
        err,
        ErrorConfinamiento::PredicadoFallo(IdPredicadoI10::SondaDiezDeDiez)
    ));
}

#[test]
fn p2_sonda_doce_deny_por_puerta_canonica_firmada() {
    let autoridad = fk();
    let libro = LibroControl::nuevo(); // sin hechos ⇒ puerta DENY control
    let res = ejecutar_sonda_doce_sin_capacidad(&libro, &sys(), 1, 5_000, &autoridad).unwrap();
    assert!(res.completo_12_deny);
    assert_eq!(res.recibos.len(), 12);
    for r in &res.recibos {
        assert!(!r.capacidad_presente);
        assert_eq!(r.resultado, sak_core::libro::ResultadoIntentoSonda::Deny);
        assert!(
            r.pasos.iter().any(|p| *p == "comprobar_puerta_control"
                || *p == "ef12_deny_incondicional"
                || *p == "capacidad_ausente_como_entrada"),
            "pasos={:?}",
            r.pasos
        );
    }
    assert!(es_deny_ef12(
        res.recibos.iter().find(|r| r.clase == ClaseEfecto::Ef12).unwrap()
    ));
    verificar_resultado_sonda(&res, &autoridad.public).unwrap();
}

#[test]
fn p2_sonda_con_hechos_altos_sigue_deny_por_capacidad_ausente() {
    let autoridad = fk();
    let mut libro = LibroControl::nuevo();
    let ahora = 10_000u64;
    // Hechos que pasarían C4/C5 mínimos de control para varias clases
    for (tipo, clase) in [
        (TipoHecho::Custodia, Some(ClaseEfecto::Ef1)),
        (TipoHecho::Exclusividad, Some(ClaseEfecto::Ef1)),
        (TipoHecho::PepAtestado, Some(ClaseEfecto::Ef1)),
        (TipoHecho::SondaOk, Some(ClaseEfecto::Ef1)),
        (TipoHecho::Delegado, Some(ClaseEfecto::Ef1)),
    ] {
        libro.registrar_hecho(
            HechoFirmadoLibro::firmar(tipo, sys(), clase, true, 1, 1, ahora, "h", &autoridad)
                .unwrap(),
        );
    }
    let res = ejecutar_sonda_doce_sin_capacidad(&libro, &sys(), 1, ahora, &autoridad).unwrap();
    assert!(res.completo_12_deny);
    let ef1 = res.recibos.iter().find(|r| r.clase == ClaseEfecto::Ef1).unwrap();
    assert!(ef1.pasos.iter().any(|p| *p == "emision_exige_capacidad"));
    assert!(ef1.codigo_razon.contains("CAPACIDAD_AUSENTE") || ef1.resultado == sak_core::libro::ResultadoIntentoSonda::Deny);
}

#[test]
fn p3_c5_calculado_sobre_hechos_aportados_no_host() {
    let v = VistaHechos {
        custodia: true,
        exclusividad: true,
        pep_atestado: true,
        sonda_ok: true,
        delegado: true,
        confinado: true,
        observable: false,
        ef9_abierto: false,
    };
    let nivel = calcular_nivel_base(v);
    assert_eq!(nivel, NivelControl::C5);
    assert_eq!(
        nivel.denominacion_c5_calculado(),
        Some(C5_CALCULADO_SOBRE_HECHOS_APORTADOS)
    );
    assert_eq!(
        sak_core::libro::denominacion_si_c5_calculado(nivel),
        Some("C5_CALCULADO_SOBRE_HECHOS_APORTADOS")
    );
    assert_ne!(C5_CALCULADO_SOBRE_HECHOS_APORTADOS, C5_HOST_REAL_PROHIBIDO);
    // Prohibido inferir host real
    assert!(!PerfilEf9::ConfinadoAtestado.afirma_c5_host_real());
}

#[test]
fn n2_confinado_sin_custodia_no_es_c5() {
    let v = VistaHechos {
        confinado: true,
        delegado: true,
        custodia: false,
        exclusividad: true,
        pep_atestado: true,
        sonda_ok: true,
        ..VistaHechos::default()
    };
    assert_ne!(calcular_nivel_base(v), NivelControl::C5);
    let v2 = VistaHechos {
        confinado: true,
        delegado: true,
        custodia: true,
        exclusividad: false,
        pep_atestado: true,
        sonda_ok: true,
        ..VistaHechos::default()
    };
    assert_ne!(calcular_nivel_base(v2), NivelControl::C5);
}

#[test]
fn p4_multiparte_quorum_vista() {
    assert_eq!(quorum_dos_tercios_mas_uno(3), 3);
    assert_eq!(quorum_dos_tercios_mas_uno(4), 3);
    assert_eq!(quorum_dos_tercios_mas_uno(5), 4);

    let n1 = IdNodo::nuevo("n1").unwrap();
    let n2 = IdNodo::nuevo("n2").unwrap();
    let n3 = IdNodo::nuevo("n3").unwrap();
    let k1 = fk();
    let k2 = fk();
    let k3 = fk();
    let nodos = vec![n1.clone(), n2.clone(), n3.clone()];
    let firmantes = [
        (n1.clone(), &k1),
        (n2.clone(), &k2),
        (n3.clone(), &k3),
    ];
    let cert = emitir_certificado_vista("vista-a", 2, 2, nodos, &firmantes).unwrap();
    let pks: Vec<_> = [
        (n1, k1.public.as_slice()),
        (n2, k2.public.as_slice()),
        (n3, k3.public.as_slice()),
    ]
    .into_iter()
    .collect();
    aceptar_certificado(&cert, &pks).unwrap();
}

#[test]
fn n4_certificado_quorum_insuficiente_o_firma_invalida() {
    let n1 = IdNodo::nuevo("a").unwrap();
    let n2 = IdNodo::nuevo("b").unwrap();
    let n3 = IdNodo::nuevo("c").unwrap();
    let k1 = fk();
    let nodos = vec![n1.clone(), n2.clone(), n3.clone()];
    // Solo 1 firma; umbral para N=3 es 3
    let err = emitir_certificado_vista("v", 1, 1, nodos, &[(n1.clone(), &k1)]).unwrap_err();
    assert!(matches!(err, ErrorVista::QuorumInsuficiente { .. }));

    let k2 = fk();
    let k3 = fk();
    let nodos = vec![n1.clone(), n2.clone(), n3.clone()];
    let cert = emitir_certificado_vista(
        "v2",
        1,
        1,
        nodos,
        &[(n1.clone(), &k1), (n2.clone(), &k2), (n3.clone(), &k3)],
    )
    .unwrap();
    // PK incorrecta
    let bad = fk();
    let pks = [
        (n1, bad.public.as_slice()),
        (n2, k2.public.as_slice()),
        (n3, k3.public.as_slice()),
    ];
    assert!(aceptar_certificado(&cert, &pks).is_err());
}

#[test]
fn p5_integracion_b18_confinado_atestado_cierra_ef9() {
    let fk = fk();
    let mut libro = LibroControl::nuevo();
    let mut eval = EvaluadorEf9::nuevo();
    let reloj = RelojInyectado::nuevo(20_000);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("s-m12").unwrap();
    let obs = ObservacionEntornoEf9 {
        senales: BTreeSet::new(),
        demostracion_codigo_ausente: true,
        runtime_minimo_declarado: true,
        salida_solo_mediada: true,
    };
    let r = eval
        .sincronizar_libro(
            &sys(),
            PerfilEf9::ConfinadoAtestado,
            &obs,
            None,
            &mut libro,
            &fk,
            1,
            reloj.ahora(),
            Some(&sujeto),
            Some(&mut ledger),
        )
        .unwrap();
    match r {
        sak_core::libro::ResultadoEvaluacionEf9::EstadoSincronizado {
            ef9_abierto,
            perfil,
        } => {
            assert!(!ef9_abierto);
            assert_eq!(perfil, PerfilEf9::ConfinadoAtestado);
        }
        other => panic!("{other}"),
    }
    assert!(!PerfilEf9::ConfinadoAtestado.afirma_c5_host_real());
}

#[test]
fn n3_allow_en_sonda_falla_verificacion() {
    let autoridad = fk();
    let libro = LibroControl::nuevo();
    let mut res = ejecutar_sonda_doce_sin_capacidad(&libro, &sys(), 1, 1, &autoridad).unwrap();
    res.recibos[0].resultado = sak_core::libro::ResultadoIntentoSonda::Allow;
    res.completo_12_deny = false;
    assert!(verificar_resultado_sonda(&res, &autoridad.public).is_err());
}

#[test]
fn n5_ef12_sonda_y_alcance_emision() {
    let autoridad = fk();
    let libro = LibroControl::nuevo();
    let res = ejecutar_sonda_doce_sin_capacidad(&libro, &sys(), 1, 1, &autoridad).unwrap();
    assert!(es_deny_ef12(
        res.recibos.iter().find(|r| r.clase == ClaseEfecto::Ef12).unwrap()
    ));

    let hash = HashPaqueteNormativo::desde_bytes([3u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-x").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let reloj = RelojInyectado::nuevo(1);
    let params = ParametrosEmision {
        sistema: sys(),
        digest_efecto: [0u8; LONGITUD_HASH_PAQUETE],
        alcance: Alcance::minimo(["EF-12"]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 100,
        clasificacion: ClasificacionEfecto::reversible_sin_personas(),
    };
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("ef12").unwrap();
    let err = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap_err();
    // emitir() rechaza alcance EF-12; el ledger lo proyecta como EmisionCapacidadRechazada.
    assert!(matches!(
        err,
        sak_core::evidencia::ErrorEvidencia::EmisionCapacidadRechazada
    ));
}

#[test]
fn n6_limites_no_comprobado_en_atestacion_y_sonda() {
    let autoridad = fk();
    let at = AtestacionConfinamiento::emitir(sys(), 1, 1, &entrada_i10_ok(), &autoridad).unwrap();
    let joined = at.no_comprobado.join("|");
    assert!(joined.contains("DESP") || joined.contains("TCB") || joined.contains("HSM"));
    assert!(joined.contains("GOB") || joined.contains("conformidad"));
    assert!(!joined.contains("C5_HOST_REAL afirmado"));

    let libro = LibroControl::nuevo();
    let sonda = ejecutar_sonda_doce_sin_capacidad(&libro, &sys(), 1, 1, &autoridad).unwrap();
    assert!(sonda.no_comprobado.iter().any(|x| x.contains("ALCANZABLES")));
}

#[test]
fn multiparte_vista_conflictiva() {
    let n1 = IdNodo::nuevo("x").unwrap();
    let n2 = IdNodo::nuevo("y").unwrap();
    let n3 = IdNodo::nuevo("z").unwrap();
    let k1 = fk();
    let k2 = fk();
    let k3 = fk();
    let nodos = vec![n1.clone(), n2.clone(), n3.clone()];
    let firmantes = [(n1.clone(), &k1), (n2.clone(), &k2), (n3.clone(), &k3)];
    let a = emitir_certificado_vista("A", 5, 5, nodos.clone(), &firmantes).unwrap();
    let b = emitir_certificado_vista("B", 5, 5, nodos, &firmantes).unwrap();
    let pks = [
        (n1, k1.public.as_slice()),
        (n2, k2.public.as_slice()),
        (n3, k3.public.as_slice()),
    ];
    let accepted = Some(a);
    let err = registrar_vista_si_compatible(&accepted, &b, &pks).unwrap_err();
    assert!(matches!(err, ErrorVista::VistaConflictiva));
}
