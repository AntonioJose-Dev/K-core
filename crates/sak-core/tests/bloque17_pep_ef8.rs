//! Harnesses rebanada repo EF-8 (tests/bloque17_*): PEP de consumo.
//! No es bloque §M. Matriz C EF-8 [V1.1-H1]. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

use sak_core::capacidad::{CausaDenegacion, ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef3, alcance_ef8, preparar_solicitud_consumo, preparar_solicitud_escritura,
    AdaptadorConsumoSimulado, ArtefactoConsumo, CAMPO_CONSECUENCIA_EF8, ClaseDecisionPersona,
    CodigoPep, CredencialEscritura, EjecutorSimulado, ErrorEgreso, EstadoConsumo, EtiquetaHecho,
    GatewayConsumoDecisionPersona, GatewayEscritura, HechoDecisionExigido, OperacionEscritura,
    PrecondicionesPepEf3, PrecondicionesPepEf8, ResultadoPepConsumo, ResultadoPepEscritura,
    SolicitudConsumoCruda, SolicitudConsumoDecisionPersona, SolicitudEscritura,
    SolicitudEscrituraCruda, TipoHechoDecision, TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(hash_pkg(seed));
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva(format!("N-EF8-{seed}")).unwrap()], vec![], 1)
            .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn hechos_base(seed: u8) -> Vec<HechoDecisionExigido> {
    vec![
        HechoDecisionExigido {
            tipo: TipoHechoDecision::SupervisionHumana,
            etiqueta: EtiquetaHecho::Gob,
            digest: [seed.wrapping_add(1); LONGITUD_HASH_PAQUETE],
            vigente_hasta: 100_000,
        },
        HechoDecisionExigido {
            tipo: TipoHechoDecision::Quorum,
            etiqueta: EtiquetaHecho::Gob,
            digest: [seed.wrapping_add(2); LONGITUD_HASH_PAQUETE],
            vigente_hasta: 100_000,
        },
        HechoDecisionExigido {
            tipo: TipoHechoDecision::Plazo,
            etiqueta: EtiquetaHecho::ValExt,
            digest: [seed.wrapping_add(3); LONGITUD_HASH_PAQUETE],
            vigente_hasta: 100_000,
        },
        HechoDecisionExigido {
            tipo: TipoHechoDecision::ClasificacionRiesgo,
            etiqueta: EtiquetaHecho::Gob,
            digest: [seed.wrapping_add(4); LONGITUD_HASH_PAQUETE],
            vigente_hasta: 100_000,
        },
    ]
}

fn sol_base(seed: u8) -> SolicitudConsumoDecisionPersona {
    SolicitudConsumoDecisionPersona::nueva(
        format!("sujeto-pseudo-{seed}"),
        ClaseDecisionPersona::Priorizacion,
        "canal-consumo-auth",
        "operador-humano",
        "aplicar_ranking",
        [0xE8u8; LONGITUD_HASH_PAQUETE],
        "modelo-scoring-v1",
        "1.0.0",
        "asignacion-turno",
        "alto",
        true,
        false,
        false,
        0,
        u64::MAX,
        hash_pkg(seed),
        1,
        [0xC8u8; LONGITUD_HASH_PAQUETE],
        hechos_base(seed),
    )
    .unwrap()
}

fn emitir_ef8(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudConsumoDecisionPersona,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_consumo(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef8(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: !s.reversible,
            afecta_personas: true,
            datos_personales: s.datos_personales,
        },
    };
    ledger
        .emitir_tras_evidencia(sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn pre_ok() -> PrecondicionesPepEf8 {
    PrecondicionesPepEf8::todas_ok()
}

fn ejercer(
    gw: &mut GatewayConsumoDecisionPersona,
    sol: &SolicitudConsumoDecisionPersona,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    pre: &PrecondicionesPepEf8,
    hechos: &[HechoDecisionExigido],
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    adap: &mut AdaptadorConsumoSimulado,
    reloj: &RelojInyectado,
    ahora: u64,
    silencio: bool,
) -> ResultadoPepConsumo {
    gw.ejercer(
        &SolicitudConsumoCruda::Tipada(sol.clone()),
        cap,
        sistema,
        sujeto,
        pre,
        hechos,
        ledger,
        adap,
        reloj,
        1,
        Some(ahora),
        silencio,
    )
}

#[test]
fn minimo_c3_capacidad_y_ciclo() {
    assert!(!GatewayConsumoDecisionPersona::puede_emitir_capacidad());
    assert!(!GatewayConsumoDecisionPersona::posee_artefacto_consumo_expuesto());

    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-c3").unwrap();
    let sujeto = IdSujeto::nuevo("suj-c3").unwrap();
    let sol = sol_base(1);
    let cap = emitir_ef8(1, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [1u8; 32]));

    let mut pre = pre_ok();
    pre.libro_c3 = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::ControlInsuficiente
        }
    ));

    let pre = pre_ok();
    assert!(matches!(
        ejercer(
            &mut gw, &sol, None, &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(2);
    let cap2 = emitir_ef8(2, &sistema, &sol2, &mut ledger2, &reloj, &sujeto);
    let mut gw2 = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap2 =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [2u8; 32]));
    assert!(cap2.un_solo_uso());
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos,
            &mut ledger2, &mut adap2, &reloj, 10, false
        ),
        ResultadoPepConsumo::Permitido(_)
    ));
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos,
            &mut ledger2, &mut adap2, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida)
        }
    ));
}

#[test]
fn sujeto_resultado_clase_accion_canal_destinatario_finalidad_version_periodo_alterados() {
    let reloj = RelojInyectado::nuevo(1);
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();

    let casos: Vec<(&str, Box<dyn Fn(&mut SolicitudConsumoDecisionPersona)>)> = vec![
        ("sujeto", Box::new(|s| s.id_sujeto_afectado = "otro".into())),
        ("resultado", Box::new(|s| s.digest_resultado[0] ^= 0xff)),
        ("clase", Box::new(|s| s.clase = ClaseDecisionPersona::Credito)),
        ("accion", Box::new(|s| s.accion_habilitada = "denegar".into())),
        ("canal", Box::new(|s| s.sistema_canal = "canal-alt".into())),
        ("destinatario", Box::new(|s| s.destinatario = "otro-op".into())),
        ("finalidad", Box::new(|s| s.finalidad = "otra".into())),
        ("version", Box::new(|s| s.version_resultado = "9.9".into())),
        ("periodo", Box::new(|s| {
            s.validez_desde = 50;
            s.validez_hasta = 60;
        })),
    ];

    for (i, (nombre, mutar)) in casos.into_iter().enumerate() {
        let seed = 10 + i as u8;
        let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
        let sol_auth = sol_base(seed);
        let cap = emitir_ef8(seed, &sistema, &sol_auth, &mut ledger, &reloj, &sujeto);
        let mut sol = sol_auth.clone();
        mutar(&mut sol);
        let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
        let mut adap = AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla(
            "canal-consumo-auth",
            [seed; 32],
        ));
        let r = ejercer(
            &mut gw,
            &sol,
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &sol.hechos_exigidos,
            &mut ledger,
            &mut adap,
            &reloj,
            10,
            false,
        );
        assert!(
            matches!(r, ResultadoPepConsumo::Denegado { .. }),
            "esperado DENY para {nombre}: {r:?}"
        );
    }
}

#[test]
fn hechos_supervision_quorum_plazo_ausentes_o_vencidos() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-hechos").unwrap();
    let sujeto = IdSujeto::nuevo("suj-hechos").unwrap();
    let sol = sol_base(20);
    let cap = emitir_ef8(20, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [20u8; 32]));

    let incompletos: Vec<_> = sol.hechos_exigidos.iter().take(1).cloned().collect();
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &incompletos,
            &mut ledger, &mut adap, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::HechoDecisionAusente
        }
    ));

    let mut vencidos = sol.hechos_exigidos.clone();
    for h in &mut vencidos {
        h.vigente_hasta = 5;
    }
    let mut sol_v = sol.clone();
    sol_v.hechos_exigidos = vencidos.clone();
    // Capacidad emitida con hechos vigentes; consumo con hechos vencidos en solicitud
    // cambia el digest → denegación por digest/capacidad. Forzamos hechos presentes vencidos
    // con misma solicitud canónica vía solo presentes.
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(21);
    let cap2 = emitir_ef8(21, &sistema, &sol2, &mut ledger2, &reloj, &sujeto);
    let mut presentes_v = sol2.hechos_exigidos.clone();
    for h in &mut presentes_v {
        h.vigente_hasta = 5;
    }
    let mut gw2 = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap2 =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [21u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &presentes_v,
            &mut ledger2, &mut adap2, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::HechoDecisionVencido
        }
    ));
}

#[test]
fn revocacion_silenciosa_deny() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-sil").unwrap();
    let sujeto = IdSujeto::nuevo("suj-sil").unwrap();
    let sol = sol_base(30);
    let cap = emitir_ef8(30, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [30u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, 10, true
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::Capacidad(_)
        }
    ));
}

#[test]
fn capacidad_expirada_revocada() {
    let reloj = RelojInyectado::nuevo(0);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-exp").unwrap();
    let sujeto = IdSujeto::nuevo("suj-exp").unwrap();
    let sol = sol_base(40);
    let (s, digest) = preparar_solicitud_consumo(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef8(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 5,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision_allow(40), params, &reloj)
        .unwrap();
    let reloj_tarde = RelojInyectado::nuevo(100);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [40u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj_tarde, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada)
        }
    ));

    let reloj2 = RelojInyectado::nuevo(1);
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(41);
    let cap2 = emitir_ef8(41, &sistema, &sol2, &mut ledger2, &reloj2, &sujeto);
    let mut gw2 = GatewayConsumoDecisionPersona::nuevo(1);
    gw2.verificador_mut().revocar(*cap2.id());
    let mut adap2 =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [41u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos,
            &mut ledger2, &mut adap2, &reloj2, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada)
        }
    ));
}

#[test]
fn artefacto_no_expuesto_y_ruta_directa_bloqueada() {
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [50u8; 32]));
    assert!(!adap.artefacto_expuesto());
    let sol = sol_base(50);
    let err = adap.llamar_directo(&sol).unwrap_err();
    assert!(matches!(err, ErrorEgreso::BloqueadoSinPep));
    assert_eq!(adap.intentos_directos, 1);
    assert_eq!(adap.consumos_delegados, 0);
}

#[test]
fn exclusividad_canal_falsa_deniega() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-excl").unwrap();
    let sujeto = IdSujeto::nuevo("suj-excl").unwrap();
    let sol = sol_base(55);
    let cap = emitir_ef8(55, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [55u8; 32]));
    let mut pre = pre_ok();
    pre.exclusividad_canal = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::ExclusividadCanalFalsa
        }
    ));
}

#[test]
fn escritura_ef3_con_consecuencia_ef8_exige_gateway() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-inter").unwrap();
    let sujeto = IdSujeto::nuevo("suj-inter").unwrap();
    let sol = SolicitudEscritura::nueva(
        OperacionEscritura::Update,
        "tabla-estado",
        [0x33u8; LONGITUD_HASH_PAQUETE],
        Some(1),
        ["estado", CAMPO_CONSECUENCIA_EF8],
        [0x44u8; LONGITUD_HASH_PAQUETE],
        1,
        "dest-kernel",
        false,
        true,
        hash_pkg(60),
    )
    .unwrap();
    let (s, digest) = preparar_solicitud_escritura(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef3(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: true,
            afecta_personas: true,
            datos_personales: true,
        },
    };
    let hash = HashPaqueteNormativo::desde_bytes(hash_pkg(60));
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF3-60").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap();

    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([60u8; 32]));
    let pre = PrecondicionesPepEf3::todas_ok();
    assert!(!pre.consumo_ef8_autorizado);
    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
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
            codigo: CodigoPep::ConsumoEf8Requerido
        }
    ));

    let mut pre_ok_ef8 = PrecondicionesPepEf3::todas_ok();
    pre_ok_ef8.consumo_ef8_autorizado = true;
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let cap2 = ledger2
        .emitir_tras_evidencia(
            &sujeto,
            DecisionPermitida::nueva(
                HashPaqueteNormativo::desde_bytes(hash_pkg(60)),
                TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF3-60b").unwrap()], vec![], 1)
                    .unwrap(),
                None,
            )
            .unwrap(),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: digest,
                alcance: alcance_ef3(&s),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto {
                    irreversible: true,
                    afecta_personas: true,
                    datos_personales: true,
                },
            },
            &reloj,
        )
        .unwrap();
    let mut gw2 = GatewayEscritura::nuevo(1);
    let mut exe2 = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([61u8; 32]));
    let r2 = gw2.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap2),
        &sistema,
        &sujeto,
        &pre_ok_ef8,
        &mut ledger2,
        &mut exe2,
        &reloj,
        1,
        false,
    );
    assert!(
        matches!(r2, ResultadoPepEscritura::Permitido(_)),
        "esperado Permitido con consumo_ef8_autorizado: {r2:?}"
    );
}

#[test]
fn respuesta_recibo_divergente_incidente() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-div").unwrap();
    let sujeto = IdSujeto::nuevo("suj-div").unwrap();
    let sol = sol_base(70);
    let cap = emitir_ef8(70, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [70u8; 32]));
    adap.forzar_divergencia = true;
    let r = ejercer(
        &mut gw,
        &sol,
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &sol.hechos_exigidos,
        &mut ledger,
        &mut adap,
        &reloj,
        10,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert!(gw
        .incidentes()
        .iter()
        .any(|i| i.tipo == TipoIncidente::DivergenciaParametros));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(71);
    let cap2 = emitir_ef8(71, &sistema, &sol2, &mut ledger2, &reloj, &sujeto);
    let mut gw2 = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap2 =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [71u8; 32]));
    adap2.forzar_accion_distinta = true;
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos,
            &mut ledger2, &mut adap2, &reloj, 10, false
        ),
        ResultadoPepConsumo::Denegado {
            codigo: CodigoPep::AccionConsumoNoAutorizada
        }
    ));
}

#[test]
fn integridad_offline_cadena_completa() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base(80);
    let cap = emitir_ef8(80, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayConsumoDecisionPersona::nuevo(1);
    let mut adap =
        AdaptadorConsumoSimulado::nuevo(ArtefactoConsumo::desde_semilla("canal-consumo-auth", [80u8; 32]));
    let r = ejercer(
        &mut gw,
        &sol,
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &sol.hechos_exigidos,
        &mut ledger,
        &mut adap,
        &reloj,
        10,
        false,
    );
    match r {
        ResultadoPepConsumo::Permitido(resp) => {
            assert_eq!(resp.estado, EstadoConsumo::Entregado);
            assert!(!resp.id_externo.is_empty());
            assert_eq!(resp.digest_solicitud, *cap.digest_efecto());
        }
        other => panic!("{other:?}"),
    }
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Decision));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::DecisionPersona));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}

#[test]
fn rechazo_solicitud_malformada() {
    assert!(SolicitudConsumoDecisionPersona::nueva(
        "*",
        ClaseDecisionPersona::Seleccion,
        "c",
        "d",
        "a",
        [0u8; LONGITUD_HASH_PAQUETE],
        "f",
        "1",
        "fin",
        "imp",
        false,
        false,
        true,
        0,
        1,
        [0u8; LONGITUD_HASH_PAQUETE],
        1,
        [0u8; LONGITUD_HASH_PAQUETE],
        vec![],
    )
    .is_err());
}
