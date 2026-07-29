//! Harnesses rebanada repo EF-11 (tests/bloque20_*): PEP físico interpuesto (simulado).
//! No es bloque §M. Matriz C EF-11 / F.9. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.
//!
//! Los tests prueban el módulo interpuesto y las rutas instrumentadas.
//! No prueban ausencia de mando manual, bypass eléctrico o ruta física desconocida.
//! No implementan hardware real, certificación sectorial, C5, HSM ni atestación física.

use sak_core::capacidad::{ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef4, alcance_ef11, preparar_solicitud_fisica, preparar_solicitud_herramienta,
    traducir_fisico_desde_herramienta, AdaptadorSimulado, AprobacionHumanaFisica,
    AutoridadBus, BrokerHerramientas, CatalogoHerramientas, ClaseEfecto, CodigoPep,
    EntradaHerramienta, ErrorEgreso, ErrorModuloFisico, EtiquetaHecho, EjecutorNegocio,
    FaseEjecucionFisica, GatewayComunicaciones, GatewayEfectoFisico, GatewayPublicacion,
    HechoFisicoExigido, InterlocksLocales, LimitesFisicos, ModoOperativo, ModuloFisicoInterpuesto,
    OperacionFisica, ParametrosFisicos, PrecondicionesPepEf4, PrecondicionesPepEf5,
    PrecondicionesPepEf6, PrecondicionesPepEf7, PrecondicionesPepEf11, ResultadoPepFisico,
    ResultadoPepHerramienta, SolicitudEfectoFisico, SolicitudFisicaCruda,
    SolicitudHerramientaCruda, TipoHechoContacto, TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(hash_pkg(seed));
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva(format!("N-EF11-{seed}")).unwrap()], vec![], 1)
            .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn hecho(seed: u8) -> HechoFisicoExigido {
    HechoFisicoExigido {
        tipo: TipoHechoContacto::AprobacionHumana,
        etiqueta: EtiquetaHecho::Gob,
        digest: [seed; LONGITUD_HASH_PAQUETE],
    }
}

fn sol_base(seed: u8) -> SolicitudEfectoFisico {
    let params = ParametrosFisicos::nuevo(10, 1, 1000, 5, "mm", "mm/s", "J").unwrap();
    SolicitudEfectoFisico::nueva(
        "sys-fis",
        "inst-1",
        "zona-a",
        "actuador-lineal",
        "act-alpha",
        "ctl-1",
        "bus-1",
        OperacionFisica::Activar,
        params,
        LimitesFisicos::tipicos(),
        "reposo",
        "activo",
        0,
        u64::MAX,
        true,
        "parada_e_stop",
        "alta",
        "mecanico",
        false,
        true,
        "ninguno",
        ModoOperativo::Normal,
        "posicionamiento",
        [seed; LONGITUD_HASH_PAQUETE],
        1,
        hash_pkg(seed),
        vec![hecho(seed)],
        true,
        "operador-fisico",
    )
    .unwrap()
}

fn emitir_ef11(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudEfectoFisico,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_fisica(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef11(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: !s.reversible,
            afecta_personas: false,
            datos_personales: false,
        },
    };
    ledger
        .emitir_tras_evidencia(sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn pre_ok() -> PrecondicionesPepEf11 {
    PrecondicionesPepEf11::todas_ok()
}

fn modulo_ok(ahora: u64) -> ModuloFisicoInterpuesto {
    let mut m = ModuloFisicoInterpuesto::nuevo(AutoridadBus::desde_semilla("bus-1", [0x11u8; 32]), ahora);
    m.declarar_bus("bus-1");
    m.set_estado("act-alpha", "reposo");
    m.latido(ahora);
    m
}

fn aprobacion_ok(sol: &SolicitudEfectoFisico, ahora: u64) -> AprobacionHumanaFisica {
    let digest = sak_core::pep::digest_solicitud_fisica(sol);
    AprobacionHumanaFisica {
        id_humano: "hum-1".into(),
        rol: "supervisor".into(),
        competencia: sol.competencia_requerida.clone(),
        independiente: true,
        firmado_en: ahora.saturating_sub(1),
        vigente_hasta: ahora.saturating_add(10_000),
        digest_solicitud: digest,
        digest_contexto: sol.digest_contexto,
        firma_presente: true,
    }
}

fn ejercer(
    gw: &mut GatewayEfectoFisico,
    sol: &SolicitudEfectoFisico,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    pre: &PrecondicionesPepEf11,
    hechos: &[HechoFisicoExigido],
    aprob: Option<&AprobacionHumanaFisica>,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    modulo: Option<&mut ModuloFisicoInterpuesto>,
    reloj: &RelojInyectado,
    ahora: u64,
    silencio: bool,
) -> ResultadoPepFisico {
    gw.ejercer(
        &SolicitudFisicaCruda::Tipada(sol.clone()),
        cap,
        sistema,
        sujeto,
        pre,
        hechos,
        aprob,
        ledger,
        modulo,
        reloj,
        1,
        Some(ahora),
        silencio,
    )
}

#[test]
fn ausencia_modulo_es_c0_deny() {
    assert!(!GatewayEfectoFisico::puede_emitir_capacidad());
    assert!(!GatewayEfectoFisico::posee_autoridad_bus_expuesta());
    assert!(!ModuloFisicoInterpuesto::nuevo(AutoridadBus::desde_semilla("bus-1", [1u8; 32]), 1)
        .autoridad_expuesta());

    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-c0").unwrap();
    let sujeto = IdSujeto::nuevo("suj-c0").unwrap();
    let sol = sol_base(1);
    let cap = emitir_ef11(1, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let aprob = aprobacion_ok(&sol, 10);

    let mut pre = pre_ok();
    pre.modulo_interpuesto = false;
    assert!(pre.clasificacion_c0());
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, None, &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::ModuloFisicoAusente
        }
    ));
}

#[test]
fn ruta_alternativa_declarada_c0_deny() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_base(2);
    let cap = emitir_ef11(2, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);
    let aprob = aprobacion_ok(&sol, 10);
    let mut pre = pre_ok();
    pre.ruta_alternativa_declarada = true;
    assert!(pre.clasificacion_c0());
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::ModuloFisicoAusente
        }
    ));
}

#[test]
fn latido_c0_c3_y_autorizacion() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-pre").unwrap();
    let sujeto = IdSujeto::nuevo("suj-pre").unwrap();
    let sol = sol_base(3);
    let cap = emitir_ef11(3, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);
    let aprob = aprobacion_ok(&sol, 10);

    let mut pre = pre_ok();
    pre.latido_modulo = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::LatidoModuloAusente
        }
    ));

    pre = pre_ok();
    pre.libro_c4 = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::ControlInsuficiente
        }
    ));

    assert!(matches!(
        ejercer(
            &mut gw, &sol, None, &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));

    // Capacidad de un solo uso: primer ALLOW; segundo DENY (capacidad o replay/estado).
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto2 = IdSujeto::nuevo("suj-reuse").unwrap();
    let sol2 = sol_base(4);
    let cap2 = emitir_ef11(4, &sistema, &sol2, &mut ledger2, &reloj, &sujeto2);
    let mut gw2 = GatewayEfectoFisico::nuevo(1);
    let mut mod2 = modulo_ok(10);
    let aprob2 = aprobacion_ok(&sol2, 10);
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto2, &pre_ok(), &sol2.hechos_exigidos,
            Some(&aprob2), &mut ledger2, Some(&mut mod2), &reloj, 10, false
        ),
        ResultadoPepFisico::Permitido(_)
    ));
    assert!(matches!(
        ejercer(
            &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto2, &pre_ok(), &sol2.hechos_exigidos,
            Some(&aprob2), &mut ledger2, Some(&mut mod2), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado { .. }
    ));
}

#[test]
fn revocacion_sincrona_sin_cache_permisiva() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-rev").unwrap();
    let sujeto = IdSujeto::nuevo("suj-rev").unwrap();
    let sol = sol_base(5);
    let cap = emitir_ef11(5, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);
    let aprob = aprobacion_ok(&sol, 10);
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, true
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::Capacidad(_)
        }
    ));
}

#[test]
fn ordenes_libres_compuestas_y_campos_alterados() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt2").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt2").unwrap();
    let mut sol = sol_base(6);
    // Sin supervisión para alcanzar validación de alcance exacto.
    sol = SolicitudEfectoFisico::nueva(
        sol.sistema.clone(),
        sol.instancia.clone(),
        sol.instalacion_zona.clone(),
        sol.familia_activo.clone(),
        sol.id_actuador.clone(),
        sol.id_controlador.clone(),
        sol.id_bus.clone(),
        sol.operacion,
        sol.parametros.clone(),
        sol.limites.clone(),
        sol.estado_inicial.clone(),
        sol.estado_objetivo.clone(),
        sol.ventana_desde,
        sol.ventana_hasta,
        sol.reversible,
        sol.procedimiento_parada.clone(),
        sol.criticidad.clone(),
        sol.categoria_dano.clone(),
        sol.presencia_humana,
        sol.zona_segura,
        sol.destinatarios_afectados.clone(),
        sol.modo,
        sol.finalidad.clone(),
        sol.digest_contexto,
        sol.epoca,
        sol.hash_paquete,
        sol.hechos_exigidos.clone(),
        false,
        "",
    )
    .unwrap();
    let cap = emitir_ef11(6, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);

    assert!(matches!(
        gw.ejercer(
            &SolicitudFisicaCruda::OrdenLibre, Some(&cap), &sistema, &sujeto, &pre_ok(),
            &sol.hechos_exigidos, None, &mut ledger, Some(&mut modulo), &reloj, 1, Some(10), false
        ),
        ResultadoPepFisico::Denegado { codigo: CodigoPep::OrdenFisicaLibre }
    ));
    assert!(matches!(
        gw.ejercer(
            &SolicitudFisicaCruda::CompuestaNoDeclarada, Some(&cap), &sistema, &sujeto, &pre_ok(),
            &sol.hechos_exigidos, None, &mut ledger, Some(&mut modulo), &reloj, 1, Some(10), false
        ),
        ResultadoPepFisico::Denegado { codigo: CodigoPep::OrdenFisicaCompuesta }
    ));

    let mut sol_alt = sol.clone();
    sol_alt.id_actuador = "act-otro".into();
    assert!(matches!(
        ejercer(
            &mut gw, &sol_alt, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            None, &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::ActuadorFisicoNoAutorizado
                | CodigoPep::Capacidad(_)
        }
    ));

    let mut sol_bus = sol.clone();
    sol_bus.id_bus = "bus-shadow".into();
    assert!(matches!(
        ejercer(
            &mut gw, &sol_bus, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            None, &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::BusFisicoNoAutorizado | CodigoPep::Capacidad(_)
        }
    ));
}

#[test]
fn aprobacion_humana_fallos() {
    let reloj = RelojInyectado::nuevo(100);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-hum").unwrap();
    let sujeto = IdSujeto::nuevo("suj-hum").unwrap();
    let sol = sol_base(7);
    let cap = emitir_ef11(7, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(100);

    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            None, &mut ledger, Some(&mut modulo), &reloj, 100, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::AprobacionHumanaAusente
        }
    ));

    let mut a = aprobacion_ok(&sol, 100);
    a.competencia = "otro".into();
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&a), &mut ledger, Some(&mut modulo), &reloj, 100, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::AprobacionHumanaIncompetente
        }
    ));

    a = aprobacion_ok(&sol, 100);
    a.independiente = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&a), &mut ledger, Some(&mut modulo), &reloj, 100, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::AprobacionHumanaNoIndependiente
        }
    ));

    a = aprobacion_ok(&sol, 100);
    a.vigente_hasta = 50;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&a), &mut ledger, Some(&mut modulo), &reloj, 100, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::AprobacionHumanaFueraPlazo
        }
    ));

    a = aprobacion_ok(&sol, 100);
    a.digest_solicitud[0] ^= 0xff;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&a), &mut ledger, Some(&mut modulo), &reloj, 100, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::AprobacionHumanaDigestDivergente
        }
    ));
}

#[test]
fn interlocks_replay_telemetria_y_ruta_directa() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-il").unwrap();
    let sujeto = IdSujeto::nuevo("suj-il").unwrap();
    let sol = sol_base(8);
    let cap = emitir_ef11(8, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);
    let aprob = aprobacion_ok(&sol, 10);

    modulo.interlocks = InterlocksLocales {
        paro_emergencia: true,
        ..Default::default()
    };
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false
        ),
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::InterlockFisico
        }
    ));

    // Nueva capacidad: timeout → incidente (no éxito).
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto2 = IdSujeto::nuevo("suj-to").unwrap();
    let sol2 = sol_base(9);
    let cap2 = emitir_ef11(9, &sistema, &sol2, &mut ledger2, &reloj, &sujeto2);
    let mut gw2 = GatewayEfectoFisico::nuevo(1);
    let mut mod2 = modulo_ok(10);
    mod2.forzar_timeout = true;
    let aprob2 = aprobacion_ok(&sol2, 10);
    let r = ejercer(
        &mut gw2, &sol2, Some(&cap2), &sistema, &sujeto2, &pre_ok(), &sol2.hechos_exigidos,
        Some(&aprob2), &mut ledger2, Some(&mut mod2), &reloj, 10, false,
    );
    assert!(matches!(
        r,
        ResultadoPepFisico::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert!(!gw2.incidentes().is_empty());

    // Ruta directa instrumentada bloqueada.
    let mut mod3 = modulo_ok(10);
    assert!(matches!(
        mod3.llamar_directo(&sol),
        Err(ErrorEgreso::BloqueadoSinPep)
    ));
    assert_eq!(mod3.intentos_directos, 1);

    // Replay en módulo.
    let sol3 = sol_base(10);
    let digest = sak_core::pep::digest_solicitud_fisica(&sol3);
    let mut mod4 = modulo_ok(10);
    assert!(mod4.ejecutar_delegado(&sol3, &digest, 10).is_ok());
    assert!(matches!(
        mod4.ejecutar_delegado(&sol3, &digest, 10),
        Err(ErrorModuloFisico::Replay)
    ));
}

#[test]
fn ciclo_permitido_recibo_fases_y_offline() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ok").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ok").unwrap();
    let sol = sol_base(11);
    let cap = emitir_ef11(11, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEfectoFisico::nuevo(1);
    let mut modulo = modulo_ok(10);
    let aprob = aprobacion_ok(&sol, 10);

    match ejercer(
        &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
        Some(&aprob), &mut ledger, Some(&mut modulo), &reloj, 10, false,
    ) {
        ResultadoPepFisico::Permitido(r) => {
            assert_eq!(r.fase, FaseEjecucionFisica::EstadoObservado);
            assert_eq!(r.estado_observado, "activo");
            assert_eq!(r.recibo.digest_parametros, sak_core::pep::digest_solicitud_fisica(&sol));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(modulo.ordenes_delegadas, 1);
    assert!(ledger
        .exportar_paquete()
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::EfectoFisico));

    ledger.cerrar_epoca().unwrap();
    let informe = verificar_paquete(&ledger.exportar_paquete());
    assert!(informe.ok, "{:?}", informe.errores);
}

#[test]
fn composicion_ef4_ef11_y_ef5_interlock() {
    use sak_core::crypto::ParMlDsa87;
    use sak_core::pep::{
        AdaptadorComunicacionSimulado, AdaptadorNegocioSimulado, AdaptadorPublicacionSimulado,
        CredencialEnvio, CredencialNegocio, CredencialPublicacion, ResultadoPepComunicacion,
        ResultadoPepNegocio, ResultadoPepPublicacion, SolicitudComunicacionCruda,
        SolicitudHerramienta, SolicitudNegocioCruda, SolicitudPublicacionCruda,
    };

    let reloj = RelojInyectado::nuevo(20);
    let auth = ParMlDsa87::generar().unwrap();
    let e = EntradaHerramienta {
        id_herramienta: "actuator".into(),
        version: "1.0.0".into(),
        servidor: "field-bus".into(),
        operacion: "activar".into(),
        digest_esquema_args: hash_pkg(20),
        destinos_permitidos: vec!["act-alpha".into()],
        efecto_subyacente: ClaseEfecto::Ef11,
        reversible: true,
        datos_personales: false,
        cuota_maxima: 3,
        timeout_ms: 5_000,
    };
    let cat =
        CatalogoHerramientas::construir(vec![e.clone()], hash_pkg(20 ^ 0x11), hash_pkg(20), &auth)
            .unwrap();

    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-comp").unwrap();
    let sujeto = IdSujeto::nuevo("suj-comp").unwrap();

    let args = [20u8; LONGITUD_HASH_PAQUETE];
    let sol4 = SolicitudHerramienta::nueva(
        e.id_herramienta.clone(),
        e.version.clone(),
        e.servidor.clone(),
        e.operacion.clone(),
        e.digest_esquema_args,
        args,
        "act-alpha",
        ClaseEfecto::Ef11,
        true,
        false,
        3,
        5_000,
        [0x44u8; LONGITUD_HASH_PAQUETE],
        hash_pkg(20),
    )
    .unwrap();
    let (s4, d4) = preparar_solicitud_herramienta(sol4.clone());
    let cap4 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            DecisionPermitida::nueva(
                HashPaqueteNormativo::desde_bytes(hash_pkg(20)),
                TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF4-fis").unwrap()], vec![], 1)
                    .unwrap(),
                None,
            )
            .unwrap(),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d4,
                alcance: alcance_ef4(&s4),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto::irreversible(),
            },
            &reloj,
        )
        .unwrap();

    let sol11 = traducir_fisico_desde_herramienta(
        "actuator",
        "field-bus",
        "activar",
        "act-alpha",
        args,
        hash_pkg(20),
        false,
        true,
    )
    .unwrap();
    let (_, d11) = preparar_solicitud_fisica(sol11.clone());
    let cap11 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            DecisionPermitida::nueva(
                HashPaqueteNormativo::desde_bytes(hash_pkg(20)),
                TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF11-fis").unwrap()], vec![], 1)
                    .unwrap(),
                None,
            )
            .unwrap(),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d11,
                alcance: alcance_ef11(&sol11),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto {
                    irreversible: false,
                    afecta_personas: false,
                    datos_personales: false,
                },
            },
            &reloj,
        )
        .unwrap();

    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap4 = AdaptadorSimulado::nuevo();
    let r_deny = broker.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4.clone()),
        Some(&cap4),
        Some(&cap11),
        &sistema,
        &sujeto,
        &PrecondicionesPepEf4::todas_ok(),
        &cat,
        &mut ledger,
        &mut adap4,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r_deny,
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::PepSubyacenteInexistente
        }
    ));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto2 = IdSujeto::nuevo("suj-comp2").unwrap();
    let cap4b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            DecisionPermitida::nueva(
                HashPaqueteNormativo::desde_bytes(hash_pkg(20)),
                TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF4-fis2").unwrap()], vec![], 1)
                    .unwrap(),
                None,
            )
            .unwrap(),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d4,
                alcance: alcance_ef4(&s4),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto::irreversible(),
            },
            &reloj,
        )
        .unwrap();
    let cap11b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            DecisionPermitida::nueva(
                HashPaqueteNormativo::desde_bytes(hash_pkg(20)),
                TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-EF11-fis2").unwrap()], vec![], 1)
                    .unwrap(),
                None,
            )
            .unwrap(),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d11,
                alcance: alcance_ef11(&sol11),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto {
                    irreversible: false,
                    afecta_personas: false,
                    datos_personales: false,
                },
            },
            &reloj,
        )
        .unwrap();

    let mut broker2 = BrokerHerramientas::nuevo(1);
    let mut adap4b = AdaptadorSimulado::nuevo();
    let mut gw11 = GatewayEfectoFisico::nuevo(1);
    let mut mod11 = ModuloFisicoInterpuesto::nuevo(
        AutoridadBus::desde_semilla("bus-field-bus", [20u8; 32]),
        20,
    );
    mod11.declarar_bus("bus-field-bus");
    mod11.set_estado("act-alpha", "reposo");
    mod11.latido(20);
    let aprob = aprobacion_ok(&sol11, 20);
    let cat2 =
        CatalogoHerramientas::construir(vec![e], hash_pkg(20 ^ 0x11), hash_pkg(20), &auth).unwrap();

    let r = broker2.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4),
        Some(&cap4b),
        Some(&cap11b),
        &sistema,
        &sujeto2,
        &PrecondicionesPepEf4::todas_ok(),
        &cat2,
        &mut ledger2,
        &mut adap4b,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&mut gw11),
        Some(&mut mod11),
        Some(&PrecondicionesPepEf11::todas_ok()),
        Some(&aprob),
        &reloj,
        1,
        false,
    );
    match r {
        ResultadoPepHerramienta::Permitido(resp) => {
            assert_eq!(resp.delegado_a, Some(ClaseEfecto::Ef11));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(mod11.ordenes_delegadas, 1);
    assert_eq!(adap4b.invocaciones_delegadas, 0);

    let mut pre5 = PrecondicionesPepEf5::todas_ok();
    pre5.ordena_efecto_fisico = true;
    let mut exe5 = EjecutorNegocio::nuevo(1);
    let mut ledger5 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut adap5 = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core", [1u8; 32]));
    let r5 = exe5.ejercer(
        &SolicitudNegocioCruda::NoTipificable,
        None,
        &sistema,
        &sujeto2,
        &pre5,
        &mut ledger5,
        &mut adap5,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r5,
        ResultadoPepNegocio::Denegado {
            codigo: CodigoPep::EfectoFisicoEf11Requerido
        }
    ));

    let mut pre6 = PrecondicionesPepEf6::todas_ok();
    pre6.presenta_orden_fisica = true;
    let mut gw6 = GatewayComunicaciones::nuevo(1);
    let mut ledger6 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut adap6 = AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("from", [1u8; 32]));
    let r6 = gw6.ejercer(
        &SolicitudComunicacionCruda::NoTipificable,
        None,
        &sistema,
        &sujeto2,
        &pre6,
        &[],
        &mut ledger6,
        &mut adap6,
        &reloj,
        1,
        Some(10),
        false,
    );
    assert!(matches!(
        r6,
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::EfectoFisicoEf11Requerido
        }
    ));

    let mut pre7 = PrecondicionesPepEf7::todas_ok();
    pre7.presenta_orden_fisica = true;
    let mut gw7 = GatewayPublicacion::nuevo(1);
    let mut ledger7 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut adap7 =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct", [1u8; 32]));
    let r7 = gw7.ejercer(
        &SolicitudPublicacionCruda::NoTipificable,
        None,
        &sistema,
        &sujeto2,
        &pre7,
        &[],
        &mut ledger7,
        &mut adap7,
        &reloj,
        1,
        Some(10),
        false,
    );
    assert!(matches!(
        r7,
        ResultadoPepPublicacion::Denegado {
            codigo: CodigoPep::EfectoFisicoEf11Requerido
        }
    ));

    let _ = TipoIncidente::ResultadoIndeterminado;
}

#[test]
fn broker_no_emite_credenciales_bus() {
    assert!(!BrokerHerramientas::puede_emitir_capacidad());
    assert!(!BrokerHerramientas::posee_credencial_herramienta_expuesta());
}
