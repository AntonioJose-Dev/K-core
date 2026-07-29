//! Harnesses rebanada repo EF-4 (tests/bloque13_*): broker herramientas/MCP.
//! No es bloque §M. Matriz C EF-4 / F.5. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

use sak_core::capacidad::{CausaDenegacion, ClasificacionEfecto, ParametrosEmision};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef3, alcance_ef4, preparar_solicitud_escritura, preparar_solicitud_herramienta,
    AdaptadorSimulado, BrokerHerramientas, CatalogoHerramientas, ClaseEfecto, CodigoPep,
    CredencialEscritura, CredencialHerramienta, EjecutorSimulado, EntradaHerramienta,
    GatewayEscritura, OperacionEscritura, PrecondicionesPepEf4, ResultadoIntento,
    ResultadoPepHerramienta, SolicitudEscritura, SolicitudHerramienta, SolicitudHerramientaCruda,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    decision_con_paquete(hash_pkg(seed), &format!("N-EF4-{seed}"))
}

fn decision_con_paquete(pkg: [u8; LONGITUD_HASH_PAQUETE], norma: &str) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(pkg);
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva(norma).unwrap()], vec![], 1).unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn entrada_pura(_seed: u8) -> EntradaHerramienta {
    EntradaHerramienta {
        id_herramienta: "calc".into(),
        version: "1.0".into(),
        servidor: "mcp-local".into(),
        operacion: "sumar".into(),
        digest_esquema_args: [0xAAu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["local".into()],
        efecto_subyacente: ClaseEfecto::Ef4,
        reversible: true,
        datos_personales: false,
        cuota_maxima: 10,
        timeout_ms: 5_000,
    }
}

/// EF-4 tipada con datos personales ⇒ capacidad de un solo uso (INV-08).
fn entrada_pii(_seed: u8) -> EntradaHerramienta {
    EntradaHerramienta {
        id_herramienta: "calc".into(),
        version: "1.0".into(),
        servidor: "mcp-local".into(),
        operacion: "sumar".into(),
        digest_esquema_args: [0xAAu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["local".into()],
        efecto_subyacente: ClaseEfecto::Ef4,
        reversible: true,
        datos_personales: true,
        cuota_maxima: 10,
        timeout_ms: 5_000,
    }
}

fn entrada_ef3(_seed: u8) -> EntradaHerramienta {
    EntradaHerramienta {
        id_herramienta: "writer".into(),
        version: "2.0".into(),
        servidor: "mcp-biz".into(),
        operacion: "persistir".into(),
        digest_esquema_args: [0xBBu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["dest-kernel".into()],
        efecto_subyacente: ClaseEfecto::Ef3,
        reversible: false,
        datos_personales: true,
        cuota_maxima: 5,
        timeout_ms: 3_000,
    }
}

fn entrada_ef6() -> EntradaHerramienta {
    EntradaHerramienta {
        id_herramienta: "mailer".into(),
        version: "1.0".into(),
        servidor: "mcp-mail".into(),
        operacion: "enviar".into(),
        digest_esquema_args: [0xCCu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["smtp://x".into()],
        efecto_subyacente: ClaseEfecto::Ef6,
        reversible: false,
        datos_personales: true,
        cuota_maxima: 1,
        timeout_ms: 2_000,
    }
}

fn catalogo(
    entradas: Vec<EntradaHerramienta>,
    seed: u8,
    auth: &ParMlDsa87,
) -> CatalogoHerramientas {
    CatalogoHerramientas::construir(entradas, hash_pkg(seed ^ 0x11), hash_pkg(seed), auth).unwrap()
}

fn sol_desde_entrada(e: &EntradaHerramienta, seed: u8) -> SolicitudHerramienta {
    SolicitudHerramienta::nueva(
        e.id_herramienta.clone(),
        e.version.clone(),
        e.servidor.clone(),
        e.operacion.clone(),
        e.digest_esquema_args,
        [0x33u8; LONGITUD_HASH_PAQUETE],
        e.destinos_permitidos.first().cloned().unwrap_or_else(|| "local".into()),
        e.efecto_subyacente,
        e.reversible,
        e.datos_personales,
        e.cuota_maxima,
        e.timeout_ms,
        [0x44u8; LONGITUD_HASH_PAQUETE],
        hash_pkg(seed),
    )
    .unwrap()
}

fn emitir_ef4(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudHerramienta,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_herramienta(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef4(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: !s.reversible,
            afecta_personas: s.datos_personales,
            datos_personales: s.datos_personales,
        },
    };
    ledger
        .emitir_tras_evidencia(sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn emitir_ef3_para_tool(
    seed: u8,
    sistema: &IdSistema,
    sol_h: &SolicitudHerramienta,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let sol3 = SolicitudEscritura::nueva(
        OperacionEscritura::Update,
        format!("tool:{}", sol_h.id_herramienta),
        sol_h.digest_argumentos,
        None,
        ["payload"],
        sol_h.digest_argumentos,
        sol_h.cuota.max(1),
        &sol_h.destino,
        sol_h.reversible,
        sol_h.datos_personales,
        sol_h.hash_paquete,
    )
    .unwrap();
    let (s, digest) = preparar_solicitud_escritura(sol3);
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef3(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    ledger
        .emitir_tras_evidencia(
            sujeto,
            decision_con_paquete(sol_h.hash_paquete, &format!("N-EF3-{seed}")),
            params,
            reloj,
        )
        .unwrap()
}

fn pre_ok() -> PrecondicionesPepEf4 {
    PrecondicionesPepEf4::todas_ok()
}

fn invocar_pura(
    broker: &mut BrokerHerramientas,
    cruda: &SolicitudHerramientaCruda,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    cat: &CatalogoHerramientas,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    adap: &mut AdaptadorSimulado,
    reloj: &RelojInyectado,
) -> ResultadoPepHerramienta {
    broker.invocar(
        cruda,
        cap,
        None,
        sistema,
        sujeto,
        &pre_ok(),
        cat,
        ledger,
        adap,
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
        reloj,
        1,
        false,
    )
}

#[test]
fn herramienta_version_servidor_no_registrados() {
    let auth = ParMlDsa87::generar().unwrap();
    let cat = catalogo(vec![entrada_pura(1)], 1, &auth);
    assert!(cat.verificar_firma().is_ok());
    assert!(!cat.expuesto("desconocida"));

    let reloj = RelojInyectado::nuevo(1);
    let mut broker = BrokerHerramientas::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut adap = AdaptadorSimulado::nuevo();
    let sistema = IdSistema::nuevo("sys-t").unwrap();
    let sujeto = IdSujeto::nuevo("suj-t").unwrap();

    let mut sol = sol_desde_entrada(&entrada_pura(1), 1);
    sol.id_herramienta = "otra".into();
    let r = invocar_pura(
        &mut broker,
        &SolicitudHerramientaCruda::Tipada(sol),
        None,
        &sistema,
        &sujeto,
        &cat,
        &mut ledger,
        &mut adap,
        &reloj,
    );
    assert!(matches!(
        r,
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::HerramientaNoRegistrada
        }
    ));
}

#[test]
fn catalogo_argumentos_destino_alterados_y_no_tipificable() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_pura(2);
    let cat = catalogo(vec![e.clone()], 2, &auth);
    let reloj = RelojInyectado::nuevo(2);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_desde_entrada(&e, 2);
    let cap = emitir_ef4(2, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("calc", [2u8; 32]));

    let mut sol_args = sol.clone();
    sol_args.digest_argumentos = [0xFFu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Tipada(sol_args),
            Some(&cap),
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::ArgumentosNoAutorizados
        }
    ));

    let mut sol_dest = sol.clone();
    sol_dest.destino = "https://evil".into();
    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Tipada(sol_dest),
            Some(&cap),
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::DestinoNoAutorizado
        }
    ));

    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::NoTipificable,
            None,
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::EfectoNoTipificado
        }
    ));

    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Redireccion,
            None,
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::RedireccionNoDeclarada
        }
    ));
}

#[test]
fn capacidad_ausente_expirada_revocada_reutilizada() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_pii(3);
    let cat = catalogo(vec![e.clone()], 3, &auth);
    let reloj = RelojInyectado::nuevo(3);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-cap").unwrap();
    let sujeto = IdSujeto::nuevo("suj-cap").unwrap();
    let sol = sol_desde_entrada(&e, 3);
    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("calc", [3u8; 32]));

    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Tipada(sol.clone()),
            None,
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));

    let cap = emitir_ef4(3, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    assert!(cap.un_solo_uso());
    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Tipada(sol.clone()),
            Some(&cap),
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Permitido(_)
    ));
    assert!(matches!(
        invocar_pura(
            &mut broker,
            &SolicitudHerramientaCruda::Tipada(sol.clone()),
            Some(&cap),
            &sistema,
            &sujeto,
            &cat,
            &mut ledger,
            &mut adap,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida)
        }
    ));

    let sol4 = sol_desde_entrada(&e, 4);
    let cat4 = catalogo(vec![entrada_pii(4)], 4, &auth);
    let mut ledger4 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let cap4 = emitir_ef4(4, &sistema, &sol4, &mut ledger4, &reloj, &sujeto);
    let mut broker4 = BrokerHerramientas::nuevo(1);
    broker4.verificador_mut().revocar(*cap4.id());
    let mut adap4 = AdaptadorSimulado::nuevo();
    adap4.custodiar(CredencialHerramienta::desde_semilla("calc", [4u8; 32]));
    assert!(matches!(
        invocar_pura(
            &mut broker4,
            &SolicitudHerramientaCruda::Tipada(sol4),
            Some(&cap4),
            &sistema,
            &sujeto,
            &cat4,
            &mut ledger4,
            &mut adap4,
            &reloj,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada)
        }
    ));

    let reloj_exp = RelojInyectado::nuevo(0);
    let mut ledger_exp = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_exp = sol_desde_entrada(&e, 5);
    let cat_exp = catalogo(vec![entrada_pii(5)], 5, &auth);
    let (s, digest) = preparar_solicitud_herramienta(sol_exp.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef4(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 5,
        clasificacion: ClasificacionEfecto {
            irreversible: false,
            afecta_personas: false,
            datos_personales: true,
        },
    };
    let cap_exp = ledger_exp
        .emitir_tras_evidencia(&sujeto, decision_allow(5), params, &reloj_exp)
        .unwrap();
    reloj_exp.avanzar(6).unwrap();
    let mut broker_exp = BrokerHerramientas::nuevo(1);
    let mut adap_exp = AdaptadorSimulado::nuevo();
    adap_exp.custodiar(CredencialHerramienta::desde_semilla("calc", [5u8; 32]));
    assert!(matches!(
        invocar_pura(
            &mut broker_exp,
            &SolicitudHerramientaCruda::Tipada(sol_exp),
            Some(&cap_exp),
            &sistema,
            &sujeto,
            &cat_exp,
            &mut ledger_exp,
            &mut adap_exp,
            &reloj_exp,
        ),
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada)
        }
    ));
}

#[test]
fn credencial_no_expuesta_y_ruta_mcp_directa_bloqueada() {
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("calc", [9u8; 32]));
    assert!(!adap.credencial_expuesta());
    assert!(!BrokerHerramientas::posee_credencial_herramienta_expuesta());
    let dbg = format!("{:?}", CredencialHerramienta::desde_semilla("x", [1u8; 32]));
    assert!(dbg.contains("REDACTED"));

    let e = entrada_pura(9);
    let sol = sol_desde_entrada(&e, 9);
    let err = adap.llamar_mcp_directo(&sol).unwrap_err();
    assert!(err.to_string().contains("inalcanzable sin PEP"));
    assert_eq!(adap.intentos_directos, 1);
    assert_eq!(adap.invocaciones_delegadas, 0);
}

#[test]
fn herramienta_ef3_pasa_por_pep_escritura() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_ef3(10);
    let cat = catalogo(vec![e.clone()], 10, &auth);
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ef3").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ef3").unwrap();
    let sol = sol_desde_entrada(&e, 10);
    let cap4 = emitir_ef4(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    // Misma época normativa que la solicitud EF-4/EF-3 traducida (paquete seed 10).
    let cap3 = emitir_ef3_para_tool(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);

    let mut broker = BrokerHerramientas::nuevo(1);
    let mut gw3 = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([10u8; 32]));
    // recurso tool:writer no existe en versiones del ejecutor → se crea en CAS sin precondición
    let mut adap = AdaptadorSimulado::nuevo();

    let r = broker.invocar(
        &SolicitudHerramientaCruda::Tipada(sol),
        Some(&cap4),
        Some(&cap3),
        &sistema,
        &sujeto,
        &pre_ok(),
        &cat,
        &mut ledger,
        &mut adap,
        Some(&mut gw3),
        Some(&mut exe),
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
    match r {
        ResultadoPepHerramienta::Permitido(resp) => {
            assert_eq!(resp.delegado_a, Some(ClaseEfecto::Ef3));
            assert_eq!(resp.id_herramienta, "writer");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(exe.mutaciones_delegadas, 1);
    assert_eq!(adap.invocaciones_delegadas, 0);
    assert!(!broker.delegaciones().is_empty());
}

#[test]
fn ef5_ef6_ef7_denegados_por_pep_inexistente() {
    // EF-7 (y EF-6 sin gateway) siguen denegados. EF-6 con gateway se cubre en rebanada repo EF-6 (bloque15_*).
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_ef6();
    // Renombrar efecto a EF-7 para mantener el harness de PEP inexistente.
    let mut e7 = e;
    e7.efecto_subyacente = ClaseEfecto::Ef7;
    e7.operacion = "enviar".into();
    let cat = catalogo(vec![e7.clone()], 12, &auth);
    let reloj = RelojInyectado::nuevo(12);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ef6").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ef6").unwrap();
    let sol = sol_desde_entrada(&e7, 12);
    let cap = emitir_ef4(12, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("mailer", [12u8; 32]));

    let r = invocar_pura(
        &mut broker,
        &SolicitudHerramientaCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &cat,
        &mut ledger,
        &mut adap,
        &reloj,
    );
    assert!(matches!(
        r,
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::PepSubyacenteInexistente
        }
    ));
    assert_eq!(adap.invocaciones_delegadas, 0);
}

#[test]
fn respuesta_divergente_y_fallo_recibo() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_pura(13);
    let cat = catalogo(vec![e.clone()], 13, &auth);
    let reloj = RelojInyectado::nuevo(13);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-div").unwrap();
    let sujeto = IdSujeto::nuevo("suj-div").unwrap();
    let sol = sol_desde_entrada(&e, 13);
    let cap = emitir_ef4(13, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("calc", [13u8; 32]));
    adap.forzar_divergencia = true;

    let r = invocar_pura(
        &mut broker,
        &SolicitudHerramientaCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
        &sujeto,
        &cat,
        &mut ledger,
        &mut adap,
        &reloj,
    );
    assert!(matches!(
        r,
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let cap2 = emitir_ef4(14, &sistema, &sol, &mut ledger2, &reloj, &sujeto);
    let _ = ledger2.reportar_hueco_secuencia(1, 99);
    let mut broker2 = BrokerHerramientas::nuevo(1);
    let mut adap2 = AdaptadorSimulado::nuevo();
    adap2.custodiar(CredencialHerramienta::desde_semilla("calc", [14u8; 32]));
    let cat14 = catalogo(vec![entrada_pura(14)], 14, &auth);
    let sol14 = sol_desde_entrada(&entrada_pura(14), 14);
    // re-emit with matching seed 14
    let mut ledger14 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let cap14 = emitir_ef4(14, &sistema, &sol14, &mut ledger14, &reloj, &sujeto);
    let _ = ledger14.reportar_hueco_secuencia(1, 99);
    let r2 = invocar_pura(
        &mut broker2,
        &SolicitudHerramientaCruda::Tipada(sol14),
        Some(&cap14),
        &sistema,
        &sujeto,
        &cat14,
        &mut ledger14,
        &mut adap2,
        &reloj,
    );
    assert!(matches!(
        r2,
        ResultadoPepHerramienta::Denegado {
            codigo: CodigoPep::Evidencia(_)
        }
    ));
    assert!(broker2
        .incidentes()
        .iter()
        .any(|i| i.tipo == sak_core::pep::TipoIncidente::EvidenciaIncompleta));
    let _ = (cap2, ledger2);
}

#[test]
fn integridad_offline_cadena_completa() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = entrada_pura(15);
    let cat = catalogo(vec![e.clone()], 15, &auth);
    let reloj = RelojInyectado::nuevo(15);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_desde_entrada(&e, 15);
    let cap = emitir_ef4(15, &sistema, &sol, &mut ledger, &reloj, &sujeto);

    ledger
        .registrar_evento_sistema(&sujeto, TipoRegistro::Herramienta, cat.serializar_payload())
        .unwrap();

    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap = AdaptadorSimulado::nuevo();
    adap.custodiar(CredencialHerramienta::desde_semilla("calc", [15u8; 32]));

    let r = invocar_pura(
        &mut broker,
        &SolicitudHerramientaCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &cat,
        &mut ledger,
        &mut adap,
        &reloj,
    );
    assert!(matches!(r, ResultadoPepHerramienta::Permitido(_)));
    assert!(broker
        .intentos()
        .iter()
        .any(|i| matches!(i.resultado, ResultadoIntento::Permitido)));

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Herramienta));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}
