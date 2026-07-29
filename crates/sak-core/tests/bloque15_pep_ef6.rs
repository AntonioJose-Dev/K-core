//! Harnesses rebanada repo EF-6 (tests/bloque15_*): gateway de comunicaciones.
//! No es bloque §M. Matriz C EF-6. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

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
    alcance_ef4, alcance_ef6, preparar_solicitud_comunicacion, preparar_solicitud_herramienta,
    traducir_comunicacion_desde_herramienta, AdaptadorComunicacionSimulado, AdaptadorSimulado,
    BrokerHerramientas, CanalComunicacion, CatalogoHerramientas, ClaseEfecto, CodigoPep,
    CondicionesComunicacion, ConjuntoDestinatarios, CredencialEnvio, EntradaHerramienta,
    EtiquetaHecho, GatewayComunicaciones, HechoContactoExigido, PrecondicionesPepEf4,
    PrecondicionesPepEf6, ResultadoPepComunicacion, ResultadoPepHerramienta, SolicitudComunicacion,
    SolicitudComunicacionCruda, SolicitudHerramienta, SolicitudHerramientaCruda, TipoHechoContacto,
    TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

/// 10:00 — dentro de franja tipica 08–20.
const TICK_OK: u64 = 10 * 3600;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    decision_con_paquete(hash_pkg(seed), &format!("N-EF6-{seed}"))
}

fn decision_con_paquete(pkg: [u8; LONGITUD_HASH_PAQUETE], norma: &str) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(pkg);
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva(norma).unwrap()], vec![], 1).unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn hecho(seed: u8) -> HechoContactoExigido {
    HechoContactoExigido {
        tipo: TipoHechoContacto::Consentimiento,
        etiqueta: EtiquetaHecho::Gob,
        digest: [seed; LONGITUD_HASH_PAQUETE],
    }
}

fn sol_base(seed: u8) -> SolicitudComunicacion {
    let h = hecho(seed);
    SolicitudComunicacion::nueva(
        CanalComunicacion::Correo,
        "smtp-kernel",
        "noreply@kernel.local",
        ConjuntoDestinatarios::nuevo([format!("user{seed}@ex.com")], 5).unwrap(),
        "tpl-aviso",
        [0xB0u8; LONGITUD_HASH_PAQUETE],
        [0xA0u8; LONGITUD_HASH_PAQUETE],
        "es",
        "servicio",
        "personal",
        true,
        false,
        0,
        u64::MAX,
        10,
        1,
        1,
        false,
        hash_pkg(seed),
        1,
        [0xC0u8; LONGITUD_HASH_PAQUETE],
        CondicionesComunicacion::tipicas(),
        vec![h],
    )
    .unwrap()
}

fn emitir_ef6(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudComunicacion,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_comunicacion(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef6(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: !s.reversible,
            afecta_personas: s.destinatario_personal,
            datos_personales: s.destinatario_personal,
        },
    };
    ledger
        .emitir_tras_evidencia(sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn pre_ok() -> PrecondicionesPepEf6 {
    PrecondicionesPepEf6::todas_ok()
}

fn ejercer(
    gw: &mut GatewayComunicaciones,
    sol: &SolicitudComunicacion,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    pre: &PrecondicionesPepEf6,
    hechos: &[HechoContactoExigido],
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    adap: &mut AdaptadorComunicacionSimulado,
    reloj: &RelojInyectado,
    ticks_hora: u64,
    silencio: bool,
) -> ResultadoPepComunicacion {
    gw.ejercer(
        &SolicitudComunicacionCruda::Tipada(sol.clone()),
        cap,
        sistema,
        sujeto,
        pre,
        hechos,
        ledger,
        adap,
        reloj,
        1,
        Some(ticks_hora),
        silencio,
    )
}

#[test]
fn minimo_c4_no_alcanzado() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-c4").unwrap();
    let sujeto = IdSujeto::nuevo("suj-c4").unwrap();
    let sol = sol_base(1);
    let cap = emitir_ef6(1, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayComunicaciones::nuevo(1);
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [1u8; 32]));
    let mut pre = pre_ok();
    pre.libro_c4 = false;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::ControlInsuficiente
        }
    ));
}

#[test]
fn capacidad_ausente_expirada_revocada_reutilizada() {
    let reloj = RelojInyectado::nuevo(2);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-cap").unwrap();
    let sujeto = IdSujeto::nuevo("suj-cap").unwrap();
    let sol = sol_base(2);
    let mut gw = GatewayComunicaciones::nuevo(1);
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [2u8; 32]));

    assert!(matches!(
        ejercer(
            &mut gw, &sol, None, &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));

    let cap = emitir_ef6(2, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    assert!(cap.un_solo_uso());
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Permitido(_)
    ));
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida)
        }
    ));

    let mut ledger_r = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_r = sol_base(4);
    let cap_r = emitir_ef6(4, &sistema, &sol_r, &mut ledger_r, &reloj, &sujeto);
    let mut gw_r = GatewayComunicaciones::nuevo(1);
    gw_r.verificador_mut().revocar(*cap_r.id());
    let mut adap_r =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [4u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw_r, &sol_r, Some(&cap_r), &sistema, &sujeto, &pre_ok(), &sol_r.hechos_exigidos,
            &mut ledger_r, &mut adap_r, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada)
        }
    ));

    let reloj_exp = RelojInyectado::nuevo(0);
    let mut ledger_e = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_e = sol_base(5);
    let (s, digest) = preparar_solicitud_comunicacion(sol_e.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef6(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 5,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap_e = ledger_e
        .emitir_tras_evidencia(&sujeto, decision_allow(5), params, &reloj_exp)
        .unwrap();
    reloj_exp.avanzar(6).unwrap();
    let mut gw_e = GatewayComunicaciones::nuevo(1);
    let mut adap_e =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [5u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw_e, &sol_e, Some(&cap_e), &sistema, &sujeto, &pre_ok(), &sol_e.hechos_exigidos,
            &mut ledger_e, &mut adap_e, &reloj_exp, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada)
        }
    ));
}

#[test]
fn campos_alterados_y_hecho_ausente() {
    let reloj = RelojInyectado::nuevo(6);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_base(6);
    let cap = emitir_ef6(6, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayComunicaciones::nuevo(1);
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [6u8; 32]));

    let mut s = sol.clone();
    s.identidad_remitente = "otro@x".into();
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::RemitenteNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.canal = CanalComunicacion::Sms;
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::CanalNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.destinatarios = ConjuntoDestinatarios::nuevo(["otro@ex.com"], 5).unwrap();
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::DestinatarioNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.id_plantilla = "otra".into();
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::PlantillaNoAutorizada
        }
    ));

    let mut s = sol.clone();
    s.digest_cuerpo = [0xFFu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::CuerpoNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.digest_adjuntos = [0xEEu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::AdjuntoNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.idioma = "en".into();
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::IdiomaNoAutorizado
        }
    ));

    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, 3 * 3600, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::HorarioNoAutorizado
        }
    ));

    let mut s = sol.clone();
    s.frecuencia_periodo = 99;
    assert!(matches!(
        ejercer(
            &mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger,
            &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::FrecuenciaNoAutorizada
        }
    ));

    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &[], &mut ledger, &mut adap,
            &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::HechoContactoAusente
        }
    ));
}

#[test]
fn conjunto_masivo_abierto_cardinalidad_y_parcial() {
    assert!(ConjuntoDestinatarios::nuevo(["*"], 10).is_err());
    assert!(ConjuntoDestinatarios::nuevo(["a@x", "b@x", "c@x"], 2).is_err());

    let reloj = RelojInyectado::nuevo(7);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-mass").unwrap();
    let sujeto = IdSujeto::nuevo("suj-mass").unwrap();
    let sol = sol_base(7);
    let cap = emitir_ef6(7, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayComunicaciones::nuevo(1);
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [7u8; 32]));
    adap.forzar_parcial = true;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert!(gw
        .incidentes()
        .iter()
        .any(|i| i.tipo == TipoIncidente::ResultadoIndeterminado));
}

#[test]
fn credencial_ruta_directa_indeterminado_recibo() {
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [9u8; 32]));
    assert!(!adap.credencial_expuesta());
    assert!(!GatewayComunicaciones::posee_credencial_envio_expuesta());
    assert!(format!("{:?}", CredencialEnvio::desde_semilla("x", [1u8; 32])).contains("REDACTED"));
    let sol = sol_base(9);
    let _ = adap.llamar_directo(&sol).unwrap_err();
    assert_eq!(adap.intentos_directos, 1);

    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ind").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ind").unwrap();
    let sol = sol_base(10);
    let cap = emitir_ef6(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayComunicaciones::nuevo(1);
    adap.forzar_indeterminado = true;
    assert!(matches!(
        ejercer(
            &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
            &mut ledger, &mut adap, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));

    let mut ledger_d = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_d = sol_base(11);
    let cap_d = emitir_ef6(11, &sistema, &sol_d, &mut ledger_d, &reloj, &sujeto);
    let mut gw_d = GatewayComunicaciones::nuevo(1);
    let mut adap_d =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [11u8; 32]));
    adap_d.forzar_divergencia = true;
    assert!(matches!(
        ejercer(
            &mut gw_d, &sol_d, Some(&cap_d), &sistema, &sujeto, &pre_ok(), &sol_d.hechos_exigidos,
            &mut ledger_d, &mut adap_d, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));

    let mut ledger_h = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_h = sol_base(12);
    let cap_h = emitir_ef6(12, &sistema, &sol_h, &mut ledger_h, &reloj, &sujeto);
    let _ = ledger_h.reportar_hueco_secuencia(1, 99);
    let mut gw_h = GatewayComunicaciones::nuevo(1);
    let mut adap_h =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [12u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw_h, &sol_h, Some(&cap_h), &sistema, &sujeto, &pre_ok(), &sol_h.hechos_exigidos,
            &mut ledger_h, &mut adap_h, &reloj, TICK_OK, false
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::Evidencia(_)
        }
    ));

    // Silencio de revocación.
    let mut ledger_s = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_s = sol_base(13);
    let cap_s = emitir_ef6(13, &sistema, &sol_s, &mut ledger_s, &reloj, &sujeto);
    let mut gw_s = GatewayComunicaciones::nuevo(1);
    let mut adap_s =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [13u8; 32]));
    assert!(matches!(
        ejercer(
            &mut gw_s, &sol_s, Some(&cap_s), &sistema, &sujeto, &pre_ok(), &sol_s.hechos_exigidos,
            &mut ledger_s, &mut adap_s, &reloj, TICK_OK, true
        ),
        ResultadoPepComunicacion::Denegado {
            codigo: CodigoPep::Capacidad(_)
        }
    ));
}

#[test]
fn delegacion_ef4_a_ef6() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = EntradaHerramienta {
        id_herramienta: "mailer".into(),
        version: "1.0".into(),
        servidor: "smtp-kernel".into(),
        operacion: "correo".into(),
        digest_esquema_args: [0xAAu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["cliente@ex.com".into()],
        efecto_subyacente: ClaseEfecto::Ef6,
        reversible: false,
        datos_personales: true,
        cuota_maxima: 3,
        timeout_ms: 5_000,
    };
    let cat = CatalogoHerramientas::construir(
        vec![e.clone()],
        hash_pkg(20 ^ 0x11),
        hash_pkg(20),
        &auth,
    )
    .unwrap();
    let reloj = RelojInyectado::nuevo(20);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-del").unwrap();
    let sujeto = IdSujeto::nuevo("suj-del").unwrap();
    let args = [0x33u8; LONGITUD_HASH_PAQUETE];
    let sol4 = SolicitudHerramienta::nueva(
        e.id_herramienta.clone(),
        e.version.clone(),
        e.servidor.clone(),
        e.operacion.clone(),
        e.digest_esquema_args,
        args,
        "cliente@ex.com",
        ClaseEfecto::Ef6,
        false,
        true,
        3,
        5_000,
        [0x44u8; LONGITUD_HASH_PAQUETE],
        hash_pkg(20),
    )
    .unwrap();
    let sol6 = traducir_comunicacion_desde_herramienta(
        &sol4.id_herramienta,
        &sol4.servidor,
        &sol4.operacion,
        &sol4.destino,
        sol4.digest_argumentos,
        sol4.hash_paquete,
        sol4.datos_personales,
        sol4.reversible,
    )
    .unwrap();

    let (s4, d4) = preparar_solicitud_herramienta(sol4.clone());
    let cap4 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            decision_con_paquete(hash_pkg(20), "N-EF4-comm"),
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
    let (s6, d6) = preparar_solicitud_comunicacion(sol6.clone());
    let cap6 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            decision_con_paquete(hash_pkg(20), "N-EF6-comm"),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d6,
                alcance: alcance_ef6(&s6),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto::irreversible(),
            },
            &reloj,
        )
        .unwrap();

    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap4 = AdaptadorSimulado::nuevo();
    // Sin gateway → DENY.
    let r_deny = broker.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4.clone()),
        Some(&cap4),
        Some(&cap6),
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
    let sujeto2 = IdSujeto::nuevo("suj-del-2").unwrap();
    let cap4b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            decision_con_paquete(hash_pkg(20), "N-EF4-comm2"),
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
    let cap6b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            decision_con_paquete(hash_pkg(20), "N-EF6-comm2"),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d6,
                alcance: alcance_ef6(&s6),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto::irreversible(),
            },
            &reloj,
        )
        .unwrap();
    let mut broker2 = BrokerHerramientas::nuevo(1);
    let mut adap4b = AdaptadorSimulado::nuevo();
    let mut gw6 = GatewayComunicaciones::nuevo(1);
    let mut adap6 =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("from:mailer", [21u8; 32]));
    let cat2 = CatalogoHerramientas::construir(
        vec![e],
        hash_pkg(20 ^ 0x11),
        hash_pkg(20),
        &auth,
    )
    .unwrap();

    let r = broker2.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4),
        Some(&cap4b),
        Some(&cap6b),
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
        Some(&mut gw6),
        Some(&mut adap6),
        Some(&PrecondicionesPepEf6::todas_ok()),
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
            assert_eq!(resp.delegado_a, Some(ClaseEfecto::Ef6));
            assert_eq!(resp.id_herramienta, "mailer");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(adap6.envios_delegados, 1);
    assert_eq!(adap4b.invocaciones_delegadas, 0);
    assert!(broker2.delegaciones().iter().any(|d| d.hacia == ClaseEfecto::Ef6));
}

#[test]
fn integridad_offline_cadena_completa() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base(30);
    let cap = emitir_ef6(30, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayComunicaciones::nuevo(1);
    let mut adap =
        AdaptadorComunicacionSimulado::nuevo(CredencialEnvio::desde_semilla("noreply@kernel.local", [30u8; 32]));

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
        TICK_OK,
        false,
    );
    assert!(matches!(r, ResultadoPepComunicacion::Permitido(_)));
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Decision));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Comunicacion));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}
