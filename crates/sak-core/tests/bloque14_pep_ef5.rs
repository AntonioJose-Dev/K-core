//! Harnesses rebanada repo EF-5 (tests/bloque14_*): ejecutor de negocio.
//! No es bloque §M. Matriz C EF-5. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

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
    alcance_ef4, alcance_ef5, preparar_solicitud_herramienta, preparar_solicitud_negocio,
    traducir_desde_herramienta, AdaptadorNegocioSimulado, AdaptadorSimulado, BrokerHerramientas,
    CatalogoHerramientas, ClaseEfecto, CodigoPep, CredencialNegocio,
    EjecutorNegocio, EntradaHerramienta, EstadoLiquidacion, ImporteNormalizado,
    PrecondicionesPepEf4, PrecondicionesPepEf5, ResultadoPepHerramienta, ResultadoPepNegocio,
    SolicitudHerramienta, SolicitudHerramientaCruda, SolicitudNegocioCruda,
    SolicitudOperacionNegocio, TipoIncidente, TipoOperacionNegocio,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    decision_con_paquete(hash_pkg(seed), &format!("N-EF5-{seed}"))
}

fn decision_con_paquete(pkg: [u8; LONGITUD_HASH_PAQUETE], norma: &str) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(pkg);
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva(norma).unwrap()], vec![], 1).unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn sol_base(seed: u8) -> SolicitudOperacionNegocio {
    let mut idem = [seed; 32];
    idem[0] = seed.wrapping_add(1);
    SolicitudOperacionNegocio::nueva(
        TipoOperacionNegocio::Pago,
        "core-banking",
        "acct-origen",
        "acct-destino",
        "EUR",
        ImporteNormalizado::nuevo(12_500).unwrap(),
        [0xB1u8; LONGITUD_HASH_PAQUETE],
        0,
        90_000,
        idem,
        false,
        [0xC2u8; LONGITUD_HASH_PAQUETE],
        true,
        hash_pkg(seed),
        1,
        [0xD3u8; LONGITUD_HASH_PAQUETE],
        false,
    )
    .unwrap()
}

fn emitir_ef5(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudOperacionNegocio,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_negocio(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef5(&s),
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

fn pre_ok() -> PrecondicionesPepEf5 {
    PrecondicionesPepEf5::todas_ok()
}

fn ejercer(
    exe: &mut EjecutorNegocio,
    sol: &SolicitudOperacionNegocio,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    pre: &PrecondicionesPepEf5,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    adap: &mut AdaptadorNegocioSimulado,
    reloj: &RelojInyectado,
    silencio: bool,
) -> ResultadoPepNegocio {
    exe.ejercer(
        &SolicitudNegocioCruda::Tipada(sol.clone()),
        cap,
        sistema,
        sujeto,
        pre,
        ledger,
        adap,
        reloj,
        1,
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
    let cap = emitir_ef5(1, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [1u8; 32]));
    let mut pre = pre_ok();
    pre.libro_c4 = false;
    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap), &sistema, &sujeto, &pre, &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::ControlInsuficiente }
    ));
    assert_eq!(adap.operaciones_delegadas, 0);
}

#[test]
fn capacidad_ausente_expirada_revocada_reutilizada_alcance() {
    let reloj = RelojInyectado::nuevo(2);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-cap").unwrap();
    let sujeto = IdSujeto::nuevo("suj-cap").unwrap();
    let sol = sol_base(2);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [2u8; 32]));

    assert!(matches!(
        ejercer(&mut exe, &sol, None, &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::CapacidadAusente }
    ));

    let cap = emitir_ef5(2, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    assert!(cap.un_solo_uso());
    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Permitido(_)
    ));
    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida) }
    ));

    // Alcance divergente (importe alterado en solicitud vs capacidad).
    let mut ledger_a = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_a = sol_base(3);
    let cap_a = emitir_ef5(3, &sistema, &sol_a, &mut ledger_a, &reloj, &sujeto);
    let mut sol_alt = sol_a.clone();
    sol_alt.importe = ImporteNormalizado::nuevo(99_999).unwrap();
    let mut exe_a = EjecutorNegocio::nuevo(1);
    let mut adap_a = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [3u8; 32]));
    assert!(matches!(
        ejercer(&mut exe_a, &sol_alt, Some(&cap_a), &sistema, &sujeto, &pre_ok(), &mut ledger_a, &mut adap_a, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::ImporteNoAutorizado }
    ));

    // Revocada.
    let mut ledger_r = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_r = sol_base(4);
    let cap_r = emitir_ef5(4, &sistema, &sol_r, &mut ledger_r, &reloj, &sujeto);
    let mut exe_r = EjecutorNegocio::nuevo(1);
    exe_r.verificador_mut().revocar(*cap_r.id());
    let mut adap_r = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [4u8; 32]));
    assert!(matches!(
        ejercer(&mut exe_r, &sol_r, Some(&cap_r), &sistema, &sujeto, &pre_ok(), &mut ledger_r, &mut adap_r, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada) }
    ));

    // Expirada.
    let reloj_exp = RelojInyectado::nuevo(0);
    let mut ledger_e = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_e = sol_base(5);
    let (s, digest) = preparar_solicitud_negocio(sol_e.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef5(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 5,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap_e = ledger_e
        .emitir_tras_evidencia(&sujeto, decision_allow(5), params, &reloj_exp)
        .unwrap();
    reloj_exp.avanzar(6).unwrap();
    let mut exe_e = EjecutorNegocio::nuevo(1);
    let mut adap_e = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [5u8; 32]));
    assert!(matches!(
        ejercer(&mut exe_e, &sol_e, Some(&cap_e), &sistema, &sujeto, &pre_ok(), &mut ledger_e, &mut adap_e, &reloj_exp, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada) }
    ));
}

#[test]
fn credencial_no_expuesta_y_ruta_directa_bloqueada() {
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [9u8; 32]));
    assert!(!adap.credencial_expuesta());
    assert!(!EjecutorNegocio::posee_credencial_negocio_expuesta());
    let dbg = format!("{:?}", CredencialNegocio::desde_semilla("x", [1u8; 32]));
    assert!(dbg.contains("REDACTED"));
    let sol = sol_base(9);
    let err = adap.llamar_directo(&sol).unwrap_err();
    assert!(err.to_string().contains("inalcanzable sin PEP") || err.to_string().contains("Bloqueado"));
    assert_eq!(adap.intentos_directos, 1);
    assert_eq!(adap.operaciones_delegadas, 0);
}

#[test]
fn importe_moneda_contraparte_tipo_objeto_alterados() {
    let reloj = RelojInyectado::nuevo(6);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_base(6);
    let cap = emitir_ef5(6, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [6u8; 32]));

    let mut s = sol.clone();
    s.moneda = "USD".into();
    assert!(matches!(
        ejercer(&mut exe, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::MonedaNoAutorizada }
    ));

    let mut s = sol.clone();
    s.contraparte = "otra".into();
    assert!(matches!(
        ejercer(&mut exe, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::ContraparteNoAutorizada }
    ));

    let mut s = sol.clone();
    s.tipo = TipoOperacionNegocio::Transferencia;
    assert!(matches!(
        ejercer(&mut exe, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::TipoOperacionNoAutorizado }
    ));

    let mut s = sol.clone();
    s.digest_objeto = [0xFFu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        ejercer(&mut exe, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::ObjetoNoAutorizado }
    ));
}

#[test]
fn idempotencia_repetida_e_incompatible() {
    let reloj = RelojInyectado::nuevo(7);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-idem").unwrap();
    let sujeto = IdSujeto::nuevo("suj-idem").unwrap();
    let sol = sol_base(7);
    let cap = emitir_ef5(7, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [7u8; 32]));

    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, false),
        ResultadoPepNegocio::Permitido(_)
    ));
    assert!(exe.clave_idempotencia_fijada(&sol.idempotency_key));

    // Misma clave, mismos parámetros, nueva capacidad → duplicada.
    let mut ledger2b = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let (s2, digest2) = preparar_solicitud_negocio(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest2,
        alcance: alcance_ef5(&s2),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let sujeto2 = IdSujeto::nuevo("suj-idem-2").unwrap();
    let cap2 = ledger2b
        .emitir_tras_evidencia(
            &sujeto2,
            decision_con_paquete(hash_pkg(7), "N-EF5-idem-dup"),
            params,
            &reloj,
        )
        .unwrap();
    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap2), &sistema, &sujeto2, &pre_ok(), &mut ledger2b, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::IdempotenciaDuplicada }
    ));

    // Misma clave, parámetros distintos → incompatible.
    let mut sol_b = sol_base(8);
    sol_b.idempotency_key = sol.idempotency_key;
    let mut ledger3 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let (s3, d3) = preparar_solicitud_negocio(sol_b.clone());
    let params3 = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: d3,
        alcance: alcance_ef5(&s3),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let sujeto3 = IdSujeto::nuevo("suj-idem-3").unwrap();
    let cap3 = ledger3
        .emitir_tras_evidencia(
            &sujeto3,
            decision_con_paquete(hash_pkg(8), "N-EF5-idem-bad"),
            params3,
            &reloj,
        )
        .unwrap();
    assert!(matches!(
        ejercer(&mut exe, &sol_b, Some(&cap3), &sistema, &sujeto3, &pre_ok(), &mut ledger3, &mut adap, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::IdempotenciaIncompatible }
    ));
}

#[test]
fn silencio_supervision_decision_deny_indeterminado_recibo() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-sil").unwrap();
    let sujeto = IdSujeto::nuevo("suj-sil").unwrap();
    let sol = sol_base(10);
    let cap = emitir_ef5(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [10u8; 32]));

    assert!(matches!(
        ejercer(&mut exe, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &mut ledger, &mut adap, &reloj, true),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::Capacidad(_) }
    ));

    // Supervisión ausente.
    let mut ledger_s = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut sol_s = sol_base(11);
    sol_s.exige_supervision = true;
    let cap_s = emitir_ef5(11, &sistema, &sol_s, &mut ledger_s, &reloj, &sujeto);
    let mut exe_s = EjecutorNegocio::nuevo(1);
    let mut adap_s = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [11u8; 32]));
    let mut pre_s = pre_ok();
    pre_s.supervision_ok = false;
    assert!(matches!(
        ejercer(&mut exe_s, &sol_s, Some(&cap_s), &sistema, &sujeto, &pre_s, &mut ledger_s, &mut adap_s, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::SupervisionAusente }
    ));

    // Decisión DENY.
    let mut pre_d = pre_ok();
    pre_d.decision_permitida = false;
    let mut exe_d = EjecutorNegocio::nuevo(1);
    let mut adap_d = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [12u8; 32]));
    let mut ledger_d = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    assert!(matches!(
        ejercer(&mut exe_d, &sol, None, &sistema, &sujeto, &pre_d, &mut ledger_d, &mut adap_d, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::DecisionDenegada }
    ));

    // Resultado indeterminado → INCIDENTE, sin reintento.
    let mut ledger_i = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_i = sol_base(13);
    let cap_i = emitir_ef5(13, &sistema, &sol_i, &mut ledger_i, &reloj, &sujeto);
    let mut exe_i = EjecutorNegocio::nuevo(1);
    let mut adap_i = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [13u8; 32]));
    adap_i.forzar_indeterminado = true;
    assert!(matches!(
        ejercer(&mut exe_i, &sol_i, Some(&cap_i), &sistema, &sujeto, &pre_ok(), &mut ledger_i, &mut adap_i, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::IncidenteMediacion }
    ));
    assert!(exe_i.incidentes().iter().any(|i| i.tipo == TipoIncidente::ResultadoIndeterminado));
    assert_eq!(adap_i.operaciones_delegadas, 0);

    // Recibo / divergencia.
    let mut ledger_v = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_v = sol_base(14);
    let cap_v = emitir_ef5(14, &sistema, &sol_v, &mut ledger_v, &reloj, &sujeto);
    let mut exe_v = EjecutorNegocio::nuevo(1);
    let mut adap_v = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [14u8; 32]));
    adap_v.forzar_divergencia = true;
    assert!(matches!(
        ejercer(&mut exe_v, &sol_v, Some(&cap_v), &sistema, &sujeto, &pre_ok(), &mut ledger_v, &mut adap_v, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::IncidenteMediacion }
    ));

    let mut ledger_h = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_h = sol_base(15);
    let cap_h = emitir_ef5(15, &sistema, &sol_h, &mut ledger_h, &reloj, &sujeto);
    let _ = ledger_h.reportar_hueco_secuencia(1, 99);
    let mut exe_h = EjecutorNegocio::nuevo(1);
    let mut adap_h = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [15u8; 32]));
    assert!(matches!(
        ejercer(&mut exe_h, &sol_h, Some(&cap_h), &sistema, &sujeto, &pre_ok(), &mut ledger_h, &mut adap_h, &reloj, false),
        ResultadoPepNegocio::Denegado { codigo: CodigoPep::Evidencia(_) }
    ));
}

#[test]
fn delegacion_ef4_a_ef5() {
    let auth = ParMlDsa87::generar().unwrap();
    let mut args = [0x33u8; LONGITUD_HASH_PAQUETE];
    args[0..8].copy_from_slice(&12_500u64.to_le_bytes());
    let e = EntradaHerramienta {
        id_herramienta: "pay".into(),
        version: "1.0".into(),
        servidor: "core-banking".into(),
        operacion: "pago".into(),
        digest_esquema_args: [0xAAu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["acct-destino".into()],
        efecto_subyacente: ClaseEfecto::Ef5,
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

    let sol4 = SolicitudHerramienta::nueva(
        e.id_herramienta.clone(),
        e.version.clone(),
        e.servidor.clone(),
        e.operacion.clone(),
        e.digest_esquema_args,
        args,
        "acct-destino",
        ClaseEfecto::Ef5,
        false,
        true,
        3,
        5_000,
        [0x44u8; LONGITUD_HASH_PAQUETE],
        hash_pkg(20),
    )
    .unwrap();
    let sol5 = traducir_desde_herramienta(
        &sol4.id_herramienta,
        &sol4.servidor,
        &sol4.operacion,
        &sol4.destino,
        sol4.digest_argumentos,
        sol4.digest_condiciones,
        sol4.hash_paquete,
        sol4.datos_personales,
        sol4.reversible,
    )
    .unwrap();

    let (s4, d4) = preparar_solicitud_herramienta(sol4.clone());
    let cap4 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            decision_con_paquete(hash_pkg(20), "N-EF4-del"),
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
    let (s5, d5) = preparar_solicitud_negocio(sol5);
    let cap5 = ledger
        .emitir_tras_evidencia(
            &sujeto,
            decision_con_paquete(hash_pkg(20), "N-EF5-del"),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d5,
                alcance: alcance_ef5(&s5),
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

    // Sin PEP EF-5 → DENY (no bypass directo).
    let r_deny = broker.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4.clone()),
        Some(&cap4),
        Some(&cap5),
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

    // Capacidad EF-4 consumida en el intento anterior; re-emitir.
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto2 = IdSujeto::nuevo("suj-del-2").unwrap();
    let cap4b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            decision_con_paquete(hash_pkg(20), "N-EF4-del2"),
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
    let cap5b = ledger2
        .emitir_tras_evidencia(
            &sujeto2,
            decision_con_paquete(hash_pkg(20), "N-EF5-del2"),
            ParametrosEmision {
                sistema: sistema.clone(),
                digest_efecto: d5,
                alcance: alcance_ef5(&s5),
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
    let mut exe5b = EjecutorNegocio::nuevo(1);
    let mut adap5b = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [21u8; 32]));
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
        Some(&cap5b),
        &sistema,
        &sujeto2,
        &PrecondicionesPepEf4::todas_ok(),
        &cat2,
        &mut ledger2,
        &mut adap4b,
        None,
        None,
        Some(&mut exe5b),
        Some(&mut adap5b),
        Some(&PrecondicionesPepEf5::todas_ok()),
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
            assert_eq!(resp.delegado_a, Some(ClaseEfecto::Ef5));
            assert_eq!(resp.id_herramienta, "pay");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(adap5b.operaciones_delegadas, 1);
    assert_eq!(adap4b.invocaciones_delegadas, 0);
    assert!(broker2.delegaciones().iter().any(|d| d.hacia == ClaseEfecto::Ef5));
}

#[test]
fn integridad_offline_cadena_completa() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base(30);
    let cap = emitir_ef5(30, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut exe = EjecutorNegocio::nuevo(1);
    let mut adap = AdaptadorNegocioSimulado::nuevo(CredencialNegocio::desde_semilla("core-banking", [30u8; 32]));

    let r = ejercer(
        &mut exe,
        &sol,
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut adap,
        &reloj,
        false,
    );
    match r {
        ResultadoPepNegocio::Permitido(resp) => {
            assert_eq!(resp.estado_liquidacion, EstadoLiquidacion::Confirmada);
            assert!(!resp.referencia_externa.is_empty());
        }
        other => panic!("{other:?}"),
    }
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Decision));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Negocio));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}
