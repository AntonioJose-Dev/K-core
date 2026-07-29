//! Harnesses rebanada repo EF-3 (tests/bloque12_*): gateway de escritura, CAS e incidente.
//! No es bloque §M. Matriz C EF-3. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

use sak_core::capacidad::{CausaDenegacion, ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef3, preparar_solicitud_escritura, CodigoPep, CredencialEscritura, EjecutorSimulado,
    GatewayEscritura, OperacionEscritura, PrecondicionesPepEf3, ResultadoIntento,
    ResultadoPepEscritura, SolicitudEscritura, SolicitudEscrituraCruda, TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(hash_pkg(seed));
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva(format!("N-EF3-{seed}")).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn sol_base(seed: u8) -> SolicitudEscritura {
    SolicitudEscritura::nueva(
        OperacionEscritura::Update,
        "tabla-estado",
        [0x11u8; LONGITUD_HASH_PAQUETE],
        Some(1),
        ["estado", "marcado"],
        [0x22u8; LONGITUD_HASH_PAQUETE],
        5,
        "dest-kernel",
        false,
        true,
        hash_pkg(seed),
    )
    .unwrap()
}

fn emitir_cap(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudEscritura,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_escritura(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef3(&s),
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

fn pre_ok() -> PrecondicionesPepEf3 {
    PrecondicionesPepEf3::todas_ok()
}

#[test]
fn sin_capacidad_no_hay_escritura() {
    assert!(!GatewayEscritura::puede_emitir_capacidad());
    assert!(!GatewayEscritura::posee_credencial_escritura());

    let reloj = RelojInyectado::nuevo(1);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([1u8; 32]));
    let sistema = IdSistema::nuevo("sys-w").unwrap();
    let sujeto = IdSujeto::nuevo("suj-w").unwrap();

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol_base(1)),
        None,
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));
    assert_eq!(exe.mutaciones_delegadas, 0);
}

#[test]
fn ruta_directa_bloqueada() {
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([2u8; 32]));
    let err = exe.llamar_directo(&sol_base(2)).unwrap_err();
    assert!(err.to_string().contains("inalcanzable sin PEP"));
    assert_eq!(exe.intentos_directos, 1);
    assert_eq!(exe.mutaciones_delegadas, 0);
}

#[test]
fn custodia_credencial_escritura() {
    let exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([3u8; 32]));
    assert!(!exe.credencial_expuesta());
    let dbg = format!("{:?}", CredencialEscritura::desde_semilla([3u8; 32]));
    assert!(dbg.contains("REDACTED"));
}

#[test]
fn exito_unica_mutacion_exactamente_autorizada() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ok").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ok").unwrap();
    let sol = sol_base(4);
    let cap = emitir_cap(4, &sistema, &sol, &mut ledger, &reloj, &sujeto);

    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([4u8; 32]));
    assert_eq!(exe.version_de("tabla-estado"), Some(1));

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    match r {
        ResultadoPepEscritura::Permitido(resp) => {
            assert_eq!(resp.version_previa, Some(1));
            assert_eq!(resp.version_posterior, Some(2));
            assert_eq!(resp.digest_cambio_autorizado, resp.digest_cambio_aplicado);
            assert_eq!(resp.filas_afectadas, 1);
            assert_ne!(resp.recibo.digest_condiciones, [0u8; LONGITUD_HASH_PAQUETE]);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(exe.mutaciones_delegadas, 1);
    assert_eq!(exe.version_de("tabla-estado"), Some(2));
}

#[test]
fn selector_campo_valor_limite_o_version_alterados() {
    let reloj = RelojInyectado::nuevo(20);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_base(5);
    let cap = emitir_cap(5, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([5u8; 32]));

    let mut sol_sel = sol.clone();
    sol_sel.digest_selector = [0xFFu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_sel),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::SelectorNoAutorizado
        }
    ));

    let mut sol_campo = sol.clone();
    sol_campo.campos.insert("secreto".into());
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_campo),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::CampoNoAutorizado
        }
    ));

    let mut sol_val = sol.clone();
    sol_val.digest_valores = [0xAAu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_val),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::ValorNoAutorizado
        }
    ));

    let mut sol_lim = sol.clone();
    sol_lim.limite_filas = 999;
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_lim),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::LimiteFilasExcedido
        }
    ));

    let mut sol_ver = sol;
    sol_ver.version_precondicion = Some(99);
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_ver),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::SelectorNoAutorizado
        }
    ));
    assert_eq!(exe.mutaciones_delegadas, 0);
}

#[test]
fn conflicto_cas() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-cas").unwrap();
    let sujeto = IdSujeto::nuevo("suj-cas").unwrap();
    // Autoriza versión 2, pero el ejecutor tiene versión 1.
    let sol = SolicitudEscritura::nueva(
        OperacionEscritura::Update,
        "tabla-estado",
        [0x11u8; LONGITUD_HASH_PAQUETE],
        Some(2),
        ["estado"],
        [0x22u8; LONGITUD_HASH_PAQUETE],
        1,
        "dest-kernel",
        true,
        false,
        hash_pkg(6),
    )
    .unwrap();
    let cap = emitir_cap(6, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([6u8; 32]));

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::ConflictoCas
        }
    ));
}

#[test]
fn repeticion_nonce_revocacion_y_expiracion() {
    let reloj = RelojInyectado::nuevo(40);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-rep").unwrap();
    let sujeto = IdSujeto::nuevo("suj-rep").unwrap();
    let sol = sol_base(7);
    let cap = emitir_cap(7, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([7u8; 32]));

    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol.clone()),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Permitido(_)
    ));
    // Tras éxito, versión ya no es 1 → CAS fallaría; emitimos otra cap con ver=2
    // para probar repetición de nonce: misma capacidad otra vez.
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol),
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida)
        }
    ));

    // Revocación.
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(8);
    let cap2 = emitir_cap(8, &sistema, &sol2, &mut ledger2, &reloj, &sujeto);
    let mut gw2 = GatewayEscritura::nuevo(1);
    gw2.verificador_mut().revocar(*cap2.id());
    let mut exe2 = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([8u8; 32]));
    assert!(matches!(
        gw2.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol2),
            Some(&cap2),
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger2,
            &mut exe2,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada)
        }
    ));

    // Expiración.
    let reloj_exp = RelojInyectado::nuevo(0);
    let mut ledger3 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol3 = sol_base(9);
    let (s3, digest3) = preparar_solicitud_escritura(sol3.clone());
    let sujeto3 = IdSujeto::nuevo("suj-exp").unwrap();
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest3,
        alcance: alcance_ef3(&s3),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 10,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap3 = ledger3
        .emitir_tras_evidencia(&sujeto3, decision_allow(9), params, &reloj_exp)
        .unwrap();
    reloj_exp.avanzar(11).unwrap();
    let mut gw3 = GatewayEscritura::nuevo(1);
    let mut exe3 = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([9u8; 32]));
    assert!(matches!(
        gw3.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol3),
            Some(&cap3),
            &sistema,
            &sujeto3,
            &pre_ok(),
            &mut ledger3,
            &mut exe3,
            &reloj_exp,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada)
        }
    ));
}

#[test]
fn irreversible_con_silencio_revocacion() {
    let reloj = RelojInyectado::nuevo(50);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-sil").unwrap();
    let sujeto = IdSujeto::nuevo("suj-sil").unwrap();
    let sol = sol_base(10);
    let cap = emitir_cap(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([10u8; 32]));

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        true, // silencio de revocación
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::Capacidad(CausaDenegacion::SilencioRevocacion)
        }
    ));
    assert_eq!(exe.mutaciones_delegadas, 0);
}

#[test]
fn divergencia_autorizado_ejecutado() {
    let reloj = RelojInyectado::nuevo(60);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-div").unwrap();
    let sujeto = IdSujeto::nuevo("suj-div").unwrap();
    let sol = sol_base(11);
    let cap = emitir_cap(11, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([11u8; 32]));
    exe.forzar_divergencia = true;

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert_eq!(gw.incidentes()[0].tipo, TipoIncidente::DivergenciaParametros);
}

#[test]
fn evidencia_posterior_fallida_es_incidente() {
    let reloj = RelojInyectado::nuevo(70);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ev").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ev").unwrap();
    let sol = sol_base(12);
    let cap = emitir_cap(12, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    // Suspender dominio tras emisión: el efecto puede ocurrir; el recibo falla.
    let _ = ledger.reportar_hueco_secuencia(1, 99);

    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([12u8; 32]));
    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(
        r,
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::Evidencia(_)
        }
    ));
    assert!(exe.mutaciones_delegadas >= 1);
    assert!(gw
        .incidentes()
        .iter()
        .any(|i| i.tipo == TipoIncidente::EvidenciaIncompleta));
}

#[test]
fn solicitud_no_tipificable_y_precondiciones() {
    let reloj = RelojInyectado::nuevo(0);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([13u8; 32]));
    let sistema = IdSistema::nuevo("sys-nt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-nt").unwrap();

    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::NoTipificable,
            None,
            &sistema,
            &sujeto,
            &pre_ok(),
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::EfectoNoTipificado
        }
    ));

    let mut pre = pre_ok();
    pre.monitor_permisivo = false;
    assert!(matches!(
        gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol_base(13)),
            None,
            &sistema,
            &sujeto,
            &pre,
            &mut ledger,
            &mut exe,
            &reloj,
            1,
            false,
        ),
        ResultadoPepEscritura::Denegado {
            codigo: CodigoPep::MonitorNoPermisivo
        }
    ));
}

#[test]
fn recibo_cadena_verifica_offline() {
    let reloj = RelojInyectado::nuevo(80);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base(14);
    let cap = emitir_cap(14, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayEscritura::nuevo(1);
    let mut exe = EjecutorSimulado::nuevo(CredencialEscritura::desde_semilla([14u8; 32]));

    let r = gw.ejercer(
        &SolicitudEscrituraCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &pre_ok(),
        &mut ledger,
        &mut exe,
        &reloj,
        1,
        false,
    );
    assert!(matches!(r, ResultadoPepEscritura::Permitido(_)));
    assert!(gw
        .intentos()
        .iter()
        .any(|i| matches!(i.resultado, ResultadoIntento::Permitido)));

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}
