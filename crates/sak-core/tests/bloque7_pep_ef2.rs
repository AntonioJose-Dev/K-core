//! Harnesses Bloque 7: PEP EF-2, gateway de datos, minimización e incidente.

use sak_core::capacidad::{ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef2, preparar_solicitud_datos, CodigoPep, CredencialDatos, GatewayDatos,
    OperacionDatos, ResultadoIntento, ResultadoPepDatos, SolicitudDatos, SolicitudDatosCruda,
    TipoIncidente, AlmacenSimulado,
};
use sak_core::reloj::RelojInyectado;

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes([seed; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva(format!("N-EF2-{seed}")).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn sol_base() -> SolicitudDatos {
    SolicitudDatos::nueva(
        OperacionDatos::AccesoExpediente,
        "expedientes",
        [0xABu8; LONGITUD_HASH_PAQUETE],
        ["id", "nombre"],
        "dest-kernel",
        10,
    )
    .unwrap()
}

fn emitir_cap(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudDatos,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_datos(sol.clone());
    let sujeto = IdSujeto::nuevo(format!("suj-d-{seed}")).unwrap();
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef2(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: false,
            afecta_personas: true,
            datos_personales: true,
        },
    };
    ledger
        .emitir_tras_evidencia(&sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

#[test]
fn sin_capacidad_no_hay_acceso() {
    assert!(!GatewayDatos::puede_emitir_capacidad());
    assert!(!GatewayDatos::posee_credencial_datos());

    let reloj = RelojInyectado::nuevo(1);
    let mut gw = GatewayDatos::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([1u8; 32]));
    let sistema = IdSistema::nuevo("sys-d").unwrap();
    let sujeto = IdSujeto::nuevo("suj-d").unwrap();

    let r = gw.ejercer(
        &SolicitudDatosCruda::Tipada(sol_base()),
        None,
        &sistema,
        &sujeto,
        &mut ledger,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));
    assert_eq!(store.consultas_delegadas, 0);
}

#[test]
fn ruta_directa_bloqueada() {
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([2u8; 32]));
    let err = store.llamar_directo(&sol_base()).unwrap_err();
    assert!(err.to_string().contains("inalcanzable sin PEP"));
    assert_eq!(store.intentos_directos, 1);
    assert_eq!(store.consultas_delegadas, 0);
}

#[test]
fn credencial_datos_no_expuesta() {
    let store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([3u8; 32]));
    assert!(!store.credencial_expuesta());
    let dbg = format!("{:?}", CredencialDatos::desde_semilla([3u8; 32]));
    assert!(dbg.contains("REDACTED"));
}

#[test]
fn solo_recurso_filtro_campos_volumen_autorizados() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ok").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ok").unwrap();
    let sol = sol_base();
    let cap = emitir_cap(1, &sistema, &sol, &mut ledger, &reloj);

    let mut gw = GatewayDatos::nuevo(1);
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([4u8; 32]));

    let r = gw.ejercer(
        &SolicitudDatosCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut store,
        &reloj,
        1,
    );
    match r {
        ResultadoPepDatos::Permitido(resp) => {
            assert_eq!(resp.campos_devueltos, vec!["id", "nombre"]);
            assert!(resp.volumen_devuelto <= 10);
            assert!(!resp.campos_devueltos.iter().any(|c| c == "secreto"));
            assert_ne!(resp.recibo.digest_condiciones, [0u8; LONGITUD_HASH_PAQUETE]);
        }
        other => panic!("{other:?}"),
    }

    // Campo no autorizado.
    let mut sol_campo = sol.clone();
    sol_campo.campos.insert("secreto".into());
    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let cap2 = emitir_cap(2, &sistema, &sol, &mut ledger2, &reloj);
    let mut gw2 = GatewayDatos::nuevo(1);
    let r2 = gw2.ejercer(
        &SolicitudDatosCruda::Tipada(sol_campo),
        Some(&cap2),
        &sistema,
        &sujeto,
        &mut ledger2,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r2,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::CampoNoAutorizado
        }
    ));

    // Volumen excedido.
    let mut sol_vol = sol.clone();
    sol_vol.limite_volumen = 999;
    let r3 = gw2.ejercer(
        &SolicitudDatosCruda::Tipada(sol_vol),
        Some(&cap2),
        &sistema,
        &sujeto,
        &mut ledger2,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r3,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::VolumenExcedido
        }
    ));

    // Filtro alterado.
    let mut sol_filtro = sol.clone();
    sol_filtro.digest_filtro = [0xFFu8; LONGITUD_HASH_PAQUETE];
    let r4 = gw2.ejercer(
        &SolicitudDatosCruda::Tipada(sol_filtro),
        Some(&cap2),
        &sistema,
        &sujeto,
        &mut ledger2,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r4,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::FiltroNoAutorizado
        }
    ));

    // Recurso distinto.
    let mut sol_rec = sol;
    sol_rec.recurso = "otra-base".into();
    let r5 = gw2.ejercer(
        &SolicitudDatosCruda::Tipada(sol_rec),
        Some(&cap2),
        &sistema,
        &sujeto,
        &mut ledger2,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r5,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::RecursoNoAutorizado
        }
    ));
}

#[test]
fn capacidad_un_solo_uso_no_se_reutiliza() {
    let reloj = RelojInyectado::nuevo(20);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-once").unwrap();
    let sujeto = IdSujeto::nuevo("suj-once").unwrap();
    let sol = sol_base();
    let cap = emitir_cap(3, &sistema, &sol, &mut ledger, &reloj);
    assert!(cap.un_solo_uso());

    let mut gw = GatewayDatos::nuevo(1);
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([5u8; 32]));

    assert!(matches!(
        gw.ejercer(
            &SolicitudDatosCruda::Tipada(sol.clone()),
            Some(&cap),
            &sistema,
            &sujeto,
            &mut ledger,
            &mut store,
            &reloj,
            1,
        ),
        ResultadoPepDatos::Permitido(_)
    ));
    assert!(matches!(
        gw.ejercer(
            &SolicitudDatosCruda::Tipada(sol),
            Some(&cap),
            &sistema,
            &sujeto,
            &mut ledger,
            &mut store,
            &reloj,
            1,
        ),
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::Capacidad(sak_core::capacidad::CausaDenegacion::Repetida)
        }
    ));
    assert_eq!(store.consultas_delegadas, 1);
}

#[test]
fn denegaciones_y_divergencias_registradas() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-div").unwrap();
    let sujeto = IdSujeto::nuevo("suj-div").unwrap();
    let sol = sol_base();
    let cap = emitir_cap(4, &sistema, &sol, &mut ledger, &reloj);

    let mut gw = GatewayDatos::nuevo(1);
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([6u8; 32]));
    store.forzar_divergencia = true;

    let r = gw.ejercer(
        &SolicitudDatosCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut store,
        &reloj,
        1,
    );
    assert!(matches!(
        r,
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert_eq!(gw.incidentes().len(), 1);
    assert_eq!(gw.incidentes()[0].tipo, TipoIncidente::DivergenciaParametros);
    assert!(gw
        .intentos()
        .iter()
        .any(|i| matches!(i.resultado, ResultadoIntento::Denegado(_))));
}

#[test]
fn efecto_no_tipificable_deny() {
    let reloj = RelojInyectado::nuevo(0);
    let mut gw = GatewayDatos::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([7u8; 32]));
    let sistema = IdSistema::nuevo("sys-nt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-nt").unwrap();

    let r = gw.ejercer(
        &SolicitudDatosCruda::NoTipificable,
        None,
        &sistema,
        &sujeto,
        &mut ledger,
        &mut store,
        &reloj,
        1,
    );
    match r {
        ResultadoPepDatos::Denegado {
            codigo: CodigoPep::EfectoNoTipificado,
        } => assert_eq!(CodigoPep::EfectoNoTipificado.token(), "EFECTO_NO_TIPIFICADO"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn recibo_cadena_verifica_offline() {
    let reloj = RelojInyectado::nuevo(40);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base();
    let cap = emitir_cap(5, &sistema, &sol, &mut ledger, &reloj);

    let mut gw = GatewayDatos::nuevo(1);
    let mut store = AlmacenSimulado::nuevo(CredencialDatos::desde_semilla([8u8; 32]));

    assert!(matches!(
        gw.ejercer(
            &SolicitudDatosCruda::Tipada(sol),
            Some(&cap),
            &sistema,
            &sujeto,
            &mut ledger,
            &mut store,
            &reloj,
            1,
        ),
        ResultadoPepDatos::Permitido(_)
    ));

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(informe.cadena_continua);
    assert!(informe.firmas_registros_ok);
}
