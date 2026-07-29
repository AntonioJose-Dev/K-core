//! Harnesses Bloque 6: PEP EF-1, ejecución delegada, recibo e incidente.

use sak_core::capacidad::{ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef1, preparar_solicitud, ClaseEfecto, CodigoPep, CredencialProveedor, GatewayModelos,
    ProveedorSimulado, ResultadoIntento, ResultadoPep, SolicitudCruda, TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes([seed; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva(format!("N-EF1-{seed}")).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn emitir_cap(
    seed: u8,
    sistema: &IdSistema,
    digest: [u8; LONGITUD_HASH_PAQUETE],
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
) -> sak_core::capacidad::Capability {
    let sujeto = IdSujeto::nuevo(format!("suj-{seed}")).unwrap();
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef1(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    ledger
        .emitir_tras_evidencia(&sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

#[test]
fn proveedor_no_alcanzable_sin_pep() {
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([1u8; 32]));
    let (sol, _) = preparar_solicitud("m1", [2u8; LONGITUD_HASH_PAQUETE], 64, 0);
    let err = prov.llamar_directo(&sol).unwrap_err();
    assert_eq!(
        err.to_string(),
        "egreso forzado: proveedor inalcanzable sin PEP"
    );
    assert_eq!(prov.intentos_directos, 1);
    assert_eq!(prov.llamadas_delegadas, 0);
}

#[test]
fn pep_no_autoriza_por_si_mismo() {
    assert!(!GatewayModelos::puede_emitir_capacidad());
    assert!(!GatewayModelos::posee_credencial_proveedor());

    let reloj = RelojInyectado::nuevo(10);
    let mut gateway = GatewayModelos::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([3u8; 32]));
    let sistema = IdSistema::nuevo("sys-a").unwrap();
    let sujeto = IdSujeto::nuevo("suj-a").unwrap();
    let (sol, _) = preparar_solicitud("m1", [4u8; LONGITUD_HASH_PAQUETE], 32, 0);

    let r = gateway.ejercer(
        &SolicitudCruda::Tipada(sol),
        None,
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    assert!(matches!(
        r,
        ResultadoPep::Denegado {
            codigo: CodigoPep::CapacidadAusente
        }
    ));
    assert_eq!(prov.llamadas_delegadas, 0);
    assert!(matches!(
        gateway.intentos().last().unwrap().resultado,
        ResultadoIntento::Denegado(CodigoPep::CapacidadAusente)
    ));
}

#[test]
fn credencial_proveedor_no_expuesta() {
    let prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([9u8; 32]));
    assert!(!prov.credencial_expuesta());
    let dbg = format!("{:?}", CredencialProveedor::desde_semilla([9u8; 32]));
    assert!(dbg.contains("REDACTED"));
    assert!(!dbg.contains('\0')); // no vuelca bytes del secreto en Debug
}

#[test]
fn capacidad_valida_ejecuta_parametros_autorizados_una_vez() {
    let reloj = RelojInyectado::nuevo(100);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-ok").unwrap();
    let sujeto = IdSujeto::nuevo("suj-ok").unwrap();
    let (sol, digest) = preparar_solicitud("gpt-test", [7u8; LONGITUD_HASH_PAQUETE], 128, 200);
    let cap = emitir_cap(1, &sistema, digest, &mut ledger, &reloj);

    let mut gateway = GatewayModelos::nuevo(1);
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([5u8; 32]));

    let r1 = gateway.ejercer(
        &SolicitudCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    match r1 {
        ResultadoPep::Permitido(resp) => {
            assert_eq!(resp.recibo.digest_parametros, digest);
            assert_ne!(resp.recibo.digest_condiciones, [0u8; LONGITUD_HASH_PAQUETE]);
            assert_eq!(resp.antiguedad_vista_ms, 0);
        }
        other => panic!("esperado permitido: {other:?}"),
    }
    assert_eq!(prov.llamadas_delegadas, 1);

    let r2 = gateway.ejercer(
        &SolicitudCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    assert!(matches!(
        r2,
        ResultadoPep::Denegado {
            codigo: CodigoPep::Capacidad(sak_core::capacidad::CausaDenegacion::Repetida)
        }
    ));
    assert_eq!(prov.llamadas_delegadas, 1);
}

#[test]
fn efecto_no_tipificable_deny() {
    let reloj = RelojInyectado::nuevo(0);
    let mut gateway = GatewayModelos::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([1u8; 32]));
    let sistema = IdSistema::nuevo("sys-x").unwrap();
    let sujeto = IdSujeto::nuevo("suj-x").unwrap();

    let r = gateway.ejercer(
        &SolicitudCruda::NoTipificable,
        None,
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    match r {
        ResultadoPep::Denegado {
            codigo: CodigoPep::EfectoNoTipificado,
        } => {
            assert_eq!(CodigoPep::EfectoNoTipificado.token(), "EFECTO_NO_TIPIFICADO");
        }
        other => panic!("{other:?}"),
    }
    let _ = ClaseEfecto::Ef1; // vocabulario tipado disponible
}

#[test]
fn denegaciones_y_divergencias_generan_registros() {
    let reloj = RelojInyectado::nuevo(50);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-div").unwrap();
    let sujeto = IdSujeto::nuevo("suj-div").unwrap();
    let (sol, digest) = preparar_solicitud("m", [8u8; LONGITUD_HASH_PAQUETE], 16, 0);
    let cap = emitir_cap(2, &sistema, digest, &mut ledger, &reloj);

    let mut gateway = GatewayModelos::nuevo(1);
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([6u8; 32]));
    prov.forzar_divergencia = true;

    let r = gateway.ejercer(
        &SolicitudCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    assert!(matches!(
        r,
        ResultadoPep::Denegado {
            codigo: CodigoPep::IncidenteMediacion
        }
    ));
    assert_eq!(gateway.incidentes().len(), 1);
    assert_eq!(
        gateway.incidentes()[0].tipo,
        TipoIncidente::DivergenciaParametros
    );
    assert!(gateway
        .intentos()
        .iter()
        .any(|i| matches!(i.resultado, ResultadoIntento::Denegado(_))));
}

#[test]
fn recibo_verifica_offline() {
    let reloj = RelojInyectado::nuevo(200);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let (sol, digest) = preparar_solicitud("offline-model", [3u8; LONGITUD_HASH_PAQUETE], 64, 0);
    let cap = emitir_cap(3, &sistema, digest, &mut ledger, &reloj);

    let mut gateway = GatewayModelos::nuevo(1);
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([7u8; 32]));

    let r = gateway.ejercer(
        &SolicitudCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    assert!(matches!(r, ResultadoPep::Permitido(_)));

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(informe.cadena_continua);
    assert!(informe.firmas_registros_ok);
}
