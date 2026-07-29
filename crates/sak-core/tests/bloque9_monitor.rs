//! Harnesses Bloque 9: máquina de estados, monitor INV-12, época monótona.

use sak_core::capacidad::VerificadorCapacidades;
use sak_core::contexto::ClaseEfecto;
use sak_core::evidencia::{
    verificar_paquete, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::monitor::{
    encadenar_transiciones_en_ledger, monitor_armado_prueba, ErrorMonitor, EstadoMaquina,
    MonitorDominio, UMBRAL_COFIRMA_DEGRADED_MS, UMBRAL_COFIRMA_SUSPEND_MS, UMBRAL_PEP_SILENCIO_MS,
};
use sak_core::reloj::RelojInyectado;

#[test]
fn no_autorizacion_fuera_de_estado_permitido() {
    let reloj = RelojInyectado::nuevo(0);
    let (mut m, _) = monitor_armado_prueba(reloj.ahora());
    assert_eq!(m.estado(), EstadoMaquina::Armed);
    m.exigir_autorizacion(ClaseEfecto::Ef1, true).unwrap();

    m.evento_hueco_secuencia(reloj.ahora(), [1u8; 48]);
    assert_eq!(m.estado(), EstadoMaquina::Suspended);
    assert!(matches!(
        m.exigir_autorizacion(ClaseEfecto::Ef1, false),
        Err(ErrorMonitor::EstadoNoPermiteAutorizacion { .. })
    ));
}

#[test]
fn supuestos_criticos_cierran_como_previsto() {
    let reloj = RelojInyectado::nuevo(1_000);
    // Hueco / reconciliación >5% / custodia clave → SUSPENDED
    let (mut m, _) = monitor_armado_prueba(reloj.ahora());
    m.evento_reconciliacion(6, reloj.ahora());
    assert_eq!(m.estado(), EstadoMaquina::Suspended);

    let (mut m2, _) = monitor_armado_prueba(reloj.ahora());
    m2.evento_custodia_clave_inalcanzable(reloj.ahora());
    assert_eq!(m2.estado(), EstadoMaquina::Suspended);

    // Cofirma: 900s → DEGRADED; 3600s → SUSPENDED
    let (mut m3, _) = monitor_armado_prueba(0);
    m3.evento_cofirma_testigos(0, UMBRAL_COFIRMA_DEGRADED_MS + 1);
    assert_eq!(m3.estado(), EstadoMaquina::Degraded);
    m3.evento_cofirma_testigos(0, UMBRAL_COFIRMA_SUSPEND_MS + 1);
    assert_eq!(m3.estado(), EstadoMaquina::Suspended);

    // Autotest → FAIL_STATIC
    let (mut m4, _) = monitor_armado_prueba(0);
    m4.evento_autotest_fallido(0);
    assert_eq!(m4.estado(), EstadoMaquina::FailStatic);
    assert!(m4.estado().es_terminal());

    // Entropía en ejecución → SUSPENDED
    let (mut m5, _) = monitor_armado_prueba(0);
    m5.evento_entropia_ejecucion_fallida(0);
    assert_eq!(m5.estado(), EstadoMaquina::Suspended);

    // PEP silencio → suspensión de clase (dominio puede seguir ARMED)
    let (mut m6, _) = monitor_armado_prueba(0);
    m6.evento_latido_pep(ClaseEfecto::Ef1, 0);
    m6.evaluar_silencio_pep(ClaseEfecto::Ef1, UMBRAL_PEP_SILENCIO_MS + 1);
    assert!(m6.clase_suspendida(ClaseEfecto::Ef1));
    assert_eq!(m6.estado(), EstadoMaquina::Armed);
    assert!(matches!(
        m6.exigir_autorizacion(ClaseEfecto::Ef1, false),
        Err(ErrorMonitor::ClaseSuspendida)
    ));
}

#[test]
fn no_doble_emision_valida_misma_epoca() {
    let (mut m, _) = monitor_armado_prueba(0);
    m.registrar_emision_epoca().unwrap();
    assert_eq!(m.n_emisiones_epoca(m.epoca()), 1);
    assert!(m.registrar_emision_epoca().is_err());
}

#[test]
fn epoca_no_retrocede_y_perdida_es_terminal() {
    let mut store = MemoriaDurable::default();
    let mut m = MonitorDominio::arrancar(&mut store, true, 0).unwrap();
    let e = m.epoca();
    assert!(m.evento_retroceso_epoca(e - 1, 0).is_err());
    assert_eq!(m.estado(), EstadoMaquina::FailStatic);

    // Persistencia: avanzar y recargar
    let mut store2 = MemoriaDurable::default();
    let mut m2 = MonitorDominio::arrancar(&mut store2, true, 0).unwrap();
    let n = m2.avanzar_epoca(&mut store2, 1).unwrap();
    assert!(n > 1);
    let m3 = MonitorDominio::arrancar(&mut store2, true, 2).unwrap();
    assert!(m3.suelo_epoca() >= n);
}

#[test]
fn recuperacion_no_automatica() {
    let (mut m, _) = monitor_armado_prueba(0);
    m.evento_hueco_secuencia(0, [2u8; 48]);
    assert!(matches!(
        m.intentar_recuperacion_automatica(),
        Err(ErrorMonitor::RecuperacionPendienteGobernanza)
    ));
}

#[test]
fn degraded_solo_reversibles() {
    let (mut m, _) = monitor_armado_prueba(0);
    m.evento_cofirma_testigos(0, UMBRAL_COFIRMA_DEGRADED_MS + 1);
    assert_eq!(m.estado(), EstadoMaquina::Degraded);
    m.exigir_autorizacion(ClaseEfecto::Ef1, false).unwrap();
    assert!(matches!(
        m.exigir_autorizacion(ClaseEfecto::Ef1, true),
        Err(ErrorMonitor::EstadoNoPermiteAutorizacion { .. })
    ));
}

#[test]
fn transiciones_encadenadas_verifican_offline() {
    let reloj = RelojInyectado::nuevo(10);
    let (mut mon, _) = monitor_armado_prueba(reloj.ahora());
    mon.evento_latido_pep(ClaseEfecto::Ef2, reloj.ahora());
    mon.evento_reconciliacion(9, reloj.ahora());
    assert!(!mon.transiciones().is_empty());

    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    // El ledger empieza OPERATIVE; registramos transiciones (incluye paso a SUSPENDED del monitor).
    // Primero una decisión mínima para tener cadena coherente no es estrictamente necesaria
    // para TransicionEstado.
    encadenar_transiciones_en_ledger(&mut ledger, &mon).unwrap();
    assert!(ledger
        .exportar_paquete()
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::TransicionEstado));

    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
    assert!(informe.cadena_continua);
    assert!(informe.firmas_registros_ok);
}

#[test]
fn revoca_capacidades_al_suspender() {
    let (mut m, _) = monitor_armado_prueba(0);
    let id = sak_core::capacidad::IdCapacidad::opaco([9u8; 48]);
    m.programar_revocacion(id);
    let mut v = VerificadorCapacidades::nuevo(1);
    m.evento_hueco_secuencia(0, [3u8; 48]);
    m.aplicar_revocaciones(&mut v);
    assert_eq!(m.estado(), EstadoMaquina::Suspended);
}

#[test]
fn arranque_autotest_falla_terminal() {
    let mut store = MemoriaDurable::default();
    let err = MonitorDominio::arrancar(&mut store, false, 0);
    assert!(matches!(err, Err(ErrorMonitor::AutotestFallido)));
}

#[test]
fn siete_estados_canonicos_tokens() {
    assert_eq!(EstadoMaquina::Cold.token(), "COLD");
    assert_eq!(EstadoMaquina::Selftest.token(), "SELFTEST");
    assert_eq!(EstadoMaquina::Sealed.token(), "SEALED");
    assert_eq!(EstadoMaquina::Armed.token(), "ARMED");
    assert_eq!(EstadoMaquina::Degraded.token(), "DEGRADED");
    assert_eq!(EstadoMaquina::Suspended.token(), "SUSPENDED");
    assert_eq!(EstadoMaquina::FailStatic.token(), "FAIL_STATIC");
}
