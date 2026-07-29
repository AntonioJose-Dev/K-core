//! Harnesses Bloque 3: INV-07 material, INV-15, cadena, checkpoints, SUSPENDED.

use sak_core::capacidad::{
    digest_efecto_canonico, Alcance, ClasificacionEfecto, CompromisoEvidencia, ParametrosEmision,
};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, AlmacenEvidencia, ErrorEvidencia, EstadoDominio, IdSujeto, LedgerEvidencia,
    MemoriaDurable, ReciboEfecto, ESQUEMA_REGISTRO_V1,
};
use sak_core::identidad::IdSistema;
use sak_core::reloj::RelojInyectado;

fn decision_ok(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes([seed; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva(format!("N-{seed}")).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn params(seed: u8) -> ParametrosEmision {
    ParametrosEmision {
        sistema: IdSistema::nuevo(format!("sys-{seed}")).unwrap(),
        digest_efecto: digest_efecto_canonico("EF-TEST", &[seed]),
        alcance: Alcance::minimo([format!("r-{seed}")]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    }
}

#[test]
fn esquema_publicado() {
    assert!(ESQUEMA_REGISTRO_V1.contains("firma_mldsa87"));
    assert!(ESQUEMA_REGISTRO_V1.contains("cofirma_testigo"));
}

#[test]
fn emitir_tras_evidencia_y_cardinalidad() {
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("s1").unwrap();
    let reloj = RelojInyectado::nuevo(1_000);
    let d = decision_ok(1);
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, d.clone(), params(1), &reloj)
        .unwrap();
    assert_eq!(ledger.n_decisiones_comprometidas(), 1);
    assert_eq!(ledger.n_capacidades_emitidas(), 1);
    assert_eq!(
        cap.compromiso_evidencia().digest().len(),
        LONGITUD_HASH_PAQUETE
    );
    let err = ledger
        .emitir_tras_evidencia(&sujeto, d, params(1), &reloj)
        .unwrap_err();
    assert_eq!(err, ErrorEvidencia::DecisionYaComprometida);
}

#[test]
fn escritura_fallida_suspende_y_no_emite() {
    let mut store = MemoriaDurable::default();
    store.fallar_escritura = true;
    let mut ledger = LedgerEvidencia::nuevo(store).unwrap();
    let sujeto = IdSujeto::nuevo("s2").unwrap();
    let reloj = RelojInyectado::nuevo(0);
    let err = ledger
        .emitir_tras_evidencia(&sujeto, decision_ok(2), params(2), &reloj)
        .unwrap_err();
    assert_eq!(err, ErrorEvidencia::EscrituraFallida);
    assert_eq!(ledger.estado(), EstadoDominio::Suspended);
    assert_eq!(ledger.n_capacidades_emitidas(), 0);
}

#[test]
fn hueco_secuencia_suspende() {
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let e = ledger.reportar_hueco_secuencia(3, 5);
    assert!(matches!(
        e,
        ErrorEvidencia::HuecoSecuencia {
            esperado: 3,
            encontrado: 5
        }
    ));
    assert_eq!(ledger.estado(), EstadoDominio::Suspended);
}

#[test]
fn recibo_checkpoint_y_verificador_offline() {
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("s3").unwrap();
    let reloj = RelojInyectado::nuevo(10);
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision_ok(3), params(3), &reloj)
        .unwrap();
    let recibo = ReciboEfecto {
        digest_parametros: [9u8; LONGITUD_HASH_PAQUETE],
        digest_resultado: [8u8; LONGITUD_HASH_PAQUETE],
        digest_decision: *cap.compromiso_evidencia().digest(),
        digest_condiciones: [0u8; LONGITUD_HASH_PAQUETE],
    };
    ledger.registrar_recibo(&sujeto, &recibo).unwrap();
    let cp = ledger.cerrar_epoca().unwrap();
    assert_eq!(cp.n_registros, 2);
    assert!(!cp.cofirma_testigo_1_slh.is_empty());
    assert!(!cp.cofirma_testigo_2_slh.is_empty());

    let pkg = ledger.exportar_paquete();
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
    assert!(informe.cadena_continua);
    assert!(informe.firmas_registros_ok);
    assert!(informe.checkpoints_ok);
    assert!(informe.cofirmas_testigos_ok);
    assert!(informe.merkle_ok);
    assert!(!informe.no_comprobado.is_empty());
}

#[test]
fn compromiso_no_es_publico() {
    let _: Option<CompromisoEvidencia> = None;
}

#[test]
fn almacen_trait_usable() {
    let mut m = MemoriaDurable::default();
    m.escribir_durable(b"k", b"v").unwrap();
    assert_eq!(m.leer(b"k").unwrap(), b"v");
}
