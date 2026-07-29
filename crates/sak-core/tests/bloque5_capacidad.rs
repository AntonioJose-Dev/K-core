//! Harnesses Bloque 5: INV-08, H.12–H.13 — emisor/verificador de capacidades.

use sak_core::capacidad::{
    digest_efecto_canonico, emitir, Alcance, CausaDenegacion, ClasificacionEfecto, IntentoUso,
    ParametrosEmision, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use sak_core::custodia::{BrokerCredenciales, SecretoRaiz};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{IdSujeto, LedgerEvidencia, MemoriaDurable};
use sak_core::identidad::IdSistema;
use sak_core::reloj::{RelojInyectado, MAX_ANTIGUEDAD_VISTA_REVOCACION_MS};

fn decision_allow(seed: u8) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes([seed; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva(format!("N-{seed}")).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn params_base(
    sistema: IdSistema,
    digest: [u8; LONGITUD_HASH_PAQUETE],
    alcance: Alcance,
    clasificacion: ClasificacionEfecto,
    ttl: u64,
) -> ParametrosEmision {
    ParametrosEmision {
        sistema,
        digest_efecto: digest,
        alcance,
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: ttl,
        clasificacion,
    }
}

fn emitir_ok(
    seed: u8,
    clasificacion: ClasificacionEfecto,
    ttl: u64,
    reloj: &RelojInyectado,
) -> sak_core::capacidad::Capability {
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo(format!("s-{seed}")).unwrap();
    let sistema = IdSistema::nuevo(format!("sys-{seed}")).unwrap();
    let digest = digest_efecto_canonico("EF-1", &[seed]);
    let alcance = Alcance::minimo(["modelo:gpt", "max_tokens:128"]).unwrap();
    let params = params_base(sistema, digest, alcance, clasificacion, ttl);
    ledger
        .emitir_tras_evidencia(&sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn intento_de(cap: &sak_core::capacidad::Capability) -> IntentoUso {
    IntentoUso {
        sistema: cap.sistema().clone(),
        digest_efecto: *cap.digest_efecto(),
        alcance: cap.alcance().clone(),
        epoca_actual: cap.epoca(),
    }
}

#[test]
fn emision_solo_tras_allow_y_compromiso_durable() {
    let reloj = RelojInyectado::nuevo(1_000);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("s-allow").unwrap();
    let sistema = IdSistema::nuevo("sys-allow").unwrap();
    let digest = digest_efecto_canonico("EF-1", b"x");
    let params = params_base(
        sistema,
        digest,
        Alcance::minimo(["r"]).unwrap(),
        ClasificacionEfecto::irreversible(),
        5_000,
    );
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision_allow(11), params, &reloj)
        .unwrap();
    assert_eq!(ledger.n_decisiones_comprometidas(), 1);
    assert_eq!(ledger.n_capacidades_emitidas(), 1);
    assert_eq!(cap.compromiso_evidencia().digest().len(), LONGITUD_HASH_PAQUETE);
    assert!(cap.un_solo_uso());
}

#[test]
fn digest_ligado_al_efecto() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(2, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    let mut v = VerificadorCapacidades::nuevo(1);
    let vista = v.vista_sincrona(&reloj);
    let mut mal = intento_de(&cap);
    mal.digest_efecto = digest_efecto_canonico("EF-1", b"otro");
    match v.verificar_uso(&cap, &mal, &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::DigestDistinto,
        } => {}
        other => panic!("esperado DigestDistinto, got {other:?}"),
    }
    assert_eq!(v.denegaciones().len(), 1);
}

#[test]
fn alcance_minimo_sin_ampliacion() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(3, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    let mut v = VerificadorCapacidades::nuevo(1);
    let vista = v.vista_sincrona(&reloj);
    let mut mal = intento_de(&cap);
    mal.alcance = Alcance::minimo(["modelo:gpt", "max_tokens:128", "admin"]).unwrap();
    match v.verificar_uso(&cap, &mal, &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::AlcanceDistinto,
        } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn vencimiento_deniega() {
    let reloj = RelojInyectado::nuevo(100);
    let cap = emitir_ok(4, ClasificacionEfecto::irreversible(), 50, &reloj);
    reloj.avanzar(51).unwrap();
    let mut v = VerificadorCapacidades::nuevo(1);
    let vista = v.vista_sincrona(&reloj);
    match v.verificar_uso(&cap, &intento_de(&cap), &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::Expirada,
        } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn revocacion_deniega() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(5, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    let mut v = VerificadorCapacidades::nuevo(1);
    v.revocar(*cap.id());
    let vista = v.vista_sincrona(&reloj);
    match v.verificar_uso(&cap, &intento_de(&cap), &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::Revocada,
        } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn no_transferencia_entre_identidades() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(6, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    let mut v = VerificadorCapacidades::nuevo(1);
    let vista = v.vista_sincrona(&reloj);
    let mut mal = intento_de(&cap);
    mal.sistema = IdSistema::nuevo("otro-sistema").unwrap();
    match v.verificar_uso(&cap, &mal, &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::SistemaDistinto,
        } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn repeticion_de_nonce_deniega() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(7, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    assert!(cap.un_solo_uso());
    let mut v = VerificadorCapacidades::nuevo(1);
    let vista = v.vista_sincrona(&reloj);
    match v.verificar_uso(&cap, &intento_de(&cap), &vista, &reloj) {
        ResultadoVerificacion::Permitido { .. } => {}
        other => panic!("primer uso: {other:?}"),
    }
    let vista2 = v.vista_sincrona(&reloj);
    match v.verificar_uso(&cap, &intento_de(&cap), &vista2, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::Repetida,
        } => {}
        other => panic!("reuso: {other:?}"),
    }
    assert!(v.nonce_consumido(cap.epoca(), cap.id()));
}

#[test]
fn epoca_invalida_o_inferior_deniega() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(8, ClasificacionEfecto::irreversible(), 10_000, &reloj);

    // Emisión con época 0 rechazada.
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut p = params_base(
        IdSistema::nuevo("sys-e0").unwrap(),
        digest_efecto_canonico("EF", b"0"),
        Alcance::minimo(["r"]).unwrap(),
        ClasificacionEfecto::irreversible(),
        100,
    );
    p.epoca = 0;
    let compromiso = ledger
        .comprometer_decision(&IdSujeto::nuevo("s-e0").unwrap(), &decision_allow(80))
        .unwrap();
    let err = emitir(decision_allow(81), compromiso, p, &reloj).unwrap_err();
    assert!(matches!(
        err,
        sak_core::capacidad::ErrorEmision::EpocaInvalida
    ));

    let mut v = VerificadorCapacidades::nuevo(1);
    v.avanzar_suelo_epoca(2).unwrap();
    let vista = v.vista_sincrona(&reloj);
    match v.verificar_uso(&cap, &intento_de(&cap), &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::EpocaInferior,
        } => {}
        other => panic!("suelo avanzado: {other:?}"),
    }
}

#[test]
fn vista_revocacion_obsoleta_deniega_reversible() {
    let reloj = RelojInyectado::nuevo(1_000);
    let cap = emitir_ok(
        9,
        ClasificacionEfecto::reversible_sin_personas(),
        60_000,
        &reloj,
    );
    assert!(!cap.un_solo_uso());
    assert!(!cap.irreversible());

    let mut v = VerificadorCapacidades::nuevo(1);
    let obtenida_en = reloj.ahora();
    let vista = VistaRevocacion::Cacheada {
        revocadas: v.snapshot_revocacion(),
        obtenida_en,
    };
    reloj
        .avanzar(MAX_ANTIGUEDAD_VISTA_REVOCACION_MS + 1)
        .unwrap();
    match v.verificar_uso(&cap, &intento_de(&cap), &vista, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::VistaRevocacionObsoleta,
        } => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn irreversible_exige_vista_sincrona_silencio_deniega() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(10, ClasificacionEfecto::irreversible(), 10_000, &reloj);
    let mut v = VerificadorCapacidades::nuevo(1);
    match v.verificar_uso(&cap, &intento_de(&cap), &VistaRevocacion::Silencio, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::SilencioRevocacion,
        } => {}
        other => panic!("{other:?}"),
    }
    let vista_cache = VistaRevocacion::Cacheada {
        revocadas: v.snapshot_revocacion(),
        obtenida_en: reloj.ahora(),
    };
    match v.verificar_uso(&cap, &intento_de(&cap), &vista_cache, &reloj) {
        ResultadoVerificacion::Denegado {
            causa: CausaDenegacion::VistaNoVerificable,
        } => {}
        other => panic!("cache en irreversible: {other:?}"),
    }
}

#[test]
fn custodia_raiz_no_exportable_y_credencial_caduca_o_reuso() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(12, ClasificacionEfecto::irreversible(), 100, &reloj);
    let mut broker = BrokerCredenciales::nuevo(SecretoRaiz::desde_semilla([9u8; 32]));
    assert!(broker.tiene_raiz_encapsulada());
    let cred = broker.emitir_desde_capacidad(&cap, &reloj).unwrap();
    broker.ejercer(&cred, &reloj).unwrap();
    assert!(broker.ejercer(&cred, &reloj).is_err());
    assert!(broker.n_denegaciones() >= 1);

    let cap2 = emitir_ok(13, ClasificacionEfecto::irreversible(), 20, &reloj);
    let mut broker2 = BrokerCredenciales::nuevo(SecretoRaiz::desde_semilla([1u8; 32]));
    let cred2 = broker2.emitir_desde_capacidad(&cap2, &reloj).unwrap();
    reloj.avanzar(21).unwrap();
    assert!(broker2.ejercer(&cred2, &reloj).is_err());
}

#[test]
fn datos_personales_implican_un_solo_uso() {
    let reloj = RelojInyectado::nuevo(0);
    let cap = emitir_ok(
        14,
        ClasificacionEfecto {
            irreversible: false,
            afecta_personas: false,
            datos_personales: true,
        },
        10_000,
        &reloj,
    );
    assert!(cap.un_solo_uso());
}
