//! INV-07: evidencia durable en disco; fallo de escritura ⇒ no capacidad.

use sak_core::capacidad::{digest_efecto_canonico, Alcance, ClasificacionEfecto, ParametrosEmision};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{AlmacenDiscoLocal, AlmacenEvidencia, IdSujeto, LedgerEvidencia};
use sak_core::identidad::IdSistema;
use sak_core::reloj::RelojInyectado;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir_tmp(tag: &str) -> std::path::PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sak-inv07-{tag}-{n}"))
}

fn decision_minima() -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes([9u8; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-D0").unwrap()], vec![], 1).unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn params() -> ParametrosEmision {
    ParametrosEmision {
        sistema: IdSistema::nuevo("sys-d0").unwrap(),
        digest_efecto: digest_efecto_canonico("EF-1", b"d0"),
        alcance: Alcance::minimo(["d0"]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    }
}

#[test]
fn inv07_escritura_disco_sobrevive_reapertura() {
    let dir = dir_tmp("ok");
    let sujeto = IdSujeto::nuevo("sujeto-d0").unwrap();
    let reloj = RelojInyectado::nuevo(1_000);
    let clave_esperada: Vec<u8>;
    {
        let almacen = AlmacenDiscoLocal::abrir(&dir).unwrap();
        let mut ledger = LedgerEvidencia::nuevo(almacen).unwrap();
        let _cap = ledger
            .emitir_tras_evidencia(&sujeto, decision_minima(), params(), &reloj)
            .unwrap();
        assert_eq!(ledger.n_capacidades_emitidas(), 1);
        // El ledger escribe reg/{sujeto}/{epoca}/{seq}
        clave_esperada = format!("reg/{}/1/0", sujeto.como_str()).into_bytes();
    }
    let abierto = AlmacenDiscoLocal::abrir(&dir).unwrap();
    assert!(
        abierto.leer(&clave_esperada).is_some(),
        "INV-07: el blob de decisión debe permanecer en disco tras cerrar el ledger"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn inv07_fallo_disco_no_emite_capacidad() {
    let dir = dir_tmp("deny");
    let mut almacen = AlmacenDiscoLocal::abrir(&dir).unwrap();
    almacen.fallar_escritura = true;
    let mut ledger = LedgerEvidencia::nuevo(almacen).unwrap();
    let sujeto = IdSujeto::nuevo("sujeto-d0").unwrap();
    let reloj = RelojInyectado::nuevo(1_000);
    let err = ledger
        .emitir_tras_evidencia(&sujeto, decision_minima(), params(), &reloj)
        .unwrap_err();
    assert_eq!(ledger.n_capacidades_emitidas(), 0);
    // EscrituraFallida o DominioSuspendido según orden interno
    let s = format!("{err:?}");
    assert!(
        s.contains("EscrituraFallida") || s.contains("DominioSuspendido") || s.contains("escritura"),
        "err={s}"
    );
    let _ = fs::remove_dir_all(&dir);
}
