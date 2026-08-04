//! INV-03 / G.5 D2: paquete normativo activado durable y cita resoluble.

use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::crypto::{dominio, sha384_dominio, ParMlDsa87};
use sak_core::decision::{HashPaqueteNormativo, Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::evidencia::{
    AlmacenDiscoLocal, AlmacenEvidencia, ErrorEvidencia, EstadoDominio, LedgerEvidencia,
    MemoriaDurable,
};
use sak_core::gobernanza::{
    activar_en_limite_epoca, cargar_gobernanza_desde_almacen, clave_almacen_paquete,
    conservar_paquete_activado, entrar_en_sombra, exigir_cita_o_suspender, exigir_diff_reconocido,
    resolver_cita_paquete, resultado_diff, validar_paquete_gobernado, AprobacionInterpretacion,
    CasoConformidad, EntradaCita, ErrorCorpusDurable, EtiquetaGob, FirmaPaquete,
    FirmanteGobernanza, GobernanzaCorpus, PropuestaNormativa, ReconocimientoCambio,
    RegistroAprobacionesInterp, RegistroCitas, RegistroFirmantesGob, RolFirmante, ESQUEMA_REQUERIDO,
    VENTANA_SOMBRA_MS,
};
use sak_core::monitor::EpocaMonotonica;
use sak_core::norma::{
    Alcance, BorradorNorma, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::reloj::RelojInyectado;
use sak_core::supervision::IdHumano;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn dig_interp(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    sha384_dominio(dominio::GOBERNANZA, &[seed])
}

fn alcance() -> Alcance {
    Alcance {
        caso_de_uso: "c".into(),
        clase_riesgo: "r".into(),
        rol_regulatorio: "rol".into(),
        sector: "s".into(),
        categorias_datos: "d".into(),
        autonomia: "a".into(),
        destinatarios: "dest".into(),
    }
}

struct Fix {
    citas: RegistroCitas,
    aprobaciones: RegistroAprobacionesInterp,
    firmantes: RegistroFirmantesGob,
    par_j: ParMlDsa87,
    par_t: ParMlDsa87,
    id_j: IdHumano,
    id_t: IdHumano,
    par_ack: ParMlDsa87,
    id_ack: IdHumano,
    dig: [u8; LONGITUD_HASH_PAQUETE],
}

fn fixture() -> Fix {
    let dig = dig_interp(42);
    let par_aprob = ParMlDsa87::generar().unwrap();
    let id_aprob = IdHumano::nuevo("aprob-interp").unwrap();
    let mut aprobaciones = RegistroAprobacionesInterp::nuevo();
    aprobaciones
        .registrar(
            AprobacionInterpretacion::firmar(&par_aprob, id_aprob, dig, EtiquetaGob::ValExt)
                .unwrap(),
        )
        .unwrap();

    let mut citas = RegistroCitas::nuevo();
    citas
        .registrar(EntradaCita {
            fuente: "instrumento-art-1".into(),
            digest_cita: sha384_dominio(dominio::GOBERNANZA, b"cita"),
            etiqueta: EtiquetaGob::Gob,
        })
        .unwrap();

    let par_j = ParMlDsa87::generar().unwrap();
    let par_t = ParMlDsa87::generar().unwrap();
    let id_j = IdHumano::nuevo("firmante-jur").unwrap();
    let id_t = IdHumano::nuevo("firmante-tec").unwrap();
    let mut firmantes = RegistroFirmantesGob::nuevo();
    firmantes
        .registrar(FirmanteGobernanza {
            id: id_j.clone(),
            rol: RolFirmante::Juridico,
            pk_mldsa: par_j.public.clone(),
            etiqueta: EtiquetaGob::Gob,
        })
        .unwrap();
    firmantes
        .registrar(FirmanteGobernanza {
            id: id_t.clone(),
            rol: RolFirmante::Tecnico,
            pk_mldsa: par_t.public.clone(),
            etiqueta: EtiquetaGob::ValExt,
        })
        .unwrap();

    let par_ack = ParMlDsa87::generar().unwrap();
    let id_ack = IdHumano::nuevo("ack-humano").unwrap();

    Fix {
        citas,
        aprobaciones,
        firmantes,
        par_j,
        par_t,
        id_j,
        id_t,
        par_ack,
        id_ack,
        dig,
    }
}

fn borrador(f: &Fix, id: &str, pred: Predicado) -> BorradorNorma {
    BorradorNorma {
        identificador: id.into(),
        fuente: "instrumento-art-1".into(),
        jurisdiccion: "EU".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L2,
        clase_de_efecto: ClaseEfecto::Ef1,
        predicado: pred,
        evidencia_exigida: vec![],
        acciones_obligatorias: vec!["registrar".into()],
        condiciones_de_denegacion: vec!["fuera-alcance".into()],
        escalado: None,
        monitorizacion: None,
        interpretacion: Interpretacion {
            texto: "interpretacion operativa aprobada".into(),
            autor: "revisor.juridico".into(),
            digest_aprobacion: f.dig,
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    }
}

fn ctx() -> Contexto {
    Contexto::con_instante(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        20_000,
    )
}

fn activar_paquete(f: &Fix, almacen: &mut dyn AlmacenEvidencia) -> HashPaqueteNormativo {
    let n = Norma::cargar(borrador(f, "N-A", Predicado::Fijo(Veredicto::Allow))).unwrap();
    let propuesto = PaqueteNormativo::cargar(vec![n]).unwrap();
    let vacio = PaqueteNormativo::cargar(vec![]).unwrap();
    validar_paquete_gobernado(ESQUEMA_REQUERIDO, &propuesto, &f.citas, &f.aprobaciones).unwrap();
    let mut gob = GobernanzaCorpus::nuevo();
    let mut prop = PropuestaNormativa::nueva_borrador(propuesto);
    prop.marcar_revision_juridica(f.id_j.clone(), true).unwrap();
    let hash = gob.proponer(prop);
    let casos = vec![CasoConformidad {
        id: "caso-1".into(),
        contexto: ctx(),
    }];
    let diff = resultado_diff(&casos, &vacio, &gob.propuesta(&hash).unwrap().paquete);
    let mut acks = Vec::new();
    for c in &diff.cambios {
        acks.push(
            ReconocimientoCambio::firmar(&f.par_ack, f.id_ack.clone(), c.digest_cambio).unwrap(),
        );
    }
    exigir_diff_reconocido(
        &diff,
        &acks,
        &[(f.id_ack.clone(), f.par_ack.public.clone())],
    )
    .unwrap();
    gob.registrar_diff(&hash, diff, acks).unwrap();
    let msg = gob.propuesta(&hash).unwrap().paquete.mensaje_firma();
    let fj = FirmaPaquete::firmar(&f.par_j, f.id_j.clone(), RolFirmante::Juridico, &msg).unwrap();
    let ft = FirmaPaquete::firmar(&f.par_t, f.id_t.clone(), RolFirmante::Tecnico, &msg).unwrap();
    let reloj = RelojInyectado::nuevo(0);
    entrar_en_sombra(&mut gob, &hash, &[fj, ft], &f.firmantes, reloj.ahora()).unwrap();
    reloj.avanzar(VENTANA_SOMBRA_MS).unwrap();
    let mut epoca = EpocaMonotonica::cargar_o_iniciar(almacen, 1).unwrap();
    activar_en_limite_epoca(
        &mut gob,
        &hash,
        &mut epoca,
        almacen,
        reloj.ahora(),
        true,
    )
    .unwrap();
    hash
}

fn dir_tmp(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sak-d2-{tag}-{n}"))
}

#[test]
fn activar_cerrar_reabrir_resuelve_cita_de_decision() {
    let f = fixture();
    let dir = dir_tmp("persist");
    let hash = {
        let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
        activar_paquete(&f, &mut a)
    };
    let a2 = AlmacenDiscoLocal::abrir(&dir).unwrap();
    let gob = cargar_gobernanza_desde_almacen(&a2).unwrap();
    assert_eq!(gob.hash_activo().copied(), Some(hash));
    let v = resolver_cita_paquete(&a2, &hash).unwrap();
    assert_eq!(v.hash, hash);
    assert!(!v.firmas.is_empty());
    assert!(v.diff.is_some());
    let mut ledger = LedgerEvidencia::nuevo(a2).unwrap();
    exigir_cita_o_suspender(&mut ledger, &hash).unwrap();
    assert_eq!(ledger.estado(), EstadoDominio::Operative);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn corrupcion_o_borrado_cita_irresoluble_suspende() {
    let f = fixture();
    let dir = dir_tmp("corrupt");
    let hash = {
        let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
        activar_paquete(&f, &mut a)
    };
    let clave = clave_almacen_paquete(&hash);
    let mut nombre = String::from("k_");
    for b in &clave {
        nombre.push_str(&format!("{b:02x}"));
    }
    fs::write(dir.join(&nombre), b"CORRUPTO").unwrap();

    let a2 = AlmacenDiscoLocal::abrir(&dir).unwrap();
    assert!(matches!(
        resolver_cita_paquete(&a2, &hash),
        Err(ErrorCorpusDurable::Corrupto) | Err(ErrorCorpusDurable::NoEncontrado)
    ));
    let mut ledger = LedgerEvidencia::nuevo(a2).unwrap();
    assert_eq!(
        exigir_cita_o_suspender(&mut ledger, &hash),
        Err(ErrorEvidencia::CitaPaqueteIrresoluble)
    );
    assert_eq!(ledger.estado(), EstadoDominio::Suspended);

    let dir2 = dir_tmp("delete");
    let hash2 = {
        let mut a = AlmacenDiscoLocal::abrir(&dir2).unwrap();
        activar_paquete(&f, &mut a)
    };
    let clave2 = clave_almacen_paquete(&hash2);
    let mut nombre2 = String::from("k_");
    for b in &clave2 {
        nombre2.push_str(&format!("{b:02x}"));
    }
    fs::remove_file(dir2.join(&nombre2)).unwrap();
    let a3 = AlmacenDiscoLocal::abrir(&dir2).unwrap();
    let mut ledger2 = LedgerEvidencia::nuevo(a3).unwrap();
    assert!(exigir_cita_o_suspender(&mut ledger2, &hash2).is_err());
    assert_eq!(ledger2.estado(), EstadoDominio::Suspended);

    let _ = fs::remove_dir_all(&dir);
    let _ = fs::remove_dir_all(&dir2);
}

#[test]
fn paquete_activado_no_sobrescribe_ni_borra_por_ruta_normal() {
    let f = fixture();
    let mut almacen = MemoriaDurable::default();
    let hash = activar_paquete(&f, &mut almacen);
    let v = resolver_cita_paquete(&almacen, &hash).unwrap();
    assert_eq!(
        conservar_paquete_activado(&mut almacen, &v),
        Err(ErrorCorpusDurable::YaExiste)
    );
    assert!(resolver_cita_paquete(&almacen, &hash).is_ok());
}
