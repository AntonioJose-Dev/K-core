//! Harnesses Bloque 11: corpus normativo ejecutable y gobernanza G.5.

use sak_core::capacidad::{
    digest_efecto_canonico, Alcance as AlcanceCap, ClasificacionEfecto, ParametrosEmision,
    VerificadorCapacidades,
};
use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::crypto::{dominio, sha384_dominio, ParMlDsa87};
use sak_core::decision::{
    Decision, DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, Veredicto,
    LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::gobernanza::{
    activar_en_limite_epoca, decision_cita_construible, entrar_en_sombra, exigir_diff_reconocido,
    resultado_diff, revocar_paquete, validar_paquete_gobernado, verificar_doble_firma,
    AprobacionInterpretacion, CasoConformidad, EntradaCita, ErrorActivacion, ErrorDiff, ErrorFirmas,
    EstadoPropuesta, EtiquetaGob, FirmaPaquete, FirmanteGobernanza, GobernanzaCorpus,
    PropuestaNormativa, ReconocimientoCambio, RegistroAprobacionesInterp, RegistroCitas,
    RegistroFirmantesGob, RolFirmante, ESQUEMA_REQUERIDO, VENTANA_SOMBRA_MS,
};
use sak_core::identidad::IdSistema;
use sak_core::monitor::EpocaMonotonica;
use sak_core::motor::decidir_paquete;
use sak_core::norma::{
    Alcance, BorradorNorma, ErrorCarga, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::reloj::RelojInyectado;
use sak_core::supervision::IdHumano;

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

fn dig_interp(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    sha384_dominio(dominio::GOBERNANZA, &[seed])
}

fn borrador(id: &str, pred: Predicado, dig: [u8; LONGITUD_HASH_PAQUETE]) -> BorradorNorma {
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
            digest_aprobacion: dig,
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    }
}

fn ctx() -> Contexto {
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    Contexto::con_instante(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        20_000,
        hash_peticion,
    )
}

struct GobFixture {
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

fn gob_fixture() -> GobFixture {
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

    GobFixture {
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

fn paquete_allow(f: &GobFixture) -> PaqueteNormativo {
    let n = Norma::cargar(borrador("N-A", Predicado::Fijo(Veredicto::Allow), f.dig)).unwrap();
    PaqueteNormativo::cargar(vec![n]).unwrap()
}

fn paquete_deny(f: &GobFixture) -> PaqueteNormativo {
    let n = Norma::cargar(borrador("N-A", Predicado::Fijo(Veredicto::Deny), f.dig)).unwrap();
    PaqueteNormativo::cargar(vec![n]).unwrap()
}

fn avanzar_a_conformidad(
    gob: &mut GobernanzaCorpus,
    f: &GobFixture,
    propuesto: PaqueteNormativo,
    anterior: &PaqueteNormativo,
) -> HashPaqueteNormativo {
    validar_paquete_gobernado(ESQUEMA_REQUERIDO, &propuesto, &f.citas, &f.aprobaciones).unwrap();
    let mut prop = PropuestaNormativa::nueva_borrador(propuesto);
    prop.marcar_revision_juridica(f.id_j.clone(), true).unwrap();
    let hash = gob.proponer(prop);
    let casos = vec![CasoConformidad {
        id: "caso-1".into(),
        contexto: ctx(),
    }];
    let diff = resultado_diff(&casos, anterior, &gob.propuesta(&hash).unwrap().paquete);
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
    hash
}

fn firmar_y_sombra(
    gob: &mut GobernanzaCorpus,
    f: &GobFixture,
    hash: &HashPaqueteNormativo,
    ahora: u64,
) {
    let msg = gob.propuesta(hash).unwrap().paquete.mensaje_firma();
    let fj = FirmaPaquete::firmar(&f.par_j, f.id_j.clone(), RolFirmante::Juridico, &msg).unwrap();
    let ft = FirmaPaquete::firmar(&f.par_t, f.id_t.clone(), RolFirmante::Tecnico, &msg).unwrap();
    entrar_en_sombra(gob, hash, &[fj, ft], &f.firmantes, ahora).unwrap();
}

#[test]
fn rechazo_esquema_desconocido_y_firma_invalida() {
    let f = gob_fixture();
    let pkg = paquete_allow(&f);
    assert_eq!(
        validar_paquete_gobernado(99, &pkg, &f.citas, &f.aprobaciones),
        Err(ErrorCarga::EsquemaDesconocido(99))
    );
    let msg = pkg.mensaje_firma();
    let bad = FirmaPaquete {
        id: f.id_j.clone(),
        rol_declarado: RolFirmante::Juridico,
        firma_mldsa: vec![1, 2, 3],
    };
    assert_eq!(
        verificar_doble_firma(&msg, &[bad.clone(), bad], &f.firmantes),
        Err(ErrorFirmas::FirmaInvalida)
    );
}

#[test]
fn rechazo_cita_e_interpretacion_sin_aprobacion() {
    let f = gob_fixture();
    let pkg = paquete_allow(&f);
    let citas_vacias = RegistroCitas::nuevo();
    assert_eq!(
        validar_paquete_gobernado(ESQUEMA_REQUERIDO, &pkg, &citas_vacias, &f.aprobaciones),
        Err(ErrorCarga::CitaNoResoluble)
    );
    let aprobs_vacias = RegistroAprobacionesInterp::nuevo();
    assert_eq!(
        validar_paquete_gobernado(ESQUEMA_REQUERIDO, &pkg, &f.citas, &aprobs_vacias),
        Err(ErrorCarga::InterpretacionSinAprobacion)
    );
}

#[test]
fn rechazo_campo_obligatorio_g1() {
    let mut b = borrador("N-X", Predicado::Fijo(Veredicto::Allow), dig_interp(1));
    b.fuente = "".into();
    assert!(matches!(
        Norma::cargar(b).unwrap_err(),
        ErrorCarga::CampoObligatorioAusente("fuente")
    ));
}

#[test]
fn prohibicion_logica_jurisdiccional_incrustada() {
    let src = include_str!("../src/gobernanza/mod.rs");
    for needle in ["GDPR", "AI Act", "Ley Orgánica", "CFR "] {
        assert!(
            !src.contains(needle),
            "gobernanza no debe incrustar instrumento {needle}"
        );
    }
}

#[test]
fn determinismo_diff_y_decision_con_cita() {
    let f = gob_fixture();
    let ant = PaqueteNormativo::cargar(vec![]).unwrap();
    let prop = paquete_allow(&f);
    let casos = vec![CasoConformidad {
        id: "c1".into(),
        contexto: ctx(),
    }];
    let d1 = resultado_diff(&casos, &ant, &prop);
    let d2 = resultado_diff(&casos, &ant, &prop);
    assert_eq!(d1, d2);
    let d = decidir_paquete(&ctx(), &prop);
    assert!(matches!(d, Decision::Permitida(_)));
    assert!(decision_cita_construible(&d));
}

#[test]
fn ausencia_de_norma() {
    let pkg = PaqueteNormativo::cargar(vec![]).unwrap();
    let d = decidir_paquete(&ctx(), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
}

#[test]
fn competencia_revisor_no_registrada() {
    let f = gob_fixture();
    let pkg = paquete_allow(&f);
    let mut prop = PropuestaNormativa::nueva_borrador(pkg);
    assert!(prop
        .marcar_revision_juridica(f.id_j.clone(), false)
        .is_err());
}

#[test]
fn diff_no_reconocido_bloquea() {
    let f = gob_fixture();
    let ant = PaqueteNormativo::cargar(vec![]).unwrap();
    let prop = paquete_allow(&f);
    let casos = vec![CasoConformidad {
        id: "c1".into(),
        contexto: ctx(),
    }];
    let diff = resultado_diff(&casos, &ant, &prop);
    assert!(!diff.vacio());
    assert_eq!(
        exigir_diff_reconocido(&diff, &[], &[]),
        Err(ErrorDiff::DiffNoReconocido)
    );
}

#[test]
fn firmas_insuficientes_repetidas_sin_diversidad() {
    let f = gob_fixture();
    let pkg = paquete_allow(&f);
    let msg = pkg.mensaje_firma();
    let fj = FirmaPaquete::firmar(&f.par_j, f.id_j.clone(), RolFirmante::Juridico, &msg).unwrap();
    assert_eq!(
        verificar_doble_firma(&msg, &[fj.clone()], &f.firmantes),
        Err(ErrorFirmas::Insuficientes)
    );
    assert_eq!(
        verificar_doble_firma(&msg, &[fj.clone(), fj.clone()], &f.firmantes),
        Err(ErrorFirmas::IdentidadRepetida)
    );
    let par_j2 = ParMlDsa87::generar().unwrap();
    let id_j2 = IdHumano::nuevo("jur-2").unwrap();
    let mut reg = f.firmantes.clone();
    reg.registrar(FirmanteGobernanza {
        id: id_j2.clone(),
        rol: RolFirmante::Juridico,
        pk_mldsa: par_j2.public.clone(),
        etiqueta: EtiquetaGob::Gob,
    })
    .unwrap();
    let f2 = FirmaPaquete::firmar(&par_j2, id_j2, RolFirmante::Juridico, &msg).unwrap();
    assert_eq!(
        verificar_doble_firma(&msg, &[fj, f2], &reg),
        Err(ErrorFirmas::SinDiversidadJuridicoTecnico)
    );
}

#[test]
fn sombra_antes_de_siete_dias_y_activacion_fuera_de_limite() {
    let f = gob_fixture();
    let mut gob = GobernanzaCorpus::nuevo();
    let vacio = PaqueteNormativo::cargar(vec![]).unwrap();
    let hash = avanzar_a_conformidad(&mut gob, &f, paquete_allow(&f), &vacio);
    let reloj = RelojInyectado::nuevo(0);
    firmar_y_sombra(&mut gob, &f, &hash, reloj.ahora());
    let mut almacen = MemoriaDurable::default();
    let mut epoca = EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1).unwrap();
    assert!(matches!(
        activar_en_limite_epoca(&mut gob, &hash, &mut epoca, &mut almacen, reloj.ahora(), true),
        Err(ErrorActivacion::SombraIncompleta { .. })
    ));
    reloj.avanzar(VENTANA_SOMBRA_MS).unwrap();
    assert!(matches!(
        activar_en_limite_epoca(
            &mut gob,
            &hash,
            &mut epoca,
            &mut almacen,
            reloj.ahora(),
            false
        ),
        Err(ErrorActivacion::FueraDeLimiteEpoca)
    ));
}

#[test]
fn ciclo_completo_activacion_revocacion_reversion_sin_borrado() {
    let f = gob_fixture();
    let mut gob = GobernanzaCorpus::nuevo();
    let vacio = PaqueteNormativo::cargar(vec![]).unwrap();
    let hash_a = avanzar_a_conformidad(&mut gob, &f, paquete_allow(&f), &vacio);
    let reloj = RelojInyectado::nuevo(10);
    firmar_y_sombra(&mut gob, &f, &hash_a, reloj.ahora());
    reloj.avanzar(VENTANA_SOMBRA_MS).unwrap();
    let mut almacen = MemoriaDurable::default();
    let mut epoca = EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1).unwrap();
    let ep = activar_en_limite_epoca(
        &mut gob,
        &hash_a,
        &mut epoca,
        &mut almacen,
        reloj.ahora(),
        true,
    )
    .unwrap();
    assert!(matches!(
        gob.estado(&hash_a),
        Some(EstadoPropuesta::Activa { .. })
    ));
    assert_eq!(gob.hash_activo().unwrap(), &hash_a);

    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("s-gob").unwrap();
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-A").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash_a, traza, None).unwrap();
    let params = ParametrosEmision {
        sistema: IdSistema::nuevo("sys").unwrap(),
        digest_efecto: digest_efecto_canonico("EF-1", b"p"),
        alcance: AlcanceCap::minimo(["x"]).unwrap(),
        epoca: ep,
        epoca_suelo: ep,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap();
    let mut ver = VerificadorCapacidades::nuevo(ep);
    ver.indexar_capacidad(&cap);
    let n = revocar_paquete(&mut gob, &hash_a, &mut ver, reloj.ahora()).unwrap();
    assert!(n >= 1);
    assert!(gob.hash_activo().is_none());
    assert!(gob.paquete_historico(&hash_a).is_some());
    assert!(gob.historial().iter().any(|(h, _)| h == &hash_a));

    let hist = gob.paquete_historico(&hash_a).unwrap().clone();
    let hash_b = avanzar_a_conformidad(&mut gob, &f, hist, &vacio);
    firmar_y_sombra(&mut gob, &f, &hash_b, reloj.ahora());
    reloj.avanzar(VENTANA_SOMBRA_MS).unwrap();
    activar_en_limite_epoca(
        &mut gob,
        &hash_b,
        &mut epoca,
        &mut almacen,
        reloj.ahora(),
        true,
    )
    .unwrap();
    assert_eq!(gob.reconstruir_en_epoca(ep).unwrap().hash(), &hash_a);
    assert!(gob.historial().len() >= 2);
    assert!(gob.todas_las_versiones().count() >= 1);
}

#[test]
fn inclusion_verificable_offline() {
    let f = gob_fixture();
    let mut gob = GobernanzaCorpus::nuevo();
    let vacio = PaqueteNormativo::cargar(vec![]).unwrap();
    let hash = avanzar_a_conformidad(&mut gob, &f, paquete_allow(&f), &vacio);
    let reloj = RelojInyectado::nuevo(0);
    firmar_y_sombra(&mut gob, &f, &hash, reloj.ahora());
    reloj.avanzar(VENTANA_SOMBRA_MS).unwrap();
    let mut almacen = MemoriaDurable::default();
    let mut epoca = EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1).unwrap();
    let ep = activar_en_limite_epoca(
        &mut gob,
        &hash,
        &mut epoca,
        &mut almacen,
        reloj.ahora(),
        true,
    )
    .unwrap();

    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("gob-ev").unwrap();
    let v = gob.propuesta(&hash).unwrap();
    ledger
        .registrar_gobernanza(
            &sujeto,
            GobernanzaCorpus::serializar_diff(v.diff.as_ref().unwrap()),
        )
        .unwrap();
    ledger
        .registrar_gobernanza(
            &sujeto,
            GobernanzaCorpus::serializar_evento_sombra(&hash, 0),
        )
        .unwrap();
    ledger
        .registrar_gobernanza(
            &sujeto,
            GobernanzaCorpus::serializar_evento_activacion(&hash, ep),
        )
        .unwrap();
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Gobernanza));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}

#[test]
fn r1_r8_y_paquete_deny_gobernado() {
    let f = gob_fixture();
    let pkg = paquete_deny(&f);
    validar_paquete_gobernado(ESQUEMA_REQUERIDO, &pkg, &f.citas, &f.aprobaciones).unwrap();
    let d = decidir_paquete(&ctx(), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
}
