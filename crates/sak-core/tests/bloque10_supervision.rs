//! Harnesses Bloque 10: supervisión humana firmada (H.10).

use sak_core::capacidad::Alcance as AlcanceCap;
use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{CodigoRazon, Decision, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::motor::decidir_paquete;
use sak_core::norma::{
    Alcance, BorradorNorma, Escalado, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, RequisitoEvidencia, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::reloj::RelojInyectado;
use sak_core::supervision::{
    construir_hecho, continuar_tras_supervision, crear_solicitud_desde_escalada, digest_contexto,
    firmar_digest_contexto, payload_expiracion, payload_fallo, payload_hecho_aprobacion,
    payload_hecho_rechazo, payload_silencio, payload_solicitud, resolver_firmas, resolver_silencio,
    verificar_hecho_completo, ErrorSolicitud, ErrorSupervision, EtiquetaCompetencia, FirmaAprobador,
    IdHumano, IdentidadHumana, RegistroHumanos, RequisitosEscalado, ResultadoSupervision,
    VeredictoHumano,
};

fn interp() -> Interpretacion {
    Interpretacion {
        texto: "Interpretacion operativa de prueba aprobada.".into(),
        autor: "revisor-prueba".into(),
        digest_aprobacion: [9u8; LONGITUD_HASH_PAQUETE],
    }
}

fn alcance_norma() -> Alcance {
    Alcance {
        caso_de_uso: "prueba".into(),
        clase_riesgo: "alto".into(),
        rol_regulatorio: "proveedor".into(),
        sector: "general".into(),
        categorias_datos: "ninguna".into(),
        autonomia: "asistido".into(),
        destinatarios: "interno".into(),
    }
}

fn norma_escalate(quorum: u8) -> (Norma, Escalado) {
    let esc = Escalado {
        rol: "ciso".into(),
        competencia: "seguridad".into(),
        quorum,
        plazo_segundos: 3_600,
        exige_independencia: true,
    };
    let mut b = BorradorNorma {
        identificador: "N-SUP".into(),
        fuente: "cita-exacta-instrumento-art-1".into(),
        jurisdiccion: "EU".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance_norma(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L1,
        clase_de_efecto: ClaseEfecto::Ef5,
        predicado: Predicado::Fijo(Veredicto::Allow),
        evidencia_exigida: vec![RequisitoEvidencia {
            productor: sak_core::contexto::IdProductor::nuevo("prod-auditor").unwrap(),
            antiguedad_maxima_segundos: 60,
        }],
        acciones_obligatorias: vec![],
        condiciones_de_denegacion: vec![],
        escalado: Some(esc.clone()),
        monitorizacion: None,
        interpretacion: interp(),
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    };
    let _ = &mut b;
    (Norma::cargar(b).unwrap(), esc)
}

fn norma_deny() -> Norma {
    let b = BorradorNorma {
        identificador: "N-DENY".into(),
        fuente: "cita-exacta-instrumento-art-1".into(),
        jurisdiccion: "EU".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance_norma(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L1,
        clase_de_efecto: ClaseEfecto::Ef5,
        predicado: Predicado::Fijo(Veredicto::Deny),
        evidencia_exigida: vec![],
        acciones_obligatorias: vec![],
        condiciones_de_denegacion: vec![],
        escalado: None,
        monitorizacion: None,
        interpretacion: interp(),
        ambigua: false,
        rango: Rango::P0,
        pretende_resolver: vec![],
    };
    Norma::cargar(b).unwrap()
}

fn ctx() -> Contexto {
    Contexto::con_instante(
        EfectoTipado::nuevo(ClaseEfecto::Ef5, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        20_000,
    )
}

struct Fixture {
    pkg: PaqueteNormativo,
    esc_req: Escalado,
    decision: Decision,
    contexto: Contexto,
    solicitante: IdHumano,
    aprobador: ParMlDsa87,
    aprobador_id: IdHumano,
    aprobador2: ParMlDsa87,
    aprobador2_id: IdHumano,
    registro: RegistroHumanos,
    sistema: IdSistema,
    reloj: RelojInyectado,
}

fn fixture(quorum: u8) -> Fixture {
    let (norma, esc_req) = norma_escalate(quorum);
    let pkg = PaqueteNormativo::cargar(vec![norma]).unwrap();
    let contexto = ctx();
    let decision = decidir_paquete(&contexto, &pkg);
    assert!(matches!(decision, Decision::Escalada(_)));

    let solicitante = IdHumano::nuevo("humano-solicitante").unwrap();
    let aprobador = ParMlDsa87::generar().unwrap();
    let aprobador_id = IdHumano::nuevo("humano-aprobador-1").unwrap();
    let aprobador2 = ParMlDsa87::generar().unwrap();
    let aprobador2_id = IdHumano::nuevo("humano-aprobador-2").unwrap();
    let atestador = ParMlDsa87::generar().unwrap();

    let mut registro = RegistroHumanos::nuevo();
    registro
        .registrar_identidad(IdentidadHumana {
            id: aprobador_id.clone(),
            pk_mldsa: aprobador.public.clone(),
        })
        .unwrap();
    registro
        .registrar_identidad(IdentidadHumana {
            id: aprobador2_id.clone(),
            pk_mldsa: aprobador2.public.clone(),
        })
        .unwrap();
    let c1 = RegistroHumanos::atestacion_prueba(
        &atestador,
        aprobador_id.clone(),
        "ciso",
        "seguridad",
        ClaseEfecto::Ef5,
        0,
        10_000_000,
    )
    .unwrap();
    let c2 = RegistroHumanos::atestacion_prueba(
        &atestador,
        aprobador2_id.clone(),
        "ciso",
        "seguridad",
        ClaseEfecto::Ef5,
        0,
        10_000_000,
    )
    .unwrap();
    registro.registrar_competencia(c1).unwrap();
    registro.registrar_competencia(c2).unwrap();

    Fixture {
        pkg,
        esc_req,
        decision,
        contexto,
        solicitante,
        aprobador,
        aprobador_id,
        aprobador2,
        aprobador2_id,
        registro,
        sistema: IdSistema::nuevo("sys-sup").unwrap(),
        reloj: RelojInyectado::nuevo(1_000),
    }
}

fn requisitos(f: &Fixture) -> RequisitosEscalado {
    RequisitosEscalado::desde_escalado(
        IdNorma::nueva("N-SUP").unwrap(),
        "evidencia-ausente-exige-supervision",
        &f.esc_req,
    )
}

fn solicitud_ok(f: &Fixture) -> sak_core::supervision::SolicitudSupervision {
    crear_solicitud_desde_escalada(
        &f.decision,
        &f.contexto,
        f.solicitante.clone(),
        f.sistema.clone(),
        requisitos(f),
        f.reloj.ahora(),
        1,
        AlcanceCap::minimo(["efecto-sup"]).unwrap(),
    )
    .unwrap()
}

fn firma_de(par: &ParMlDsa87, id: &IdHumano, sol: &sak_core::supervision::SolicitudSupervision) -> FirmaAprobador {
    let sig = firmar_digest_contexto(par, sol.digest_contexto()).unwrap();
    FirmaAprobador {
        id: id.clone(),
        rol_declarado: sol.rol_requerido().into(),
        competencia_declarada: sol.competencia_requerida().into(),
        etiqueta: EtiquetaCompetencia::ValExt,
        firma_mldsa: sig,
    }
}

fn esc(d: &Decision) -> &sak_core::decision::DecisionEscalada {
    match d {
        Decision::Escalada(e) => e,
        _ => panic!("se esperaba ESCALATE"),
    }
}

#[test]
fn solicitud_con_campos_obligatorios() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    assert!(s.integra());
    assert_eq!(s.quorum(), 1);
    assert_eq!(s.rol_requerido(), "ciso");
    assert_eq!(*s.digest_contexto(), digest_contexto(&f.contexto));
}

#[test]
fn solicitud_incompleta_invalida() {
    let f = fixture(1);
    let mut req = requisitos(&f);
    req.rol = String::new();
    let err = crear_solicitud_desde_escalada(
        &f.decision,
        &f.contexto,
        f.solicitante.clone(),
        f.sistema.clone(),
        req,
        f.reloj.ahora(),
        1,
        AlcanceCap::minimo(["x"]).unwrap(),
    );
    assert!(matches!(err, Err(ErrorSolicitud::CampoObligatorioAusente(_))));
}

#[test]
fn firma_valida_sobre_digest_correcto_y_continuacion() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    )
    .unwrap();
    verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()).unwrap();
    let r = continuar_tras_supervision(
        &s,
        &hecho,
        &f.decision,
        &f.contexto,
        &f.pkg,
        &f.registro,
        f.reloj.ahora(),
    );
    assert!(matches!(r, ResultadoSupervision::Continuar(_)));
}

#[test]
fn firma_sobre_digest_incorrecto_falla() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let mut firma = firma_de(&f.aprobador, &f.aprobador_id, &s);
    // Firmar un digest distinto (alteración del mensaje firmado).
    let digest_falso = [7u8; LONGITUD_HASH_PAQUETE];
    firma.firma_mldsa = firmar_digest_contexto(&f.aprobador, &digest_falso).unwrap();
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, vec![firma], f.reloj.ahora());
    assert_eq!(
        verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()),
        Err(ErrorSupervision::FirmaInvalida)
    );
}

#[test]
fn alteracion_del_contexto_deniega() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    )
    .unwrap();
    let ctx2 = Contexto::con_instante(
        EfectoTipado::nuevo(ClaseEfecto::Ef5, [99u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        20_000,
    );
    let r = continuar_tras_supervision(
        &s,
        &hecho,
        &f.decision,
        &ctx2,
        &f.pkg,
        &f.registro,
        f.reloj.ahora(),
    );
    match r {
        ResultadoSupervision::Denegar(d) => {
            assert_eq!(d.codigo(), CodigoRazon::QuorumSupervision)
        }
        _ => panic!("se esperaba DENY"),
    }
}

#[test]
fn aprobador_no_registrado() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let fantasma = ParMlDsa87::generar().unwrap();
    let id = IdHumano::nuevo("no-reg").unwrap();
    let firmas = vec![firma_de(&fantasma, &id, &s)];
    let err = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    );
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().codigo(), CodigoRazon::QuorumSupervision);
}

#[test]
fn rol_competencia_ausente() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let mut firma = firma_de(&f.aprobador, &f.aprobador_id, &s);
    firma.rol_declarado = "otro-rol".into();
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, vec![firma], f.reloj.ahora());
    let e = verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora());
    assert_eq!(e, Err(ErrorSupervision::RolOCompetenciaAusente));
}

#[test]
fn competencia_vencida() {
    let mut f = fixture(1);
    // Sustituir competencia por una ya vencida.
    let atestador = ParMlDsa87::generar().unwrap();
    let mut reg = RegistroHumanos::nuevo();
    reg.registrar_identidad(IdentidadHumana {
        id: f.aprobador_id.clone(),
        pk_mldsa: f.aprobador.public.clone(),
    })
    .unwrap();
    let vencida = RegistroHumanos::atestacion_prueba(
        &atestador,
        f.aprobador_id.clone(),
        "ciso",
        "seguridad",
        ClaseEfecto::Ef5,
        0,
        500, // vencida respecto a reloj=1000
    )
    .unwrap();
    reg.registrar_competencia(vencida).unwrap();
    f.registro = reg;
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, firmas, f.reloj.ahora());
    assert_eq!(
        verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()),
        Err(ErrorSupervision::RolOCompetenciaVencida)
    );
}

#[test]
fn identidad_duplicada() {
    let f = fixture(2);
    let s = solicitud_ok(&f);
    let a = firma_de(&f.aprobador, &f.aprobador_id, &s);
    let firmas = vec![a.clone(), a];
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, firmas, f.reloj.ahora());
    assert_eq!(
        verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()),
        Err(ErrorSupervision::IdentidadDuplicada)
    );
}

#[test]
fn solicitante_como_aprobador_rompe_independencia() {
    let mut f = fixture(1);
    // Registrar solicitante como aprobador con competencia.
    let sol_par = ParMlDsa87::generar().unwrap();
    f.registro
        .registrar_identidad(IdentidadHumana {
            id: f.solicitante.clone(),
            pk_mldsa: sol_par.public.clone(),
        })
        .unwrap();
    let at = ParMlDsa87::generar().unwrap();
    let c = RegistroHumanos::atestacion_prueba(
        &at,
        f.solicitante.clone(),
        "ciso",
        "seguridad",
        ClaseEfecto::Ef5,
        0,
        10_000_000,
    )
    .unwrap();
    f.registro.registrar_competencia(c).unwrap();
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&sol_par, &f.solicitante, &s)];
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, firmas, f.reloj.ahora());
    assert_eq!(
        verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()),
        Err(ErrorSupervision::FaltaIndependencia)
    );
}

#[test]
fn quorum_insuficiente() {
    let f = fixture(2);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = construir_hecho(&s, VeredictoHumano::Aprobado, firmas, f.reloj.ahora());
    assert_eq!(
        verificar_hecho_completo(&s, &hecho, &f.registro, f.reloj.ahora()),
        Err(ErrorSupervision::QuorumInsuficiente)
    );
}

#[test]
fn vencimiento_deniega() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    f.reloj.avanzar(3_600_000 + 1).unwrap();
    let err = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    );
    assert_eq!(err.unwrap_err().codigo(), CodigoRazon::QuorumSupervision);
}

#[test]
fn rechazo_explicito() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let err = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Rechazado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    );
    assert_eq!(err.unwrap_err().codigo(), CodigoRazon::QuorumSupervision);
}

#[test]
fn silencio_nunca_autoriza() {
    let f = fixture(1);
    let d = resolver_silencio(esc(&f.decision));
    assert_eq!(d.codigo(), CodigoRazon::QuorumSupervision);
    assert_eq!(d.veredicto(), Veredicto::Deny);
}

#[test]
fn decision_original_deny_no_aprueba() {
    let pkg = PaqueteNormativo::cargar(vec![norma_deny()]).unwrap();
    let contexto = ctx();
    let decision = decidir_paquete(&contexto, &pkg);
    assert!(matches!(decision, Decision::Denegada(_)));
    let err = crear_solicitud_desde_escalada(
        &decision,
        &contexto,
        IdHumano::nuevo("s").unwrap(),
        IdSistema::nuevo("sys").unwrap(),
        RequisitosEscalado {
            id_norma: IdNorma::nueva("N-DENY").unwrap(),
            obligacion: "x".into(),
            rol: "ciso".into(),
            competencia: "seguridad".into(),
            quorum: 1,
            exige_independencia: true,
            plazo_segundos: 60,
        },
        0,
        1,
        AlcanceCap::minimo(["x"]).unwrap(),
    );
    assert!(matches!(err, Err(ErrorSolicitud::NoEsEscalada)));

    // Continuar sobre DENY también deniega con QUORUM_SUPERVISION.
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    )
    .unwrap();
    let r = continuar_tras_supervision(
        &s,
        &hecho,
        &decision,
        &contexto,
        &pkg,
        &f.registro,
        f.reloj.ahora(),
    );
    match r {
        ResultadoSupervision::Denegar(d) => {
            assert_eq!(d.codigo(), CodigoRazon::QuorumSupervision)
        }
        _ => panic!("DENY original no debe convertirse en ALLOW"),
    }
}

#[test]
fn trazabilidad_offline_completa() {
    let f = fixture(1);
    let s = solicitud_ok(&f);
    let firmas = vec![firma_de(&f.aprobador, &f.aprobador_id, &s)];
    let hecho = resolver_firmas(
        &s,
        esc(&f.decision),
        VeredictoHumano::Aprobado,
        firmas,
        &f.registro,
        f.reloj.ahora(),
    )
    .unwrap();
    let r = continuar_tras_supervision(
        &s,
        &hecho,
        &f.decision,
        &f.contexto,
        &f.pkg,
        &f.registro,
        f.reloj.ahora(),
    );
    let permitida = match r {
        ResultadoSupervision::Continuar(p) => p,
        _ => panic!("se esperaba continuar"),
    };

    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("sujeto-sup").unwrap();
    ledger
        .registrar_supervision(&sujeto, payload_solicitud(&s))
        .unwrap();
    ledger
        .registrar_supervision(&sujeto, payload_hecho_aprobacion(&hecho))
        .unwrap();
    // También registrar caminos de fallo/silencio/expiración/rechazo como evidencia.
    ledger
        .registrar_supervision(
            &sujeto,
            payload_fallo(s.digest_solicitud(), "ejemplo-fallo"),
        )
        .unwrap();
    ledger
        .registrar_supervision(&sujeto, payload_silencio(s.digest_solicitud()))
        .unwrap();
    ledger
        .registrar_supervision(&sujeto, payload_expiracion(s.digest_solicitud()))
        .unwrap();
    let rechazo = construir_hecho(
        &s,
        VeredictoHumano::Rechazado,
        vec![firma_de(&f.aprobador2, &f.aprobador2_id, &s)],
        f.reloj.ahora(),
    );
    ledger
        .registrar_supervision(&sujeto, payload_hecho_rechazo(&rechazo))
        .unwrap();

    let cap_params = sak_core::capacidad::ParametrosEmision {
        sistema: f.sistema.clone(),
        digest_efecto: sak_core::capacidad::digest_efecto_canonico("EF-SUP", b"p"),
        alcance: AlcanceCap::minimo(["efecto-sup"]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: sak_core::capacidad::ClasificacionEfecto::irreversible(),
    };
    let _cap = ledger
        .emitir_tras_evidencia(&sujeto, permitida, cap_params, &f.reloj)
        .unwrap();
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Supervision));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "errores: {:?}", informe.errores);
}
