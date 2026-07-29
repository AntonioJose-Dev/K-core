//! Harnesses rebanada repo EF-7 (tests/bloque16_*): gateway de publicación.
//! No es bloque §M. Matriz C EF-7. Ver docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md.

use sak_core::capacidad::{CausaDenegacion, ClasificacionEfecto, ParametrosEmision};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    verificar_paquete, IdSujeto, LedgerEvidencia, MemoriaDurable, TipoRegistro,
};
use sak_core::identidad::IdSistema;
use sak_core::pep::{
    alcance_ef4, alcance_ef7, preparar_solicitud_herramienta, preparar_solicitud_publicacion,
    traducir_publicacion_desde_herramienta, AdaptadorPublicacionSimulado, AdaptadorSimulado,
    BrokerHerramientas, CanalPublicacion, CatalogoHerramientas, ClaseEfecto, CodigoPep,
    CondicionesPublicacion, CredencialPublicacion, EntradaHerramienta, EstadoPublicacion,
    EtiquetaHecho, GatewayPublicacion, HechoPublicacionExigido, OperacionPublicacion,
    PrecondicionesPepEf4, PrecondicionesPepEf7, ResultadoPepHerramienta, ResultadoPepPublicacion,
    SolicitudHerramienta, SolicitudHerramientaCruda, SolicitudPublicacion,
    SolicitudPublicacionCruda, TipoHechoContacto, TipoIncidente,
};
use sak_core::reloj::RelojInyectado;

fn hash_pkg(seed: u8) -> [u8; LONGITUD_HASH_PAQUETE] {
    [seed; LONGITUD_HASH_PAQUETE]
}

fn decision_allow(seed: u8) -> DecisionPermitida {
    decision_con_paquete(hash_pkg(seed), &format!("N-EF7-{seed}"))
}

fn decision_con_paquete(pkg: [u8; LONGITUD_HASH_PAQUETE], norma: &str) -> DecisionPermitida {
    let hash = HashPaqueteNormativo::desde_bytes(pkg);
    let traza = TrazaPrecedencia::nueva(vec![IdNorma::nueva(norma).unwrap()], vec![], 1).unwrap();
    DecisionPermitida::nueva(hash, traza, None).unwrap()
}

fn hecho(seed: u8) -> HechoPublicacionExigido {
    HechoPublicacionExigido {
        tipo: TipoHechoContacto::AprobacionHumana,
        etiqueta: EtiquetaHecho::Gob,
        digest: [seed; LONGITUD_HASH_PAQUETE],
    }
}

fn sol_base(seed: u8) -> SolicitudPublicacion {
    SolicitudPublicacion::nueva(
        CanalPublicacion::Web,
        "cms-kernel",
        "acct-pub",
        format!("/noticias/{seed}"),
        OperacionPublicacion::Crear,
        "Titulo canonico",
        [0xB7u8; LONGITUD_HASH_PAQUETE],
        [0xA7u8; LONGITUD_HASH_PAQUETE],
        "es",
        "tag:aviso",
        "audiencia-cerrada",
        "restringida",
        0,
        u64::MAX,
        "informacion",
        "general",
        false,
        true,
        hash_pkg(seed),
        1,
        [0xC7u8; LONGITUD_HASH_PAQUETE],
        CondicionesPublicacion::tipicas(),
        vec![hecho(seed)],
        false,
    )
    .unwrap()
}

fn emitir_ef7(
    seed: u8,
    sistema: &IdSistema,
    sol: &SolicitudPublicacion,
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    reloj: &RelojInyectado,
    sujeto: &IdSujeto,
) -> sak_core::capacidad::Capability {
    let (s, digest) = preparar_solicitud_publicacion(sol.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef7(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto {
            irreversible: !s.reversible,
            afecta_personas: true,
            datos_personales: false,
        },
    };
    ledger
        .emitir_tras_evidencia(sujeto, decision_allow(seed), params, reloj)
        .unwrap()
}

fn pre_ok() -> PrecondicionesPepEf7 {
    PrecondicionesPepEf7::todas_ok()
}

fn ejercer(
    gw: &mut GatewayPublicacion,
    sol: &SolicitudPublicacion,
    cap: Option<&sak_core::capacidad::Capability>,
    sistema: &IdSistema,
    sujeto: &IdSujeto,
    pre: &PrecondicionesPepEf7,
    hechos: &[HechoPublicacionExigido],
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    adap: &mut AdaptadorPublicacionSimulado,
    reloj: &RelojInyectado,
    ahora: u64,
    silencio: bool,
) -> ResultadoPepPublicacion {
    gw.ejercer(
        &SolicitudPublicacionCruda::Tipada(sol.clone()),
        cap,
        sistema,
        sujeto,
        pre,
        hechos,
        ledger,
        adap,
        reloj,
        1,
        Some(ahora),
        silencio,
    )
}

#[test]
fn minimo_c4_y_capacidad_ciclo() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-c4").unwrap();
    let sujeto = IdSujeto::nuevo("suj-c4").unwrap();
    let sol = sol_base(1);
    let cap = emitir_ef7(1, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayPublicacion::nuevo(1);
    let mut adap =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [1u8; 32]));
    let mut pre = pre_ok();
    pre.libro_c4 = false;
    assert!(matches!(
        ejercer(&mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre, &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::ControlInsuficiente }
    ));

    let pre = pre_ok();
    assert!(matches!(
        ejercer(&mut gw, &sol, None, &sistema, &sujeto, &pre, &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::CapacidadAusente }
    ));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol2 = sol_base(2);
    let cap2 = emitir_ef7(2, &sistema, &sol2, &mut ledger2, &reloj, &sujeto);
    let mut gw2 = GatewayPublicacion::nuevo(1);
    let mut adap2 =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [2u8; 32]));
    assert!(cap2.un_solo_uso());
    assert!(matches!(
        ejercer(&mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos, &mut ledger2, &mut adap2, &reloj, 10, false),
        ResultadoPepPublicacion::Permitido(_)
    ));
    assert!(matches!(
        ejercer(&mut gw2, &sol2, Some(&cap2), &sistema, &sujeto, &pre_ok(), &sol2.hechos_exigidos, &mut ledger2, &mut adap2, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Repetida) }
    ));

    let mut ledger_r = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_r = sol_base(3);
    let cap_r = emitir_ef7(3, &sistema, &sol_r, &mut ledger_r, &reloj, &sujeto);
    let mut gw_r = GatewayPublicacion::nuevo(1);
    gw_r.verificador_mut().revocar(*cap_r.id());
    let mut adap_r =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [3u8; 32]));
    assert!(matches!(
        ejercer(&mut gw_r, &sol_r, Some(&cap_r), &sistema, &sujeto, &pre_ok(), &sol_r.hechos_exigidos, &mut ledger_r, &mut adap_r, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Revocada) }
    ));

    let reloj_exp = RelojInyectado::nuevo(0);
    let mut ledger_e = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_e = sol_base(4);
    let (s, digest) = preparar_solicitud_publicacion(sol_e.clone());
    let params = ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef7(&s),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 5,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap_e = ledger_e.emitir_tras_evidencia(&sujeto, decision_allow(4), params, &reloj_exp).unwrap();
    reloj_exp.avanzar(6).unwrap();
    let mut gw_e = GatewayPublicacion::nuevo(1);
    let mut adap_e =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [4u8; 32]));
    assert!(matches!(
        ejercer(&mut gw_e, &sol_e, Some(&cap_e), &sistema, &sujeto, &pre_ok(), &sol_e.hechos_exigidos, &mut ledger_e, &mut adap_e, &reloj_exp, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::Capacidad(CausaDenegacion::Expirada) }
    ));
}

#[test]
fn campos_alterados_contenido_activo_hechos_supervision() {
    let reloj = RelojInyectado::nuevo(6);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-alt").unwrap();
    let sujeto = IdSujeto::nuevo("suj-alt").unwrap();
    let sol = sol_base(6);
    let cap = emitir_ef7(6, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayPublicacion::nuevo(1);
    let mut adap =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [6u8; 32]));

    let mut s = sol.clone();
    s.cuenta_publicadora = "otra".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::CuentaPublicacionNoAutorizada }
    ));
    let mut s = sol.clone();
    s.canal = CanalPublicacion::RedesSociales;
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::CanalPublicacionNoAutorizado }
    ));
    let mut s = sol.clone();
    s.destino = "/otra".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::DestinoPublicacionNoAutorizado }
    ));
    let mut s = sol.clone();
    s.operacion = OperacionPublicacion::Actualizar;
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::OperacionPublicacionNoAutorizada }
    ));
    let mut s = sol.clone();
    s.digest_contenido = [0xFFu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::ContenidoPublicacionNoAutorizado }
    ));
    let mut s = sol.clone();
    s.digest_medios = [0xEEu8; LONGITUD_HASH_PAQUETE];
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::MedioPublicacionNoAutorizado }
    ));
    let mut s = sol.clone();
    s.idioma = "en".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::IdiomaNoAutorizado }
    ));
    let mut s = sol.clone();
    s.etiquetas = "otra".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::EtiquetaNoAutorizada }
    ));
    let mut s = sol.clone();
    s.audiencia = "otra-aud".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::AudienciaNoAutorizada }
    ));
    let mut s = sol.clone();
    s.visibilidad = "interna".into();
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::VisibilidadNoAutorizada }
    ));
    let mut s = sol.clone();
    s.ventana_hasta = 5;
    assert!(matches!(
        ejercer(&mut gw, &s, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::VentanaPublicacionNoAutorizada }
    ));

    assert!(matches!(
        gw.ejercer(
            &SolicitudPublicacionCruda::ContenidoActivo,
            Some(&cap),
            &sistema,
            &sujeto,
            &pre_ok(),
            &sol.hechos_exigidos,
            &mut ledger,
            &mut adap,
            &reloj,
            1,
            Some(10),
            false,
        ),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::ContenidoNoCanonico }
    ));
    assert!(SolicitudPublicacion::nueva(
        CanalPublicacion::Web, "p", "c", "/x", OperacionPublicacion::Crear, "t",
        [0u8; LONGITUD_HASH_PAQUETE], [0u8; LONGITUD_HASH_PAQUETE], "es", "tag",
        "*", "restringida", 0, 1, "f", "g", false, true, hash_pkg(0), 1,
        [0u8; LONGITUD_HASH_PAQUETE], CondicionesPublicacion::tipicas(), vec![], false,
    ).is_err());
    assert!(SolicitudPublicacion::nueva(
        CanalPublicacion::Web, "p", "c", "/x", OperacionPublicacion::Crear, "t",
        [0u8; LONGITUD_HASH_PAQUETE], [0u8; LONGITUD_HASH_PAQUETE], "es", "tag",
        "aud", "restringida", 0, 1, "f", "g", false, false, hash_pkg(0), 1,
        [0u8; LONGITUD_HASH_PAQUETE], CondicionesPublicacion::tipicas(), vec![], false,
    ).is_err());

    assert!(matches!(
        ejercer(&mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &[], &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::HechoPublicacionAusente }
    ));
    let mut pre_s = pre_ok();
    pre_s.supervision_ok = false;
    let mut sol_s = sol.clone();
    sol_s.exige_supervision = true;
    assert!(matches!(
        ejercer(&mut gw, &sol_s, Some(&cap), &sistema, &sujeto, &pre_s, &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::SupervisionAusente }
    ));
}

#[test]
fn parcial_credencial_ruta_recibo_retirada() {
    let reloj = RelojInyectado::nuevo(10);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-p").unwrap();
    let sujeto = IdSujeto::nuevo("suj-p").unwrap();
    let sol = sol_base(10);
    let cap = emitir_ef7(10, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayPublicacion::nuevo(1);
    let mut adap =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [10u8; 32]));
    adap.forzar_parcial = true;
    assert!(matches!(
        ejercer(&mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos, &mut ledger, &mut adap, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::IncidenteMediacion }
    ));
    assert!(gw.incidentes().iter().any(|i| i.tipo == TipoIncidente::ResultadoIndeterminado));

    assert!(!adap.credencial_expuesta());
    assert!(!GatewayPublicacion::posee_credencial_publicacion_expuesta());
    assert!(format!("{:?}", CredencialPublicacion::desde_semilla("x", [1u8; 32])).contains("REDACTED"));
    let _ = adap.llamar_directo(&sol).unwrap_err();
    assert_eq!(adap.intentos_directos, 1);

    let mut ledger_d = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_d = sol_base(11);
    let cap_d = emitir_ef7(11, &sistema, &sol_d, &mut ledger_d, &reloj, &sujeto);
    let mut gw_d = GatewayPublicacion::nuevo(1);
    let mut adap_d =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [11u8; 32]));
    adap_d.forzar_divergencia = true;
    assert!(matches!(
        ejercer(&mut gw_d, &sol_d, Some(&cap_d), &sistema, &sujeto, &pre_ok(), &sol_d.hechos_exigidos, &mut ledger_d, &mut adap_d, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::IncidenteMediacion }
    ));

    let mut ledger_h = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sol_h = sol_base(12);
    let cap_h = emitir_ef7(12, &sistema, &sol_h, &mut ledger_h, &reloj, &sujeto);
    let _ = ledger_h.reportar_hueco_secuencia(1, 99);
    let mut gw_h = GatewayPublicacion::nuevo(1);
    let mut adap_h =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [12u8; 32]));
    assert!(matches!(
        ejercer(&mut gw_h, &sol_h, Some(&cap_h), &sistema, &sujeto, &pre_ok(), &sol_h.hechos_exigidos, &mut ledger_h, &mut adap_h, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::Evidencia(_) }
    ));

    // Retirada fuera de alcance (sin publicación previa).
    let mut ledger_r = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let mut sol_r = sol_base(13);
    sol_r.operacion = OperacionPublicacion::Retirar;
    let cap_r = emitir_ef7(13, &sistema, &sol_r, &mut ledger_r, &reloj, &sujeto);
    let mut gw_r = GatewayPublicacion::nuevo(1);
    let mut adap_r =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [13u8; 32]));
    assert!(matches!(
        ejercer(&mut gw_r, &sol_r, Some(&cap_r), &sistema, &sujeto, &pre_ok(), &sol_r.hechos_exigidos, &mut ledger_r, &mut adap_r, &reloj, 10, false),
        ResultadoPepPublicacion::Denegado { codigo: CodigoPep::RetiradaFueraAlcance }
    ));
}

#[test]
fn delegacion_ef4_a_ef7() {
    let auth = ParMlDsa87::generar().unwrap();
    let e = EntradaHerramienta {
        id_herramienta: "publisher".into(),
        version: "1.0".into(),
        servidor: "cms-kernel".into(),
        operacion: "web".into(),
        digest_esquema_args: [0xAAu8; LONGITUD_HASH_PAQUETE],
        destinos_permitidos: vec!["/blog/post".into()],
        efecto_subyacente: ClaseEfecto::Ef7,
        reversible: false,
        datos_personales: false,
        cuota_maxima: 3,
        timeout_ms: 5_000,
    };
    let cat = CatalogoHerramientas::construir(vec![e.clone()], hash_pkg(20 ^ 0x11), hash_pkg(20), &auth).unwrap();
    let reloj = RelojInyectado::nuevo(20);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-del").unwrap();
    let sujeto = IdSujeto::nuevo("suj-del").unwrap();
    let args = [0x33u8; LONGITUD_HASH_PAQUETE];
    let sol4 = SolicitudHerramienta::nueva(
        e.id_herramienta.clone(), e.version.clone(), e.servidor.clone(), e.operacion.clone(),
        e.digest_esquema_args, args, "/blog/post", ClaseEfecto::Ef7, false, false, 3, 5_000,
        [0x44u8; LONGITUD_HASH_PAQUETE], hash_pkg(20),
    ).unwrap();
    let sol7 = traducir_publicacion_desde_herramienta(
        &sol4.id_herramienta, &sol4.servidor, &sol4.operacion, &sol4.destino,
        sol4.digest_argumentos, sol4.hash_paquete, sol4.datos_personales, sol4.reversible,
    ).unwrap();
    let (s4, d4) = preparar_solicitud_herramienta(sol4.clone());
    let cap4 = ledger.emitir_tras_evidencia(
        &sujeto, decision_con_paquete(hash_pkg(20), "N-EF4-pub"),
        ParametrosEmision { sistema: sistema.clone(), digest_efecto: d4, alcance: alcance_ef4(&s4), epoca: 1, epoca_suelo: 1, ttl_ticks: 60_000, clasificacion: ClasificacionEfecto::irreversible() },
        &reloj,
    ).unwrap();
    let (s7, d7) = preparar_solicitud_publicacion(sol7);
    let cap7 = ledger.emitir_tras_evidencia(
        &sujeto, decision_con_paquete(hash_pkg(20), "N-EF7-pub"),
        ParametrosEmision { sistema: sistema.clone(), digest_efecto: d7, alcance: alcance_ef7(&s7), epoca: 1, epoca_suelo: 1, ttl_ticks: 60_000, clasificacion: ClasificacionEfecto::irreversible() },
        &reloj,
    ).unwrap();

    let mut broker = BrokerHerramientas::nuevo(1);
    let mut adap4 = AdaptadorSimulado::nuevo();
    let r_deny = broker.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4.clone()), Some(&cap4), Some(&cap7),
        &sistema, &sujeto, &PrecondicionesPepEf4::todas_ok(), &cat, &mut ledger, &mut adap4,
        None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, &reloj, 1, false,
    );
    assert!(matches!(r_deny, ResultadoPepHerramienta::Denegado { codigo: CodigoPep::PepSubyacenteInexistente }));

    let mut ledger2 = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto2 = IdSujeto::nuevo("suj-del-2").unwrap();
    let cap4b = ledger2.emitir_tras_evidencia(
        &sujeto2, decision_con_paquete(hash_pkg(20), "N-EF4-pub2"),
        ParametrosEmision { sistema: sistema.clone(), digest_efecto: d4, alcance: alcance_ef4(&s4), epoca: 1, epoca_suelo: 1, ttl_ticks: 60_000, clasificacion: ClasificacionEfecto::irreversible() },
        &reloj,
    ).unwrap();
    let cap7b = ledger2.emitir_tras_evidencia(
        &sujeto2, decision_con_paquete(hash_pkg(20), "N-EF7-pub2"),
        ParametrosEmision { sistema: sistema.clone(), digest_efecto: d7, alcance: alcance_ef7(&s7), epoca: 1, epoca_suelo: 1, ttl_ticks: 60_000, clasificacion: ClasificacionEfecto::irreversible() },
        &reloj,
    ).unwrap();
    let mut broker2 = BrokerHerramientas::nuevo(1);
    let mut adap4b = AdaptadorSimulado::nuevo();
    let mut gw7 = GatewayPublicacion::nuevo(1);
    let mut adap7 =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct:publisher", [21u8; 32]));
    let cat2 = CatalogoHerramientas::construir(vec![e], hash_pkg(20 ^ 0x11), hash_pkg(20), &auth).unwrap();

    let r = broker2.invocar(
        &SolicitudHerramientaCruda::Tipada(sol4), Some(&cap4b), Some(&cap7b),
        &sistema, &sujeto2, &PrecondicionesPepEf4::todas_ok(), &cat2, &mut ledger2, &mut adap4b,
        None, None, None, None, None, None, None, None,
        Some(&mut gw7), Some(&mut adap7), Some(&PrecondicionesPepEf7::todas_ok()),
        None, None, None,
        None, None, None, None,
        &reloj, 1, false,
    );
    match r {
        ResultadoPepHerramienta::Permitido(resp) => {
            assert_eq!(resp.delegado_a, Some(ClaseEfecto::Ef7));
            assert_eq!(resp.id_herramienta, "publisher");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(adap7.publicaciones_delegadas, 1);
    assert_eq!(adap4b.invocaciones_delegadas, 0);
}

#[test]
fn integridad_offline_cadena_completa() {
    let reloj = RelojInyectado::nuevo(30);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("sys-off").unwrap();
    let sujeto = IdSujeto::nuevo("suj-off").unwrap();
    let sol = sol_base(30);
    let cap = emitir_ef7(30, &sistema, &sol, &mut ledger, &reloj, &sujeto);
    let mut gw = GatewayPublicacion::nuevo(1);
    let mut adap =
        AdaptadorPublicacionSimulado::nuevo(CredencialPublicacion::desde_semilla("acct-pub", [30u8; 32]));
    let r = ejercer(
        &mut gw, &sol, Some(&cap), &sistema, &sujeto, &pre_ok(), &sol.hechos_exigidos,
        &mut ledger, &mut adap, &reloj, 10, false,
    );
    match r {
        ResultadoPepPublicacion::Permitido(resp) => {
            assert_eq!(resp.estado, EstadoPublicacion::Publicado);
            assert!(!resp.id_externo.is_empty());
        }
        other => panic!("{other:?}"),
    }
    ledger.cerrar_epoca().unwrap();
    let pkg = ledger.exportar_paquete();
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Decision));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Recibo));
    assert!(pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Publicacion));
    let informe = verificar_paquete(&pkg);
    assert!(informe.ok, "{:?}", informe.errores);
}
