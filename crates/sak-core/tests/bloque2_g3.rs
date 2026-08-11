//! Vectores del Bloque 2: G.3, R1–R8 y cierre conservador.

use sak_core::contexto::{
    ClaseEfecto, Contexto, EfectoTipado, FirmaProductor, HechoFirmado, IdProductor, ValorHecho,
};
use sak_core::decision::{CodigoRazon, Decision, MotivoInercia, Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::motor::decidir_paquete;
use sak_core::norma::{
    Alcance, BorradorNorma, Escalado, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, RequisitoEvidencia, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;

fn interp() -> Interpretacion {
    Interpretacion {
        texto: "Interpretacion operativa de prueba aprobada.".into(),
        autor: "revisor-prueba".into(),
        digest_aprobacion: [9u8; LONGITUD_HASH_PAQUETE],
    }
}

fn alcance() -> Alcance {
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

fn borrador(
    id: &str,
    clase: ClaseEfecto,
    rango: Rango,
    juris: &str,
    pred: Predicado,
    ambigua: bool,
) -> BorradorNorma {
    BorradorNorma {
        identificador: id.into(),
        fuente: "cita-exacta-instrumento-art-1".into(),
        jurisdiccion: juris.into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L1,
        clase_de_efecto: clase,
        predicado: pred,
        evidencia_exigida: vec![],
        acciones_obligatorias: vec![],
        condiciones_de_denegacion: vec![],
        escalado: None,
        monitorizacion: None,
        interpretacion: interp(),
        ambigua,
        rango,
        pretende_resolver: vec![],
    }
}

fn paquete(normas: Vec<Norma>) -> PaqueteNormativo {
    PaqueteNormativo::cargar(normas).unwrap()
}

fn ctx(clase: ClaseEfecto, instante: u32) -> Contexto {
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    Contexto::con_instante(
        EfectoTipado::nuevo(clase, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        instante,
        hash_peticion,
    )
}

fn codigo(d: &Decision) -> CodigoRazon {
    d.codigo().expect("codigo")
}

#[test]
fn g3_sin_norma_aplicable() {
    let pkg = paquete(vec![]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef1, 20_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::SinNormaAplicable);
}

#[test]
fn g3_precedencia_r1_r2() {
    let n_deny = Norma::cargar(borrador(
        "N-P0",
        ClaseEfecto::Ef1,
        Rango::P0,
        "EU",
        Predicado::Fijo(Veredicto::Deny),
        false,
    ))
    .unwrap();
    let n_allow = Norma::cargar(borrador(
        "N-P5",
        ClaseEfecto::Ef1,
        Rango::P5,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    ))
    .unwrap();
    let pkg = paquete(vec![n_deny, n_allow]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef1, 20_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::PrecedenciaAplicada);
    assert!(d
        .traza()
        .inertes()
        .iter()
        .any(|i| i.motivo() == MotivoInercia::R1RestriccionMonotona));
}

#[test]
fn g3_conflicto_jurisdiccion_r3() {
    let a = Norma::cargar(borrador(
        "N-EU",
        ClaseEfecto::Ef2,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    ))
    .unwrap();
    let b = Norma::cargar(borrador(
        "N-US",
        ClaseEfecto::Ef2,
        Rango::P2,
        "US",
        Predicado::Fijo(Veredicto::Deny),
        false,
    ))
    .unwrap();
    let pkg = paquete(vec![a, b]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef2, 20_000), &pkg);
    assert!(matches!(d, Decision::Escalada(_)));
    assert_eq!(codigo(&d), CodigoRazon::ConflictoJurisdiccion);
}

#[test]
fn g3_norma_vencida_deja_descubierto_r4() {
    let mut b = borrador(
        "N-OLD",
        ClaseEfecto::Ef3,
        Rango::P1,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    );
    b.vigencia = Vigencia {
        entrada: Fecha::nueva(2010, 1, 1).unwrap(),
        termino: Some(Fecha::nueva(2015, 1, 1).unwrap()),
    };
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    // instante muy posterior al término
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef3, 50_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::SinNormaAplicable);
    assert!(d
        .traza()
        .inertes()
        .iter()
        .any(|i| i.motivo() == MotivoInercia::R4FuenteVencida));
}

#[test]
fn r5_fuente_no_vigente_sombra() {
    let mut b = borrador(
        "N-FUT",
        ClaseEfecto::Ef4,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Deny),
        false,
    );
    b.vigencia = Vigencia {
        entrada: Fecha::nueva(2090, 1, 1).unwrap(),
        termino: None,
    };
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef4, 10_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    let inerte = d.traza().inertes().iter().next().unwrap();
    assert_eq!(inerte.motivo(), MotivoInercia::R5FuenteNoVigenteAun);
    assert_eq!(inerte.veredicto_en_sombra(), Some(Veredicto::Deny));
}

#[test]
fn g3_evidencia_ausente_r7_deny() {
    let mut b = borrador(
        "N-EV",
        ClaseEfecto::Ef5,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    );
    b.evidencia_exigida = vec![RequisitoEvidencia {
        productor: IdProductor::nuevo("prod-auditor").unwrap(),
        antiguedad_maxima_segundos: 60,
    }];
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef5, 20_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::EvidenciaAusente);
}

#[test]
fn g3_evidencia_ausente_r7_escalate_si_norma_preve() {
    let mut b = borrador(
        "N-EV2",
        ClaseEfecto::Ef5,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    );
    b.evidencia_exigida = vec![RequisitoEvidencia {
        productor: IdProductor::nuevo("prod-auditor").unwrap(),
        antiguedad_maxima_segundos: 60,
    }];
    b.escalado = Some(Escalado {
        rol: "ciso".into(),
        competencia: "seguridad".into(),
        quorum: 1,
        plazo_segundos: 3600,
        exige_independencia: true,
    });
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef5, 20_000), &pkg);
    assert!(matches!(d, Decision::Escalada(_)));
    assert_eq!(codigo(&d), CodigoRazon::EvidenciaAusente);
}

#[test]
fn g3_norma_no_evaluable_r6() {
    // Predicado que agota el presupuesto de la norma.
    use sak_core::presupuesto::PASOS_POR_NORMA;
    // Árbol Y ancho que consume > PASOS_POR_NORMA.
    let mut xs = Vec::new();
    for _ in 0..(PASOS_POR_NORMA as usize + 10) {
        xs.push(Predicado::Fijo(Veredicto::Allow));
    }
    let leaf = Predicado::Y(xs);
    let b = borrador(
        "N-HEAVY",
        ClaseEfecto::Ef6,
        Rango::P0,
        "EU",
        leaf,
        false,
    );
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef6, 20_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::NormaNoEvaluable);
}

#[test]
fn g3_ambiguedad_declarada_r8() {
    let b = borrador(
        "N-AMB",
        ClaseEfecto::Ef7,
        Rango::P3,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        true,
    );
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef7, 20_000), &pkg);
    assert!(matches!(d, Decision::Escalada(_)));
    assert_eq!(codigo(&d), CodigoRazon::AmbiguedadDeclarada);
}

#[test]
fn g3_l4_fuera_de_alcance() {
    let mut b = borrador(
        "N-L4",
        ClaseEfecto::Ef8,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    );
    b.operacionalidad = Operacionalidad::L4;
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let d = decidir_paquete(&ctx(ClaseEfecto::Ef8, 20_000), &pkg);
    assert!(matches!(d, Decision::Denegada(_)));
    assert_eq!(codigo(&d), CodigoRazon::FueraDeAlcanceTecnico);
}

#[test]
fn evidencia_presente_permite() {
    let mut b = borrador(
        "N-OK",
        ClaseEfecto::Ef1,
        Rango::P2,
        "EU",
        Predicado::Fijo(Veredicto::Allow),
        false,
    );
    let prod = IdProductor::nuevo("prod-ok").unwrap();
    b.evidencia_exigida = vec![RequisitoEvidencia {
        productor: prod.clone(),
        antiguedad_maxima_segundos: 100,
    }];
    let token = ValorHecho::token("token-hecho-ok").unwrap();
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    let hecho = HechoFirmado::nuevo(
        prod,
        token,
        [2u8; LONGITUD_HASH_PAQUETE],
        FirmaProductor::nueva(vec![1, 2, 3]).unwrap(),
        10,
        100,
        hash_peticion,
    );
    let pkg = paquete(vec![Norma::cargar(b).unwrap()]);
    let ctx = Contexto::con_instante(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho],
        20_000,
        hash_peticion,
    );
    let d = decidir_paquete(&ctx, &pkg);
    assert!(matches!(d, Decision::Permitida(_)));
}

#[test]
fn ninguna_anomalia_termina_en_allow() {
    // R6, R7, R8, sin norma: nunca Allow.
    let casos: Vec<Decision> = {
        let pkg_empty = paquete(vec![]);
        let d0 = decidir_paquete(&ctx(ClaseEfecto::Ef1, 1), &pkg_empty);

        let mut b = borrador(
            "X",
            ClaseEfecto::Ef1,
            Rango::P0,
            "EU",
            Predicado::Fijo(Veredicto::Allow),
            true,
        );
        let d1 = decidir_paquete(&ctx(ClaseEfecto::Ef1, 20_000), &paquete(vec![Norma::cargar(b.clone()).unwrap()]));

        b.ambigua = false;
        b.evidencia_exigida = vec![RequisitoEvidencia {
            productor: IdProductor::nuevo("z").unwrap(),
            antiguedad_maxima_segundos: 1,
        }];
        let d2 = decidir_paquete(&ctx(ClaseEfecto::Ef1, 20_000), &paquete(vec![Norma::cargar(b).unwrap()]));
        vec![d0, d1, d2]
    };
    for d in casos {
        assert!(!matches!(d, Decision::Permitida(_)));
    }
}
