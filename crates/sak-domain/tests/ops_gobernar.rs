//! Fase 3 — MVP-GOBERNAR recortado: proponer→revisión→diff→ack→doble firma (sin activar).

use sak_core::crypto::{dominio, sha384_dominio, ParMlDsa87};
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::gobernanza::{
    AprobacionInterpretacion, EtiquetaGob, FirmaPaquete, RolFirmante,
};
use sak_core::norma::{
    Alcance, BorradorNorma, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::contexto::ClaseEfecto;
use sak_core::decision::Veredicto;
use sak_core::supervision::IdHumano;
use sak_domain::ops::{despachar_con_estado, EstadoOps};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn alcance() -> Alcance {
    Alcance {
        caso_de_uso: "mvp-gobernar".into(),
        clase_riesgo: "limitado".into(),
        rol_regulatorio: "operador".into(),
        sector: "demo".into(),
        categorias_datos: "ninguna".into(),
        autonomia: "asistido".into(),
        destinatarios: "humano".into(),
    }
}

/// Construye el mismo paquete que el handler para poder firmar el hash de antemano.
fn hash_y_firmas(ident: &str, fuente: &str, dig: [u8; LONGITUD_HASH_PAQUETE]) -> (String, ParMlDsa87, ParMlDsa87, ParMlDsa87) {
    let borrador = BorradorNorma {
        identificador: ident.into(),
        fuente: fuente.into(),
        jurisdiccion: "EU".into(),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L2,
        clase_de_efecto: ClaseEfecto::Ef1,
        predicado: Predicado::Fijo(Veredicto::Allow),
        evidencia_exigida: vec![],
        acciones_obligatorias: vec!["registrar".into()],
        condiciones_de_denegacion: vec!["fuera-alcance".into()],
        escalado: None,
        monitorizacion: None,
        interpretacion: Interpretacion {
            texto: "interpretacion operativa borrador MVP".into(),
            autor: "revisor".into(),
            digest_aprobacion: dig,
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    };
    let n = Norma::cargar(borrador).unwrap();
    let p = PaqueteNormativo::cargar(vec![n]).unwrap();
    let hx = hex(p.hash().bytes());
    let par_prop = ParMlDsa87::generar().unwrap();
    let par_ap = ParMlDsa87::generar().unwrap();
    let par_ack = ParMlDsa87::generar().unwrap();
    (hx, par_prop, par_ap, par_ack)
}

fn body_proponer(
    ident: &str,
    fuente: &str,
    dig: [u8; LONGITUD_HASH_PAQUETE],
    par_prop: &ParMlDsa87,
    par_ap: &ParMlDsa87,
    hash_hex: &str,
) -> String {
    let hash_bytes = {
        let b = (0..hash_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hash_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let mut a = [0u8; LONGITUD_HASH_PAQUETE];
        a.copy_from_slice(&b);
        a
    };
    let firma_prop = hex(&par_prop.firmar(&hash_bytes).unwrap());
    let aprob = AprobacionInterpretacion::firmar(
        par_ap,
        IdHumano::nuevo("aprob-interp").unwrap(),
        dig,
        EtiquetaGob::ValExt,
    )
    .unwrap();
    format!(
        r#"{{"op":"gob.proponer","req_id":"p","schema_v":1,"identificador":"{ident}","fuente":"{fuente}","interpretacion":"interpretacion operativa borrador MVP","autor_interpretacion":"revisor","veredicto":"ALLOW","digest_aprobacion_hex":"{dig}","firma_aprobacion_hex":"{fa}","pk_aprobacion_hex":"{pa}","id_aprobador":"aprob-interp","firma_proponente_hex":"{fp}","pk_proponente_hex":"{pp}"}}"#,
        dig = hex(&dig),
        fa = hex(&aprob.firma_mldsa),
        pa = hex(&par_ap.public),
        fp = firma_prop,
        pp = hex(&par_prop.public),
    )
}

#[test]
fn flujo_completo_sin_activar() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let dig = sha384_dominio(dominio::GOBERNANZA, b"interpretacion operativa borrador MVP");
    let (hash_hex, par_prop, par_ap, par_ack) =
        hash_y_firmas("N-MVP-1", "instrumento-mvp-art-1", dig);
    let raw = body_proponer(
        "N-MVP-1",
        "instrumento-mvp-art-1",
        dig,
        &par_prop,
        &par_ap,
        &hash_hex,
    );
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains(&hash_hex));
    assert!(r.cuerpo.contains("epoca_activada\":false"));
    assert!(r.cuerpo.contains("conformidad_certificada\":false"));

    let rev = format!(
        r#"{{"op":"gob.revision_juridica","req_id":"r","schema_v":1,"hash_paquete":"{hash_hex}","revisor_id":"revisor-mvp","competencia_registrada":true}}"#
    );
    let rv = despachar_con_estado(&rev, Some(&mut st));
    assert_eq!(rv.resultado, "OK", "{}", rv.a_json());

    let diff = despachar_con_estado(
        &format!(
            r#"{{"op":"gob.diff_conformidad","req_id":"d","schema_v":1,"hash_paquete":"{hash_hex}"}}"#
        ),
        Some(&mut st),
    );
    assert_eq!(diff.resultado, "OK", "{}", diff.a_json());
    assert!(diff.cuerpo.contains("conformidad_certificada\":false"));
    // Extraer digest_cambio
    let dig_cambio = {
        let marker = "\"digest_cambio\":\"";
        let i = diff.cuerpo.find(marker).expect("digest_cambio");
        let rest = &diff.cuerpo[i + marker.len()..];
        rest.split('"').next().unwrap().to_string()
    };
    let dig_bytes: Vec<u8> = (0..dig_cambio.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&dig_cambio[i..i + 2], 16).unwrap())
        .collect();
    let mut dig_arr = [0u8; LONGITUD_HASH_PAQUETE];
    dig_arr.copy_from_slice(&dig_bytes);
    let mut msg = Vec::new();
    msg.extend_from_slice(b"diff-ack|");
    msg.extend_from_slice(&dig_arr);
    let firma_ack = hex(&par_ack.firmar(&msg).unwrap());

    let ack = format!(
        r#"{{"op":"gob.reconocer_diff","req_id":"a","schema_v":1,"hash_paquete":"{hash_hex}","reconocimientos":[{{"digest_cambio_hex":"{dig_cambio}","id_humano":"ack-humano","firma_hex":"{firma_ack}","pk_hex":"{pk}"}}]}}"#,
        pk = hex(&par_ack.public),
    );
    let a = despachar_con_estado(&ack, Some(&mut st));
    assert_eq!(a.resultado, "OK", "{}", a.a_json());
    assert!(a.cuerpo.contains("conformidad_certificada\":false"));
    assert!(a.cuerpo.contains("epoca_activada\":false"));

    // Doble firma
    let ver = st.gob.propuesta(&{
        let b = (0..hash_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hash_hex[i..i + 2], 16).unwrap())
            .collect::<Vec<_>>();
        let mut a = [0u8; LONGITUD_HASH_PAQUETE];
        a.copy_from_slice(&b);
        sak_core::decision::HashPaqueteNormativo::desde_bytes(a)
    })
    .unwrap();
    let msg_pkg = ver.paquete.mensaje_firma();
    let par_j = ParMlDsa87::generar().unwrap();
    let par_t = ParMlDsa87::generar().unwrap();
    let fj = FirmaPaquete::firmar(
        &par_j,
        IdHumano::nuevo("firmante-jur").unwrap(),
        RolFirmante::Juridico,
        &msg_pkg,
    )
    .unwrap();
    let ft = FirmaPaquete::firmar(
        &par_t,
        IdHumano::nuevo("firmante-tec").unwrap(),
        RolFirmante::Tecnico,
        &msg_pkg,
    )
    .unwrap();
    let df = format!(
        r#"{{"op":"gob.doble_firma","req_id":"f","schema_v":1,"hash_paquete":"{hash_hex}","id_juridico":"firmante-jur","firma_juridico_hex":"{fj}","pk_juridico_hex":"{pj}","id_tecnico":"firmante-tec","firma_tecnico_hex":"{ft}","pk_tecnico_hex":"{pt}"}}"#,
        fj = hex(&fj.firma_mldsa),
        pj = hex(&par_j.public),
        ft = hex(&ft.firma_mldsa),
        pt = hex(&par_t.public),
    );
    let f = despachar_con_estado(&df, Some(&mut st));
    assert_eq!(f.resultado, "OK", "{}", f.a_json());
    assert!(f.cuerpo.contains("FIRMADA"));
    assert!(f.cuerpo.contains("epoca_activada\":false"));
    assert!(f.cuerpo.contains("en_sombra\":false"));
    assert!(st.gob.hash_activo().is_none());
}

#[test]
fn proponer_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"gob.proponer","req_id":"x","schema_v":1,"identificador":"N1","fuente":"f"}"#,
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn activar_en_payload_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"gob.proponer","req_id":"x","schema_v":1,"identificador":"N1","activar_epoca":true}"#,
        Some(&mut st),
    );
    assert_eq!(r.codigo, "FUERA_MVP");
}

#[test]
fn ops_excluidas_deny_fijo() {
    // Fase 5.4: G.5 ops en allowlist; DENY fijo restante cubierto en ops_fase0.
    assert!(!sak_domain::ops::es_deny_fijo_ops("gob.revocar"));
    assert!(!sak_domain::ops::es_deny_fijo_ops("gob.revertir"));
}

#[test]
fn alcanzables_implementado_no_stub() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let r = despachar_con_estado(
        r#"{"op":"con.inventario.alcanzables","req_id":"a","schema_v":1,"vista":true}"#,
        Some(&mut st),
    );
    assert_ne!(r.codigo, "FASE0_SIN_HANDLER");
    assert_eq!(r.resultado, "OK");
}

#[test]
fn revision_sin_competencia_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let dig = sha384_dominio(dominio::GOBERNANZA, b"interpretacion operativa borrador MVP");
    let (hash_hex, par_prop, par_ap, _) = hash_y_firmas("N-MVP-2", "instrumento-mvp-art-1", dig);
    let raw = body_proponer(
        "N-MVP-2",
        "instrumento-mvp-art-1",
        dig,
        &par_prop,
        &par_ap,
        &hash_hex,
    );
    assert_eq!(despachar_con_estado(&raw, Some(&mut st)).resultado, "OK");
    let rev = format!(
        r#"{{"op":"gob.revision_juridica","req_id":"r","schema_v":1,"hash_paquete":"{hash_hex}","revisor_id":"r1","competencia_registrada":false}}"#
    );
    let r = despachar_con_estado(&rev, Some(&mut st));
    assert_eq!(r.codigo, "SIN_COMPETENCIA");
}
