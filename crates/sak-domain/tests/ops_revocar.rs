//! Fase 5.4 — gob.revocar / gob.revertir (sin borrar historia ni saltar traza).

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::{dominio, sha384_dominio, ParMlDsa87};
use sak_core::decision::{Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::gobernanza::{
    AprobacionInterpretacion, EtiquetaGob, FirmaPaquete, RolFirmante, VENTANA_SOMBRA_MS,
};
use sak_core::norma::{
    Alcance, BorradorNorma, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::supervision::IdHumano;
use sak_domain::ops::{despachar_con_estado, es_deny_fijo_ops, EstadoOps};

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

fn hash_y_pares(
    ident: &str,
    fuente: &str,
    dig: [u8; LONGITUD_HASH_PAQUETE],
) -> (String, ParMlDsa87, ParMlDsa87, ParMlDsa87) {
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
    (
        hex(p.hash().bytes()),
        ParMlDsa87::generar().unwrap(),
        ParMlDsa87::generar().unwrap(),
        ParMlDsa87::generar().unwrap(),
    )
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

fn hasta_activa(st: &mut EstadoOps, ident: &str) -> String {
    let dig = sha384_dominio(dominio::GOBERNANZA, b"interpretacion operativa borrador MVP");
    let (hash_hex, par_prop, par_ap, par_ack) =
        hash_y_pares(ident, "instrumento-mvp-art-1", dig);
    assert_eq!(
        despachar_con_estado(
            &body_proponer(
                ident,
                "instrumento-mvp-art-1",
                dig,
                &par_prop,
                &par_ap,
                &hash_hex,
            ),
            Some(st),
        )
        .resultado,
        "OK"
    );
    assert_eq!(
        despachar_con_estado(
            &format!(
                r#"{{"op":"gob.revision_juridica","req_id":"r","schema_v":1,"hash_paquete":"{hash_hex}","revisor_id":"revisor-mvp","competencia_registrada":true}}"#
            ),
            Some(st),
        )
        .resultado,
        "OK"
    );
    let diff = despachar_con_estado(
        &format!(
            r#"{{"op":"gob.diff_conformidad","req_id":"d","schema_v":1,"hash_paquete":"{hash_hex}"}}"#
        ),
        Some(st),
    );
    assert_eq!(diff.resultado, "OK");
    let dig_cambio = {
        let marker = "\"digest_cambio\":\"";
        let i = diff.cuerpo.find(marker).unwrap();
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
    assert_eq!(
        despachar_con_estado(
            &format!(
                r#"{{"op":"gob.reconocer_diff","req_id":"a","schema_v":1,"hash_paquete":"{hash_hex}","reconocimientos":[{{"digest_cambio_hex":"{dig_cambio}","id_humano":"ack-humano","firma_hex":"{firma_ack}","pk_hex":"{pk}"}}]}}"#,
                pk = hex(&par_ack.public),
            ),
            Some(st),
        )
        .resultado,
        "OK"
    );
    let ver = st
        .gob
        .propuesta(&{
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
    assert_eq!(
        despachar_con_estado(
            &format!(
                r#"{{"op":"gob.doble_firma","req_id":"f","schema_v":1,"hash_paquete":"{hash_hex}","id_juridico":"firmante-jur","firma_juridico_hex":"{fj}","pk_juridico_hex":"{pj}","id_tecnico":"firmante-tec","firma_tecnico_hex":"{ft}","pk_tecnico_hex":"{pt}"}}"#,
                fj = hex(&fj.firma_mldsa),
                pj = hex(&par_j.public),
                ft = hex(&ft.firma_mldsa),
                pt = hex(&par_t.public),
            ),
            Some(st),
        )
        .resultado,
        "OK"
    );
    let desde = 1_000u64;
    assert_eq!(
        despachar_con_estado(
            &format!(
                r#"{{"op":"gob.entrar_sombra","req_id":"s","schema_v":1,"hash_paquete":"{hash_hex}","identidad":"op","rol":"gobernanza-sombra","epoca_vista":"1","confirmacion_independiente":true,"ahora_ms":"{desde}"}}"#
            ),
            Some(st),
        )
        .resultado,
        "OK"
    );
    let ahora = desde + VENTANA_SOMBRA_MS;
    let par_act = ParMlDsa87::generar().unwrap();
    let mut cuerpo = Vec::new();
    cuerpo.extend_from_slice(b"SAK-GOB-ACTIVAR-v1");
    cuerpo.push(0);
    cuerpo.extend_from_slice(hash_hex.as_bytes());
    cuerpo.push(0);
    cuerpo.extend_from_slice(&1u64.to_le_bytes());
    cuerpo.push(0);
    cuerpo.extend_from_slice(b"gobernanza-activar");
    let fa = hex(&par_act.firmar(&cuerpo).unwrap());
    let r = despachar_con_estado(
        &format!(
            r#"{{"op":"gob.activar_epoca","req_id":"act","schema_v":1,"hash_paquete":"{hash_hex}","identidad":"op","rol":"gobernanza-activar","epoca_vista":1,"en_limite_epoca":true,"confirmacion_independiente":true,"ahora_ms":"{ahora}","firma_operador_hex":"{fa}","pk_operador_hex":"{pk}"}}"#,
            pk = hex(&par_act.public),
        ),
        Some(st),
    );
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    hash_hex
}

fn firmas_2dn(tag: &[u8], hash_hex: &str) -> (String, String, String, String, String, String) {
    let mut v = Vec::new();
    v.extend_from_slice(tag);
    v.push(0);
    v.extend_from_slice(hash_hex.as_bytes());
    let dig = sha384_dominio(dominio::GOBERNANZA, &v);
    let par_j = ParMlDsa87::generar().unwrap();
    let par_t = ParMlDsa87::generar().unwrap();
    let fj = FirmaPaquete::firmar(
        &par_j,
        IdHumano::nuevo("rev-jur").unwrap(),
        RolFirmante::Juridico,
        &dig,
    )
    .unwrap();
    let ft = FirmaPaquete::firmar(
        &par_t,
        IdHumano::nuevo("rev-tec").unwrap(),
        RolFirmante::Tecnico,
        &dig,
    )
    .unwrap();
    (
        "rev-jur".into(),
        hex(&fj.firma_mldsa),
        hex(&par_j.public),
        "rev-tec".into(),
        hex(&ft.firma_mldsa),
        hex(&par_t.public),
    )
}

fn req_revocar(hash: &str, con_firmas: bool, extra: &str) -> String {
    let firmas = if con_firmas {
        let (ij, fj, pj, it, ft, pt) = firmas_2dn(b"SAK-GOB-REVOCAR-v1", hash);
        format!(
            r#","id_juridico":"{ij}","firma_juridico_hex":"{fj}","pk_juridico_hex":"{pj}","id_tecnico":"{it}","firma_tecnico_hex":"{ft}","pk_tecnico_hex":"{pt}""#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{"op":"gob.revocar","req_id":"rv","schema_v":1,"hash_paquete":"{hash}","identidad":"op","rol":"gobernanza-revocar","epoca_vista":"1","confirmacion_independiente":true{firmas}{extra}}}"#
    )
}

fn req_revertir(hash: &str, con_firmas: bool, extra: &str) -> String {
    let firmas = if con_firmas {
        let (ij, fj, pj, it, ft, pt) = firmas_2dn(b"SAK-GOB-REVERTIR-v1", hash);
        format!(
            r#","id_juridico":"{ij}","firma_juridico_hex":"{fj}","pk_juridico_hex":"{pj}","id_tecnico":"{it}","firma_tecnico_hex":"{ft}","pk_tecnico_hex":"{pt}""#
        )
    } else {
        String::new()
    };
    format!(
        r#"{{"op":"gob.revertir","req_id":"rt","schema_v":1,"hash_paquete":"{hash}","identidad":"op","rol":"gobernanza-revertir","epoca_vista":"1","confirmacion_independiente":true{firmas}{extra}}}"#
    )
}

#[test]
fn revocar_ok_conserva_historial_y_firmas() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-1");
    let n_hist = st.gob.historial().len();
    let r = despachar_con_estado(&req_revocar(&hash, true, ""), Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("REVOCADA") || r.codigo == "REVOCADO");
    assert!(r.cuerpo.contains("historial_conservado\":true"));
    assert!(r.cuerpo.contains("firmas_conservadas\":true"));
    assert!(r.cuerpo.contains("diff_conservado\":true"));
    assert!(r.cuerpo.contains("decisiones_pasadas_intactas\":true"));
    assert!(r.cuerpo.contains("conformidad_certificada\":false"));
    assert!(r.limites.iter().any(|l| *l == "IRREVERSIBLE"));
    assert!(st.gob.hash_activo().is_none());
    assert_eq!(st.gob.historial().len(), n_hist);
}

#[test]
fn revertir_ok_exige_sombra_posterior() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-2");
    assert_eq!(
        despachar_con_estado(&req_revocar(&hash, true, ""), Some(&mut st)).resultado,
        "OK"
    );
    let r = despachar_con_estado(&req_revertir(&hash, true, ""), Some(&mut st));
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("FIRMADA"));
    assert!(r.cuerpo.contains("firmas_conservadas\":true"));
    assert!(r.cuerpo.contains("diff_conservado\":true"));
    assert!(r.cuerpo.contains("historial_conservado\":true"));
    assert!(r.cuerpo.contains("epoca_activada\":false"));
    assert!(r.cuerpo.contains("conformidad_certificada\":false"));
    assert!(r.cuerpo.contains("gob.entrar_sombra"));
    assert!(r.cuerpo.contains("gob.activar_epoca"));
    assert!(st.gob.hash_activo().is_none());
}

#[test]
fn revocar_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-3");
    let r = despachar_con_estado(&req_revocar(&hash, false, ""), Some(&mut st));
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn revocar_borrar_historia_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-4");
    let r = despachar_con_estado(
        &req_revocar(&hash, true, r#","borrar_historia":true"#),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "TRAZA_INMUTABLE");
}

#[test]
fn revertir_saltar_sombra_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-5");
    assert_eq!(
        despachar_con_estado(&req_revocar(&hash, true, ""), Some(&mut st)).resultado,
        "OK"
    );
    let r = despachar_con_estado(
        &req_revertir(&hash, true, r#","saltar_sombra":true"#),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "TRAZA_INMUTABLE");
}

#[test]
fn revertir_sin_revocar_activo_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-6");
    let r = despachar_con_estado(&req_revertir(&hash, true, ""), Some(&mut st));
    assert_eq!(r.codigo, "PRECONDICION");
}

#[test]
fn certificar_auto_sigue_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let hash = hasta_activa(&mut st, "N-REV-7");
    let r = despachar_con_estado(
        &req_revocar(&hash, true, r#","certificar_conformidad":true"#),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "FUERA_MVP");
}

#[test]
fn revocar_revertir_ya_no_deny_fijo() {
    assert!(!es_deny_fijo_ops("gob.revocar"));
    assert!(!es_deny_fijo_ops("gob.revertir"));
}
