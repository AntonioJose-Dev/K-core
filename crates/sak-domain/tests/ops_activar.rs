//! Fase 5.3 — gob.activar_epoca IRREVERSIBLE (sin revocar).

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

fn hasta_sombra(st: &mut EstadoOps, ident: &str, desde: u64) -> String {
    let dig = sha384_dominio(dominio::GOBERNANZA, b"interpretacion operativa borrador MVP");
    let (hash_hex, par_prop, par_ap, par_ack) =
        hash_y_pares(ident, "instrumento-mvp-art-1", dig);
    let raw = body_proponer(
        ident,
        "instrumento-mvp-art-1",
        dig,
        &par_prop,
        &par_ap,
        &hash_hex,
    );
    assert_eq!(despachar_con_estado(&raw, Some(st)).resultado, "OK");
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
    let s = despachar_con_estado(
        &format!(
            r#"{{"op":"gob.entrar_sombra","req_id":"s","schema_v":1,"hash_paquete":"{hash_hex}","identidad":"op-sombra","rol":"gobernanza-sombra","epoca_vista":"1","confirmacion_independiente":true,"ahora_ms":"{desde}"}}"#
        ),
        Some(st),
    );
    assert_eq!(s.resultado, "OK", "{}", s.a_json());
    hash_hex
}

fn cuerpo_activar(hash_hex: &str, epoca_vista: u64, rol: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-GOB-ACTIVAR-v1");
    v.push(0);
    v.extend_from_slice(hash_hex.as_bytes());
    v.push(0);
    v.extend_from_slice(&epoca_vista.to_le_bytes());
    v.push(0);
    v.extend_from_slice(rol.as_bytes());
    v
}

fn req_activar(
    hash: &str,
    epoca_vista: u64,
    ahora: u64,
    en_limite: bool,
    confirm: bool,
    firma: Option<(&ParMlDsa87, &str)>,
) -> String {
    let rol = "gobernanza-activar";
    let (fh, ph) = match firma {
        Some((par, _)) => {
            let c = cuerpo_activar(hash, epoca_vista, rol);
            (hex(&par.firmar(&c).unwrap()), hex(&par.public))
        }
        None => (String::new(), String::new()),
    };
    let firma_campos = if fh.is_empty() {
        String::new()
    } else {
        format!(r#","firma_operador_hex":"{fh}","pk_operador_hex":"{ph}""#)
    };
    format!(
        r#"{{"op":"gob.activar_epoca","req_id":"act","schema_v":1,"hash_paquete":"{hash}","identidad":"op-act","rol":"{rol}","epoca_vista":{epoca_vista},"en_limite_epoca":{en_limite},"confirmacion_independiente":{confirm},"ahora_ms":"{ahora}"{firma_campos}}}"#
    )
}

#[test]
fn activar_ok_conserva_historial() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-1", desde);
    let ahora = desde + VENTANA_SOMBRA_MS;
    let epoca_antes = st.epoca.actual();
    let par = ParMlDsa87::generar().unwrap();
    let r = despachar_con_estado(
        &req_activar(&hash, 1, ahora, true, true, Some((&par, "x"))),
        Some(&mut st),
    );
    assert_eq!(r.resultado, "OK", "{}", r.a_json());
    assert!(r.cuerpo.contains("EPOCA_ACTIVADA") || r.codigo == "EPOCA_ACTIVADA");
    assert!(r.cuerpo.contains("epoca_activada\":true"));
    assert!(r.cuerpo.contains("activo_cambiado\":true"));
    assert!(r.cuerpo.contains("aplica_como_vivo\":true"));
    assert!(r.cuerpo.contains("conformidad_certificada\":false"));
    assert!(r.cuerpo.contains("historial_conservado\":true"));
    assert!(r.cuerpo.contains("anti_engano"));
    assert!(r.limites.iter().any(|l| *l == "IRREVERSIBLE"));
    assert_eq!(st.gob.hash_activo().map(|h| hex(h.bytes())), Some(hash));
    assert!(st.epoca.actual() > epoca_antes);
    assert_eq!(st.gob.historial().len(), 1);
}

#[test]
fn activar_sin_sombra_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    // Solo hasta firmada: reutilizar flujo sombra sin entrar_sombra
    let dig = sha384_dominio(dominio::GOBERNANZA, b"interpretacion operativa borrador MVP");
    let (hash_hex, par_prop, par_ap, _) = hash_y_pares("N-ACT-2", "instrumento-mvp-art-1", dig);
    let raw = body_proponer(
        "N-ACT-2",
        "instrumento-mvp-art-1",
        dig,
        &par_prop,
        &par_ap,
        &hash_hex,
    );
    assert_eq!(despachar_con_estado(&raw, Some(&mut st)).resultado, "OK");
    let par = ParMlDsa87::generar().unwrap();
    let r = despachar_con_estado(
        &req_activar(&hash_hex, 1, 9_000_000, true, true, Some((&par, "x"))),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "NO_EN_SOMBRA");
}

#[test]
fn activar_sombra_incompleta_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-3", desde);
    let ahora = desde + VENTANA_SOMBRA_MS / 2;
    let par = ParMlDsa87::generar().unwrap();
    let r = despachar_con_estado(
        &req_activar(&hash, 1, ahora, true, true, Some((&par, "x"))),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SOMBRA_INCOMPLETA");
}

#[test]
fn activar_fuera_limite_epoca_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-4", desde);
    let ahora = desde + VENTANA_SOMBRA_MS;
    let par = ParMlDsa87::generar().unwrap();
    let r = despachar_con_estado(
        &req_activar(&hash, 1, ahora, false, true, Some((&par, "x"))),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "FUERA_LIMITE_EPOCA");
}

#[test]
fn activar_sin_confirmacion_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-5", desde);
    let ahora = desde + VENTANA_SOMBRA_MS;
    let par = ParMlDsa87::generar().unwrap();
    let r = despachar_con_estado(
        &req_activar(&hash, 1, ahora, true, false, Some((&par, "x"))),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SIN_CONFIRMACION");
}

#[test]
fn activar_sin_firma_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-6", desde);
    let ahora = desde + VENTANA_SOMBRA_MS;
    let r = despachar_con_estado(
        &req_activar(&hash, 1, ahora, true, true, None),
        Some(&mut st),
    );
    assert_eq!(r.codigo, "SIN_FIRMA");
}

#[test]
fn activar_certificar_auto_deny() {
    let mut st = EstadoOps::en_memoria().unwrap();
    let desde = 1_000u64;
    let hash = hasta_sombra(&mut st, "N-ACT-7", desde);
    let ahora = desde + VENTANA_SOMBRA_MS;
    let par = ParMlDsa87::generar().unwrap();
    let mut raw = req_activar(&hash, 1, ahora, true, true, Some((&par, "x")));
    raw.insert_str(raw.len() - 1, r#","certificar_conformidad":true"#);
    let r = despachar_con_estado(&raw, Some(&mut st));
    assert_eq!(r.codigo, "FUERA_MVP");
}

#[test]
fn revocar_sigue_deny_fijo() {
    // Fase 5.4: revocar/revertir ya no son DENY_FIJO (ver ops_revocar).
    assert!(!es_deny_fijo_ops("gob.revocar"));
    assert!(!es_deny_fijo_ops("gob.revertir"));
    assert!(!es_deny_fijo_ops("gob.activar_epoca"));
}
