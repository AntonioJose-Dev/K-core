//! Handlers Custodiar: referencias + rotación IRREVERSIBLE (Fase 5.1).

use sak_core::crypto::{self, dominio, ParMlDsa87};

use super::estado::{hex_decode, hex_encode, EstadoOps, HistRotacion, RefCustodia};
use super::schema::{campo_bool_raw, campo_str_raw, campo_u32_raw, RespuestaOps};

const LIMITE: &str = "custodia: solo handles/metadatos; sin material exportable";
const CONSECUENCIAS_ROTAR: &str =
    "IRREVERSIBLE: sustituye handle activo; conserva huella/historial anterior; NO exporta material antiguo ni nuevo; NO revela raíz.";

fn deny_secreto(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    let lower = raw.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "begin private",
        "private_key",
        "secret_key",
        "\"seed\"",
        "\"pem\"",
        "\"material\"",
        "\"raw\"",
        "api_key",
        "apikey",
        "-----begin",
        "wrapping_key",
        "exportable",
    ];
    if BAD.iter().any(|b| lower.contains(b)) {
        return Some(RespuestaOps::deny(
            req_id,
            "SECRETO_PROHIBIDO",
            "Custodiar rechaza material/PEM/raw/seed/exportable",
        ));
    }
    None
}

fn deny_pedir_raw(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    if campo_str_raw(raw, "pedir_raw").is_some()
        || campo_str_raw(raw, "exportar").is_some()
        || raw.contains("\"reveal\":true")
        || raw.contains("\"pedir_raw\":true")
    {
        return Some(RespuestaOps::deny(
            req_id,
            "REVEAL_PROHIBIDO",
            "cus.* no entregan ni piden material",
        ));
    }
    None
}

fn cuerpo_canonico(alias: &str, clase_ef: &str, handle: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-CUS-REF-v1");
    v.push(0);
    v.extend_from_slice(alias.as_bytes());
    v.push(0);
    v.extend_from_slice(clase_ef.as_bytes());
    v.push(0);
    v.extend_from_slice(handle.as_bytes());
    v
}

fn cuerpo_rotar(
    secreto_id: &str,
    huella_anterior: &str,
    nuevo_handle: &str,
    epoca: u64,
    rol: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-CUS-ROTAR-v1");
    v.push(0);
    v.extend_from_slice(secreto_id.as_bytes());
    v.push(0);
    v.extend_from_slice(huella_anterior.as_bytes());
    v.push(0);
    v.extend_from_slice(nuevo_handle.as_bytes());
    v.push(0);
    v.extend_from_slice(&epoca.to_le_bytes());
    v.push(0);
    v.extend_from_slice(rol.as_bytes());
    v
}

fn huella_de(alias: &str, clase_ef: &str, handle: &str) -> String {
    hex_encode(&crypto::sha384_dominio(
        dominio::CUSTODIA,
        &cuerpo_canonico(alias, clase_ef, handle),
    ))
}

fn digest_rotar(cuerpo: &[u8]) -> String {
    hex_encode(&crypto::sha384_dominio(dominio::CUSTODIA, cuerpo))
}

fn clase_ef_ok(c: &str) -> bool {
    matches!(
        c,
        "EF-1"
            | "EF-2"
            | "EF-3"
            | "EF-4"
            | "EF-5"
            | "EF-6"
            | "EF-7"
            | "EF-8"
            | "EF-10"
            | "EF-11"
    )
}

fn handle_ok(handle: &str) -> Result<(), &'static str> {
    if handle.trim().is_empty() || handle.len() > 512 {
        return Err("handle invalido");
    }
    if handle.starts_with("-----") || (handle.len() > 256 && !handle.contains(':')) {
        return Err("handle no parece referencia KMS/PKCS#11");
    }
    Ok(())
}

pub fn manejar(estado: &mut EstadoOps, op: &str, req_id: &str, raw: &str) -> RespuestaOps {
    if let Some(d) = deny_secreto(req_id, raw) {
        return d;
    }
    if let Some(d) = deny_pedir_raw(req_id, raw) {
        return d;
    }
    match op {
        "cus.alta_referencia" => alta(estado, req_id, raw),
        "cus.estado" => estado_vista(estado, req_id, raw),
        "cus.rotar" => rotar(estado, req_id, raw),
        _ => RespuestaOps::deny(req_id, "OP_DESCONOCIDA", "op Custodiar no manejada"),
    }
}

fn alta(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let alias = match campo_str_raw(raw, "alias") {
        Some(a) if !a.trim().is_empty() => a,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta alias"),
    };
    let clase_ef = match campo_str_raw(raw, "clase_ef")
        .or_else(|| campo_str_raw(raw, "clase"))
    {
        Some(c) if clase_ef_ok(&c) => c,
        Some(_) => return RespuestaOps::deny(req_id, "SCHEMA", "clase_ef no reconocida"),
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta clase_ef"),
    };
    let handle = match campo_str_raw(raw, "handle")
        .or_else(|| campo_str_raw(raw, "ref"))
        .or_else(|| campo_str_raw(raw, "handle_kms"))
    {
        Some(h) => match handle_ok(&h) {
            Ok(()) => h,
            Err(e) => {
                let codigo = if e.contains("KMS") {
                    "SECRETO_PROHIBIDO"
                } else {
                    "SCHEMA"
                };
                return RespuestaOps::deny(req_id, codigo, e);
            }
        },
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta handle/ref"),
    };

    let firma_hex = campo_str_raw(raw, "firma_operador_hex").unwrap_or_default();
    let pk_hex = campo_str_raw(raw, "pk_operador_hex").unwrap_or_default();
    if firma_hex.is_empty() || pk_hex.is_empty() {
        return RespuestaOps::deny(req_id, "SIN_FIRMA", "firma de operador ausente");
    }
    let firma = match hex_decode(&firma_hex) {
        Ok(f) => f,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let pk = match hex_decode(&pk_hex) {
        Ok(p) => p,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let cuerpo = cuerpo_canonico(&alias, &clase_ef, &handle);
    if ParMlDsa87::verificar(&pk, &cuerpo, &firma).is_err() {
        return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "firma operador no verifica");
    }

    if estado.ref_por_alias(&alias).is_some() {
        return RespuestaOps::deny(req_id, "ALIAS_EXISTE", "alias ya registrado; no reescribe");
    }

    let huella = huella_de(&alias, &clase_ef, &handle);
    let secreto_id = campo_str_raw(raw, "secreto_id").unwrap_or_else(|| {
        format!("sec-{}", &huella[..16.min(huella.len())])
    });
    if estado.refs.contains_key(&secreto_id) {
        return RespuestaOps::deny(req_id, "ID_EXISTE", "secreto_id ya existe");
    }

    let ttl = campo_u32_raw(raw, "ttl_derivadas_secs").unwrap_or(3600);
    let r = RefCustodia {
        secreto_id: secreto_id.clone(),
        alias: alias.clone(),
        clase_ef: clase_ef.clone(),
        handle: handle.clone(),
        huella: huella.clone(),
        estado: "presente".into(),
        ttl_derivadas_secs: ttl,
        operador_id: campo_str_raw(raw, "operador_id").unwrap_or_else(|| "operador".into()),
        historial: Vec::new(),
        n_rotaciones: 0,
    };
    if let Err(e) = estado.guardar_ref(&r) {
        return RespuestaOps::deny(req_id, "ALMACEN", &e);
    }

    RespuestaOps::ok(
        req_id,
        "REF_ALTA_OK",
        &format!(
            r#"{{"secreto_id":"{}","alias":"{}","clase_ef":"{}","handle":"{}","huella":"{}","estado":"presente","material":null,"nota":"alta por referencia; sin material"}}"#,
            esc(&secreto_id),
            esc(&alias),
            esc(&clase_ef),
            esc(&handle),
            huella
        ),
        vec!["no_comprobado", LIMITE],
    )
}

fn rotar(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    if !campo_bool_raw(raw, "confirmacion_independiente").unwrap_or(false) {
        return RespuestaOps::deny(
            req_id,
            "SIN_CONFIRMACION",
            "cus.rotar IRREVERSIBLE exige confirmacion_independiente=true",
        );
    }
    let epoca = match campo_u32_raw(raw, "epoca_vista").or_else(|| campo_u32_raw(raw, "epoca")) {
        Some(e) => e as u64,
        None => {
            return RespuestaOps::deny(req_id, "SCHEMA", "falta epoca_vista");
        }
    };
    let identidad = match campo_str_raw(raw, "identidad")
        .or_else(|| campo_str_raw(raw, "operador_id"))
    {
        Some(i) if !i.trim().is_empty() => i,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta identidad/operador_id"),
    };
    let rol = match campo_str_raw(raw, "rol") {
        Some(r) if !r.trim().is_empty() => r,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta rol"),
    };

    let id = campo_str_raw(raw, "secreto_id");
    let alias_q = campo_str_raw(raw, "alias");
    let secreto_key = match (&id, &alias_q) {
        (Some(i), _) => i.clone(),
        (None, Some(a)) => match estado.alias_a_id.get(a) {
            Some(sid) => sid.clone(),
            None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "alias inexistente"),
        },
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta secreto_id o alias"),
    };

    let nuevo_handle = match campo_str_raw(raw, "nuevo_handle")
        .or_else(|| campo_str_raw(raw, "handle_nuevo"))
    {
        Some(h) => match handle_ok(&h) {
            Ok(()) => h,
            Err(e) => {
                let codigo = if e.contains("KMS") {
                    "SECRETO_PROHIBIDO"
                } else {
                    "SCHEMA"
                };
                return RespuestaOps::deny(req_id, codigo, e);
            }
        },
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta nuevo_handle"),
    };

    let actual = match estado.refs.get(&secreto_key) {
        Some(r) => r.clone(),
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "referencia inexistente"),
    };
    if nuevo_handle == actual.handle {
        return RespuestaOps::deny(req_id, "HANDLE_IGUAL", "nuevo_handle debe diferir del actual");
    }

    let huella_anterior = actual.huella.clone();
    let handle_anterior = actual.handle.clone();
    let cuerpo = cuerpo_rotar(
        &actual.secreto_id,
        &huella_anterior,
        &nuevo_handle,
        epoca,
        &rol,
    );
    let digest = digest_rotar(&cuerpo);
    let objeto_canonico = format!(
        "SAK-CUS-ROTAR-v1|{}|{}|{}|epoca={}|rol={}",
        actual.secreto_id, huella_anterior, nuevo_handle, epoca, rol
    );

    let firma_hex = campo_str_raw(raw, "firma_operador_hex").unwrap_or_default();
    let pk_hex = campo_str_raw(raw, "pk_operador_hex").unwrap_or_default();
    if firma_hex.is_empty() || pk_hex.is_empty() {
        return RespuestaOps::deny(req_id, "SIN_FIRMA", "firma de operador ausente");
    }
    let firma = match hex_decode(&firma_hex) {
        Ok(f) => f,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let pk = match hex_decode(&pk_hex) {
        Ok(p) => p,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    if ParMlDsa87::verificar(&pk, &cuerpo, &firma).is_err() {
        return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "firma operador no verifica");
    }

    let nueva_huella = huella_de(&actual.alias, &actual.clase_ef, &nuevo_handle);
    let mut actualizado = actual;
    actualizado.historial.push(HistRotacion {
        huella: huella_anterior.clone(),
        handle: handle_anterior.clone(),
        epoca,
    });
    actualizado.handle = nuevo_handle.clone();
    actualizado.huella = nueva_huella.clone();
    actualizado.estado = "rotado".into();
    actualizado.n_rotaciones = actualizado.n_rotaciones.saturating_add(1);
    actualizado.operador_id = identidad.clone();

    if let Err(e) = estado.guardar_ref(&actualizado) {
        return RespuestaOps::deny(req_id, "ALMACEN", &e);
    }

    let hist_json: String = actualizado
        .historial
        .iter()
        .map(|h| {
            format!(
                r#"{{"huella":"{}","handle":"{}","epoca":{}}}"#,
                esc(&h.huella),
                esc(&h.handle),
                h.epoca
            )
        })
        .collect::<Vec<_>>()
        .join(",");

    RespuestaOps::ok(
        req_id,
        "ROTAR_OK",
        &format!(
            r#"{{"secreto_id":"{}","alias":"{}","estado":"rotado","n_rotaciones":{},"huella_anterior":"{}","handle_anterior":"{}","huella":"{}","handle":"{}","historial":[{}],"material":null,"anti_engano":{{"objeto_canonico":"{}","digest":"{}","identidad":"{}","rol":"{}","consecuencias":"{}","epoca":"{}","confirmacion_independiente":true}},"nota":"rotacion sin bytes; historial conservado"}}"#,
            esc(&actualizado.secreto_id),
            esc(&actualizado.alias),
            actualizado.n_rotaciones,
            esc(&huella_anterior),
            esc(&handle_anterior),
            esc(&nueva_huella),
            esc(&nuevo_handle),
            hist_json,
            esc(&objeto_canonico),
            digest,
            esc(&identidad),
            esc(&rol),
            esc(CONSECUENCIAS_ROTAR),
            epoca
        ),
        vec!["no_comprobado", LIMITE, "IRREVERSIBLE"],
    )
}

fn estado_vista(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let tiene_raiz = estado.broker.tiene_raiz_encapsulada();
    let id = campo_str_raw(raw, "secreto_id");
    let alias = campo_str_raw(raw, "alias");

    if id.is_none() && alias.is_none() {
        let mut items = Vec::new();
        for r in estado.refs.values() {
            items.push(format!(
                r#"{{"secreto_id":"{}","alias":"{}","clase_ef":"{}","huella":"{}","estado":"{}","n_rotaciones":{},"ttl_derivadas_secs":{}}}"#,
                esc(&r.secreto_id),
                esc(&r.alias),
                esc(&r.clase_ef),
                esc(&r.huella),
                esc(&r.estado),
                r.n_rotaciones,
                r.ttl_derivadas_secs
            ));
        }
        return RespuestaOps::ok(
            req_id,
            "CUS_ESTADO",
            &format!(
                r#"{{"tiene_raiz_encapsulada":{},"n_referencias":{},"referencias":[{}],"material":null,"nota":"metadatos; sin bytes de clave"}}"#,
                tiene_raiz,
                estado.refs.len(),
                items.join(",")
            ),
            vec!["no_comprobado", LIMITE],
        );
    }

    let r = if let Some(i) = id {
        estado.refs.get(&i)
    } else if let Some(a) = alias {
        estado.ref_por_alias(&a)
    } else {
        None
    };

    match r {
        Some(r) => {
            let hist: String = r
                .historial
                .iter()
                .map(|h| {
                    format!(
                        r#"{{"huella":"{}","handle":"{}","epoca":{}}}"#,
                        esc(&h.huella),
                        esc(&h.handle),
                        h.epoca
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            RespuestaOps::ok(
                req_id,
                "CUS_ESTADO",
                &format!(
                    r#"{{"secreto_id":"{}","alias":"{}","clase_ef":"{}","handle":"{}","huella":"{}","estado":"{}","ttl_derivadas_secs":{},"n_rotaciones":{},"historial":[{}],"tiene_raiz_encapsulada":{},"rotado":{},"material":null}}"#,
                    esc(&r.secreto_id),
                    esc(&r.alias),
                    esc(&r.clase_ef),
                    esc(&r.handle),
                    esc(&r.huella),
                    esc(&r.estado),
                    r.ttl_derivadas_secs,
                    r.n_rotaciones,
                    hist,
                    tiene_raiz,
                    r.estado == "rotado" || r.n_rotaciones > 0
                ),
                vec!["no_comprobado", LIMITE],
            )
        }
        None => RespuestaOps::deny(req_id, "NO_ENCONTRADO", "referencia inexistente"),
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
