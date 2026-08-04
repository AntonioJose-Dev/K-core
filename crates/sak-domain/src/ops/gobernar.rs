//! Handlers Gobernar: G.5 completo hasta revocar/revertir (Fase 5.4).
//! Sin certificar conformidad automáticamente; sin borrar historial.

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::{self, dominio, ParMlDsa87};
use sak_core::decision::{HashPaqueteNormativo, Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::gobernanza::{
    entrar_en_sombra, exigir_diff_reconocido, resultado_diff, verificar_doble_firma,
    AprobacionInterpretacion, EntradaCita, EstadoPropuesta, EtiquetaGob, FirmaPaquete,
    FirmanteGobernanza, PropuestaNormativa, ReconocimientoCambio, RolFirmante, ESQUEMA_REQUERIDO,
    VENTANA_SOMBRA_MS,
};
use sak_core::norma::{
    Alcance, BorradorNorma, Fecha, Interpretacion, Naturaleza, Norma, Operacionalidad,
    PaqueteNormativo, Vigencia,
};
use sak_core::perfil::Rango;
use sak_core::predicado::Predicado;
use sak_core::supervision::IdHumano;

use super::estado::{hex_decode, hex_encode, EstadoOps};
use super::schema::{campo_bool_raw, campo_str_raw, campo_u32_raw, RespuestaOps};

const LIMITE: &str =
    "Gobernar: registra firmas/diff/sombra/activación/revocación; NO certifica conformidad; NO borra historia";
const LIMITE_SOMBRA: &str =
    "sombra 7d: evalúa sin aplicar en vivo; NO activa; NO aplica como vivo; NO certifica conformidad";
const LIMITE_ACTIVAR: &str =
    "IRREVERSIBLE: activa en límite de época tras sombra completa; NO certifica conformidad; NO revoca";
const LIMITE_REVOCAR: &str =
    "IRREVERSIBLE: revoca activo vivo; NO borra historia ni invalida decisiones pasadas; NO certifica conformidad";
const LIMITE_REVERTIR: &str =
    "IRREVERSIBLE: prepara reactivación gobernada (FIRMADA→sombra→activar); conserva firmas/diff/historial; NO salta trazabilidad";
const CONSECUENCIAS_SOMBRA: &str =
    "NO activa época. NO aplica como vivo. NO certifica conformidad. Abre ventana de sombra de 7 días: evalúa sin ALLOW reales.";
const CONSECUENCIAS_ACTIVAR: &str =
    "IRREVERSIBLE: avanza época y marca el paquete como activo vivo; conserva historial y paquete anterior; NO certifica conformidad; NO revoca.";
const CONSECUENCIAS_REVOCAR: &str =
    "IRREVERSIBLE: deja de ser activo vivo e invalida caps bajo su hash; NO borra historial, expediente, firmas ni diff; NO invalida decisiones pasadas; NO certifica conformidad.";
const CONSECUENCIAS_REVERTIR: &str =
    "IRREVERSIBLE: reabre ciclo en FIRMADA para el hash histórico; exige sombra+activar de nuevo; conserva expediente/firmas/diff; NO borra ni salta trazabilidad; NO certifica conformidad.";

fn deny_secreto(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    let lower = raw.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "begin private",
        "private_key",
        "secret_key",
        "\"seed\"",
        "\"pem\"",
        "api_key",
        "-----begin",
    ];
    if BAD.iter().any(|b| lower.contains(b)) {
        return Some(RespuestaOps::deny(
            req_id,
            "SECRETO_PROHIBIDO",
            "payload contiene patrón de secreto",
        ));
    }
    None
}

fn deny_borrar_o_saltar(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    let lower = raw.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "borrar_historia",
        "borrar_historial",
        "eliminar_historial",
        "\"borrar\":true",
        "saltar_sombra",
        "saltar_firma",
        "saltar_diff",
        "saltar_trazabilidad",
        "activar_inmediato",
        "sin_sombra",
        "forzar_activacion",
        "wipe_history",
        "truncate_historial",
    ];
    if BAD.iter().any(|b| lower.contains(b)) {
        return Some(RespuestaOps::deny(
            req_id,
            "TRAZA_INMUTABLE",
            "prohibido borrar historia o saltar trazabilidad (sombra/firmas/diff)",
        ));
    }
    None
}

fn deny_activar_o_cap(req_id: &str, op: &str, raw: &str) -> Option<RespuestaOps> {
    let sneak_sombra = op != "gob.entrar_sombra"
        && (campo_bool_raw(raw, "entrar_sombra").unwrap_or(false)
            || raw.contains("\"entrar_sombra\":true"));
    let sneak_activar = op != "gob.activar_epoca"
        && (campo_bool_raw(raw, "activar_epoca").unwrap_or(false)
            || raw.contains("\"activar\":true"));
    if sneak_activar
        || sneak_sombra
        || campo_bool_raw(raw, "emitir_capacidad").unwrap_or(false)
        || raw.contains("\"certificar_conformidad\":true")
        || (op != "gob.activar_epoca"
            && campo_bool_raw(raw, "aplica_como_vivo").unwrap_or(false))
    {
        return Some(RespuestaOps::deny(
            req_id,
            "FUERA_MVP",
            "activación/vivo prematuro/capacidades/certificación auto fuera de contexto",
        ));
    }
    None
}

fn ahora_ms(raw: &str) -> u64 {
    campo_str_raw(raw, "ahora_ms")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        })
}

fn cuerpo_canonico_sombra(hash_hex: &str) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"SAK-GOB-SOMBRA-v1");
    v.push(0);
    v.extend_from_slice(hash_hex.as_bytes());
    v.push(0);
    v.extend_from_slice(format!("{VENTANA_SOMBRA_MS}").as_bytes());
    v
}

fn digest_sombra(hash_hex: &str) -> String {
    hex_encode(&crypto::sha384_dominio(
        dominio::GOBERNANZA,
        &cuerpo_canonico_sombra(hash_hex),
    ))
}

fn cuerpo_canonico_activar(hash_hex: &str, epoca_vista: u64, rol: &str) -> Vec<u8> {
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

fn digest_activar(hash_hex: &str, epoca_vista: u64, rol: &str) -> String {
    hex_encode(&crypto::sha384_dominio(
        dominio::GOBERNANZA,
        &cuerpo_canonico_activar(hash_hex, epoca_vista, rol),
    ))
}

fn digest_bytes_op(op_tag: &[u8], hash_hex: &str) -> [u8; LONGITUD_HASH_PAQUETE] {
    let mut v = Vec::new();
    v.extend_from_slice(op_tag);
    v.push(0);
    v.extend_from_slice(hash_hex.as_bytes());
    crypto::sha384_dominio(dominio::GOBERNANZA, &v)
}

fn parse_doble_firma_payload(
    estado: &mut EstadoOps,
    raw: &str,
    mensaje: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<Vec<FirmaPaquete>, RespuestaOps> {
    let req_id = campo_str_raw(raw, "req_id").unwrap_or_else(|| "sin-id".into());
    let mut firmas = Vec::new();
    for (rol, pref) in [
        (RolFirmante::Juridico, "juridico"),
        (RolFirmante::Tecnico, "tecnico"),
    ] {
        let id_s = campo_str_raw(raw, &format!("id_{pref}"))
            .or_else(|| campo_str_raw(raw, &format!("{pref}_id")));
        let firma_hx = campo_str_raw(raw, &format!("firma_{pref}_hex"));
        let pk_hx = campo_str_raw(raw, &format!("pk_{pref}_hex"));
        let (Some(id_s), Some(fh), Some(ph)) = (id_s, firma_hx, pk_hx) else {
            return Err(RespuestaOps::deny(
                &req_id,
                "SIN_FIRMA",
                &format!("faltan campos {pref} (id/firma/pk) — umbral 2-de-N"),
            ));
        };
        let id = IdHumano::nuevo(id_s).map_err(|e| RespuestaOps::deny(&req_id, "SCHEMA", e))?;
        let firma = hex_decode(&fh).map_err(|e| RespuestaOps::deny(&req_id, "FIRMA_INVALIDA", &e))?;
        let pk = hex_decode(&ph).map_err(|e| RespuestaOps::deny(&req_id, "FIRMA_INVALIDA", &e))?;
        let _ = estado.firmantes.registrar(FirmanteGobernanza {
            id: id.clone(),
            rol,
            pk_mldsa: pk,
            etiqueta: EtiquetaGob::Gob,
        });
        firmas.push(FirmaPaquete {
            id,
            rol_declarado: rol,
            firma_mldsa: firma,
        });
    }
    if firmas[0].id == firmas[1].id {
        return Err(RespuestaOps::deny(
            &req_id,
            "MISMO_ROL",
            "ids juridico y tecnico deben ser distintas",
        ));
    }
    if let Err(e) = verificar_doble_firma(mensaje, &firmas, &estado.firmantes) {
        return Err(RespuestaOps::deny(
            &req_id,
            "FIRMA_INVALIDA",
            &format!("{e}"),
        ));
    }
    Ok(firmas)
}

fn exigir_anti_engano_irreversible(
    req_id: &str,
    raw: &str,
) -> Result<(String, String, String), RespuestaOps> {
    if !campo_bool_raw(raw, "confirmacion_independiente").unwrap_or(false) {
        return Err(RespuestaOps::deny(
            req_id,
            "SIN_CONFIRMACION",
            "exige confirmacion_independiente",
        ));
    }
    let identidad = match campo_str_raw(raw, "identidad").or_else(|| campo_str_raw(raw, "operador_id"))
    {
        Some(i) if !i.trim().is_empty() => i,
        _ => {
            return Err(RespuestaOps::deny(req_id, "SCHEMA", "falta identidad"));
        }
    };
    let rol = match campo_str_raw(raw, "rol") {
        Some(r) if !r.trim().is_empty() => r,
        _ => return Err(RespuestaOps::deny(req_id, "SCHEMA", "falta rol")),
    };
    let epoca = match campo_str_raw(raw, "epoca_vista")
        .or_else(|| campo_u32_raw(raw, "epoca_vista").map(|u| u.to_string()))
    {
        Some(e) => e,
        None => return Err(RespuestaOps::deny(req_id, "SCHEMA", "falta epoca_vista")),
    };
    Ok((identidad, rol, epoca))
}

fn parse_hash(raw: &str) -> Result<HashPaqueteNormativo, String> {
    let hx = campo_str_raw(raw, "hash_paquete")
        .or_else(|| campo_str_raw(raw, "hash"))
        .ok_or_else(|| "falta hash_paquete".to_string())?;
    let b = hex_decode(&hx)?;
    if b.len() != LONGITUD_HASH_PAQUETE {
        return Err("hash_paquete longitud invalida".into());
    }
    let mut arr = [0u8; LONGITUD_HASH_PAQUETE];
    arr.copy_from_slice(&b);
    Ok(HashPaqueteNormativo::desde_bytes(arr))
}

fn alcance_demo() -> Alcance {
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

pub fn manejar(estado: &mut EstadoOps, op: &str, req_id: &str, raw: &str) -> RespuestaOps {
    if let Some(d) = deny_secreto(req_id, raw) {
        return d;
    }
    if let Some(d) = deny_borrar_o_saltar(req_id, raw) {
        return d;
    }
    if let Some(d) = deny_activar_o_cap(req_id, op, raw) {
        return d;
    }
    match op {
        "gob.proponer" => proponer(estado, req_id, raw),
        "gob.revision_juridica" => revision_juridica(estado, req_id, raw),
        "gob.diff_conformidad" => diff_conformidad(estado, req_id, raw),
        "gob.reconocer_diff" => reconocer_diff(estado, req_id, raw),
        "gob.doble_firma" => doble_firma(estado, req_id, raw),
        "gob.entrar_sombra" => entrar_sombra(estado, req_id, raw),
        "gob.estado_sombra" => estado_sombra(estado, req_id, raw),
        "gob.activar_epoca" => activar_epoca(estado, req_id, raw),
        "gob.revocar" => revocar(estado, req_id, raw),
        "gob.revertir" => revertir(estado, req_id, raw),
        _ => RespuestaOps::deny(req_id, "OP_DESCONOCIDA", "op Gobernar no manejada"),
    }
}

fn proponer(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    // DENY L1 / materias reservadas / EF-12
    if let Some(op) = campo_str_raw(raw, "operacionalidad") {
        if op.eq_ignore_ascii_case("L1") {
            return RespuestaOps::deny(
                req_id,
                "L1_RESERVADO",
                "materias L1 / reservadas no codificables vía MVP proponer",
            );
        }
    }
    if let Some(c) = campo_str_raw(raw, "clase_ef").or_else(|| campo_str_raw(raw, "clase")) {
        if c.contains("12") || c.eq_ignore_ascii_case("EF-12") {
            return RespuestaOps::deny(req_id, "EF12_IA", "EF-12 no emitible a IA");
        }
    }

    let identificador = match campo_str_raw(raw, "identificador").or_else(|| campo_str_raw(raw, "id_norma"))
    {
        Some(i) if !i.trim().is_empty() => i,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta identificador"),
    };
    let fuente = campo_str_raw(raw, "fuente").unwrap_or_else(|| "instrumento-mvp-art-1".into());
    let interpretacion = campo_str_raw(raw, "interpretacion")
        .unwrap_or_else(|| "interpretacion operativa borrador MVP".into());
    let autor = campo_str_raw(raw, "autor_interpretacion").unwrap_or_else(|| "revisor".into());
    let veredicto = match campo_str_raw(raw, "veredicto")
        .unwrap_or_else(|| "ALLOW".into())
        .to_ascii_uppercase()
        .as_str()
    {
        "ALLOW" => Veredicto::Allow,
        "DENY" => Veredicto::Deny,
        "SUSPEND" => Veredicto::Suspend,
        "ESCALATE" => Veredicto::Escalate,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "veredicto invalido"),
    };

    // Aprobación de interpretación (VAL-EXT/GOB): firma humana; Kernel no certifica calidad.
    let dig_hex = campo_str_raw(raw, "digest_aprobacion_hex");
    let firma_ap = campo_str_raw(raw, "firma_aprobacion_hex");
    let pk_ap = campo_str_raw(raw, "pk_aprobacion_hex");
    let id_ap = campo_str_raw(raw, "id_aprobador").unwrap_or_else(|| "aprob-interp".into());
    let dig = if let Some(hx) = dig_hex {
        let b = match hex_decode(&hx) {
            Ok(b) if b.len() == LONGITUD_HASH_PAQUETE => {
                let mut a = [0u8; LONGITUD_HASH_PAQUETE];
                a.copy_from_slice(&b);
                a
            }
            _ => {
                return RespuestaOps::deny(req_id, "SCHEMA", "digest_aprobacion_hex invalido");
            }
        };
        b
    } else {
        crypto::sha384_dominio(dominio::GOBERNANZA, interpretacion.as_bytes())
    };

    match (firma_ap, pk_ap) {
        (Some(fh), Some(ph)) => {
            let firma = match hex_decode(&fh) {
                Ok(f) => f,
                Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
            };
            let pk = match hex_decode(&ph) {
                Ok(p) => p,
                Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
            };
            let id = match IdHumano::nuevo(id_ap) {
                Ok(i) => i,
                Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", e),
            };
            let mut msg = Vec::new();
            msg.extend_from_slice(b"interp-aprob|");
            msg.extend_from_slice(&dig);
            if ParMlDsa87::verificar(&pk, &msg, &firma).is_err() {
                return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "aprobacion interpretacion");
            }
            let aprob = AprobacionInterpretacion {
                id_aprobador: id,
                digest: dig,
                firma_mldsa: firma,
                pk_aprobador: pk,
                etiqueta: EtiquetaGob::ValExt,
            };
            if let Err(e) = estado.aprobaciones.registrar(aprob) {
                return RespuestaOps::deny(req_id, "APROBACION", &format!("{e}"));
            }
        }
        _ => {
            return RespuestaOps::deny(
                req_id,
                "SIN_FIRMA",
                "falta firma_aprobacion_hex / pk_aprobacion_hex",
            );
        }
    }

    let _ = estado.citas.registrar(EntradaCita {
        fuente: fuente.clone(),
        digest_cita: crypto::sha384_dominio(dominio::GOBERNANZA, fuente.as_bytes()),
        etiqueta: EtiquetaGob::Gob,
    });

    let borrador = BorradorNorma {
        identificador: identificador.clone(),
        fuente: fuente.clone(),
        jurisdiccion: campo_str_raw(raw, "jurisdiccion").unwrap_or_else(|| "EU".into()),
        vigencia: Vigencia {
            entrada: Fecha::nueva(2020, 1, 1).unwrap(),
            termino: None,
        },
        alcance: alcance_demo(),
        naturaleza: Naturaleza::Condicion,
        operacionalidad: Operacionalidad::L2,
        clase_de_efecto: ClaseEfecto::Ef1,
        predicado: Predicado::Fijo(veredicto),
        evidencia_exigida: vec![],
        acciones_obligatorias: vec!["registrar".into()],
        condiciones_de_denegacion: vec!["fuera-alcance".into()],
        escalado: None,
        monitorizacion: None,
        interpretacion: Interpretacion {
            texto: interpretacion.clone(),
            autor,
            digest_aprobacion: dig,
        },
        ambigua: false,
        rango: Rango::P2,
        pretende_resolver: vec![],
    };
    let norma = match Norma::cargar(borrador) {
        Ok(n) => n,
        Err(e) => return RespuestaOps::deny(req_id, "NORMA", &format!("{e}")),
    };
    let paquete = match PaqueteNormativo::cargar(vec![norma]) {
        Ok(p) => p,
        Err(e) => return RespuestaOps::deny(req_id, "PAQUETE", &format!("{e}")),
    };
    let hash = *paquete.hash();

    // Firma del proponente sobre hash del borrador (IPC).
    let firma_prop = campo_str_raw(raw, "firma_proponente_hex").unwrap_or_default();
    let pk_prop = campo_str_raw(raw, "pk_proponente_hex").unwrap_or_default();
    if firma_prop.is_empty() || pk_prop.is_empty() {
        return RespuestaOps::deny(req_id, "SIN_FIRMA", "firma de proponente ausente");
    }
    let firma = match hex_decode(&firma_prop) {
        Ok(f) => f,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let pk = match hex_decode(&pk_prop) {
        Ok(p) => p,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    if ParMlDsa87::verificar(&pk, hash.bytes(), &firma).is_err() {
        return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "firma proponente no verifica");
    }

    let prop = PropuestaNormativa::nueva_borrador(paquete);
    let _ = ESQUEMA_REQUERIDO;
    let h = estado.gob.proponer(prop);
    let hx = hex_encode(h.bytes());

    RespuestaOps::ok(
        req_id,
        "PROPUESTA_OK",
        &format!(
            r#"{{"hash_paquete":"{hx}","estado":"BORRADOR","identificador":"{}","fuente":"{}","esquema":{},"activo_cambiado":false,"epoca_activada":false,"conformidad_certificada":false,"vista_canonica":{{"hash_paquete":"{hx}","identificador":"{}","fuente":"{}"}}}}"#,
            esc(&identificador),
            esc(&fuente),
            ESQUEMA_REQUERIDO,
            esc(&identificador),
            esc(&fuente)
        ),
        vec!["no_comprobado", "GOB", LIMITE],
    )
}

fn revision_juridica(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    let revisor = match campo_str_raw(raw, "revisor_id").or_else(|| campo_str_raw(raw, "revisor")) {
        Some(r) => match IdHumano::nuevo(r) {
            Ok(i) => i,
            Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", e),
        },
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta revisor_id"),
    };
    let competencia = campo_bool_raw(raw, "competencia_registrada").unwrap_or(false);
    let mut prop = PropuestaNormativa::nueva_borrador(ver.paquete.clone());
    if let Err(e) = prop.marcar_revision_juridica(revisor.clone(), competencia) {
        return RespuestaOps::deny(req_id, "SIN_COMPETENCIA", &format!("{e}"));
    }
    let h = estado.gob.proponer(prop);
    RespuestaOps::ok(
        req_id,
        "REVISION_OK",
        &format!(
            r#"{{"hash_paquete":"{}","estado":"REVISADA","revisor_id":"{}","activo_cambiado":false,"epoca_activada":false}}"#,
            hex_encode(h.bytes()),
            esc(revisor.como_str())
        ),
        vec!["no_comprobado", "GOB", LIMITE],
    )
}

fn diff_conformidad(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    let anterior = estado.gob.activo().unwrap_or(&estado.baseline);
    let diff = resultado_diff(&estado.casos_conformidad, anterior, &ver.paquete);
    estado
        .diffs_pendientes
        .insert(*hash.bytes(), diff.clone());

    let mut cambios = Vec::new();
    for c in &diff.cambios {
        cambios.push(format!(
            r#"{{"id_caso":"{}","digest_cambio":"{}","anterior":"{}","nuevo":"{}"}}"#,
            esc(&c.id_caso),
            hex_encode(&c.digest_cambio),
            c.anterior.token(),
            c.nuevo.token()
        ));
    }
    RespuestaOps::ok(
        req_id,
        "DIFF",
        &format!(
            r#"{{"hash_paquete":"{}","n_cambios":{},"cambios":[{}],"reconocido":false,"conformidad_certificada":false,"nota":"diff informativo; no certifica conformidad"}}"#,
            hex_encode(hash.bytes()),
            diff.cambios.len(),
            cambios.join(",")
        ),
        vec!["no_comprobado", "GOB", LIMITE],
    )
}

fn reconocer_diff(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v.clone(),
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    let diff = match estado.diffs_pendientes.get(hash.bytes()) {
        Some(d) => d.clone(),
        None => {
            let anterior = estado.gob.activo().unwrap_or(&estado.baseline);
            resultado_diff(&estado.casos_conformidad, anterior, &ver.paquete)
        }
    };
    if diff.vacio() {
        // Diff vacío: reconocer = registrar vacío → ConformidadOk sin cambios.
        if let Err(e) = estado.gob.registrar_diff(&hash, diff, vec![]) {
            return RespuestaOps::deny(req_id, "DIFF", &format!("{e}"));
        }
        return RespuestaOps::ok(
            req_id,
            "DIFF_RECONOCIDO",
            &format!(
                r#"{{"hash_paquete":"{}","estado":"CONFORMIDAD_OK","n_acks":0,"activo_cambiado":false,"epoca_activada":false,"conformidad_certificada":false,"nota":"diff vacio reconocido; no es certificacion automatica"}}"#,
                hex_encode(hash.bytes())
            ),
            vec!["no_comprobado", "GOB", LIMITE],
        );
    }

    // Reconocimientos: preferir campos planos; si no, array con digest_cambio_hex.
    let mut acks = Vec::new();
    let mut pks = Vec::new();
    for c in &diff.cambios {
        let dig_hx = hex_encode(&c.digest_cambio);
        let (id_s, fh, ph) = match resolver_ack(raw, &dig_hx) {
            Ok(t) => t,
            Err(e) => return RespuestaOps::deny(req_id, "DIFF_NO_RECONOCIDO", &e),
        };
        let firma = match hex_decode(&fh) {
            Ok(f) => f,
            Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
        };
        let pk = match hex_decode(&ph) {
            Ok(p) => p,
            Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
        };
        let id = match IdHumano::nuevo(id_s.clone()) {
            Ok(i) => i,
            Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", e),
        };
        let mut msg = Vec::new();
        msg.extend_from_slice(b"diff-ack|");
        msg.extend_from_slice(&c.digest_cambio);
        if ParMlDsa87::verificar(&pk, &msg, &firma).is_err() {
            return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "reconocimiento invalido");
        }
        estado
            .pks_reconocedores
            .insert(id.como_str().to_string(), pk.clone());
        acks.push(ReconocimientoCambio {
            digest_cambio: c.digest_cambio,
            id_humano: id.clone(),
            firma_mldsa: firma,
        });
        pks.push((id, pk));
    }

    if let Err(e) = exigir_diff_reconocido(&diff, &acks, &pks) {
        return RespuestaOps::deny(req_id, "DIFF_NO_RECONOCIDO", &format!("{e}"));
    }
    if let Err(e) = estado.gob.registrar_diff(&hash, diff, acks.clone()) {
        return RespuestaOps::deny(req_id, "DIFF", &format!("{e}"));
    }
    estado.diffs_pendientes.remove(hash.bytes());

    RespuestaOps::ok(
        req_id,
        "DIFF_RECONOCIDO",
        &format!(
            r#"{{"hash_paquete":"{}","estado":"CONFORMIDAD_OK","n_acks":{},"activo_cambiado":false,"epoca_activada":false,"conformidad_certificada":false,"nota":"reconocimiento humano; Kernel no certifica conformidad"}}"#,
            hex_encode(hash.bytes()),
            acks.len()
        ),
        vec!["no_comprobado", "GOB", LIMITE],
    )
}

/// Resuelve id/firma/pk de un reconocimiento (campos planos o tras el digest en array).
fn resolver_ack(raw: &str, digest_hex: &str) -> Result<(String, String, String), String> {
    if let (Some(fh), Some(ph)) = (
        campo_str_raw(raw, "firma_reconocimiento_hex"),
        campo_str_raw(raw, "pk_reconocimiento_hex"),
    ) {
        let id = campo_str_raw(raw, "id_reconocedor").unwrap_or_else(|| "ack-humano".into());
        return Ok((id, fh, ph));
    }
    let i = raw
        .find(digest_hex)
        .ok_or_else(|| format!("falta reconocimiento firmado para {digest_hex}"))?;
    let rest = &raw[i..];
    let fh = campo_str_despues(rest, "firma_hex")
        .ok_or_else(|| format!("falta firma_hex para {digest_hex}"))?;
    let ph = campo_str_despues(rest, "pk_hex")
        .ok_or_else(|| format!("falta pk_hex para {digest_hex}"))?;
    let id = campo_str_despues(rest, "id_humano").unwrap_or_else(|| "ack-humano".into());
    Ok((id, fh, ph))
}

fn campo_str_despues(raw: &str, clave: &str) -> Option<String> {
    let pat = format!("\"{clave}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let colon = rest.find(':')?;
    let mut s = rest[colon + 1..].trim_start();
    if !s.starts_with('"') {
        return None;
    }
    s = &s[1..];
    let end = s.find('"')?;
    Some(s[..end].to_string())
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn doble_firma(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    if !matches!(
        ver.estado,
        EstadoPropuesta::ConformidadOk | EstadoPropuesta::Firmada
    ) {
        return RespuestaOps::deny(
            req_id,
            "ESTADO",
            "doble firma requiere diff reconocido (CONFORMIDAD_OK); no activa época",
        );
    }

    let msg = ver.paquete.mensaje_firma();
    let mut firmas = Vec::new();

    for (rol, pref) in [
        (RolFirmante::Juridico, "juridico"),
        (RolFirmante::Tecnico, "tecnico"),
    ] {
        let id_s = campo_str_raw(raw, &format!("id_{pref}"))
            .or_else(|| campo_str_raw(raw, &format!("{pref}_id")));
        let firma_hx = campo_str_raw(raw, &format!("firma_{pref}_hex"));
        let pk_hx = campo_str_raw(raw, &format!("pk_{pref}_hex"));
        let (Some(id_s), Some(fh), Some(ph)) = (id_s, firma_hx, pk_hx) else {
            return RespuestaOps::deny(
                req_id,
                "SIN_FIRMA",
                &format!("faltan campos {pref} (id/firma/pk)"),
            );
        };
        let id = match IdHumano::nuevo(id_s) {
            Ok(i) => i,
            Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", e),
        };
        let firma = match hex_decode(&fh) {
            Ok(f) => f,
            Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
        };
        let pk = match hex_decode(&ph) {
            Ok(p) => p,
            Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
        };
        let _ = estado.firmantes.registrar(FirmanteGobernanza {
            id: id.clone(),
            rol,
            pk_mldsa: pk,
            etiqueta: EtiquetaGob::Gob,
        });
        firmas.push(FirmaPaquete {
            id,
            rol_declarado: rol,
            firma_mldsa: firma,
        });
    }

    if firmas[0].id == firmas[1].id {
        return RespuestaOps::deny(req_id, "MISMO_ROL", "ids juridico y tecnico deben ser distintas");
    }

    if let Err(e) = verificar_doble_firma(&msg, &firmas, &estado.firmantes) {
        return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &format!("{e}"));
    }

    estado.gob.registrar_firmas(&hash, firmas);
    let _ = estado
        .gob
        .transicionar(&hash, EstadoPropuesta::Firmada, 0);

    RespuestaOps::ok(
        req_id,
        "DOBLE_FIRMA_OK",
        &format!(
            r#"{{"hash_paquete":"{}","estado":"FIRMADA","activo_cambiado":false,"epoca_activada":false,"en_sombra":false,"nota":"firmas registradas; NO activa ni entra en sombra"}}"#,
            hex_encode(hash.bytes())
        ),
        vec!["no_comprobado", "GOB", LIMITE],
    )
}

fn entrar_sombra(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let hash_hex = hex_encode(hash.bytes());
    let digest = digest_sombra(&hash_hex);

    if !campo_bool_raw(raw, "confirmacion_independiente").unwrap_or(false) {
        return RespuestaOps::deny(
            req_id,
            "SIN_CONFIRMACION",
            "entrar_sombra exige confirmacion_independiente",
        );
    }
    let identidad = match campo_str_raw(raw, "identidad").or_else(|| campo_str_raw(raw, "operador_id"))
    {
        Some(i) if !i.trim().is_empty() => i,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta identidad"),
    };
    let rol = match campo_str_raw(raw, "rol") {
        Some(r) if !r.trim().is_empty() => r,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta rol"),
    };
    let epoca = match campo_str_raw(raw, "epoca_vista")
        .or_else(|| campo_u32_raw(raw, "epoca_vista").map(|u| u.to_string()))
    {
        Some(e) => e,
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta epoca_vista"),
    };

    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    if !matches!(ver.estado, EstadoPropuesta::Firmada) {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "entrar_sombra exige paquete FIRMADA (revisión + diff reconocido + doble firma); no activa",
        );
    }
    if ver.firmas.len() < 2 {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "faltan firmas jurídico+técnico registradas",
        );
    }
    // Diff reconocido: ConformidadOk previo deja diff y/o reconocimientos en la versión.
    if ver.diff.is_none() {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "diff de conformidad no registrado / no reconocido",
        );
    }

    let firmas = ver.firmas.clone();
    let ahora = ahora_ms(raw);
    if let Err(e) = entrar_en_sombra(&mut estado.gob, &hash, &firmas, &estado.firmantes, ahora) {
        return RespuestaOps::deny(req_id, "SOMBRA", &format!("{e}"));
    }

    let objeto = format!(
        "SAK-GOB-SOMBRA-v1|{}|ventana_ms={}",
        hash_hex, VENTANA_SOMBRA_MS
    );
    RespuestaOps::ok(
        req_id,
        "SOMBRA_OK",
        &format!(
            r#"{{"hash_paquete":"{hash_hex}","estado":"EN_SOMBRA","sombra_desde_ms":{ahora},"ventana_sombra_ms":{VENTANA_SOMBRA_MS},"evalua_sin_aplicar":true,"aplica_como_vivo":false,"epoca_activada":false,"activo_cambiado":false,"conformidad_certificada":false,"no_activa":true,"no_aplica_como_vivo":true,"no_certifica_conformidad":true,"anti_engano":{{"objeto_canonico":"{}","digest":"{digest}","identidad":"{}","rol":"{}","consecuencias":"{}","epoca":"{}","confirmacion_independiente":true}},"nota":"sombra 7d: evalúa sin aplicar en vivo; NO activa; NO aplica como vivo; NO certifica conformidad"}}"#,
            esc(&objeto),
            esc(&identidad),
            esc(&rol),
            esc(CONSECUENCIAS_SOMBRA),
            esc(&epoca),
        ),
        vec!["no_comprobado", "GOB", LIMITE_SOMBRA],
    )
}

fn estado_sombra(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    let hash_hex = hex_encode(hash.bytes());
    let ahora = ahora_ms(raw);
    let (en_sombra, desde, restante) = match &ver.estado {
        EstadoPropuesta::EnSombra { desde } => {
            let elapsed = ahora.saturating_sub(*desde);
            let restante = VENTANA_SOMBRA_MS.saturating_sub(elapsed);
            (true, *desde, restante)
        }
        _ => (false, 0u64, VENTANA_SOMBRA_MS),
    };
    let ventana_completa = en_sombra && restante == 0;
    RespuestaOps::ok(
        req_id,
        "ESTADO_SOMBRA",
        &format!(
            r#"{{"hash_paquete":"{hash_hex}","estado":"{}","en_sombra":{en_sombra},"sombra_desde_ms":{desde},"ventana_sombra_ms":{VENTANA_SOMBRA_MS},"restante_ms":{restante},"ventana_completa":{ventana_completa},"evalua_sin_aplicar":true,"aplica_como_vivo":false,"epoca_activada":false,"activo_cambiado":false,"conformidad_certificada":false,"no_activa":true,"no_aplica_como_vivo":true,"no_certifica_conformidad":true,"nota":"lectura: evalúa sin aplicar en vivo; no es activación"}}"#,
            ver.estado,
        ),
        vec!["no_comprobado", "GOB", "LECTURA", LIMITE_SOMBRA],
    )
}

fn activar_epoca(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let hash_hex = hex_encode(hash.bytes());

    if !campo_bool_raw(raw, "confirmacion_independiente").unwrap_or(false) {
        return RespuestaOps::deny(
            req_id,
            "SIN_CONFIRMACION",
            "activar_epoca exige confirmacion_independiente",
        );
    }
    if !campo_bool_raw(raw, "en_limite_epoca").unwrap_or(false) {
        return RespuestaOps::deny(
            req_id,
            "FUERA_LIMITE_EPOCA",
            "activación solo en límite de época (en_limite_epoca=true)",
        );
    }

    let identidad = match campo_str_raw(raw, "identidad").or_else(|| campo_str_raw(raw, "operador_id"))
    {
        Some(i) if !i.trim().is_empty() => i,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta identidad"),
    };
    let rol = match campo_str_raw(raw, "rol") {
        Some(r) if !r.trim().is_empty() => r,
        _ => return RespuestaOps::deny(req_id, "SCHEMA", "falta rol"),
    };
    let epoca_vista = match campo_u32_raw(raw, "epoca_vista").or_else(|| {
        campo_str_raw(raw, "epoca_vista").and_then(|s| s.parse().ok())
    }) {
        Some(e) => e as u64,
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta epoca_vista"),
    };

    let firma_hx = match campo_str_raw(raw, "firma_operador_hex") {
        Some(f) if !f.is_empty() => f,
        _ => {
            return RespuestaOps::deny(
                req_id,
                "SIN_FIRMA",
                "activar_epoca exige firma_operador_hex sobre objeto canónico",
            )
        }
    };
    let pk_hx = match campo_str_raw(raw, "pk_operador_hex") {
        Some(p) if !p.is_empty() => p,
        _ => return RespuestaOps::deny(req_id, "SIN_FIRMA", "falta pk_operador_hex"),
    };
    let firma = match hex_decode(&firma_hx) {
        Ok(f) => f,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let pk = match hex_decode(&pk_hx) {
        Ok(p) => p,
        Err(e) => return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", &e),
    };
    let cuerpo = cuerpo_canonico_activar(&hash_hex, epoca_vista, &rol);
    if ParMlDsa87::verificar(&pk, &cuerpo, &firma).is_err() {
        return RespuestaOps::deny(
            req_id,
            "FIRMA_INVALIDA",
            "firma no verifica objeto canónico de activación",
        );
    }
    let digest = digest_activar(&hash_hex, epoca_vista, &rol);

    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    match &ver.estado {
        EstadoPropuesta::EnSombra { desde } => {
            let ahora = ahora_ms(raw);
            let elapsed = ahora.saturating_sub(*desde);
            if elapsed < VENTANA_SOMBRA_MS {
                return RespuestaOps::deny(
                    req_id,
                    "SOMBRA_INCOMPLETA",
                    &format!(
                        "ventana sombra incompleta; faltan {} ms",
                        VENTANA_SOMBRA_MS - elapsed
                    ),
                );
            }
        }
        _ => {
            return RespuestaOps::deny(
                req_id,
                "NO_EN_SOMBRA",
                "activar_epoca exige estado EN_SOMBRA (revisión→diff→doble firma→sombra)",
            );
        }
    }
    // Cadena previa intacta (rastro en versión).
    if ver.diff.is_none() {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "diff de conformidad no registrado / no reconocido",
        );
    }
    if ver.firmas.len() < 2 {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "faltan firmas jurídico+técnico de la cadena previa",
        );
    }

    let hash_anterior = estado
        .gob
        .hash_activo()
        .map(|h| hex_encode(h.bytes()))
        .unwrap_or_default();
    let n_hist_antes = estado.gob.historial().len();
    let ahora = ahora_ms(raw);

    let epoca_nueva = match estado.activar_paquete_en_limite(&hash, ahora, true) {
        Ok(e) => e,
        Err(e) => {
            let lower = e.to_ascii_lowercase();
            let codigo = if lower.contains("limite") {
                "FUERA_LIMITE_EPOCA"
            } else if lower.contains("sombra incompleta") {
                "SOMBRA_INCOMPLETA"
            } else if lower.contains("no esta en sombra") {
                "NO_EN_SOMBRA"
            } else {
                "ACTIVACION"
            };
            return RespuestaOps::deny(req_id, codigo, &e);
        }
    };

    let objeto = format!(
        "SAK-GOB-ACTIVAR-v1|{}|epoca_vista={}|rol={}",
        hash_hex, epoca_vista, rol
    );
    let hist_n = estado.gob.historial().len();
    let hash_ant_json = if hash_anterior.is_empty() {
        "null".into()
    } else {
        format!("\"{}\"", esc(&hash_anterior))
    };

    RespuestaOps::ok(
        req_id,
        "EPOCA_ACTIVADA",
        &format!(
            r#"{{"hash_paquete":"{hash_hex}","estado":"ACTIVA","epoca":{epoca_nueva},"epoca_vista":{epoca_vista},"epoca_activada":true,"activo_cambiado":true,"aplica_como_vivo":true,"conformidad_certificada":false,"hash_anterior":{hash_ant_json},"n_historial_antes":{n_hist_antes},"n_historial":{hist_n},"historial_conservado":true,"anti_engano":{{"objeto_canonico":"{}","digest":"{digest}","identidad":"{}","rol":"{}","consecuencias":"{}","epoca":"{epoca_vista}","confirmacion_independiente":true}},"nota":"activación en límite de época; historial y paquete anterior conservados; Kernel no certifica conformidad"}}"#,
            esc(&objeto),
            esc(&identidad),
            esc(&rol),
            esc(CONSECUENCIAS_ACTIVAR),
        ),
        vec!["no_comprobado", "GOB", "IRREVERSIBLE", LIMITE_ACTIVAR],
    )
}

fn revocar(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let hash_hex = hex_encode(hash.bytes());
    let (identidad, rol, epoca) = match exigir_anti_engano_irreversible(req_id, raw) {
        Ok(t) => t,
        Err(d) => return d,
    };

    let dig = digest_bytes_op(b"SAK-GOB-REVOCAR-v1", &hash_hex);
    let digest = hex_encode(&dig);
    if let Err(d) = parse_doble_firma_payload(estado, raw, &dig) {
        return d;
    }

    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    if !matches!(ver.estado, EstadoPropuesta::Activa { .. }) {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "revocar exige paquete ACTIVA",
        );
    }
    let n_firmas = ver.firmas.len();
    let tiene_diff = ver.diff.is_some();
    let n_hist_antes = estado.gob.historial().len();
    let ahora = ahora_ms(raw);

    let n_caps = match estado.revocar_paquete_activo(&hash, ahora) {
        Ok(n) => n,
        Err(e) => return RespuestaOps::deny(req_id, "REVOCACION", &e),
    };

    // Conservación: versión sigue, historial intacto, firmas/diff intactos.
    let ver_post = estado.gob.propuesta(&hash).unwrap();
    let firmas_ok = ver_post.firmas.len() == n_firmas && n_firmas >= 2;
    let diff_ok = ver_post.diff.is_some() == tiene_diff && tiene_diff;
    let hist_ok = estado.gob.historial().len() == n_hist_antes
        && estado
            .gob
            .historial()
            .iter()
            .any(|(h, _)| h.bytes() == hash.bytes());

    let objeto = format!("SAK-GOB-REVOCAR-v1|{hash_hex}");
    RespuestaOps::ok(
        req_id,
        "REVOCADO",
        &format!(
            r#"{{"hash_paquete":"{hash_hex}","estado":"REVOCADA","activo_cambiado":true,"epoca_activada":false,"aplica_como_vivo":false,"conformidad_certificada":false,"caps_invalidas":{n_caps},"historial_conservado":{hist_ok},"firmas_conservadas":{firmas_ok},"diff_conservado":{diff_ok},"decisiones_pasadas_intactas":true,"n_historial":{},"anti_engano":{{"objeto_canonico":"{}","digest":"{digest}","identidad":"{}","rol":"{}","consecuencias":"{}","epoca":"{}","confirmacion_independiente":true}},"nota":"revocado sin borrar historia; decisiones pasadas intactas; Kernel no certifica conformidad"}}"#,
            estado.gob.historial().len(),
            esc(&objeto),
            esc(&identidad),
            esc(&rol),
            esc(CONSECUENCIAS_REVOCAR),
            esc(&epoca),
        ),
        vec!["no_comprobado", "GOB", "IRREVERSIBLE", LIMITE_REVOCAR],
    )
}

fn revertir(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let hash = match parse_hash(raw) {
        Ok(h) => h,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    let hash_hex = hex_encode(hash.bytes());
    let (identidad, rol, epoca) = match exigir_anti_engano_irreversible(req_id, raw) {
        Ok(t) => t,
        Err(d) => return d,
    };

    // Atajos explícitos de activación inmediata / saltar sombra → DENY.
    if campo_bool_raw(raw, "activar_inmediato").unwrap_or(false)
        || campo_bool_raw(raw, "saltar_sombra").unwrap_or(false)
    {
        return RespuestaOps::deny(
            req_id,
            "TRAZA_INMUTABLE",
            "revertir no salta sombra ni activa de inmediato",
        );
    }

    let dig = digest_bytes_op(b"SAK-GOB-REVERTIR-v1", &hash_hex);
    let digest = hex_encode(&dig);
    if let Err(d) = parse_doble_firma_payload(estado, raw, &dig) {
        return d;
    }

    let ver = match estado.gob.propuesta(&hash) {
        Some(v) => v,
        None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "propuesta inexistente"),
    };
    if ver.diff.is_none() || ver.firmas.len() < 2 {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "revertir exige firmas y diff reconocidos conservados en el expediente",
        );
    }
    if !estado
        .gob
        .historial()
        .iter()
        .any(|(h, _)| h.bytes() == hash.bytes())
    {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "hash no figura en historial de activaciones (no hay versión anterior gobernada)",
        );
    }
    if estado.gob.hash_activo().map(|h| h.bytes()) == Some(hash.bytes()) {
        return RespuestaOps::deny(
            req_id,
            "PRECONDICION",
            "paquete aún activo: revocar antes de revertir",
        );
    }

    let n_firmas = ver.firmas.len();
    let dig_diff = ver
        .diff
        .as_ref()
        .and_then(|d| d.cambios.first())
        .map(|c| hex_encode(&c.digest_cambio))
        .unwrap_or_default();
    let n_hist = estado.gob.historial().len();

    if let Err(e) = estado.preparar_reversion(&hash) {
        return RespuestaOps::deny(req_id, "REVERSION", &e);
    }

    let ver_post = estado.gob.propuesta(&hash).unwrap();
    let firmas_ok = ver_post.firmas.len() == n_firmas;
    let diff_ok = ver_post.diff.is_some();
    let hist_ok = estado.gob.historial().len() == n_hist;

    let objeto = format!("SAK-GOB-REVERTIR-v1|{hash_hex}");
    RespuestaOps::ok(
        req_id,
        "REVERSION_PREPARADA",
        &format!(
            r#"{{"hash_paquete":"{hash_hex}","estado":"FIRMADA","epoca_activada":false,"activo_cambiado":false,"aplica_como_vivo":false,"conformidad_certificada":false,"historial_conservado":{hist_ok},"firmas_conservadas":{firmas_ok},"diff_conservado":{diff_ok},"digest_diff_muestra":"{dig_diff}","procedimiento_pendiente":["gob.entrar_sombra","gob.activar_epoca"],"anti_engano":{{"objeto_canonico":"{}","digest":"{digest}","identidad":"{}","rol":"{}","consecuencias":"{}","epoca":"{}","confirmacion_independiente":true}},"nota":"reversión gobernada: exige sombra 7d + activar_epoca; no salta trazabilidad; Kernel no certifica conformidad"}}"#,
            esc(&objeto),
            esc(&identidad),
            esc(&rol),
            esc(CONSECUENCIAS_REVERTIR),
            esc(&epoca),
        ),
        vec!["no_comprobado", "GOB", "IRREVERSIBLE", LIMITE_REVERTIR],
    )
}
