//! Handlers MVP-CONECTAR (Fase 1).

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::{self, dominio};
use sak_core::identidad::{DeclaracionResponsable, IdSistema};
use sak_core::libro::{antigüedad_maxima, InventarioAlcanzables, ProductorHecho, TipoHecho};
use std::collections::BTreeSet;

use super::estado::{hex_decode, hex_encode, id_sistema_ok, AltaSistema, EstadoOps, PepMapa};
use super::schema::{campo_bool_raw, campo_str_raw, campo_u32_raw, RespuestaOps};

const NOTA_ALTA: &str = "registra; no autoriza efectos";
const LIMITE_NO_AUTH: &str = "UI/canal no autoriza efectos; solo Kernel tras cadena H";

fn deny_secreto(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    let lower = raw.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "begin private",
        "private_key",
        "secret_key",
        "\"seed\"",
        "\"pem\"",
        "api_key",
        "apikey",
        "-----begin",
    ];
    if BAD.iter().any(|b| lower.contains(b)) {
        return Some(RespuestaOps::deny(
            req_id,
            "SECRETO_PROHIBIDO",
            "payload contiene patrón de secreto / API key",
        ));
    }
    None
}

fn deny_autorizar_efectos(req_id: &str, raw: &str) -> Option<RespuestaOps> {
    if campo_bool_raw(raw, "autorizar_efectos").unwrap_or(false)
        || campo_bool_raw(raw, "emitir_capacidad").unwrap_or(false)
        || raw.contains("\"autorizar_efectos\":true")
    {
        return Some(RespuestaOps::deny(
            req_id,
            "INTENTO_AUTORIZAR",
            "Conectar registra; no autoriza efectos ni emite capacidades",
        ));
    }
    None
}

fn decl_desde_raw(raw: &str) -> Result<DeclaracionResponsable, String> {
    let sistema = campo_str_raw(raw, "sistema_id").ok_or("falta sistema_id")?;
    if !id_sistema_ok(&sistema) {
        return Err("sistema_id invalido".into());
    }
    let firma_hex = campo_str_raw(raw, "firma_responsable_hex")
        .or_else(|| campo_str_raw(raw, "firma_hex"))
        .unwrap_or_default();
    let pk_hex = campo_str_raw(raw, "pk_responsable_hex")
        .or_else(|| campo_str_raw(raw, "pk_hex"))
        .unwrap_or_default();
    if firma_hex.is_empty() || pk_hex.is_empty() {
        return Err("firma de responsable ausente".into());
    }
    let firma = hex_decode(&firma_hex)?;
    let pk = hex_decode(&pk_hex)?;
    let sid = IdSistema::nuevo(sistema).map_err(|e| e.to_string())?;
    DeclaracionResponsable::reconstruir(
        sid,
        campo_str_raw(raw, "responsable").unwrap_or_default(),
        campo_str_raw(raw, "finalidad").unwrap_or_default(),
        campo_str_raw(raw, "modelos").unwrap_or_default(),
        campo_str_raw(raw, "jurisdiccion").unwrap_or_default(),
        campo_str_raw(raw, "datos").unwrap_or_default(),
        campo_str_raw(raw, "autonomia_por_clase").unwrap_or_default(),
        campo_str_raw(raw, "herramientas").unwrap_or_default(),
        campo_str_raw(raw, "efectores").unwrap_or_default(),
        campo_str_raw(raw, "clasificacion_riesgo").unwrap_or_default(),
        campo_u32_raw(raw, "vigente_desde_dias").unwrap_or(1),
        campo_u32_raw(raw, "vigente_hasta_dias").unwrap_or(999_999),
        firma,
        pk,
    )
    .map_err(|e| e.to_string())
}

pub fn manejar(estado: &mut EstadoOps, op: &str, req_id: &str, raw: &str) -> RespuestaOps {
    if let Some(d) = deny_secreto(req_id, raw) {
        return d;
    }
    if let Some(d) = deny_autorizar_efectos(req_id, raw) {
        return d;
    }
    match op {
        "con.sistema.alta" => alta(estado, req_id, raw),
        "con.pasaporte.emitir" => emitir(estado, req_id, raw),
        "con.pasaporte.get" => get_pasaporte(estado, req_id, raw),
        "con.sistemas.listar" => listar(estado, req_id),
        "con.pep.vista" => pep_vista(estado, req_id),
        "con.pep.configurar" => pep_configurar(estado, req_id, raw),
        "con.inventario.alcanzables" => inventario_alcanzables(estado, req_id, raw),
        _ => RespuestaOps::deny(req_id, "OP_DESCONOCIDA", "op Conectar no manejada"),
    }
}

fn alta(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let decl = match decl_desde_raw(raw) {
        Ok(d) => d,
        Err(e) => {
            let codigo = if e.contains("ausente") {
                "SIN_FIRMA"
            } else if e.contains("invalida") {
                "FIRMA_INVALIDA"
            } else {
                "SCHEMA"
            };
            return RespuestaOps::deny(req_id, codigo, &e);
        }
    };
    let sistema_id = decl.sistema_id().como_str().to_string();
    let pasaporte_id = campo_str_raw(raw, "pasaporte_id").unwrap_or_else(|| sistema_id.clone());
    let digest = hex_encode(&decl.digest_cuerpo());
    let alta = AltaSistema {
        sistema_id: sistema_id.clone(),
        pasaporte_id: pasaporte_id.clone(),
        responsable: decl.responsable().to_string(),
        finalidad: decl.finalidad().to_string(),
        clasificacion_riesgo: decl.clasificacion_riesgo().to_string(),
        digest_decl: digest.clone(),
        nota: NOTA_ALTA,
    };
    if let Err(e) = estado.guardar_alta(&alta) {
        return RespuestaOps::deny(req_id, "ALMACEN", &e);
    }
    RespuestaOps::ok(
        req_id,
        "ALTA_OK",
        &format!(
            r#"{{"sistema_id":"{}","pasaporte_id":"{}","digest_declaracion":"{}","nota":"{}","autoriza_efectos":false}}"#,
            esc(&sistema_id),
            esc(&pasaporte_id),
            digest,
            NOTA_ALTA
        ),
        vec!["no_comprobado", LIMITE_NO_AUTH],
    )
}

fn emitir(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let decl = match decl_desde_raw(raw) {
        Ok(d) => d,
        Err(e) => {
            let codigo = if e.contains("ausente") {
                "SIN_FIRMA"
            } else {
                "FIRMA_INVALIDA"
            };
            return RespuestaOps::deny(req_id, codigo, &e);
        }
    };
    let sistema_id = decl.sistema_id().como_str();
    if !estado.altas.contains_key(sistema_id) {
        return RespuestaOps::deny(
            req_id,
            "SIN_ALTA",
            "requiere con.sistema.alta previo para este sistema_id",
        );
    }
    let pasaporte_id = campo_str_raw(raw, "pasaporte_id")
        .or_else(|| estado.altas.get(sistema_id).map(|a| a.pasaporte_id.clone()))
        .unwrap_or_else(|| sistema_id.to_string());
    let version = campo_u32_raw(raw, "version").unwrap_or(1);
    if version == 0 {
        return RespuestaOps::deny(req_id, "VERSION", "version debe ser >= 1");
    }
    // No reescribir: si existe misma versión → DENY
    if estado.registro.obtener(&pasaporte_id, version).is_some() {
        return RespuestaOps::deny(
            req_id,
            "VERSION_YA_EXISTE",
            "pasaporte existente no se edita; emitir nueva version",
        );
    }
    match estado.emitir_pasaporte(&pasaporte_id, version, &decl) {
        Ok(p) => {
            let dig = hex_encode(&p.digest());
            RespuestaOps::ok(
                req_id,
                "PASAPORTE_EMITIDO",
                &format!(
                    r#"{{"pasaporte_id":"{}","version":{},"sistema_id":"{}","digest":"{}","firma_valida":{},"editable":false,"autoriza_efectos":false}}"#,
                    esc(p.id()),
                    p.version(),
                    esc(p.sistema_id()),
                    dig,
                    p.firma_valida()
                ),
                vec!["no_comprobado", LIMITE_NO_AUTH],
            )
        }
        Err(e) => {
            if e.contains("YaExiste") || e.contains("ya conservado") {
                RespuestaOps::deny(req_id, "VERSION_YA_EXISTE", &e)
            } else {
                RespuestaOps::deny(req_id, "EMITIR", &e)
            }
        }
    }
}

fn get_pasaporte(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let id = match campo_str_raw(raw, "pasaporte_id").or_else(|| campo_str_raw(raw, "id")) {
        Some(i) => i,
        None => return RespuestaOps::deny(req_id, "SCHEMA", "falta pasaporte_id"),
    };
    let version = match campo_u32_raw(raw, "version") {
        Some(v) => v,
        None => match estado.registro.version_activa(&id) {
            Some(v) => v,
            None => return RespuestaOps::deny(req_id, "NO_ENCONTRADO", "pasaporte inexistente"),
        },
    };
    match estado.registro.obtener(&id, version) {
        Some(p) => RespuestaOps::ok(
            req_id,
            "PASAPORTE",
            &format!(
                r#"{{"pasaporte_id":"{}","version":{},"sistema_id":"{}","responsable":"{}","finalidad":"{}","modelos":"{}","jurisdiccion":"{}","datos":"{}","autonomia_por_clase":"{}","herramientas":"{}","efectores":"{}","clasificacion_riesgo":"{}","vigente_desde_dias":{},"vigente_hasta_dias":{},"digest":"{}","firma_valida":{},"editable":false}}"#,
                esc(p.id()),
                p.version(),
                esc(p.sistema_id()),
                esc(p.responsable()),
                esc(p.finalidad()),
                esc(p.modelos()),
                esc(p.jurisdiccion()),
                esc(p.datos()),
                esc(p.autonomia_por_clase()),
                esc(p.herramientas()),
                esc(p.efectores()),
                esc(p.clasificacion_riesgo()),
                p.vigente_desde_dias(),
                p.vigente_hasta_dias(),
                hex_encode(&p.digest()),
                p.firma_valida()
            ),
            vec!["no_comprobado"],
        ),
        None => RespuestaOps::deny(req_id, "NO_ENCONTRADO", "pasaporte/version no encontrada"),
    }
}

fn listar(estado: &mut EstadoOps, req_id: &str) -> RespuestaOps {
    let mut items = Vec::new();
    for alta in estado.altas.values() {
        let ver = estado.registro.version_activa(&alta.pasaporte_id);
        items.push(format!(
            r#"{{"sistema_id":"{}","pasaporte_id":"{}","finalidad":"{}","clasificacion_riesgo":"{}","pasaporte_version":{},"nota":"{}"}}"#,
            esc(&alta.sistema_id),
            esc(&alta.pasaporte_id),
            esc(&alta.finalidad),
            esc(&alta.clasificacion_riesgo),
            ver.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            NOTA_ALTA
        ));
    }
    RespuestaOps::ok(
        req_id,
        "LISTA",
        &format!(r#"{{"sistemas":[{}],"autoriza_efectos":false}}"#, items.join(",")),
        vec!["no_comprobado", LIMITE_NO_AUTH],
    )
}

fn pep_vista(estado: &mut EstadoOps, req_id: &str) -> RespuestaOps {
    RespuestaOps::ok(
        req_id,
        "PEP_VISTA",
        &format!(
            r#"{{"mapa":{},"secretos":"prohibidos","nota":"configuracion declarativa; sin API keys"}}"#,
            estado.pep.a_json()
        ),
        vec!["no_comprobado"],
    )
}

fn pep_configurar(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    // Rechazar claves en claro ya cubierto por deny_secreto.
    let mapa_json = campo_str_raw(raw, "mapa_json").unwrap_or_else(|| {
        // permitir objeto "mapa" embebido tomando substring
        if let Some(i) = raw.find("\"mapa\"") {
            raw[i..].to_string()
        } else {
            String::new()
        }
    });
    let nuevo = match PepMapa::desde_json_lineas(&mapa_json) {
        Ok(m) => m,
        Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", &e),
    };
    estado.pep = nuevo;
    if let Err(e) = estado.guardar_pep() {
        return RespuestaOps::deny(req_id, "ALMACEN", &e);
    }
    RespuestaOps::ok(
        req_id,
        "PEP_CONFIG",
        &format!(
            r#"{{"mapa":{},"ack":true,"secretos":"prohibidos"}}"#,
            estado.pep.a_json()
        ),
        vec!["no_comprobado"],
    )
}

fn inventario_alcanzables(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let tiene_firma = campo_str_raw(raw, "firma_productor_hex").is_some()
        || campo_str_raw(raw, "firma_hex").is_some();
    if campo_bool_raw(raw, "vista").unwrap_or(false) || !tiene_firma {
        return vista_alcanzables(estado, req_id, raw);
    }

    if campo_bool_raw(raw, "afirma_completitud").unwrap_or(false)
        || campo_bool_raw(raw, "completo").unwrap_or(false)
        || raw.contains("\"afirma_completitud\":true")
        || raw.contains("\"completo\":true")
    {
        return RespuestaOps::deny(
            req_id,
            "COMPLETITUD_PROHIBIDA",
            "ALCANZABLES no afirma completitud (INV-11); declare incompleto o omita",
        );
    }

    let inv = match inv_desde_raw(raw) {
        Ok(i) => i,
        Err(e) => {
            let codigo = if e.contains("ausente") {
                "SIN_FIRMA"
            } else if e.contains("invalida") {
                "FIRMA_INVALIDA"
            } else {
                "SCHEMA"
            };
            return RespuestaOps::deny(req_id, codigo, &e);
        }
    };
    if !inv.integridad_ok() {
        return RespuestaOps::deny(req_id, "FIRMA_INVALIDA", "inventario no verifica");
    }

    let sid = inv.sistema.como_str().to_string();
    let dig = hex_encode(&inv.digest);
    let productor = inv.productor_id.clone();
    let caducidad = inv.antigüedad_max;
    let emitido = inv.emitido_en;
    let vigente = inv.vigente(emitido);
    let incompleto = inv.incompleto_declarado;
    let version = inv.version;
    let epoca = inv.epoca;
    let efectores: Vec<String> = inv.efectores.iter().map(|e| e.token().to_string()).collect();

    estado.libro.registrar_alcanzables(inv);
    if let Err(e) = estado.guardar_libro() {
        return RespuestaOps::deny(req_id, "ALMACEN", &e);
    }

    RespuestaOps::ok(
        req_id,
        "ALCANZABLES_OK",
        &format!(
            r#"{{"sistema_id":"{}","version":{},"epoca":{},"productor_id":"{}","productor":"{}","digest":"{}","emitido_en":{},"antiguedad_max":{},"vigente_en_emision":{},"incompleto_declarado":{},"efectores":[{}],"afirma_completitud":false,"no_demuestra":"{}","limites":["no_comprobado","ALCANZABLES","INV-11"],"deep_links":{{"libro":"/observar?panel=libro","hechos":"/observar?panel=hechos","limites":"/observar?panel=limites"}},"material":null}}"#,
            esc(&sid),
            version,
            epoca,
            esc(&productor),
            ProductorHecho::InventarioAlcanzables.token(),
            dig,
            emitido,
            caducidad,
            vigente,
            incompleto,
            efectores
                .iter()
                .map(|e| format!("\"{}\"", esc(e)))
                .collect::<Vec<_>>()
                .join(","),
            InventarioAlcanzables::NO_DEMUESTRA
        ),
        vec!["no_comprobado", "ALCANZABLES", LIMITE_NO_AUTH],
    )
}

fn vista_alcanzables(estado: &mut EstadoOps, req_id: &str, raw: &str) -> RespuestaOps {
    let ahora = campo_u32_raw(raw, "ahora").unwrap_or(0) as u64;
    if let Some(sid) = campo_str_raw(raw, "sistema_id") {
        let id = match IdSistema::nuevo(&sid) {
            Ok(i) => i,
            Err(e) => return RespuestaOps::deny(req_id, "SCHEMA", e),
        };
        return match estado.libro.inventario(&id) {
            Some(inv) => RespuestaOps::ok(
                req_id,
                "ALCANZABLES_VISTA",
                &format_inv_json(inv, ahora),
                vec!["no_comprobado", "ALCANZABLES"],
            ),
            None => RespuestaOps::deny(req_id, "NO_ENCONTRADO", "sin inventario para sistema"),
        };
    }
    let mut items = Vec::new();
    for inv in estado.libro.alcanzables_map().values() {
        items.push(format_inv_json(inv, ahora));
    }
    RespuestaOps::ok(
        req_id,
        "ALCANZABLES_LISTA",
        &format!(
            r#"{{"inventarios":[{}],"afirma_completitud":false,"limites":["no_comprobado","ALCANZABLES","INV-11"],"deep_links":{{"libro":"/observar?panel=libro","hechos":"/observar?panel=hechos","limites":"/observar?panel=limites"}}}}"#,
            items.join(",")
        ),
        vec!["no_comprobado", "ALCANZABLES"],
    )
}

fn format_inv_json(inv: &InventarioAlcanzables, ahora: u64) -> String {
    let efectores: Vec<String> = inv
        .efectores
        .iter()
        .map(|e| format!("\"{}\"", e.token()))
        .collect();
    format!(
        r#"{{"sistema_id":"{}","instancia":"{}","version":{},"epoca":{},"productor_id":"{}","productor":"{}","digest":"{}","emitido_en":{},"antiguedad_max":{},"vigente":{},"no_caducado":{},"incompleto_declarado":{},"efectores":[{}],"afirma_completitud":false,"no_demuestra":"{}"}}"#,
        esc(inv.sistema.como_str()),
        esc(&inv.instancia),
        inv.version,
        inv.epoca,
        esc(&inv.productor_id),
        inv.productor.token(),
        hex_encode(&inv.digest),
        inv.emitido_en,
        inv.antigüedad_max,
        inv.vigente(ahora),
        inv.no_caducado(ahora),
        inv.incompleto_declarado,
        efectores.join(","),
        InventarioAlcanzables::NO_DEMUESTRA
    )
}

fn inv_desde_raw(raw: &str) -> Result<InventarioAlcanzables, String> {
    let sistema = campo_str_raw(raw, "sistema_id").ok_or("falta sistema_id")?;
    if !id_sistema_ok(&sistema) {
        return Err("sistema_id invalido".into());
    }
    let sid = IdSistema::nuevo(sistema).map_err(|e| e.to_string())?;
    let instancia = campo_str_raw(raw, "instancia").unwrap_or_else(|| "default".into());
    let productor_id = campo_str_raw(raw, "productor_id")
        .or_else(|| campo_str_raw(raw, "productor"))
        .ok_or("falta productor_id")?;
    let firma_hex = campo_str_raw(raw, "firma_productor_hex")
        .or_else(|| campo_str_raw(raw, "firma_hex"))
        .unwrap_or_default();
    let pk_hex = campo_str_raw(raw, "pk_productor_hex")
        .or_else(|| campo_str_raw(raw, "pk_hex"))
        .unwrap_or_default();
    if firma_hex.is_empty() || pk_hex.is_empty() {
        return Err("firma de productor ausente".into());
    }
    let firma = hex_decode(&firma_hex)?;
    let pk = hex_decode(&pk_hex)?;

    let efectores = parse_efectores(raw)?;
    let rutas = parse_set_csv(raw, "rutas_red");
    let creds = parse_set_csv(raw, "credenciales_detectadas");
    for c in &creds {
        if !c.starts_with("cred:digest:") && !c.starts_with("huella:") {
            return Err("credencial debe ser digest/huella (sin material)".into());
        }
    }
    let almacenes = parse_set_csv(raw, "almacenes");
    let puntos = parse_set_csv(raw, "puntos_servicio");
    let canales = parse_set_csv(raw, "canales_consumo");

    // Por defecto incompleto=true (no afirma completitud). Solo false si se declara explícitamente.
    let incompleto = campo_bool_raw(raw, "incompleto_declarado").unwrap_or(true);
    let version = campo_u32_raw(raw, "version").unwrap_or(1);
    let epoca = campo_u32_raw(raw, "epoca").unwrap_or(1) as u64;
    let emitido = campo_u32_raw(raw, "emitido_en").unwrap_or(0) as u64;

    let mut inv = InventarioAlcanzables {
        sistema: sid,
        instancia,
        efectores,
        rutas_red: rutas,
        credenciales_detectadas: creds,
        almacenes,
        puntos_servicio: puntos,
        canales_consumo: canales,
        incompleto_declarado: incompleto,
        version,
        epoca,
        emitido_en: emitido,
        antigüedad_max: antigüedad_maxima(TipoHecho::Alcanzables),
        productor: ProductorHecho::InventarioAlcanzables,
        productor_id,
        digest: [0u8; sak_core::decision::LONGITUD_HASH_PAQUETE],
        firma,
        pk_firmante: pk,
        no_demuestra: InventarioAlcanzables::NO_DEMUESTRA,
    };
    inv.digest = crypto::sha384_dominio(dominio::LIBRO, &inv.cuerpo_canonico());
    if !inv.integridad_ok() {
        return Err("firma de productor invalida".into());
    }
    Ok(inv)
}

fn parse_efectores(raw: &str) -> Result<BTreeSet<ClaseEfecto>, String> {
    let s = campo_str_raw(raw, "efectores").unwrap_or_default();
    let mut out = BTreeSet::new();
    if s.trim().is_empty() {
        return Ok(out);
    }
    for part in s.split(|c| c == ',' || c == '|' || c == ' ') {
        let p = part.trim().trim_matches('"');
        if p.is_empty() {
            continue;
        }
        if p.contains("12") || p.eq_ignore_ascii_case("EF-12") {
            return Err("EF-12 no admitido en inventario hacia IA".into());
        }
        let c = ClaseEfecto::desde_token(p).ok_or_else(|| format!("efector invalido: {p}"))?;
        out.insert(c);
    }
    Ok(out)
}

fn parse_set_csv(raw: &str, clave: &str) -> BTreeSet<String> {
    let s = campo_str_raw(raw, clave).unwrap_or_default();
    let mut out = BTreeSet::new();
    for part in s.split(|c| c == ',' || c == '|') {
        let p = part.trim().trim_matches('"');
        if !p.is_empty() {
            out.insert(p.to_string());
        }
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}
