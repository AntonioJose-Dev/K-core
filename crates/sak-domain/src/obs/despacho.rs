//! Despacho de peticiones `obs.*` (solo lectura, familia Observar).

use super::schema::{
    es_deny_fijo, es_op_observar, parsear_peticion, Peticion, Respuesta, SCHEMA_V,
};
use super::vista::{
    cuerpo_decision_get, cuerpo_decisiones_listar, cuerpo_describir_canal, cuerpo_estado,
    cuerpo_exportar, cuerpo_hechos, cuerpo_incidentes, cuerpo_libro, cuerpo_limites, cuerpo_salud,
    cuerpo_verificar, cuerpo_version, ObsVista,
};

/// Despacha una petición JSON del canal operador. No muta la vista.
pub fn despachar(vista: &ObsVista, raw: &str) -> Respuesta {
    let pet = match parsear_peticion(raw) {
        Ok(p) => p,
        Err(e) => return Respuesta::error("sin-id", "SCHEMA", &e),
    };
    despachar_peticion(vista, &pet)
}

pub fn despachar_peticion(vista: &ObsVista, pet: &Peticion) -> Respuesta {
    if pet.schema_v != SCHEMA_V {
        return Respuesta::deny(&pet.req_id, "SCHEMA_V", "schema_v no soportado");
    }
    if es_deny_fijo(&pet.op) {
        return Respuesta::deny(&pet.req_id, "DENY_FIJO", "operación prohibida por esquema");
    }
    if !es_op_observar(&pet.op) {
        return Respuesta::deny(
            &pet.req_id,
            "NO_OBSERVAR",
            "solo familia Observar (obs.*) de lectura",
        );
    }
    if let Some(did) = &pet.dominio_id {
        if did != &vista.dominio_id {
            return Respuesta::deny(&pet.req_id, "DOMINIO", "dominio_id no coincide");
        }
    }

    let limites = vista.limites.clone();
    match pet.op.as_str() {
        "obs.estado" => Respuesta::ok(&pet.req_id, "ESTADO", cuerpo_estado(vista), limites),
        "obs.salud" => Respuesta::ok(&pet.req_id, "SALUD", cuerpo_salud(vista), limites),
        "obs.version" => Respuesta::ok(&pet.req_id, "VERSION", cuerpo_version(), limites),
        "obs.describir_canal" => {
            Respuesta::ok(&pet.req_id, "CANAL", cuerpo_describir_canal(), limites)
        }
        "obs.libro.matriz" => Respuesta::ok(
            &pet.req_id,
            "LIBRO",
            cuerpo_libro(vista, pet.sistema.as_deref(), pet.clase),
            limites,
        ),
        "obs.hechos.listar" => {
            Respuesta::ok(&pet.req_id, "HECHOS", cuerpo_hechos(vista), limites)
        }
        "obs.decisiones.listar" => Respuesta::ok(
            &pet.req_id,
            "DECISIONES",
            cuerpo_decisiones_listar(vista, pet.sujeto.as_deref()),
            limites,
        ),
        "obs.decisiones.get" => match cuerpo_decision_get(vista, pet.id.as_deref(), pet.seq) {
            Some(c) => Respuesta::ok(&pet.req_id, "DECISION", c, limites),
            None => Respuesta::deny(&pet.req_id, "NO_ENCONTRADO", "decisión inexistente"),
        },
        "obs.evidencia.exportar" => {
            if !pet.confirmacion_explicita {
                return Respuesta::deny(
                    &pet.req_id,
                    "SIN_CONFIRMACION",
                    "confirmacion_explicita requerida",
                );
            }
            Respuesta::ok(&pet.req_id, "EXPORT", cuerpo_exportar(vista), limites)
        }
        "obs.evidencia.verificar" => {
            Respuesta::ok(&pet.req_id, "VERIFY", cuerpo_verificar(vista), limites)
        }
        "obs.expediente.get" => Respuesta::deny(
            &pet.req_id,
            "EXPEDIENTE_AUSENTE",
            "no hay expediente indexado en este dominio (solo se serializa lo existente)",
        ),
        "obs.limites" => Respuesta::ok(&pet.req_id, "LIMITES", cuerpo_limites(vista), limites),
        "obs.incidentes" => {
            Respuesta::ok(&pet.req_id, "INCIDENTES", cuerpo_incidentes(vista), limites)
        }
        _ => Respuesta::deny(&pet.req_id, "NO_OBSERVAR", "op no implementada en Observar"),
    }
}
