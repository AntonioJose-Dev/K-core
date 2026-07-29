//! Solicitud tipada EF-11: efecto físico / ciberfísico.

use crate::capacidad::{digest_efecto_canonico, Alcance};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::solicitud::ClaseEfecto;
use crate::pep::solicitud_comunicacion::{EtiquetaHecho, TipoHechoContacto};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperacionFisica {
    Activar,
    Desactivar,
    Posicionar,
    LimitarEnergia,
    ParadaSegura,
    SecuenciaDeclarada,
}

impl OperacionFisica {
    pub fn token(self) -> &'static str {
        match self {
            OperacionFisica::Activar => "activar",
            OperacionFisica::Desactivar => "desactivar",
            OperacionFisica::Posicionar => "posicionar",
            OperacionFisica::LimitarEnergia => "limitar_energia",
            OperacionFisica::ParadaSegura => "parada_segura",
            OperacionFisica::SecuenciaDeclarada => "secuencia_declarada",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "activar" | "actuate" | "fisico" => Some(OperacionFisica::Activar),
            "desactivar" => Some(OperacionFisica::Desactivar),
            "posicionar" => Some(OperacionFisica::Posicionar),
            "limitar_energia" => Some(OperacionFisica::LimitarEnergia),
            "parada_segura" => Some(OperacionFisica::ParadaSegura),
            "secuencia_declarada" => Some(OperacionFisica::SecuenciaDeclarada),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModoOperativo {
    Normal,
    Mantenimiento,
    Emergencia,
    Prueba,
}

impl ModoOperativo {
    pub fn token(self) -> &'static str {
        match self {
            ModoOperativo::Normal => "normal",
            ModoOperativo::Mantenimiento => "mantenimiento",
            ModoOperativo::Emergencia => "emergencia",
            ModoOperativo::Prueba => "prueba",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParametrosFisicos {
    pub magnitud: i64,
    pub velocidad: i64,
    pub duracion_ms: u64,
    pub energia: i64,
    pub unidad_magnitud: String,
    pub unidad_velocidad: String,
    pub unidad_energia: String,
}

impl ParametrosFisicos {
    pub fn nuevo(
        magnitud: i64,
        velocidad: i64,
        duracion_ms: u64,
        energia: i64,
        unidad_magnitud: impl Into<String>,
        unidad_velocidad: impl Into<String>,
        unidad_energia: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let unidad_magnitud = unidad_magnitud.into();
        let unidad_velocidad = unidad_velocidad.into();
        let unidad_energia = unidad_energia.into();
        if unidad_magnitud.trim().is_empty()
            || unidad_velocidad.trim().is_empty()
            || unidad_energia.trim().is_empty()
            || unidad_magnitud == "*"
            || unidad_velocidad == "*"
            || unidad_energia == "*"
        {
            return Err("unidades no normalizadas");
        }
        Ok(ParametrosFisicos {
            magnitud,
            velocidad,
            duracion_ms,
            energia,
            unidad_magnitud,
            unidad_velocidad,
            unidad_energia,
        })
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.magnitud.to_le_bytes());
        v.extend_from_slice(&self.velocidad.to_le_bytes());
        v.extend_from_slice(&self.duracion_ms.to_le_bytes());
        v.extend_from_slice(&self.energia.to_le_bytes());
        escribir(&mut v, &self.unidad_magnitud);
        escribir(&mut v, &self.unidad_velocidad);
        escribir(&mut v, &self.unidad_energia);
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LimitesFisicos {
    pub mag_min: i64,
    pub mag_max: i64,
    pub vel_max: i64,
    pub dur_max_ms: u64,
    pub energia_max: i64,
}

impl LimitesFisicos {
    pub fn tipicos() -> Self {
        LimitesFisicos {
            mag_min: -1000,
            mag_max: 1000,
            vel_max: 100,
            dur_max_ms: 60_000,
            energia_max: 500,
        }
    }

    pub fn contiene(&self, p: &ParametrosFisicos) -> bool {
        p.magnitud >= self.mag_min
            && p.magnitud <= self.mag_max
            && p.velocidad.abs() <= self.vel_max
            && p.duracion_ms <= self.dur_max_ms
            && p.energia.abs() <= self.energia_max
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.mag_min.to_le_bytes());
        v.extend_from_slice(&self.mag_max.to_le_bytes());
        v.extend_from_slice(&self.vel_max.to_le_bytes());
        v.extend_from_slice(&self.dur_max_ms.to_le_bytes());
        v.extend_from_slice(&self.energia_max.to_le_bytes());
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoFisicoExigido {
    pub tipo: TipoHechoContacto,
    pub etiqueta: EtiquetaHecho,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
}

/// Aprobación humana previa (digest exacto). El Kernel no determina competencia material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AprobacionHumanaFisica {
    pub id_humano: String,
    pub rol: String,
    pub competencia: String,
    pub independiente: bool,
    pub firmado_en: u64,
    pub vigente_hasta: u64,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_presente: bool,
}

impl AprobacionHumanaFisica {
    pub fn valida_para(
        &self,
        digest_sol: &[u8; LONGITUD_HASH_PAQUETE],
        digest_ctx: &[u8; LONGITUD_HASH_PAQUETE],
        ahora: u64,
        competencia_requerida: &str,
    ) -> Result<(), &'static str> {
        if !self.firma_presente {
            return Err("firma ausente");
        }
        if !self.independiente {
            return Err("no independiente");
        }
        if self.competencia != competencia_requerida {
            return Err("competencia inadecuada");
        }
        if ahora < self.firmado_en || ahora > self.vigente_hasta {
            return Err("fuera de plazo");
        }
        if &self.digest_solicitud != digest_sol || &self.digest_contexto != digest_ctx {
            return Err("digest divergente");
        }
        if self.id_humano.trim().is_empty() || self.rol.trim().is_empty() {
            return Err("identidad humana vacia");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudEfectoFisico {
    pub sistema: String,
    pub instancia: String,
    pub instalacion_zona: String,
    pub familia_activo: String,
    pub id_actuador: String,
    pub id_controlador: String,
    pub id_bus: String,
    pub operacion: OperacionFisica,
    pub parametros: ParametrosFisicos,
    pub limites: LimitesFisicos,
    pub estado_inicial: String,
    pub estado_objetivo: String,
    pub ventana_desde: u64,
    pub ventana_hasta: u64,
    pub reversible: bool,
    pub procedimiento_parada: String,
    pub criticidad: String,
    pub categoria_dano: String,
    pub presencia_humana: bool,
    pub zona_segura: bool,
    pub destinatarios_afectados: String,
    pub modo: ModoOperativo,
    pub finalidad: String,
    pub digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
    pub epoca: u64,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub hechos_exigidos: Vec<HechoFisicoExigido>,
    pub exige_supervision: bool,
    pub competencia_requerida: String,
}

impl SolicitudEfectoFisico {
    #[allow(clippy::too_many_arguments)]
    pub fn nueva(
        sistema: impl Into<String>,
        instancia: impl Into<String>,
        instalacion_zona: impl Into<String>,
        familia_activo: impl Into<String>,
        id_actuador: impl Into<String>,
        id_controlador: impl Into<String>,
        id_bus: impl Into<String>,
        operacion: OperacionFisica,
        parametros: ParametrosFisicos,
        limites: LimitesFisicos,
        estado_inicial: impl Into<String>,
        estado_objetivo: impl Into<String>,
        ventana_desde: u64,
        ventana_hasta: u64,
        reversible: bool,
        procedimiento_parada: impl Into<String>,
        criticidad: impl Into<String>,
        categoria_dano: impl Into<String>,
        presencia_humana: bool,
        zona_segura: bool,
        destinatarios_afectados: impl Into<String>,
        modo: ModoOperativo,
        finalidad: impl Into<String>,
        digest_contexto: [u8; LONGITUD_HASH_PAQUETE],
        epoca: u64,
        hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
        hechos_exigidos: Vec<HechoFisicoExigido>,
        exige_supervision: bool,
        competencia_requerida: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let sistema = sistema.into();
        let instancia = instancia.into();
        let instalacion_zona = instalacion_zona.into();
        let familia_activo = familia_activo.into();
        let id_actuador = id_actuador.into();
        let id_controlador = id_controlador.into();
        let id_bus = id_bus.into();
        let estado_inicial = estado_inicial.into();
        let estado_objetivo = estado_objetivo.into();
        let procedimiento_parada = procedimiento_parada.into();
        let criticidad = criticidad.into();
        let categoria_dano = categoria_dano.into();
        let destinatarios_afectados = destinatarios_afectados.into();
        let finalidad = finalidad.into();
        let competencia_requerida = competencia_requerida.into();

        for s in [
            &sistema,
            &instancia,
            &instalacion_zona,
            &familia_activo,
            &id_actuador,
            &id_controlador,
            &id_bus,
            &estado_inicial,
            &estado_objetivo,
            &procedimiento_parada,
            &criticidad,
            &categoria_dano,
            &finalidad,
        ] {
            if s.trim().is_empty() || *s == "*" {
                return Err("campo ambiguo o vacio");
            }
        }
        if ventana_hasta < ventana_desde {
            return Err("ventana invalida");
        }
        if !limites.contiene(&parametros) {
            return Err("parametros fuera de envolvente");
        }
        if criticidad == "indeterminada" || categoria_dano == "indeterminada" {
            return Err("riesgo o dano indeterminable");
        }
        if !reversible && procedimiento_parada.trim().is_empty() {
            return Err("parada requerida si irreversible");
        }
        if exige_supervision && competencia_requerida.trim().is_empty() {
            return Err("competencia requerida ausente");
        }
        Ok(SolicitudEfectoFisico {
            sistema,
            instancia,
            instalacion_zona,
            familia_activo,
            id_actuador,
            id_controlador,
            id_bus,
            operacion,
            parametros,
            limites,
            estado_inicial,
            estado_objetivo,
            ventana_desde,
            ventana_hasta,
            reversible,
            procedimiento_parada,
            criticidad,
            categoria_dano,
            presencia_humana,
            zona_segura,
            destinatarios_afectados,
            modo,
            finalidad,
            digest_contexto,
            epoca,
            hash_paquete,
            hechos_exigidos,
            exige_supervision,
            competencia_requerida,
        })
    }

    pub fn clase_efecto(&self) -> ClaseEfecto {
        ClaseEfecto::Ef11
    }

    pub fn canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"EF-11|");
        escribir(&mut v, &self.sistema);
        escribir(&mut v, &self.instancia);
        escribir(&mut v, &self.instalacion_zona);
        escribir(&mut v, &self.familia_activo);
        escribir(&mut v, &self.id_actuador);
        escribir(&mut v, &self.id_controlador);
        escribir(&mut v, &self.id_bus);
        v.extend_from_slice(self.operacion.token().as_bytes());
        v.push(0);
        v.extend_from_slice(&self.parametros.canonico());
        v.extend_from_slice(&self.limites.canonico());
        escribir(&mut v, &self.estado_inicial);
        escribir(&mut v, &self.estado_objetivo);
        v.extend_from_slice(&self.ventana_desde.to_le_bytes());
        v.extend_from_slice(&self.ventana_hasta.to_le_bytes());
        v.push(u8::from(self.reversible));
        escribir(&mut v, &self.procedimiento_parada);
        escribir(&mut v, &self.criticidad);
        escribir(&mut v, &self.categoria_dano);
        v.push(u8::from(self.presencia_humana));
        v.push(u8::from(self.zona_segura));
        escribir(&mut v, &self.destinatarios_afectados);
        v.extend_from_slice(self.modo.token().as_bytes());
        v.push(0);
        escribir(&mut v, &self.finalidad);
        v.extend_from_slice(&self.digest_contexto);
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.extend_from_slice(&self.hash_paquete);
        v.push(u8::from(self.exige_supervision));
        escribir(&mut v, &self.competencia_requerida);
        for h in &self.hechos_exigidos {
            v.extend_from_slice(h.tipo.token().as_bytes());
            v.push(0);
            v.extend_from_slice(h.etiqueta.token().as_bytes());
            v.push(0);
            v.extend_from_slice(&h.digest);
        }
        v
    }
}

fn escribir(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SolicitudFisicaCruda {
    Tipada(SolicitudEfectoFisico),
    NoTipificable,
    Malformada(&'static str),
    OrdenLibre,
    CompuestaNoDeclarada,
    BusAlternativo,
    ClaseNoSoportada(ClaseEfecto),
}

pub fn digest_solicitud_fisica(s: &SolicitudEfectoFisico) -> [u8; LONGITUD_HASH_PAQUETE] {
    digest_efecto_canonico("EF-11", &s.canonico())
}

fn hex48(d: &[u8; LONGITUD_HASH_PAQUETE]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn alcance_ef11(s: &SolicitudEfectoFisico) -> Alcance {
    let mut tokens = vec![
        "EF-11".to_string(),
        format!("sys:{}", s.sistema),
        format!("inst:{}", s.instancia),
        format!("zona:{}", s.instalacion_zona),
        format!("fam:{}", s.familia_activo),
        format!("act:{}", s.id_actuador),
        format!("ctl:{}", s.id_controlador),
        format!("bus:{}", s.id_bus),
        format!("op:{}", s.operacion.token()),
        format!("mag:{}", s.parametros.magnitud),
        format!("vel:{}", s.parametros.velocidad),
        format!("dur:{}", s.parametros.duracion_ms),
        format!("ene:{}", s.parametros.energia),
        format!("um:{}", s.parametros.unidad_magnitud),
        format!("uv:{}", s.parametros.unidad_velocidad),
        format!("ue:{}", s.parametros.unidad_energia),
        format!("ei:{}", s.estado_inicial),
        format!("eo:{}", s.estado_objetivo),
        format!("vd:{}", s.ventana_desde),
        format!("vh:{}", s.ventana_hasta),
        format!("modo:{}", s.modo.token()),
        format!("fin:{}", s.finalidad),
        format!("pkg:{}", hex48(&s.hash_paquete)),
        format!("ep:{}", s.epoca),
        format!("ctx:{}", hex48(&s.digest_contexto)),
    ];
    for h in &s.hechos_exigidos {
        tokens.push(format!(
            "hecho:{}:{}:{}",
            h.tipo.token(),
            h.etiqueta.token(),
            hex48(&h.digest)
        ));
    }
    Alcance::minimo(tokens).expect("alcance EF-11")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlcanceAutorizadoFisico {
    pub id_actuador: String,
    pub id_controlador: String,
    pub id_bus: String,
    pub operacion: String,
    pub magnitud: i64,
    pub velocidad: i64,
    pub duracion_ms: u64,
    pub energia: i64,
    pub unidad_magnitud: String,
    pub instalacion_zona: String,
    pub modo: String,
    pub ventana_desde: u64,
    pub ventana_hasta: u64,
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
}

impl AlcanceAutorizadoFisico {
    pub fn desde_alcance(a: &Alcance) -> Result<Self, &'static str> {
        if !a.tokens().contains("EF-11") {
            return Err("falta EF-11");
        }
        let get = |pref: &str| -> Result<String, &'static str> {
            a.tokens()
                .iter()
                .find_map(|t| t.strip_prefix(pref).map(str::to_string))
                .ok_or("token")
        };
        Ok(AlcanceAutorizadoFisico {
            id_actuador: get("act:")?,
            id_controlador: get("ctl:")?,
            id_bus: get("bus:")?,
            operacion: get("op:")?,
            magnitud: get("mag:")?.parse().map_err(|_| "mag")?,
            velocidad: get("vel:")?.parse().map_err(|_| "vel")?,
            duracion_ms: get("dur:")?.parse().map_err(|_| "dur")?,
            energia: get("ene:")?.parse().map_err(|_| "ene")?,
            unidad_magnitud: get("um:")?,
            instalacion_zona: get("zona:")?,
            modo: get("modo:")?,
            ventana_desde: get("vd:")?.parse().map_err(|_| "vd")?,
            ventana_hasta: get("vh:")?.parse().map_err(|_| "vh")?,
            hash_paquete: parse_hex48(&get("pkg:")?)?,
        })
    }
}

fn parse_hex48(s: &str) -> Result<[u8; LONGITUD_HASH_PAQUETE], &'static str> {
    if s.len() != LONGITUD_HASH_PAQUETE * 2 {
        return Err("hex");
    }
    let mut out = [0u8; LONGITUD_HASH_PAQUETE];
    for i in 0..LONGITUD_HASH_PAQUETE {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| "hex")?;
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecondicionesPepEf11 {
    pub identidad_vigente: bool,
    pub pasaporte_vigente: bool,
    /// Libro EF-11 en C4. Si módulo ausente / ruta alternativa ⇒ tratar como C0 (denegar).
    pub libro_c4: bool,
    pub monitor_permisivo: bool,
    pub hechos_ok: bool,
    pub modulo_interpuesto: bool,
    pub ruta_alternativa_declarada: bool,
    pub latido_modulo: bool,
    pub supervision_ok: bool,
}

impl PrecondicionesPepEf11 {
    pub fn todas_ok() -> Self {
        PrecondicionesPepEf11 {
            identidad_vigente: true,
            pasaporte_vigente: true,
            libro_c4: true,
            monitor_permisivo: true,
            hechos_ok: true,
            modulo_interpuesto: true,
            ruta_alternativa_declarada: false,
            latido_modulo: true,
            supervision_ok: true,
        }
    }

    /// Sin módulo o con ruta alternativa ⇒ C0 efectivo (denegación, no degradación permisiva).
    pub fn clasificacion_c0(self) -> bool {
        !self.modulo_interpuesto || self.ruta_alternativa_declarada
    }
}

pub fn traducir_fisico_desde_herramienta(
    id_herramienta: &str,
    servidor: &str,
    operacion: &str,
    destino: &str,
    digest_argumentos: [u8; LONGITUD_HASH_PAQUETE],
    hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    _datos_personales: bool,
    reversible: bool,
) -> Result<SolicitudEfectoFisico, &'static str> {
    let op = OperacionFisica::desde_token(operacion).unwrap_or(OperacionFisica::Activar);
    let params = ParametrosFisicos::nuevo(10, 1, 1000, 5, "mm", "mm/s", "J")?;
    let hecho = HechoFisicoExigido {
        tipo: TipoHechoContacto::AprobacionHumana,
        etiqueta: EtiquetaHecho::Gob,
        digest: digest_argumentos,
    };
    SolicitudEfectoFisico::nueva(
        "sys-fis",
        "inst-1",
        "zona-a",
        "actuador-lineal",
        if destino.trim().is_empty() {
            format!("act-{id_herramienta}")
        } else {
            destino.to_string()
        },
        format!("ctl-{servidor}"),
        format!("bus-{servidor}"),
        op,
        params,
        LimitesFisicos::tipicos(),
        "reposo",
        "activo",
        0,
        u64::MAX,
        reversible,
        "parada_e_stop",
        "alta",
        "mecanico",
        false,
        true,
        "ninguno",
        ModoOperativo::Normal,
        "posicionamiento",
        digest_argumentos,
        1,
        hash_paquete,
        vec![hecho],
        true,
        "operador-fisico",
    )
}

impl fmt::Display for OperacionFisica {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
