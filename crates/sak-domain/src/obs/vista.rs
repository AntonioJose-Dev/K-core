//! Vista de solo lectura del estado del dominio para handlers `obs.*`.

use sak_core::contexto::ClaseEfecto;
use sak_core::evidencia::{
    EstadoDominio, LedgerEvidencia, RegistroFirmado, TipoRegistro, verificar_paquete,
};
use sak_core::identidad::IdSistema;
use sak_core::libro::LibroControl;
use sak_core::reloj::Ticks;
use std::collections::BTreeSet;
use std::path::Path;

use super::schema::{hex, json_str};

#[derive(Debug, Clone)]
pub struct ObsVista {
    pub dominio_id: String,
    pub evidencia_path: String,
    pub epoca: u64,
    pub suelo_epoca: u64,
    pub estado: String,
    pub n_pasaportes: usize,
    pub n_certs: usize,
    pub identidad_perfil: String,
    pub paquete_activo_hex: String,
    pub libro_ok: bool,
    pub hechos: Vec<HechoVista>,
    pub matriz: Vec<CeldaLibro>,
    pub decisiones: Vec<DecisionVista>,
    pub merkle_roots: Vec<String>,
    pub huella_pk_autoridad: String,
    pub huellas_pk_testigos: (String, String),
    pub limites: Vec<String>,
    pub incidentes: Vec<String>,
    /// Digests de registros (export Observable; sin claves privadas).
    pub digests_registros: Vec<String>,
    pub n_registros: usize,
    /// Paquete verificación in-process (solo claves públicas + digests).
    pub informe_verify_cache: Option<InformeVista>,
}

#[derive(Debug, Clone)]
pub struct HechoVista {
    pub tipo: String,
    pub productor: String,
    pub sistema: String,
    pub clase: Option<u8>,
    pub valor: bool,
    pub digest: String,
    pub epoca: u64,
    pub antigüedad_max: u64,
    pub vigente_nota: String,
}

#[derive(Debug, Clone)]
pub struct CeldaLibro {
    pub sistema: String,
    pub clase: u8,
    pub nivel_base: String,
    pub nivel_vigente: String,
    pub bypass: String,
    pub c5_denominacion: Option<String>,
    pub causa: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DecisionVista {
    pub sujeto: String,
    pub epoca: u64,
    pub secuencia: u64,
    pub digest: String,
    pub veredicto: String,
    pub hash_paquete: String,
}

#[derive(Debug, Clone)]
pub struct InformeVista {
    pub ok: bool,
    pub no_comprobado: Vec<String>,
    pub errores: Vec<String>,
}

impl ObsVista {
    pub fn desde_ledger<A: sak_core::evidencia::AlmacenEvidencia>(
        dominio_id: &str,
        evidencia_path: &Path,
        ledger: &LedgerEvidencia<A>,
        libro: Option<&LibroControl>,
        n_pasaportes: usize,
        n_certs: usize,
        identidad_perfil: &str,
        paquete_activo_hex: &str,
        ahora: Ticks,
    ) -> Self {
        let estado = match ledger.estado() {
            EstadoDominio::Operative => "Operative",
            EstadoDominio::Suspended => "Suspended",
        };
        let mut hechos = Vec::new();
        let mut matriz = Vec::new();
        let mut pares: BTreeSet<(String, u8)> = BTreeSet::new();
        let libro_ok = libro.is_some();
        if let Some(lib) = libro {
            for h in lib.hechos() {
                let clase_n = h.clase.map(|c| c as u8);
                hechos.push(HechoVista {
                    tipo: h.tipo.token().into(),
                    productor: h.productor.token().into(),
                    sistema: h.sistema.como_str().into(),
                    clase: clase_n,
                    valor: h.valor,
                    digest: hex::encode(&h.digest),
                    epoca: h.epoca,
                    antigüedad_max: h.antigüedad_max,
                    vigente_nota: if h.integridad_ok() {
                        "integridad_ok".into()
                    } else {
                        "integridad_fallo".into()
                    },
                });
                if let Some(c) = clase_n {
                    pares.insert((h.sistema.como_str().into(), c));
                }
            }
            for (sistema, clase_u8) in &pares {
                let Ok(id) = IdSistema::nuevo(sistema.clone()) else {
                    continue;
                };
                let Some(clase) = u8_a_clase(*clase_u8) else {
                    continue;
                };
                let ev = lib.evaluar(&id, clase, ahora);
                matriz.push(CeldaLibro {
                    sistema: sistema.clone(),
                    clase: *clase_u8,
                    nivel_base: ev.nivel_base.token().into(),
                    nivel_vigente: ev.nivel_vigente.token().into(),
                    bypass: ev.bypass_residual.to_string(),
                    c5_denominacion: ev.nivel_vigente.denominacion_c5_calculado().map(str::to_string),
                    causa: ev.causa_degradacion,
                });
            }
        }

        let mut decisiones = Vec::new();
        let mut digests_registros = Vec::new();
        for r in ledger.registros() {
            digests_registros.push(hex::encode(&r.digest));
            if r.tipo == TipoRegistro::Decision {
                if let Some(d) = decision_desde_registro(r) {
                    decisiones.push(d);
                }
            }
        }

        let merkle_roots: Vec<String> = ledger
            .checkpoints()
            .iter()
            .map(|c| hex::encode(&c.merkle_root))
            .collect();

        let (t1, t2) = ledger.pk_testigos();
        let pkg = ledger.exportar_paquete();
        let informe = verificar_paquete(&pkg);
        let informe_verify_cache = Some(InformeVista {
            ok: informe.ok,
            no_comprobado: informe.no_comprobado,
            errores: informe.errores,
        });

        let mut limites = vec![
            "no_comprobado".into(),
            "[DESP]".into(),
            "[VAL-EXT]".into(),
            "[GOB]".into(),
            "C5_HOST_REAL_prohibido".into(),
        ];
        if !libro_ok {
            limites.push("libro_no_cargado".into());
        }

        let mut incidentes = Vec::new();
        if let Some(lib) = libro {
            for (par, nivel, causa, epoca) in lib.historial() {
                incidentes.push(format!(
                    "libro_hist sistema={} clase={} nivel={} epoca={} causa={}",
                    par.sistema.como_str(),
                    par.clase as u8,
                    nivel.token(),
                    epoca,
                    causa
                ));
            }
        }
        if ledger.estado() == EstadoDominio::Suspended {
            incidentes.push("dominio_SUSPENDED".into());
        }

        ObsVista {
            dominio_id: dominio_id.into(),
            evidencia_path: evidencia_path.display().to_string(),
            epoca: ledger.epoca(),
            suelo_epoca: ledger.suelo_epoca(),
            estado: estado.into(),
            n_pasaportes,
            n_certs,
            identidad_perfil: identidad_perfil.into(),
            paquete_activo_hex: paquete_activo_hex.into(),
            libro_ok,
            hechos,
            matriz,
            decisiones,
            merkle_roots,
            huella_pk_autoridad: hex::huella_pk(ledger.pk_autoridad()),
            huellas_pk_testigos: (hex::huella_pk(t1), hex::huella_pk(t2)),
            limites,
            incidentes,
            digests_registros,
            n_registros: ledger.registros().len(),
            informe_verify_cache,
        }
    }
}

fn u8_a_clase(c: u8) -> Option<ClaseEfecto> {
    match c {
        1 => Some(ClaseEfecto::Ef1),
        2 => Some(ClaseEfecto::Ef2),
        3 => Some(ClaseEfecto::Ef3),
        4 => Some(ClaseEfecto::Ef4),
        5 => Some(ClaseEfecto::Ef5),
        6 => Some(ClaseEfecto::Ef6),
        7 => Some(ClaseEfecto::Ef7),
        8 => Some(ClaseEfecto::Ef8),
        9 => Some(ClaseEfecto::Ef9),
        10 => Some(ClaseEfecto::Ef10),
        11 => Some(ClaseEfecto::Ef11),
        12 => Some(ClaseEfecto::Ef12),
        _ => None,
    }
}

fn decision_desde_registro(r: &RegistroFirmado) -> Option<DecisionVista> {
    if r.payload.len() < 2 + 48 {
        return None;
    }
    let veredicto = match r.payload[1] {
        0 => "DENY",
        1 => "SUSPEND",
        2 => "ESCALATE",
        3 => "ALLOW",
        _ => "DESCONOCIDO",
    };
    let hash_paquete = hex::encode(&r.payload[2..50]);
    Some(DecisionVista {
        sujeto: r.sujeto.como_str().into(),
        epoca: r.epoca,
        secuencia: r.secuencia,
        digest: hex::encode(&r.digest),
        veredicto: veredicto.into(),
        hash_paquete,
    })
}

pub fn cuerpo_estado(v: &ObsVista) -> String {
    format!(
        r#"{{"dominio_id":{},"estado":{},"epoca":{},"suelo_epoca":{},"evidencia_path":{},"paquete_activo":{},"pasaportes":{},"certificados":{},"identidad_perfil":{},"libro_ok":{},"n_registros":{},"limites":[{}]}}"#,
        json_str(&v.dominio_id),
        json_str(&v.estado),
        v.epoca,
        v.suelo_epoca,
        json_str(&v.evidencia_path),
        json_str(&v.paquete_activo_hex),
        v.n_pasaportes,
        v.n_certs,
        json_str(&v.identidad_perfil),
        v.libro_ok,
        v.n_registros,
        v.limites
            .iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn cuerpo_salud(v: &ObsVista) -> String {
    let ok = v.estado == "Operative";
    format!(
        r#"{{"salud":{},"latido":"local","autotest":"canal_obs_ok","estado_dominio":{}}}"#,
        if ok { "\"OK\"" } else { "\"DEGRADADA\"" },
        json_str(&v.estado)
    )
}

pub fn cuerpo_version() -> String {
    format!(
        r#"{{"version_crate":{},"schema_ipc":{},"familia":"Observar"}}"#,
        json_str(env!("CARGO_PKG_VERSION")),
        super::schema::SCHEMA_V
    )
}

pub fn cuerpo_describir_canal() -> String {
    format!(
        r#"{{"transporte":["in-process","stdio","loopback_127.0.0.1"],"bind_publico":"DENY","telemetria":"DENY","nota":{},"familia":{}}}"#,
        json_str(super::schema::NOTA_CANAL),
        json_str(super::schema::FAMILIA)
    )
}

pub fn cuerpo_libro(v: &ObsVista, sistema: Option<&str>, clase: Option<u8>) -> String {
    let celdas: Vec<String> = v
        .matriz
        .iter()
        .filter(|c| sistema.map(|s| s == c.sistema).unwrap_or(true))
        .filter(|c| clase.map(|k| k == c.clase).unwrap_or(true))
        .map(|c| {
            format!(
                r#"{{"sistema":{},"clase":{},"nivel_base":{},"nivel_vigente":{},"bypass":{},"c5_calculado":{},"causa":{}}}"#,
                json_str(&c.sistema),
                c.clase,
                json_str(&c.nivel_base),
                json_str(&c.nivel_vigente),
                json_str(&c.bypass),
                c.c5_denominacion
                    .as_ref()
                    .map(|s| json_str(s))
                    .unwrap_or_else(|| "null".into()),
                c.causa
                    .as_ref()
                    .map(|s| json_str(s))
                    .unwrap_or_else(|| "null".into())
            )
        })
        .collect();
    format!(
        r#"{{"libro_ok":{},"celdas":[{}],"limites":[{}]}}"#,
        v.libro_ok,
        celdas.join(","),
        v.limites
            .iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn cuerpo_hechos(v: &ObsVista) -> String {
    let items: Vec<String> = v
        .hechos
        .iter()
        .map(|h| {
            format!(
                r#"{{"tipo":{},"productor":{},"sistema":{},"clase":{},"valor":{},"digest":{},"epoca":{},"ttl":{},"nota":{}}}"#,
                json_str(&h.tipo),
                json_str(&h.productor),
                json_str(&h.sistema),
                h.clase
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "null".into()),
                h.valor,
                json_str(&h.digest),
                h.epoca,
                h.antigüedad_max,
                json_str(&h.vigente_nota)
            )
        })
        .collect();
    format!(r#"{{"hechos":[{}]}}"#, items.join(","))
}

pub fn cuerpo_decisiones_listar(v: &ObsVista, sujeto: Option<&str>) -> String {
    let items: Vec<String> = v
        .decisiones
        .iter()
        .filter(|d| sujeto.map(|s| s == d.sujeto).unwrap_or(true))
        .map(|d| {
            format!(
                r#"{{"sujeto":{},"epoca":{},"seq":{},"digest":{},"veredicto":{},"hash_paquete":{}}}"#,
                json_str(&d.sujeto),
                d.epoca,
                d.secuencia,
                json_str(&d.digest),
                json_str(&d.veredicto),
                json_str(&d.hash_paquete)
            )
        })
        .collect();
    format!(r#"{{"decisiones":[{}]}}"#, items.join(","))
}

pub fn cuerpo_decision_get(v: &ObsVista, id: Option<&str>, seq: Option<u64>) -> Option<String> {
    let d = v.decisiones.iter().find(|d| {
        if let Some(i) = id {
            return d.digest == i;
        }
        if let Some(s) = seq {
            return d.secuencia == s;
        }
        false
    })?;
    Some(format!(
        r#"{{"sujeto":{},"epoca":{},"seq":{},"digest":{},"veredicto":{},"hash_paquete":{}}}"#,
        json_str(&d.sujeto),
        d.epoca,
        d.secuencia,
        json_str(&d.digest),
        json_str(&d.veredicto),
        json_str(&d.hash_paquete)
    ))
}

pub fn cuerpo_exportar(v: &ObsVista) -> String {
    let digs: String = v
        .digests_registros
        .iter()
        .map(|d| json_str(d))
        .collect::<Vec<_>>()
        .join(",");
    let roots: String = v
        .merkle_roots
        .iter()
        .map(|d| json_str(d))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        r#"{{"n_registros":{},"digests_registros":[{}],"merkle_roots":[{}],"huella_pk_autoridad":{},"huellas_pk_testigos":[{},{}],"material_clave":"prohibido","secretos_raiz":"prohibido"}}"#,
        v.n_registros,
        digs,
        roots,
        json_str(&v.huella_pk_autoridad),
        json_str(&v.huellas_pk_testigos.0),
        json_str(&v.huellas_pk_testigos.1)
    )
}

pub fn cuerpo_verificar(v: &ObsVista) -> String {
    match &v.informe_verify_cache {
        Some(i) => {
            let nc: String = i
                .no_comprobado
                .iter()
                .map(|x| json_str(x))
                .collect::<Vec<_>>()
                .join(",");
            let er: String = i
                .errores
                .iter()
                .map(|x| json_str(x))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                r#"{{"ok":{},"no_comprobado":[{}],"errores":[{}],"veredicto_conformidad":"no_emitido"}}"#,
                i.ok, nc, er
            )
        }
        None => r#"{"ok":false,"no_comprobado":["sin_paquete"],"errores":[],"veredicto_conformidad":"no_emitido"}"#.into(),
    }
}

pub fn cuerpo_limites(v: &ObsVista) -> String {
    format!(
        r#"{{"limites":[{}]}}"#,
        v.limites
            .iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(",")
    )
}

pub fn cuerpo_incidentes(v: &ObsVista) -> String {
    format!(
        r#"{{"incidentes":[{}]}}"#,
        v.incidentes
            .iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Escaneo defensivo: el JSON de respuesta no debe contener material de clave.
pub fn contiene_secreto_prohibido(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "begin private",
        "begin rsa private",
        "begin secret",
        "\"sk\"",
        "\"seed\"",
        "\"pem\"",
        "material_clave_exportable",
        "secret_key",
        "private_key",
    ];
    BAD.iter().any(|b| lower.contains(b))
}
