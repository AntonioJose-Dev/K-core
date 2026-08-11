//! Frontera sujeto Bloque B — decidir → emitir (Kernel) → ejercer PEP EF-1.
//! Misma cadena que el espejo `obs.diagnostico.*` (B4). Sin HTTP nuevo.

use sak_core::capacidad::{Capability, ClasificacionEfecto, ParametrosEmision};
use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
use sak_core::decision::{
    Decision, HashPaqueteNormativo, IdNorma, Veredicto, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{IdSujeto, LedgerEvidencia, MemoriaDurable};
use sak_core::identidad::{IdSistema, RegistroSoberano};
use sak_core::libro::{decidir_con_libro, LibroControl};
use sak_core::monitor::EpocaMonotonica;
use sak_core::pep::{
    alcance_ef1, preparar_solicitud, parse_clave_hex, CredencialProveedor, GatewayModelos,
    ProveedorLoopbackEf1, ProveedorModelo, ProveedorSimulado, ResultadoPep, SolicitudCruda,
    HANDLE_EF1_PROBE_MEDIADO,
    ProveedorNvidiaEf1, HANDLE_EF1_PILOTO_NVIDIA,
};
use std::net::SocketAddr;
use sak_core::perfil::{NormaMinima, PerfilNormativo, PredicadoMinimo, Rango};
use sak_core::reloj::{RelojInyectado, Ticks};
use std::collections::BTreeMap;

use crate::ops::estado::EstadoOps;
use crate::ops::schema::{campo_str_raw, RespuestaOps};

/// Resultado de decisión en dominio (B1/B2).
#[derive(Debug, Clone)]
pub struct ResultadoDecidir {
    pub veredicto: &'static str,
    pub codigo: String,
    pub sistema_id: String,
    pub clase: String,
    pub nivel_en_instante: String,
    pub mango: Option<String>,
}

/// Resultado de ejercicio EF-1 (B3).
#[derive(Debug, Clone)]
pub struct ResultadoEjercer {
    pub ok: bool,
    pub codigo: String,
    pub recibo_digest_hex: Option<String>,
}

/// Backend EF-1: simulado (default) o loopback autenticado (solo probe-mediado).
enum BackendEf1 {
    Simulado(ProveedorSimulado),
    Loopback(ProveedorLoopbackEf1),
    Nvidia(ProveedorNvidiaEf1),
}

impl ProveedorModelo for BackendEf1 {
    fn inferir_delegado(
        &mut self,
        solicitud: &sak_core::pep::SolicitudInferencia,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<sak_core::pep::RespuestaModelo, sak_core::pep::ErrorProveedor> {
        match self {
            BackendEf1::Simulado(p) => p.inferir_delegado(solicitud, digest_autorizado),
            BackendEf1::Loopback(p) => p.inferir_delegado(solicitud, digest_autorizado),
            BackendEf1::Nvidia(p) => p.inferir_delegado(solicitud, digest_autorizado),
        }
    }
}

pub struct FronteraSujeto {
    ledger: LedgerEvidencia<MemoriaDurable>,
    mangos: BTreeMap<String, Capability>,
    gateway: GatewayModelos,
    proveedor: BackendEf1,
    reloj: RelojInyectado,
    ahora: Ticks,
    seq_norma: u64,
}

impl FronteraSujeto {
    /// Harness / memoria: siempre `ProveedorSimulado` (sin leer env de loopback).
    pub fn nueva() -> Result<Self, String> {
        Self::desde_backend(BackendEf1::Simulado(ProveedorSimulado::nuevo(
            CredencialProveedor::desde_semilla([0x42; 32]),
        )))
    }

    /// Dominio durable: loopback solo si `dominio_id == "probe-mediado"` y existen
    /// `SAK_PROBE_MEDIADO_LOOPBACK` + `SAK_PROBE_MEDIADO_LOOPBACK_KEY`.
    /// Para `piloto-telegram-nvidia`: fail-closed; si falta la clave, devuelve error.
    pub fn nueva_para_dominio(dominio_id: &str) -> Result<Self, String> {
        if dominio_id == "probe-mediado" {
            if let Ok(raw) = std::env::var("SAK_PROBE_MEDIADO_LOOPBACK") {
                let raw = raw.trim();
                if !raw.is_empty() {
                    let addr: SocketAddr = raw
                        .parse()
                        .map_err(|e| format!("SAK_PROBE_MEDIADO_LOOPBACK: {e}"))?;
                    let clave_hex = std::env::var("SAK_PROBE_MEDIADO_LOOPBACK_KEY")
                        .map_err(|_| "SAK_PROBE_MEDIADO_LOOPBACK_KEY ausente".to_string())?;
                    let clave = parse_clave_hex(&clave_hex)?;
                    return Self::nueva_loopback(addr, HANDLE_EF1_PROBE_MEDIADO, clave);
                }
            }
        }
        // Fail-closed: dominio piloto-telegram-nvidia requiere SAK_PILOTO_NVIDIA_KEY.
        if dominio_id == "piloto-telegram-nvidia" {
            let prov = ProveedorNvidiaEf1::desde_env()
                .map_err(|e| format!("piloto-telegram-nvidia: {e}"))?;
            return Self::desde_backend(BackendEf1::Nvidia(prov));
        }
        Self::nueva()
    }

    /// Corte 2A / tests: EF-1 contra mock loopback con handle y clave efímera.
    pub fn nueva_loopback(
        addr: SocketAddr,
        handle: &str,
        clave: [u8; 32],
    ) -> Result<Self, String> {
        if !addr.ip().is_loopback() {
            return Err("loopback EF-1 exige destino 127.0.0.1".into());
        }
        Self::desde_backend(BackendEf1::Loopback(ProveedorLoopbackEf1::nuevo(
            addr, handle, clave,
        )))
    }

    fn desde_backend(proveedor: BackendEf1) -> Result<Self, String> {
        Ok(Self {
            ledger: LedgerEvidencia::nuevo(MemoriaDurable::default())
                .map_err(|e| format!("ledger: {e}"))?,
            mangos: BTreeMap::new(),
            gateway: GatewayModelos::nuevo(1),
            proveedor,
            reloj: RelojInyectado::nuevo(1_000),
            ahora: 1_000,
            seq_norma: 0,
        })
    }

    pub fn es_loopback_ef1(&self) -> bool {
        matches!(self.proveedor, BackendEf1::Loopback(_))
    }

    pub fn n_mangos(&self) -> usize {
        self.mangos.len()
    }

    /// B1: pasaporte + puerta Libro + motor. B2: si ALLOW EF-1 → emisión interna.
    pub fn decidir_y_emitir_si_allow(
        &mut self,
        registro: &RegistroSoberano,
        libro: &LibroControl,
        epoca: &EpocaMonotonica,
        sistema_id: &str,
        clase: ClaseEfecto,
        digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
        datos_personales: bool,
    ) -> Result<ResultadoDecidir, String> {
        if clase == ClaseEfecto::Ef12 {
            return Ok(ResultadoDecidir {
                veredicto: "DENY",
                codigo: "EF12_IA".into(),
                sistema_id: sistema_id.into(),
                clase: "EF-12".into(),
                nivel_en_instante: "-".into(),
                mango: None,
            });
        }

        let sid = IdSistema::nuevo(sistema_id).map_err(|e| e.to_string())?;
        if registro.version_activa(sistema_id).is_none() {
            return Ok(ResultadoDecidir {
                veredicto: "DENY",
                codigo: "SIN_PASAPORTE".into(),
                sistema_id: sistema_id.into(),
                clase: token_clase(clase).into(),
                nivel_en_instante: "-".into(),
                mango: None,
            });
        }

        let efecto = EfectoTipado::nuevo(clase, digest_parametros);
        let hash_peticion = [0u8; LONGITUD_HASH_PAQUETE];
        let ctx = Contexto::nuevo(efecto, vec![], hash_peticion);
        let perfil = self.perfil_allow(clase)?;
        let dc = decidir_con_libro(
            &ctx,
            &perfil,
            libro,
            &sid,
            datos_personales,
            self.ahora,
        );

        let nivel = format!("{:?}", dc.nivel_en_instante);
        match dc.decision {
            Decision::Denegada(d) => Ok(ResultadoDecidir {
                veredicto: "DENY",
                codigo: format!("{:?}", d.codigo()),
                sistema_id: sistema_id.into(),
                clase: token_clase(clase).into(),
                nivel_en_instante: nivel,
                mango: None,
            }),
            Decision::Escalada(_) => Ok(ResultadoDecidir {
                veredicto: "DENY",
                codigo: "ESCALADA".into(),
                sistema_id: sistema_id.into(),
                clase: token_clase(clase).into(),
                nivel_en_instante: nivel,
                mango: None,
            }),
            Decision::Suspendida(_) => Ok(ResultadoDecidir {
                veredicto: "DENY",
                codigo: "SUSPENDIDA".into(),
                sistema_id: sistema_id.into(),
                clase: token_clase(clase).into(),
                nivel_en_instante: nivel,
                mango: None,
            }),
            Decision::Permitida(perm) => {
                if clase != ClaseEfecto::Ef1 {
                    return Ok(ResultadoDecidir {
                        veredicto: "ALLOW",
                        codigo: "ALLOW_SIN_EJERCICIO".into(),
                        sistema_id: sistema_id.into(),
                        clase: token_clase(clase).into(),
                        nivel_en_instante: nivel,
                        mango: None,
                    });
                }
                let sujeto =
                    IdSujeto::nuevo(format!("suj-{sistema_id}")).map_err(|e| e.to_string())?;
                let params = ParametrosEmision {
                    sistema: sid,
                    digest_efecto: digest_parametros,
                    alcance: alcance_ef1(),
                    epoca: epoca.actual(),
                    epoca_suelo: epoca.suelo(),
                    ttl_ticks: 60_000,
                    clasificacion: ClasificacionEfecto::irreversible(),
                };
                let cap = self
                    .ledger
                    .emitir_tras_evidencia(&sujeto, perm, params, &self.reloj)
                    .map_err(|e| format!("emitir: {e}"))?;
                let mango = hex_bytes(cap.id().as_bytes());
                self.mangos.insert(mango.clone(), cap);
                Ok(ResultadoDecidir {
                    veredicto: "ALLOW",
                    codigo: "ALLOW_EMITIDO".into(),
                    sistema_id: sistema_id.into(),
                    clase: token_clase(clase).into(),
                    nivel_en_instante: nivel,
                    mango: Some(mango),
                })
            }
        }
    }

    /// B3 — ejercer EF-1; credencial del proveedor no se expone.
    pub fn ejercer_ef1(
        &mut self,
        sistema_id: &str,
        mango: &str,
        modelo_id: &str,
        digest_parametros: [u8; LONGITUD_HASH_PAQUETE],
        max_tokens: u32,
    ) -> Result<ResultadoEjercer, String> {
        let sid = IdSistema::nuevo(sistema_id).map_err(|e| e.to_string())?;
        let sujeto = IdSujeto::nuevo(format!("suj-{sistema_id}")).map_err(|e| e.to_string())?;
        let Some(cap) = self.mangos.get(mango).cloned() else {
            return Ok(ResultadoEjercer {
                ok: false,
                codigo: "MANGO_AUSENTE".into(),
                recibo_digest_hex: None,
            });
        };
        let (sol, _) = preparar_solicitud(modelo_id, digest_parametros, max_tokens, 0);
        let r = self.gateway.ejercer(
            &SolicitudCruda::Tipada(sol),
            Some(&cap),
            &sid,
            &sujeto,
            &mut self.ledger,
            &mut self.proveedor,
            &self.reloj,
            1,
        );
        self.mangos.remove(mango);
        match r {
            ResultadoPep::Permitido(resp) => Ok(ResultadoEjercer {
                ok: true,
                codigo: "RECIBO_OK".into(),
                recibo_digest_hex: Some(hex_bytes(&resp.recibo.digest_parametros)),
            }),
            ResultadoPep::Denegado { codigo } => Ok(ResultadoEjercer {
                ok: false,
                codigo: format!("{codigo:?}"),
                recibo_digest_hex: None,
            }),
        }
    }

    fn perfil_allow(&mut self, clase: ClaseEfecto) -> Result<PerfilNormativo, String> {
        self.seq_norma += 1;
        let hash = HashPaqueteNormativo::desde_bytes([0xB1; LONGITUD_HASH_PAQUETE]);
        let id = IdNorma::nueva(format!("B-NORM-{}", self.seq_norma)).map_err(|e| e.to_string())?;
        let norma = NormaMinima::nueva(
            id,
            Rango::P2,
            clase,
            PredicadoMinimo::Constante(Veredicto::Allow),
            false,
        );
        Ok(PerfilNormativo::nuevo(hash, vec![norma], false))
    }
}

fn token_clase(c: ClaseEfecto) -> &'static str {
    match c {
        ClaseEfecto::Ef1 => "EF-1",
        ClaseEfecto::Ef2 => "EF-2",
        ClaseEfecto::Ef3 => "EF-3",
        ClaseEfecto::Ef4 => "EF-4",
        ClaseEfecto::Ef5 => "EF-5",
        ClaseEfecto::Ef6 => "EF-6",
        ClaseEfecto::Ef7 => "EF-7",
        ClaseEfecto::Ef8 => "EF-8",
        ClaseEfecto::Ef9 => "EF-9",
        ClaseEfecto::Ef10 => "EF-10",
        ClaseEfecto::Ef11 => "EF-11",
        ClaseEfecto::Ef12 => "EF-12",
    }
}

fn hex_bytes(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn resultado_decidir_json(r: &ResultadoDecidir) -> String {
    format!(
        r#"{{"veredicto":"{}","codigo":"{}","sistema_id":"{}","clase":"{}","nivel_en_instante":"{}","mango":{},"material":null,"nota":"UI no emite; emisor=Kernel"}}"#,
        r.veredicto,
        esc(&r.codigo),
        esc(&r.sistema_id),
        esc(&r.clase),
        esc(&r.nivel_en_instante),
        r.mango
            .as_ref()
            .map(|m| format!("\"{}\"", esc(m)))
            .unwrap_or_else(|| "null".into()),
    )
}

pub fn resultado_ejercer_json(r: &ResultadoEjercer) -> String {
    format!(
        r#"{{"ok":{},"codigo":"{}","recibo_digest_hex":{},"material":null}}"#,
        r.ok,
        esc(&r.codigo),
        r.recibo_digest_hex
            .as_ref()
            .map(|h| format!("\"{}\"", esc(h)))
            .unwrap_or_else(|| "null".into()),
    )
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// B4 — espejo IPC (misma cadena; UI no es emisor).
pub fn manejar_diagnostico(estado: &mut EstadoOps, op: &str, req_id: &str, raw: &str) -> RespuestaOps {
    match op {
        "obs.diagnostico.decidir" => {
            let sistema = match campo_str_raw(raw, "sistema_id").or_else(|| campo_str_raw(raw, "sistema"))
            {
                Some(s) => s,
                None => return RespuestaOps::deny(req_id, "SCHEMA", "falta sistema_id"),
            };
            let clase = match campo_str_raw(raw, "clase").as_deref() {
                Some("EF-1") | Some("ef1") | None => ClaseEfecto::Ef1,
                Some("EF-12") => ClaseEfecto::Ef12,
                Some(o) => {
                    return RespuestaOps::deny(
                        req_id,
                        "CLASE_MVP",
                        &format!("MVP Bloque B solo EF-1; got {o}"),
                    );
                }
            };
            let digest = digest_desde_raw(raw);
            let r = {
                let EstadoOps {
                    ref mut frontera,
                    ref registro,
                    ref libro,
                    ref epoca,
                    ..
                } = *estado;
                match frontera.decidir_y_emitir_si_allow(
                    registro,
                    libro,
                    epoca,
                    &sistema,
                    clase,
                    digest,
                    false,
                ) {
                    Ok(x) => x,
                    Err(e) => return RespuestaOps::deny(req_id, "ERROR", &e),
                }
            };
            if r.veredicto == "ALLOW" {
                RespuestaOps::ok(
                    req_id,
                    "DIAG_DECIDIR",
                    &resultado_decidir_json(&r),
                    vec!["no_comprobado", "diagnostico≠autoridad_ui"],
                )
            } else {
                RespuestaOps::deny(
                    req_id,
                    &r.codigo,
                    "decisión DENY (cadena H / pasaporte / control)",
                )
            }
        }
        "obs.diagnostico.ejercer" => {
            let sistema = match campo_str_raw(raw, "sistema_id").or_else(|| campo_str_raw(raw, "sistema"))
            {
                Some(s) => s,
                None => return RespuestaOps::deny(req_id, "SCHEMA", "falta sistema_id"),
            };
            let mango = match campo_str_raw(raw, "mango").or_else(|| campo_str_raw(raw, "cap_id")) {
                Some(m) => m,
                None => return RespuestaOps::deny(req_id, "SCHEMA", "falta mango/cap_id"),
            };
            let modelo = campo_str_raw(raw, "modelo_id").unwrap_or_else(|| "modelo-harness".into());
            let digest = digest_desde_raw(raw);
            let max_tokens = crate::ops::schema::campo_u32_raw(raw, "max_tokens").unwrap_or(32);
            let r = match estado
                .frontera
                .ejercer_ef1(&sistema, &mango, &modelo, digest, max_tokens)
            {
                Ok(x) => x,
                Err(e) => return RespuestaOps::deny(req_id, "ERROR", &e),
            };
            if r.ok {
                RespuestaOps::ok(
                    req_id,
                    "DIAG_EJERCER",
                    &resultado_ejercer_json(&r),
                    vec!["no_comprobado", "material:null"],
                )
            } else {
                RespuestaOps::deny(req_id, &r.codigo, "ejercicio DENY")
            }
        }
        _ => RespuestaOps::deny(req_id, "OP_DESCONOCIDA", "diagnostico no manejado"),
    }
}

fn digest_desde_raw(raw: &str) -> [u8; LONGITUD_HASH_PAQUETE] {
    if let Some(h) = campo_str_raw(raw, "digest_parametros_hex") {
        let mut out = [0u8; LONGITUD_HASH_PAQUETE];
        let bytes = hex_decode(&h);
        let n = bytes.len().min(LONGITUD_HASH_PAQUETE);
        out[..n].copy_from_slice(&bytes[..n]);
        return out;
    }
    [0xD1; LONGITUD_HASH_PAQUETE]
}

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
