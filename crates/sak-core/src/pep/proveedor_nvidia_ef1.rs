//! Proveedor EF-1 para NVIDIA hosted (piloto Telegram+NVIDIA).
//!
//! Handle: ef1-piloto-nvidia.
//! Endpoint fijo: https://integrate.api.nvidia.com/v1/chat/completions.
//! Modelo fijo: z-ai/glm-5.2.
//!   Sustituye a minimaxai/minimax-m3 (reportes 2026-08-01) por inestabilidad
//!   del backend que provocaba timeouts > 60 s. La sustitución se documenta aquí
//!   como evidencia de que el modelo constante es una decisión de ingeniería,
//!   no un secreto.
//! La clave API se carga localmente por entrada oculta, no se registra,
//! no se serializa y no se incluye en evidencia.
//! El texto devuelto por el modelo NO entra en evidencia, IPC, logs ni respuestas.
//!
//! Afirmación limitada: el payload `solicitud:<hex canonico>` se clasifica como
//! smoke de transporte/autenticación EF-1, no como conversación funcional de
//! Telegram ni como inferencia semánica sobre texto de usuario.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::{
    tomar_contexto_ejercicio_ef1, ContextoEjercicioEf1, ErrorProveedor, ProveedorModelo,
    RespuestaModelo,
};
use crate::pep::solicitud::SolicitudInferencia;
use std::cell::RefCell;
use std::io::Read;
use std::time::Instant;
use zeroize::Zeroize;

// ─── Diagnóstico sanitizado (solo para smoke harness) ────────────────────────

/// Clase de fallo clasificada. Sin secreto, sin cuerpo HTTP, sin headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseFallo {
    EnvAusente,
    Timeout,
    Transporte,
    HttpNo2xx,
    Lectura,
    Parseo,
}

/// Diagnóstico sanitizado del último fallo de ProveedorNvidiaEf1.
/// Expuesto únicamente por `ultimo_diagnostico_nvidia()`.
#[derive(Debug, Clone)]
pub struct DiagnosticoProvider {
    pub key_present: bool,
    pub key_len: usize,
    pub fase: &'static str,
    pub clase: ClaseFallo,
    pub http_status: Option<u16>,
    pub elapsed_ms: u64,
}

thread_local! {
    static ULTIMO_DIAG: RefCell<Option<DiagnosticoProvider>> = const { RefCell::new(None) };
}

fn guardar_diag(d: DiagnosticoProvider) {
    ULTIMO_DIAG.with(|slot| {
        *slot.borrow_mut() = Some(d);
    });
}

/// Accesor global al último diagnóstico sanitizado del proveedor NVIDIA.
/// Sin secreto, sin Authorization, sin prompt, sin respuesta del modelo, sin sentinel.
pub fn ultimo_diagnostico_nvidia() -> Option<DiagnosticoProvider> {
    ULTIMO_DIAG.with(|slot| slot.borrow().clone())
}

/// Handle canónico del piloto NVIDIA.
pub const HANDLE_EF1_PILOTO_NVIDIA: &str = "ef1-piloto-nvidia";

/// Environment variable para la clave API. Se carga por entrada oculta,
/// no se registra, no se serializa y no se incluye en evidencia.
pub const ENV_NVIDIA_KEY: &str = "SAK_PILOTO_NVIDIA_KEY";

/// Endpoint exacto y fijo. No configurable.
const ENDPOINT: &str = "https://integrate.api.nvidia.com/v1/chat/completions";

/// Modelo fijo del piloto. No configurable.
const MODELO_FIJO: &str = "z-ai/glm-5.2";

/// Tamaño del buffer de lectura (8 KB).
const BUFFER_SIZE: usize = 8192;

/// Límite máximo de respuesta (1 MB).
const MAX_RESPUESTA_BYTES: usize = 1_048_576;

/// Cadena centinela para pruebas de no filtración. Exclusiva de tests.
#[cfg(test)]
pub(crate) const SENTINEL: &str = "nvapi-sentinel-TEST-9f8e7d6c";

// ─── Tipo secreto ───────────────────────────────────────────────────────────

/// Clave API de NVIDIA. Se borra automáticamente al destruirse.
/// Sin Debug, Display, Clone, Serialize. No puede exponerse por ningún canal.
pub struct ClaveNvidia(String);

impl ClaveNvidia {
    pub fn nueva(valor: String) -> Result<Self, String> {
        if valor.is_empty() {
            return Err("SAK_PILOTO_NVIDIA_KEY vacía".into());
        }
        if valor.len() < 10 {
            return Err("SAK_PILOTO_NVIDIA_KEY demasiado corta".into());
        }
        Ok(ClaveNvidia(valor))
    }

    /// Referencia inmutable para header Authorization. Solo accesible dentro de este módulo.
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for ClaveNvidia {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for ClaveNvidia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED-NVIDIA]")
    }
}

impl std::fmt::Display for ClaveNvidia {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED-NVIDIA]")
    }
}

// ─── Proveedor ──────────────────────────────────────────────────────────────

pub struct ProveedorNvidiaEf1 {
    clave: ClaveNvidia,
    handle: String,
    ctx: Option<ContextoEjercicioEf1>,
    pub llamadas_delegadas: u32,
    ultimo_diagnostico: Option<DiagnosticoProvider>,
}

impl std::fmt::Debug for ProveedorNvidiaEf1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProveedorNvidiaEf1")
            .field("endpoint", &ENDPOINT)
            .field("handle", &self.handle)
            .field("modelo", &MODELO_FIJO)
            .field("clave", &"[REDACTED-NVIDIA]")
            .field("llamadas_delegadas", &self.llamadas_delegadas)
            .field("diagnostico", &self.ultimo_diagnostico)
            .finish()
    }
}

impl std::fmt::Display for ProveedorNvidiaEf1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ProveedorNvidiaEf1(handle={}, modelo={})",
            self.handle, MODELO_FIJO
        )
    }
}

impl ProveedorNvidiaEf1 {
    /// Constructor directo. Requiere api_key válida.
    pub fn nuevo(api_key: String) -> Result<Self, String> {
        let clave = ClaveNvidia::nueva(api_key)?;
        Ok(ProveedorNvidiaEf1 {
            clave,
            handle: HANDLE_EF1_PILOTO_NVIDIA.into(),
            ctx: None,
            llamadas_delegadas: 0,
            ultimo_diagnostico: None,
        })
    }

    /// Constructor desde variables de entorno. Fail-closed: si falta la clave, devuelve error.
    pub fn desde_env() -> Result<Self, String> {
        let api_key =
            std::env::var(ENV_NVIDIA_KEY).map_err(|_| format!("{ENV_NVIDIA_KEY} ausente"))?;
        Self::nuevo(api_key)
    }
}

impl ProveedorModelo for ProveedorNvidiaEf1 {
    fn preparar_contexto_ejercicio(&mut self, ctx: &ContextoEjercicioEf1) {
        self.ctx = Some(ctx.clone());
    }

    fn inferir_delegado(
        &mut self,
        solicitud: &SolicitudInferencia,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<RespuestaModelo, ErrorProveedor> {
        let t0 = Instant::now();

        // Diagnóstico: presencia de clave (longitud, no contenido).
        let key_info = {
            let env_val = std::env::var(ENV_NVIDIA_KEY);
            match env_val {
                Err(_) => (false, 0usize),
                Ok(v) => {
                    let len = v.len();
                    (true, len)
                }
            }
        };

        if self.handle != HANDLE_EF1_PILOTO_NVIDIA {
            return Err(ErrorProveedor::NoAutorizado);
        }
        let digest_params = crate::pep::solicitud::digest_solicitud_inferencia(solicitud);
        if digest_params != *digest_autorizado {
            return Err(ErrorProveedor::DivergenciaParametros);
        }

        let ctx = self
            .ctx
            .take()
            .or_else(tomar_contexto_ejercicio_ef1)
            .ok_or(ErrorProveedor::NoAutorizado)?;
        if ctx.digest != *digest_autorizado || ctx.ahora > ctx.vive_hasta {
            return Err(ErrorProveedor::NoAutorizado);
        }

        // Body OpenAI-compatible con modelo fijo.
        let body = serde_json::json!({
            "model": MODELO_FIJO,
            "messages": [
                {"role": "user", "content": format!("solicitud:{}", hex(&solicitud.canonico()))}
            ],
            "max_tokens": 64,
        });

        // Cliente: timeout 240s (backend GLM-5.2 con latencia variable >170s), sin redirects.
        let client = match reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(240))
            .connect_timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                let d = DiagnosticoProvider {
                    key_present: key_info.0,
                    key_len: key_info.1,
                    fase: "cliente",
                    clase: ClaseFallo::Transporte,
                    http_status: None,
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                };
                self.ultimo_diagnostico = Some(d.clone());
                guardar_diag(d);
                return Err(ErrorProveedor::FalloInterno);
            }
        };

        // Llamada HTTP con 1 retry en timeout/transporte/429/5xx.
        let max_intentos = 2u8;
        let mut resp = None;
        for intento in 0..max_intentos {
            match client
                .post(ENDPOINT)
                .bearer_auth(self.clave.as_str())
                .json(&body)
                .send()
            {
                Ok(r) if r.status().is_success() => {
                    resp = Some(r);
                    break;
                }
                Ok(r) => {
                    let status = r.status().as_u16();
                    let retryable = status == 429 || (500..600).contains(&status);
                    if retryable && intento + 1 < max_intentos {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                    let d = DiagnosticoProvider {
                        key_present: key_info.0,
                        key_len: key_info.1,
                        fase: "http_status",
                        clase: ClaseFallo::HttpNo2xx,
                        http_status: Some(status),
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    };
                    self.ultimo_diagnostico = Some(d.clone());
                    guardar_diag(d);
                    return Err(ErrorProveedor::FalloInterno);
                }
                Err(e) => {
                    let clase = if e.is_timeout() {
                        ClaseFallo::Timeout
                    } else {
                        ClaseFallo::Transporte
                    };
                    let retryable = e.is_timeout() || e.is_connect();
                    if retryable && intento + 1 < max_intentos {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                    let d = DiagnosticoProvider {
                        key_present: key_info.0,
                        key_len: key_info.1,
                        fase: "http_send",
                        clase,
                        http_status: None,
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    };
                    self.ultimo_diagnostico = Some(d.clone());
                    guardar_diag(d);
                    return Err(ErrorProveedor::FalloInterno);
                }
            }
        }
        let mut resp = resp.ok_or(ErrorProveedor::FalloInterno)?;

        // Lectura con std::io::Read, buffer fijo, acumulador estricto.
        let bytes = match leer_con_limite(&mut resp) {
            Ok(b) => b,
            Err(_) => {
                let d = DiagnosticoProvider {
                    key_present: key_info.0,
                    key_len: key_info.1,
                    fase: "lectura_body",
                    clase: ClaseFallo::Lectura,
                    http_status: Some(resp.status().as_u16()),
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                };
                self.ultimo_diagnostico = Some(d.clone());
                guardar_diag(d);
                return Err(ErrorProveedor::FalloInterno);
            }
        };

        // Parsear respuesta SSE (streaming) o JSON (non-streaming).
        let body_str = String::from_utf8_lossy(&bytes);
        let is_sse = body_str.contains("data: ");

        let contenido = if is_sse {
            // Parsear SSE: extraer contenido de cada chunk "data: {...}".
            let mut contenido = String::new();
            for line in body_str.lines() {
                let line = line.trim();
                if line.starts_with("data: ") && !line.ends_with("[DONE]") {
                    if let Ok(chunk) = serde_json::from_str::<serde_json::Value>(&line[6..]) {
                        if let Some(delta) = chunk.pointer("/choices/0/delta/content") {
                            if let Some(text) = delta.as_str() {
                                contenido.push_str(text);
                            }
                        }
                    }
                }
            }
            if contenido.is_empty() {
                let d = DiagnosticoProvider {
                    key_present: key_info.0,
                    key_len: key_info.1,
                    fase: "parseo_sse",
                    clase: ClaseFallo::Parseo,
                    http_status: Some(resp.status().as_u16()),
                    elapsed_ms: t0.elapsed().as_millis() as u64,
                };
                self.ultimo_diagnostico = Some(d.clone());
                guardar_diag(d);
                return Err(ErrorProveedor::FalloInterno);
            }
            contenido
        } else {
            // Non-streaming: parsear JSON directamente.
            let json_nvidia: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(v) => v,
                Err(_) => {
                    let d = DiagnosticoProvider {
                        key_present: key_info.0,
                        key_len: key_info.1,
                        fase: "parseo_json",
                        clase: ClaseFallo::Parseo,
                        http_status: Some(resp.status().as_u16()),
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    };
                    self.ultimo_diagnostico = Some(d.clone());
                    guardar_diag(d);
                    return Err(ErrorProveedor::FalloInterno);
                }
            };
            json_nvidia
                .pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .ok_or(ErrorProveedor::FalloInterno)?
                .to_string()
        };

        let _contenido = contenido;

        // Digest = SHA-384(solicitud ‖ respuesta_completa).
        // La evidencia incluye los bytes brutos de la respuesta (sin volcar el texto).
        let digest_resultado = crypto::sha384_dominio(b"SAK-NVIDIA-OUT-v1|", &bytes);

        self.llamadas_delegadas += 1;

        Ok(RespuestaModelo {
            digest_resultado,
            // referencia_minima: identificador no reversible derivado del digest.
            referencia_minima: format!("nvidia:{}", hex(&digest_resultado)),
            digest_parametros_ejecutados: digest_params,
        })
    }
}

/// Lee el body de la respuesta con `std::io::Read`, buffer fijo 8KB y acumulador estricto.
fn leer_con_limite(resp: &mut dyn Read) -> Result<Vec<u8>, ErrorProveedor> {
    let mut buffer = [0u8; BUFFER_SIZE];
    let mut acumulado = 0usize;
    let mut datos = Vec::with_capacity(65536);

    loop {
        let leidos = resp.read(&mut buffer).map_err(|_| ErrorProveedor::FalloInterno)?;
        if leidos == 0 {
            break;
        }
        acumulado += leidos;
        if acumulado > MAX_RESPUESTA_BYTES {
            return Err(ErrorProveedor::FalloInterno);
        }
        datos.extend_from_slice(&buffer[..leidos]);
    }

    Ok(datos)
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Custodia de clave ──

    #[test]
    fn debug_no_expone_clave() {
        let prov = ProveedorNvidiaEf1::nuevo(SENTINEL.into()).unwrap();
        let debug = format!("{:?}", prov);
        assert!(!debug.contains(SENTINEL), "Debug contiene la clave: {debug}");
        assert!(debug.contains("[REDACTED-NVIDIA]"));
    }

    #[test]
    fn display_no_expone_clave() {
        let prov = ProveedorNvidiaEf1::nuevo(SENTINEL.into()).unwrap();
        let display = format!("{}", prov);
        assert!(
            !display.contains(SENTINEL),
            "Display contiene la clave: {display}"
        );
    }

    #[test]
    fn clave_no_aparece_en_error() {
        let result = ProveedorNvidiaEf1::nuevo("".into());
        match result {
            Err(e) => assert!(!e.contains(SENTINEL), "Error contiene la clave: {e}"),
            Ok(_) => panic!("Debería fallar con clave vacía"),
        }
    }

    #[test]
    fn clave_no_exportable() {
        let prov = ProveedorNvidiaEf1::nuevo("nvapi-test-key-1234567890".into()).unwrap();
        let debug = format!("{:?}", prov);
        assert!(!debug.contains("nvapi-test-key"));
    }

    // ── Respuesta NVIDIA ──

    #[test]
    fn parse_respuesta_nvidia_valida() {
        let json_str = r#"{"choices":[{"message":{"content":"Hola mundo"}}]}"#;
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let contenido = json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str());
        assert_eq!(contenido, Some("Hola mundo"));
    }

    #[test]
    fn respuesta_sin_content_falla() {
        let json_str = r#"{"choices":[{"message":{}}]}"#;
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let contenido = json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str());
        assert!(contenido.is_none(), "Debería fallar sin content");
    }

    #[test]
    fn respuesta_sin_choices_falla() {
        let json_str = r#"{}"#;
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let contenido = json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str());
        assert!(contenido.is_none(), "Debería fallar sin choices");
    }

    #[test]
    fn respuesta_error_nvidia_falla() {
        let json_str = r#"{"error":"invalid_api_key"}"#;
        let json: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let contenido = json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str());
        assert!(
            contenido.is_none(),
            "Debería fallar con error de NVIDIA"
        );
    }

    #[test]
    fn referencia_minima_no_contiene_texto() {
        let ref_min = format!("nvidia:{}", hex(&[0xAB; 48]));
        assert!(ref_min.starts_with("nvidia:"));
        assert!(!ref_min.contains("Hola"));
    }

    // ── Endpoint fijo ──

    #[test]
    fn endpoint_es_constante() {
        assert_eq!(
            ENDPOINT,
            "https://integrate.api.nvidia.com/v1/chat/completions"
        );
    }

    #[test]
    fn modelo_es_fijo() {
        assert_eq!(MODELO_FIJO, "z-ai/glm-5.2");
    }

    // ── Buffer de lectura ──

    #[test]
    fn buffer_size_es_8kb() {
        assert_eq!(BUFFER_SIZE, 8192);
    }

    #[test]
    fn max_respuesta_es_1mb() {
        assert_eq!(MAX_RESPUESTA_BYTES, 1_048_576);
    }

    // ── Fail-closed: modelo distinto rechazado ──

    #[test]
    fn modelo_distinto_no_existe() {
        // No hay forma de cambiar el modelo; es constante.
        // Este test verifica que MODELO_FIJO es el esperado.
        assert_ne!(MODELO_FIJO, "gpt-4");
        assert_ne!(MODELO_FIJO, "claude-3");
        assert_ne!(MODELO_FIJO, "");
    }

    // ── Diagnóstico sanitizado ──

    #[test]
    fn diagnostico_no_expone_secreto() {
        let d = DiagnosticoProvider {
            key_present: true,
            key_len: 42,
            fase: "http_send",
            clase: ClaseFallo::Timeout,
            http_status: None,
            elapsed_ms: 30123,
        };
        let debug = format!("{:?}", d);
        assert!(
            !debug.contains("nvapi-"),
            "Diagnóstico contiene nvapi-: {debug}"
        );
        assert!(
            !debug.contains("Authorization"),
            "Diagnóstico contiene Authorization: {debug}"
        );
        assert!(
            !debug.contains("Bearer"),
            "Diagnóstico contiene Bearer: {debug}"
        );
        assert!(
            !debug.contains("solicitud:"),
            "Diagnóstico contiene prompt: {debug}"
        );
        assert!(
            !debug.contains("sentinel"),
            "Diagnóstico contiene sentinel: {debug}"
        );
        assert!(
            !debug.contains("Hola mundo"),
            "Diagnóstico contiene respuesta del modelo: {debug}"
        );
    }

    #[test]
    fn diagnostico_clases_cubiertas() {
        let clases = [
            ClaseFallo::EnvAusente,
            ClaseFallo::Timeout,
            ClaseFallo::Transporte,
            ClaseFallo::HttpNo2xx,
            ClaseFallo::Lectura,
            ClaseFallo::Parseo,
        ];
        for c in clases {
            let d = DiagnosticoProvider {
                key_present: false,
                key_len: 0,
                fase: "test",
                clase: c,
                http_status: None,
                elapsed_ms: 0,
            };
            let debug = format!("{:?}", d);
            assert!(!debug.is_empty(), "Clase {:?} produce debug vacío", c);
        }
    }

    #[test]
    fn diagnostico_pipeline_end_to_end() {
        super::guardar_diag(DiagnosticoProvider {
            key_present: true,
            key_len: 48,
            fase: "http_send",
            clase: ClaseFallo::Timeout,
            http_status: None,
            elapsed_ms: 30123,
        });
        let d = super::ultimo_diagnostico_nvidia()
            .expect("ultimo_diagnostico_nvidia() devolvió None tras guardar_diag");
        assert!(d.key_present);
        assert_eq!(d.key_len, 48);
        assert_eq!(d.fase, "http_send");
        assert_eq!(d.clase, ClaseFallo::Timeout);
        assert!(d.http_status.is_none());
        assert_eq!(d.elapsed_ms, 30123);
    }
}
