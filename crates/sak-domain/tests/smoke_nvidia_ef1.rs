use std::time::Duration;
use sak_core::pep::{GatewayModelos, ProveedorSimulado};

#[test]
fn smoke_nvidia_ef1_cadena_completa() {
    use sak_core::capacidad::ClasificacionEfecto;
    use sak_core::decision::{
        DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
    };
    use sak_core::evidencia::{IdSujeto, LedgerEvidencia, MemoriaDurable};
    use sak_core::identidad::IdSistema;
    use sak_core::pep::{
        alcance_ef1, preparar_solicitud, CodigoPep, CredencialProveedor, SolicitudCruda,
    };
    use sak_core::reloj::RelojInyectado;

    let reloj = RelojInyectado::nuevo(100);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sistema = IdSistema::nuevo("smoke-nvidia").unwrap();
    let sujeto = IdSujeto::nuevo("suj-smoke").unwrap();

    let hash = HashPaqueteNormativo::desde_bytes([1u8; LONGITUD_HASH_PAQUETE]);
    let traza = TrazaPrecedencia::nueva(
        vec![IdNorma::nueva("N-SMOKE-1".to_string()).unwrap()],
        vec![],
        1,
    )
    .unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();

    let (sol, digest) = preparar_solicitud("z-ai/glm-5.2", [2u8; LONGITUD_HASH_PAQUETE], 64, 200);

    let params = sak_core::capacidad::ParametrosEmision {
        sistema: sistema.clone(),
        digest_efecto: digest,
        alcance: alcance_ef1(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap = ledger
        .emitir_tras_evidencia(&sujeto, decision, params, &reloj)
        .unwrap();

    let mut gateway = GatewayModelos::nuevo(1);
    let mut prov = ProveedorSimulado::nuevo(CredencialProveedor::desde_semilla([5u8; 32]));

    let r1 = gateway.ejercer(
        &SolicitudCruda::Tipada(sol.clone()),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    match r1 {
        sak_core::pep::ResultadoPep::Permitido(resp) => {
            println!("OK: digest_parametros={:?}", resp.recibo.digest_parametros);
            assert_eq!(resp.recibo.digest_parametros, digest);
        }
        other => panic!("esperado permitido: {other:?}"),
    }
    assert_eq!(prov.llamadas_delegadas, 1);

    // Segunda llamada: capability ya consumida.
    let r2 = gateway.ejercer(
        &SolicitudCruda::Tipada(sol),
        Some(&cap),
        &sistema,
        &sujeto,
        &mut ledger,
        &mut prov,
        &reloj,
        1,
    );
    println!("r2={:?}", r2);
    // La capability fue consumida en el primer intento; la segunda debe denegar.
    assert!(matches!(r2, sak_core::pep::ResultadoPep::Denegado { .. }));
    assert_eq!(prov.llamadas_delegadas, 1);

    println!("smoke_nvidia_ef1_cadena_completa: PASS");
}

#[tokio::test]
#[ignore]
async fn manual_minima_post_pong() {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client build");

    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY")
        .expect("SAK_PILOTO_NVIDIA_KEY no definida");

    let body = serde_json::json!({
        "model": "z-ai/glm-5.2",
        "messages": [{"role": "user", "content": "pong"}],
        "max_tokens": 64,
    });

    let resp = client.post("https://integrate.api.nvidia.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
        .expect("request falló");

    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    println!("status={}", status.as_u16());
    println!("body_len={}", text.len());
    println!("body_snippet={}", &text[..text.len().min(500)]);
}

#[tokio::test]
#[ignore]
async fn manual_async_minima() {
    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY")
        .expect("SAK_PILOTO_NVIDIA_KEY no definida");

    let body = serde_json::json!({
        "model": "z-ai/glm-5.2",
        "messages": [{"role": "user", "content": "pong"}],
        "stream": true,
        "max_tokens": 64,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("curl/8.0")
        .build()
        .expect("client build");

    println!("phase=request_start");
    let t0 = std::time::Instant::now();

    let resp = client.post("https://integrate.api.nvidia.com/v1/chat/completions")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await;

    println!("phase=request_done elapsed_ms={}", t0.elapsed().as_millis());

    match resp {
        Ok(r) => {
            let status = r.status();
            println!("phase=status_read elapsed_ms={} status={}", t0.elapsed().as_millis(), status.as_u16());
            let text = r.text().await.unwrap_or_default();

            println!("===MANUAL_ASYNC===");
            println!("http_status={}", status.as_u16());
            println!("is_success={}", status.is_success());
            println!("response_len={}", text.len());
            println!("body_snippet={}", &text[..text.len().min(500)]);
            println!("===FIN_MANUAL_ASYNC===");
        }
        Err(e) => {
            println!("===MANUAL_ASYNC_ERROR===");
            println!("error={}", e);
            println!("elapsed_ms={}", t0.elapsed().as_millis());
            println!("===FIN_MANUAL_ASYNC_ERROR===");
        }
    }
}

#[test]
#[ignore]
fn raw_tls_diagnostico() {
    use std::net::TcpStream;
    use std::time::Instant;
    use std::io::{Read, Write};
    use sha2::{Sha256, Digest};

    let t0 = Instant::now();
    let addr = "integrate.api.nvidia.com:443";
    println!("phase=tcp_connect start");
    let tcp = TcpStream::connect(addr).expect("TCP connect falló");
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    println!("phase=tcp_connect done elapsed_ms={}", t0.elapsed().as_millis());

    println!("phase=tls_handshake start");
    let connector = native_tls::TlsConnector::new().expect("TlsConnector::new falló");
    let mut tls = connector.connect("integrate.api.nvidia.com", tcp).expect("TLS handshake falló");
    println!("phase=tls_handshake done elapsed_ms={}", t0.elapsed().as_millis());

    let body = r#"{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"pong"}]}"#;
    let body_bytes = body.as_bytes();
    let content_length_declared = body_bytes.len();

    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY").expect("SAK_PILOTO_NVIDIA_KEY no definida");

    let request_line = "POST /v1/chat/completions HTTP/1.1";
    let headers_raw = [
        "Host: integrate.api.nvidia.com",
        "Content-Type: application/json",
        "Connection: close",
    ];

    let mut body_hasher = Sha256::new();
    body_hasher.update(body_bytes);
    let body_sha256 = hex::encode(body_hasher.finalize());

    let full_request_for_hash = format!(
        "{request_line}\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Authorization: Bearer [REDACTED]\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length_declared}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    let mut req_hasher = Sha256::new();
    req_hasher.update(full_request_for_hash.as_bytes());
    let request_sha256 = hex::encode(req_hasher.finalize());

    println!("===DIAG_REQUEST===");
    println!("request_line={}", request_line);
    for h in &headers_raw {
        println!("header={}", h);
    }
    println!("header=Authorization: Bearer [REDACTED]");
    println!("body_sha256={}", body_sha256);
    println!("request_sha256={}", request_sha256);
    println!("content_length_declared={}", content_length_declared);
    println!("body_len_actual={}", body_bytes.len());
    println!("body_utf8_valid={}", std::str::from_utf8(body_bytes).is_ok());
    println!("===FIN_DIAG_REQUEST===");

    let request = format!(
        "{request_line}\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Authorization: Bearer {api_key}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {content_length_declared}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    let request_bytes = request.as_bytes();

    println!("phase=http_write start");
    tls.write_all(request_bytes).expect("write falló");
    tls.flush().ok();
    println!("phase=http_write done elapsed_ms={} request_total_bytes={}", t0.elapsed().as_millis(), request_bytes.len());

    println!("phase=http_read start");
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    let mut header_end_idx = None;

    for _ in 0..4096u32 {
        match tls.read_exact(&mut one) {
            Ok(()) => {
                buf.push(one[0]);
                if buf.len() >= 4 && &buf[buf.len()-4..] == b"\r\n\r\n" {
                    header_end_idx = Some(buf.len());
                    break;
                }
            }
            Err(e) => {
                println!("header_read_error={} at_buf_len={}", e, buf.len());
                break;
            }
        }
    }

    println!("phase=headers_done elapsed_ms={} buf_len={}", t0.elapsed().as_millis(), buf.len());

    let Some(end) = header_end_idx else {
        panic!(
            "FAIL: no se recibió línea de estado HTTP \
             (buf_len={} tras 4096 lecturas máximas o error de lectura)",
            buf.len()
        );
    };

    let header_str = String::from_utf8_lossy(&buf[..end]);
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code = status_line.split_whitespace().nth(1).unwrap_or("?");

    println!("===DIAG_STATUS===");
    println!("status_line={}", status_line);
    println!("status_code={}", status_code);
    println!("===FIN_DIAG_STATUS===");

    let content_length_header = header_str.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok());

    let transfer_encoding = header_str.lines()
        .find(|l| l.to_lowercase().starts_with("transfer-encoding:"))
        .map(|l| l.trim().to_string());

    println!("===DIAG_HEADERS===");
    println!("content_length_header={:?}", content_length_header);
    println!("transfer_encoding={:?}", transfer_encoding);
    println!("===FIN_DIAG_HEADERS===");

    let mut body_buf = Vec::new();
    if let Some(cl) = content_length_header {
        body_buf.extend_from_slice(&buf[end..]);
        let remaining = cl.saturating_sub(body_buf.len());
        if remaining > 0 {
            let mut tail = vec![0u8; remaining];
            match tls.read_exact(&mut tail) {
                Ok(()) => body_buf.extend_from_slice(&tail),
                Err(e) => println!("body_read_error={} got={}/{}", e, body_buf.len(), cl),
            }
        }
        println!("body_from_content_length={}", body_buf.len());
    } else if transfer_encoding.is_some() {
        loop {
            match tls.read_exact(&mut one) {
                Ok(()) => {
                    body_buf.push(one[0]);
                    if body_buf.len() >= 2 && &body_buf[body_buf.len()-2..] == b"\r\n" {
                        break;
                    }
                }
                Err(e) => {
                    println!("chunk_read_error={} at={}", e, body_buf.len());
                    break;
                }
            }
        }
        println!("body_chunk_terminator={}", body_buf.len());
    } else {
        body_buf.extend_from_slice(&buf[end..]);
        match tls.read_to_end(&mut body_buf) {
            Ok(n) => println!("body_eof_bytes={}", n),
            Err(e) => println!("body_eof_error={} partial={}", e, body_buf.len()),
        }
    }

    println!("===DIAG_BODY===");
    let body_str = String::from_utf8_lossy(&body_buf);
    println!("body_len={}", body_buf.len());
    println!("body_snippet={}", &body_str[..body_str.len().min(500)]);
    println!("===FIN_DIAG_BODY===");

    println!("===FIN_RAW_TLS===");
}

#[test]
#[ignore]
fn raw_tls_streaming() {
    use std::net::TcpStream;
    use std::time::Instant;
    use std::io::{Read, Write};
    use sha2::{Sha256, Digest};

    let t0 = Instant::now();
    let addr = "integrate.api.nvidia.com:443";
    println!("phase=tcp_connect start");
    let tcp = TcpStream::connect(addr).expect("TCP connect falló");
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(15))).ok();
    println!("phase=tcp_connect done elapsed_ms={}", t0.elapsed().as_millis());

    println!("phase=tls_handshake start");
    let connector = native_tls::TlsConnector::new().expect("TlsConnector::new falló");
    let mut tls = connector.connect("integrate.api.nvidia.com", tcp).expect("TLS handshake falló");
    println!("phase=tls_handshake done elapsed_ms={}", t0.elapsed().as_millis());

    let body = r#"{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"pong"}],"stream":true,"max_tokens":64}"#;
    let body_bytes = body.as_bytes();
    let content_length_declared = body_bytes.len();

    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY").expect("SAK_PILOTO_NVIDIA_KEY no definida");

    let request_line = "POST /v1/chat/completions HTTP/1.1";

    let mut body_hasher = Sha256::new();
    body_hasher.update(body_bytes);
    let body_sha256 = hex::encode(body_hasher.finalize());

    let full_request_for_hash = format!(
        "{request_line}\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Authorization: Bearer [REDACTED]\r\n\
         Content-Type: application/json\r\n\
         Accept: text/event-stream\r\n\
         Content-Length: {content_length_declared}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    let mut req_hasher = Sha256::new();
    req_hasher.update(full_request_for_hash.as_bytes());
    let request_sha256 = hex::encode(req_hasher.finalize());

    println!("===DIAG_REQUEST_STREAMING===");
    println!("request_line={}", request_line);
    println!("header=Host: integrate.api.nvidia.com");
    println!("header=Authorization: Bearer [REDACTED]");
    println!("header=Content-Type: application/json");
    println!("header=Accept: text/event-stream");
    println!("header=Connection: close");
    println!("body_sha256={}", body_sha256);
    println!("request_sha256={}", request_sha256);
    println!("content_length_declared={}", content_length_declared);
    println!("body_len_actual={}", body_bytes.len());
    println!("body_utf8_valid={}", std::str::from_utf8(body_bytes).is_ok());
    println!("===FIN_DIAG_REQUEST_STREAMING===");

    let request = format!(
        "{request_line}\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Authorization: Bearer {api_key}\r\n\
         Content-Type: application/json\r\n\
         Accept: text/event-stream\r\n\
         Content-Length: {content_length_declared}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    let request_bytes = request.as_bytes();

    println!("phase=http_write start");
    tls.write_all(request_bytes).expect("write falló");
    tls.flush().ok();
    println!("phase=http_write done elapsed_ms={} request_total_bytes={}", t0.elapsed().as_millis(), request_bytes.len());

    println!("phase=http_read start");
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    let mut header_end_idx = None;

    for _ in 0..4096u32 {
        match tls.read_exact(&mut one) {
            Ok(()) => {
                buf.push(one[0]);
                if buf.len() >= 4 && &buf[buf.len()-4..] == b"\r\n\r\n" {
                    header_end_idx = Some(buf.len());
                    break;
                }
            }
            Err(e) => {
                println!("header_read_error={} at_buf_len={}", e, buf.len());
                break;
            }
        }
    }

    println!("phase=headers_done elapsed_ms={} buf_len={}", t0.elapsed().as_millis(), buf.len());

    let Some(end) = header_end_idx else {
        panic!(
            "FAIL: no se recibió línea de estado HTTP \
             (buf_len={} tras 4096 lecturas máximas o error de lectura)",
            buf.len()
        );
    };

    let header_str = String::from_utf8_lossy(&buf[..end]);
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code = status_line.split_whitespace().nth(1).unwrap_or("?");

    println!("===DIAG_STATUS===");
    println!("status_line={}", status_line);
    println!("status_code={}", status_code);
    println!("===FIN_DIAG_STATUS===");

    let content_type_is_sse = header_str.lines()
        .any(|l| l.to_lowercase().contains("text/event-stream"));

    println!("content_type_is_sse={}", content_type_is_sse);

    if !content_type_is_sse {
        let content_length_header = header_str.lines()
            .find(|l| l.to_lowercase().starts_with("content-length:"))
            .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok());

        let mut body_buf = Vec::new();
        if let Some(cl) = content_length_header {
            body_buf.extend_from_slice(&buf[end..]);
            let remaining = cl.saturating_sub(body_buf.len());
            if remaining > 0 {
                let mut tail = vec![0u8; remaining];
                match tls.read_exact(&mut tail) {
                    Ok(()) => body_buf.extend_from_slice(&tail),
                    Err(e) => println!("body_read_error={} got={}/{}", e, body_buf.len(), cl),
                }
            }
        } else {
            body_buf.extend_from_slice(&buf[end..]);
            match tls.read_to_end(&mut body_buf) {
                Ok(_) => {}
                Err(e) => println!("body_eof_error={} partial={}", e, body_buf.len()),
            }
        }
        let body_str = String::from_utf8_lossy(&body_buf);
        println!("===NON_SSE_BODY===");
        println!("body_len={}", body_buf.len());
        println!("body_snippet={}", &body_str[..body_str.len().min(500)]);
        println!("===FIN_NON_SSE_BODY===");
    } else {
        println!("phase=sse_read start");
        let mut sse_buf = Vec::new();
        sse_buf.extend_from_slice(&buf[end..]);

        let mut chunks_received = 0u32;
        let mut last_event_snippet = String::new();

        loop {
            match tls.read_exact(&mut one) {
                Ok(()) => {
                    sse_buf.push(one[0]);
                    if sse_buf.len() >= 2 && &sse_buf[sse_buf.len()-2..] == b"\n\n" {
                        chunks_received += 1;
                        if let Some(pos) = sse_buf.windows(6).position(|w| w == b"data: ") {
                            let chunk_end = sse_buf.len();
                            let start = pos;
                            if start < chunk_end {
                                last_event_snippet = String::from_utf8_lossy(&sse_buf[start..chunk_end]).to_string();
                            }
                        }
                        println!("sse_chunk={} elapsed_ms={} total_bytes={}", chunks_received, t0.elapsed().as_millis(), sse_buf.len());
                        if last_event_snippet.contains("[DONE]") {
                            println!("sse_done_received");
                            break;
                        }
                    }
                }
                Err(e) => {
                    println!("sse_read_error={} at={} chunks={}", e, sse_buf.len(), chunks_received);
                    break;
                }
            }

            if chunks_received >= 100 {
                println!("sse_safety_limit reached");
                break;
            }
        }

        println!("phase=sse_read done elapsed_ms={} total_bytes={} chunks={}", t0.elapsed().as_millis(), sse_buf.len(), chunks_received);
        println!("===SSE_EVENTS===");
        println!("total_sse_bytes={}", sse_buf.len());
        println!("last_event_snippet={}", &last_event_snippet[..last_event_snippet.len().min(300)]);
        println!("===FIN_SSE_EVENTS===");
    }

    println!("===FIN_RAW_TLS_STREAMING===");
}

#[tokio::test]
#[ignore]
async fn raw_alpn_negotiated() {
    use std::time::Instant;
    use sha2::{Sha256, Digest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let t0 = Instant::now();
    let addr = "integrate.api.nvidia.com:443";
    println!("phase=tcp_connect start");
    let tcp = tokio::net::TcpStream::connect(addr).await.expect("TCP connect falló");
    println!("phase=tcp_connect done elapsed_ms={}", t0.elapsed().as_millis());

    println!("phase=tls_handshake start");
    let connector = native_tls::TlsConnector::new().expect("TlsConnector::new falló");
    let tokio_connector = tokio_native_tls::TlsConnector::from(connector);
    let mut tls = tokio_connector
        .connect("integrate.api.nvidia.com", tcp)
        .await
        .expect("TLS handshake falló");
    println!("phase=tls_handshake done elapsed_ms={}", t0.elapsed().as_millis());

    let body = r#"{"model":"z-ai/glm-5.2","messages":[{"role":"user","content":"solicitud:7b227469706f223a22636f6e73756c7461222c22726571756573746f223a2274657374227d"}],"stream":true,"max_tokens":64,"chat_template_kwargs":{"enable_thinking":false}}"#;
    let body_bytes = body.as_bytes();
    let content_length_declared = body_bytes.len();

    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY").expect("SAK_PILOTO_NVIDIA_KEY no definida");

    let mut body_hasher = Sha256::new();
    body_hasher.update(body_bytes);
    let body_sha256 = hex::encode(body_hasher.finalize());

    println!("===DIAG_REQUEST===");
    println!("uri=/v1/chat/completions");
    println!("header=content-type: application/json");
    println!("header=accept: text/event-stream");
    println!("header=authorization: Bearer [REDACTED]");
    println!("body_sha256={}", body_sha256);
    println!("content_length_declared={}", content_length_declared);
    println!("===FIN_DIAG_REQUEST===");

    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Authorization: Bearer {api_key}\r\n\
         Content-Type: application/json\r\n\
         Accept: text/event-stream\r\n\
         Content-Length: {content_length_declared}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}"
    );
    let request_bytes = request.as_bytes();

    println!("phase=http_write start");
    tls.write_all(request_bytes).await.expect("write falló");
    tls.flush().await.ok();
    println!("phase=http_write done elapsed_ms={} request_total_bytes={}", t0.elapsed().as_millis(), request_bytes.len());

    println!("phase=http_read start");
    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    let mut header_end_idx = None;

    for _ in 0..4096u32 {
        match tls.read_exact(&mut one).await {
            Ok(_) => {
                buf.push(one[0]);
                if buf.len() >= 4 && &buf[buf.len()-4..] == b"\r\n\r\n" {
                    header_end_idx = Some(buf.len());
                    break;
                }
            }
            Err(e) => {
                println!("header_read_error={} at_buf_len={}", e, buf.len());
                break;
            }
        }
    }

    println!("phase=headers_done elapsed_ms={} buf_len={}", t0.elapsed().as_millis(), buf.len());

    let Some(end) = header_end_idx else {
        panic!("FAIL: no se recibió línea de estado HTTP (buf_len={})", buf.len());
    };

    let header_str = String::from_utf8_lossy(&buf[..end]);
    let status_line = header_str.lines().next().unwrap_or("");
    let status_code = status_line.split_whitespace().nth(1).unwrap_or("?");

    println!("===DIAG_STATUS===");
    println!("status_line={}", status_line);
    println!("status_code={}", status_code);
    println!("===FIN_DIAG_STATUS===");

    let content_length_header = header_str.lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok());

    let mut body_buf = Vec::new();
    if let Some(cl) = content_length_header {
        body_buf.extend_from_slice(&buf[end..]);
        let remaining = cl.saturating_sub(body_buf.len());
        if remaining > 0 {
            let mut tail = vec![0u8; remaining];
            match tls.read_exact(&mut tail).await {
                Ok(_) => body_buf.extend_from_slice(&tail),
                Err(e) => println!("body_read_error={} got={}/{}", e, body_buf.len(), cl),
            }
        }
    } else {
        body_buf.extend_from_slice(&buf[end..]);
        match tls.read_to_end(&mut body_buf).await {
            Ok(_) => {}
            Err(e) => println!("body_eof_error={} partial={}", e, body_buf.len()),
        }
    }

    println!("===DIAG_RESPONSE===");
    println!("body_len={}", body_buf.len());
    let body_str = String::from_utf8_lossy(&body_buf);
    println!("body_snippet={}", &body_str[..body_buf.len().min(500)]);
    println!("===FIN_DIAG_RESPONSE===");

    println!("===FIN_RAW_NEGOTIATED===");
}

#[test]
#[ignore]
fn equivalence_raw_vs_reqwest() {
    use std::net::TcpStream;
    use std::time::Instant;
    use std::io::{Read, Write};
    use sha2::{Sha256, Digest};

    let api_key = std::env::var("SAK_PILOTO_NVIDIA_KEY").expect("SAK_PILOTO_NVIDIA_KEY no definida");

    // Body EXACTO que usa ProveedorNvidiaEf1.
    let body = serde_json::json!({
        "model": "z-ai/glm-5.2",
        "messages": [
            {"role": "user", "content": "solicitud:7b227469706f223a22636f6e73756c7461222c22726571756573746f223a2274657374227d"}
        ],
        "stream": true,
        "max_tokens": 64,
        "chat_template_kwargs": {"enable_thinking": false},
    });
    let body_str = serde_json::to_string(&body).expect("body serialize");
    let body_bytes = body_str.as_bytes();

    // SHA-256 del body.
    let mut hasher = Sha256::new();
    hasher.update(body_bytes);
    let body_sha256 = hex::encode(hasher.finalize());

    println!("===EQUIV_DIAG===");
    println!("body_sha256={}", body_sha256);
    println!("body_len={}", body_bytes.len());
    println!("body_utf8_valid={}", std::str::from_utf8(body_bytes).is_ok());
    println!("header=Host: integrate.api.nvidia.com");
    println!("header=Content-Type: application/json");
    println!("header=Accept: text/event-stream");
    println!("header=Authorization: Bearer [REDACTED]");
    println!("header=Connection: close");
    println!("===FIN_EQUIV_DIAG===");

    // ── RAW native_tls ──
    println!("===EQUIV_RAW_START===");
    let t0 = Instant::now();

    let tcp = TcpStream::connect("integrate.api.nvidia.com:443").expect("TCP raw");
    tcp.set_read_timeout(Some(std::time::Duration::from_secs(180))).ok();
    let connector = native_tls::TlsConnector::new().expect("TLS new");
    let mut tls = connector.connect("integrate.api.nvidia.com", tcp).expect("TLS handshake");

    let raw_request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: integrate.api.nvidia.com\r\n\
         Content-Type: application/json\r\n\
         Accept: text/event-stream\r\n\
         Authorization: Bearer {api_key}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body_str}",
        body_bytes.len()
    );
    let raw_bytes = raw_request.as_bytes();

    tls.write_all(raw_bytes).expect("raw write");
    tls.flush().ok();

    let mut buf = Vec::new();
    let mut one = [0u8; 1];
    let mut header_end = None;
    for _ in 0..4096u32 {
        match tls.read_exact(&mut one) {
            Ok(()) => {
                buf.push(one[0]);
                if buf.len() >= 4 && &buf[buf.len()-4..] == b"\r\n\r\n" {
                    header_end = Some(buf.len());
                    break;
                }
            }
            Err(e) => {
                println!("raw_header_error={}", e);
                break;
            }
        }
    }

    let raw_ms = t0.elapsed().as_millis();
    match header_end {
        Some(end) => {
            let hdr = String::from_utf8_lossy(&buf[..end]);
            let status = hdr.lines().next().unwrap_or("")
                .split_whitespace().nth(1).unwrap_or("?");
            let cl = hdr.lines()
                .find(|l| l.to_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1)?.trim().parse::<usize>().ok());
            let mut body_buf = Vec::new();
            body_buf.extend_from_slice(&buf[end..]);
            if let Some(cl) = cl {
                let rem = cl.saturating_sub(body_buf.len());
                if rem > 0 {
                    let mut tail = vec![0u8; rem];
                    let _ = tls.read_exact(&mut tail);
                    body_buf.extend_from_slice(&tail);
                }
            } else {
                let _ = tls.read_to_end(&mut body_buf);
            }
            println!("raw_status={} elapsed_ms={} body_len={}", status, raw_ms, body_buf.len());
            println!("===EQUIV_RAW_OK===");
        }
        None => {
            println!("raw_fail elapsed_ms={} buf_len={}", raw_ms, buf.len());
            println!("===EQUIV_RAW_FAIL===");
        }
    }

    // ── reqwest ──
    println!("===EQUIV_REQWEST_START===");
    let t1 = Instant::now();

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(180))
        .connect_timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest build");

    let req_result = client.post("https://integrate.api.nvidia.com/v1/chat/completions")
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .header("Authorization", format!("Bearer {}", api_key))
        .body(body_bytes.to_vec())
        .send();

    let req_ms = t1.elapsed().as_millis();
    match req_result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body_resp = resp.text().unwrap_or_default();
            println!("reqwest_status={} elapsed_ms={} body_len={}", status, req_ms, body_resp.len());
            println!("===EQUIV_REQWEST_OK===");
        }
        Err(e) => {
            println!("reqwest_fail elapsed_ms={} error={}", req_ms, e);
            println!("===EQUIV_REQWEST_FAIL===");
        }
    }

    println!("===FIN_EQUIV===");
}
