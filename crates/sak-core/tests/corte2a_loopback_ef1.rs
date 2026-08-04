//! Corte 2A/2B/2C — loopback + anti-replay + ticket v2 (cap.id/epoca/TTL).

use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::pep::{
    atender_peticion_mock, construir_peticion_con_nonce, emitir_ticket_bytes, enviar_linea_mock,
    generar_clave_efimera, generar_nonce_aleatorio, llamada_directa_sin_sello, preparar_solicitud,
    sello_protocolo_antiguo, ContextoEjercicioEf1, MockEf1Loopback, ProveedorLoopbackEf1,
    ProveedorModelo, HANDLE_EF1_PROBE_MEDIADO,
};
use std::collections::HashSet;

fn ctx_ok(digest: [u8; LONGITUD_HASH_PAQUETE]) -> ContextoEjercicioEf1 {
    ContextoEjercicioEf1 {
        cap_id: [0xCA; LONGITUD_HASH_PAQUETE],
        digest,
        epoca: 1,
        vive_hasta: 10_000,
        ahora: 1_000,
    }
}

fn con_ctx(prov: &mut ProveedorLoopbackEf1, ctx: &ContextoEjercicioEf1) {
    prov.preparar_contexto_ejercicio(ctx);
}

#[test]
fn camino_permitido_loopback() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).expect("mock");
    let mut prov = ProveedorLoopbackEf1::nuevo(mock.addr(), HANDLE_EF1_PROBE_MEDIADO, clave);
    let digest = [0x11; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    con_ctx(&mut prov, &ctx_ok(d));
    let r = prov.inferir_delegado(&sol, &d).expect("inferir_delegado");
    assert_eq!(r.digest_parametros_ejecutados, d);
    assert_eq!(prov.llamadas_delegadas, 1);
    mock.detener();
}

#[test]
fn primera_peticion_valida_ticket_v2_ok() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xAA; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let line = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(resp.contains("\"ok\":true"), "{resp}");
}

#[test]
fn reenvio_literal_replay() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).expect("mock");
    let digest = [0xBB; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let line = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    let r1 = enviar_linea_mock(mock.addr(), &line).expect("r1");
    assert!(r1.contains("\"ok\":true"), "{r1}");
    let r2 = enviar_linea_mock(mock.addr(), &line).expect("r2");
    assert!(r2.contains("REPLAY"), "{r2}");
    mock.detener();
}

#[test]
fn ticket_ausente_deny() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xC1; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let full = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    let sello = full
        .split("\"sello\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let line = format!(
        "{{\"v\":\"SAK-EF1-LB-1\",\"sello\":\"{sello}\",\"digest\":\"{}\",\"canon\":\"{}\",\"nonce\":\"{}\",\"cap_id\":\"{}\",\"epoca\":1,\"vive_hasta\":10000,\"ahora\":1000}}\n",
        hex(&d),
        hex(&sol.canonico()),
        hex(&nonce),
        hex(&ctx.cap_id),
    );
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(resp.contains("NO_TICKET"), "{resp}");
}

#[test]
fn ticket_cap_id_incoherente_deny() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xC3; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let ticket = emitir_ticket_bytes(&clave, &ctx, &nonce);
    let line_ok = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    let sello = line_ok
        .split("\"sello\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let otro_cap = [0xEE; LONGITUD_HASH_PAQUETE];
    let line = format!(
        "{{\"v\":\"SAK-EF1-LB-1\",\"sello\":\"{sello}\",\"digest\":\"{}\",\"canon\":\"{}\",\"nonce\":\"{}\",\"ticket\":\"{}\",\"cap_id\":\"{}\",\"epoca\":{},\"vive_hasta\":{},\"ahora\":{}}}\n",
        hex(&d),
        hex(&sol.canonico()),
        hex(&nonce),
        hex(&ticket),
        hex(&otro_cap),
        ctx.epoca,
        ctx.vive_hasta,
        ctx.ahora,
    );
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(resp.contains("TICKET_INVALIDO"), "{resp}");
}

#[test]
fn ticket_expirado_ttl_deny() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xC5; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let mut ctx = ctx_ok(d);
    ctx.ahora = 20_000;
    ctx.vive_hasta = 10_000;
    let nonce = generar_nonce_aleatorio();
    let line = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(resp.contains("TICKET_EXPIRADO"), "{resp}");
    assert!(vistos.is_empty());
}

#[test]
fn ticket_invalido_deny() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xC2; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let mut line = construir_peticion_con_nonce(&clave, &sol.canonico(), &ctx, &nonce);
    line = line.replace("\"ticket\":\"", "\"ticket\":\"ff");
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(
        resp.contains("TICKET_INVALIDO") || resp.contains("FORMATO"),
        "{resp}"
    );
}

#[test]
fn sello_protocolo_antiguo_deny() {
    let clave = generar_clave_efimera();
    let mut vistos = HashSet::new();
    let digest = [0xDD; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    let ctx = ctx_ok(d);
    let nonce = generar_nonce_aleatorio();
    let sello_old = sello_protocolo_antiguo(&clave, &sol.canonico(), &d);
    let ticket = emitir_ticket_bytes(&clave, &ctx, &nonce);
    let line = format!(
        "{{\"v\":\"SAK-EF1-LB-1\",\"sello\":\"{}\",\"digest\":\"{}\",\"canon\":\"{}\",\"nonce\":\"{}\",\"ticket\":\"{}\",\"cap_id\":\"{}\",\"epoca\":1,\"vive_hasta\":10000,\"ahora\":1000}}\n",
        hex(&sello_old),
        hex(&d),
        hex(&sol.canonico()),
        hex(&nonce),
        hex(&ticket),
        hex(&ctx.cap_id),
    );
    let resp = atender_peticion_mock(&clave, &line, &mut vistos);
    assert!(resp.contains("SELLO_INVALIDO"), "{resp}");
}

#[test]
fn dos_ejercicios_legitimos_nonces_distintos() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).expect("mock");
    let mut prov = ProveedorLoopbackEf1::nuevo(mock.addr(), HANDLE_EF1_PROBE_MEDIADO, clave);
    let (sol1, d1) = preparar_solicitud("modelo-harness", [0xE1; LONGITUD_HASH_PAQUETE], 32, 0);
    let (sol2, d2) = preparar_solicitud("modelo-harness", [0xE2; LONGITUD_HASH_PAQUETE], 32, 0);
    con_ctx(&mut prov, &ctx_ok(d1));
    let r1 = prov.inferir_delegado(&sol1, &d1).expect("ej1");
    let n1 = prov.ultimo_nonce.expect("n1");
    con_ctx(&mut prov, &ctx_ok(d2));
    let r2 = prov.inferir_delegado(&sol2, &d2).expect("ej2");
    let n2 = prov.ultimo_nonce.expect("n2");
    assert_eq!(r1.digest_parametros_ejecutados, d1);
    assert_eq!(r2.digest_parametros_ejecutados, d2);
    assert_ne!(n1, n2);
    mock.detener();
}

#[test]
fn directa_sin_sello_rechazada() {
    let mock = MockEf1Loopback::arrancar(generar_clave_efimera()).expect("mock");
    let line = llamada_directa_sin_sello(mock.addr()).expect("tcp");
    assert!(line.contains("NO_SELLO") || line.contains("\"ok\":false"));
    mock.detener();
}

#[test]
fn handle_inexistente_sin_socket_util() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).expect("mock");
    let mut prov = ProveedorLoopbackEf1::nuevo(mock.addr(), "handle-fantasma", clave);
    let digest = [0x22; LONGITUD_HASH_PAQUETE];
    let (sol, d) = preparar_solicitud("modelo-harness", digest, 32, 0);
    con_ctx(&mut prov, &ctx_ok(d));
    let err = prov.inferir_delegado(&sol, &d).expect_err("debe fallar");
    assert!(matches!(err, sak_core::pep::ErrorProveedor::NoAutorizado));
    mock.detener();
}

#[test]
fn sin_contexto_deny() {
    let clave = generar_clave_efimera();
    let mock = MockEf1Loopback::arrancar(clave).expect("mock");
    let mut prov = ProveedorLoopbackEf1::nuevo(mock.addr(), HANDLE_EF1_PROBE_MEDIADO, clave);
    let (sol, d) = preparar_solicitud("modelo-harness", [0x99; LONGITUD_HASH_PAQUETE], 32, 0);
    let err = prov.inferir_delegado(&sol, &d).expect_err("sin ctx");
    assert!(matches!(err, sak_core::pep::ErrorProveedor::NoAutorizado));
    mock.detener();
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}
