//! Prepara un dominio durable para el agente externo `sak-agent-probe`.
//! Emite fixtures JSON (sin material de clave). No es API nueva: usa EstadoOps in-process.

use sak_core::contexto::ClaseEfecto;
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::identidad::{DeclaracionResponsable, IdSistema};
use sak_core::libro::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use sak_core::pep::preparar_solicitud;
use sak_domain::ops::{despachar_con_estado, EstadoOps};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn uso() -> ! {
    eprintln!(
        "uso: sak-prepare-probe --dominio <id> --out <dir_fixtures>\n\
         Prepara alta+pasaporte+ALCANZABLES+hecho CUSTODIA (C2) en el almacén del dominio\n\
         y escribe fixtures para el agente externo (sin secretos)."
    );
    process::exit(2);
}

fn evidencia_dir(dominio_id: &str) -> PathBuf {
    let base = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("SovereignAIKernel")
        .join("domains")
        .join(dominio_id)
        .join("evidencia")
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut dominio = None;
    let mut out = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dominio" => {
                i += 1;
                dominio = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            "-h" | "--help" => uso(),
            _ => uso(),
        }
        i += 1;
    }
    let dominio = dominio.unwrap_or_else(|| uso());
    let out = PathBuf::from(out.unwrap_or_else(|| uso()));
    fs::create_dir_all(&out).expect("crear out");

    let dir = evidencia_dir(&dominio);
    fs::create_dir_all(&dir).expect("crear evidencia");
    let mut st = EstadoOps::abrir_disco(&dir, &dominio).expect("abrir dominio");

    let sistema = "sys-probe-externo";
    let (pk, firma) = {
        let par = ParMlDsa87::generar().unwrap();
        let sid = IdSistema::nuevo(sistema).unwrap();
        let d = DeclaracionResponsable::firmar(
            &par,
            sid,
            "responsable@probe",
            "probe-externo",
            "modelo-harness",
            "EU",
            "datos-demo",
            "ef1:asistido",
            "herramienta-a",
            "efector-a",
            "limitado",
            10_000,
            50_000,
        )
        .unwrap();
        (hex(&par.public), hex(d.firma_responsable()))
    };

    let alta = format!(
        r#"{{"op":"con.sistema.alta","req_id":"prep","schema_v":1,"operador_id":"prep","sistema_id":"{sistema}","pasaporte_id":"{sistema}","responsable":"responsable@probe","finalidad":"probe-externo","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let r = despachar_con_estado(&alta, Some(&mut st));
    if r.resultado != "OK" && r.codigo != "ALIAS_EXISTE" && !r.cuerpo.contains("ya") {
        // re-alta puede fallar si existe; continuar si pasaporte ya está
        eprintln!("alta: {} {}", r.resultado, r.codigo);
    }

    let emit = format!(
        r#"{{"op":"con.pasaporte.emitir","req_id":"prep-e","schema_v":1,"sistema_id":"{sistema}","pasaporte_id":"{sistema}","version":1,"responsable":"responsable@probe","finalidad":"probe-externo","modelos":"modelo-harness","jurisdiccion":"EU","datos":"datos-demo","autonomia_por_clase":"ef1:asistido","herramientas":"herramienta-a","efectores":"efector-a","clasificacion_riesgo":"limitado","vigente_desde_dias":10000,"vigente_hasta_dias":50000,"firma_responsable_hex":"{firma}","pk_responsable_hex":"{pk}"}}"#
    );
    let e = despachar_con_estado(&emit, Some(&mut st));
    if e.resultado != "OK" && e.codigo != "VERSION_YA_EXISTE" {
        eprintln!("pasaporte: {} {}", e.resultado, e.codigo);
    }

    let par_inv = ParMlDsa87::generar().unwrap();
    let sid = IdSistema::nuevo(sistema).unwrap();
    let mut efectores = BTreeSet::new();
    efectores.insert(ClaseEfecto::Ef1);
    let inv = InventarioAlcanzables::firmar_completo(
        sid.clone(),
        "inst-probe",
        efectores,
        BTreeSet::from(["127.0.0.1:1".into()]),
        BTreeSet::from(["cred:digest:probe".into()]),
        BTreeSet::from(["s".into()]),
        BTreeSet::from(["svc".into()]),
        BTreeSet::from(["c".into()]),
        true,
        1,
        1,
        0,
        "det-probe",
        &par_inv,
    )
    .unwrap();
    let alc = format!(
        r#"{{"op":"con.inventario.alcanzables","req_id":"prep-a","schema_v":1,"sistema_id":"{sistema}","instancia":"inst-probe","productor_id":"{prod}","efectores":"EF-1","rutas_red":"127.0.0.1:1","credenciales_detectadas":"cred:digest:probe","almacenes":"s","puntos_servicio":"svc","canales_consumo":"c","incompleto_declarado":true,"version":1,"epoca":1,"emitido_en":0,"firma_productor_hex":"{firma}","pk_productor_hex":"{pk}"}}"#,
        prod = inv.productor_id,
        firma = hex(&inv.firma),
        pk = hex(&inv.pk_firmante),
    );
    let a = despachar_con_estado(&alc, Some(&mut st));
    eprintln!("alcanzables: {} {}", a.resultado, a.codigo);

    // Hecho CUSTODIA → C2 (mínimo EF-1). Persistido en Libro durable.
    let fk = ParMlDsa87::generar().unwrap();
    let h = HechoFirmadoLibro::firmar(
        TipoHecho::Custodia,
        sid,
        Some(ClaseEfecto::Ef1),
        true,
        1,
        1,
        0,
        "prepare-probe",
        &fk,
    )
    .unwrap();
    st.libro.registrar_hecho(h).expect("hecho");
    st.guardar_libro().expect("guardar libro");

    let seed = [0xEE; LONGITUD_HASH_PAQUETE];
    let (_sol, digest) = preparar_solicitud("modelo-harness", seed, 32, 0);

    let fixture = format!(
        r#"{{
  "schema": "sak-agent-probe-fixtures-v1",
  "dominio_id": "{dominio}",
  "sistema_id": "{sistema}",
  "clase": "EF-1",
  "modelo_id": "modelo-harness",
  "max_tokens": 32,
  "digest_parametros_hex": "{dig}",
  "seed_parametros_hex": "{seed}",
  "pasaporte_id": "{sistema}",
  "notas": {{
    "bloque_a": "identidad/ALCANZABLES/custodia-hecho preparados en dominio durable",
    "bloque_b": "agente debe obs.diagnostico.decidir luego .ejercer via IPC loopback (no HTTP nuevo)",
    "sin_material": true,
    "ui_sin_autoridad": true
  }},
  "afirmacion_permitida_si_ok": "Para EF-1 del harness, decision+ejercicio pasan por Kernel; agente sin material",
  "afirmacion_no_permitida": "Control total / unica frontera si el agente llama al proveedor por su cuenta"
}}
"#,
        dig = hex(&digest),
        seed = hex(&seed),
    );
    let path = out.join("probe.json");
    fs::write(&path, fixture).expect("write fixture");
    fs::write(
        out.join("README_FIXTURES.txt"),
        "Generado por sak-prepare-probe. El agente NO importa sak-*. Solo lee este JSON y habla TCP JSON-line al canal obs del dominio.\n",
    )
    .ok();

    println!("ok dominio={dominio}");
    println!("evidencia={}", dir.display());
    println!("fixtures={}", path.display());
    println!("siguiente: sak-domain run {dominio}  # anotar obs_loopback");
    println!("luego: python agent.py --modo correcto --host 127.0.0.1 --port <PORT>");
}
