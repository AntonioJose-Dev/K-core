//! Proceso autoritativo por dominio (§E) — D1–D5 + canal obs.* D3.
//!
//! Evidencia durable, corpus, pasaportes, identidad, Libro.
//! Canal operador: Observar (`obs.*`) local / in-process / loopback.
//! Sin UI, sin telemetría, sin bind público, sin secretos exportables.

use sak_core::evidencia::{AlmacenDiscoLocal, EstadoDominio, LedgerEvidencia};
use sak_core::gobernanza::{cargar_gobernanza_desde_almacen, exigir_cita_o_suspender};
use sak_core::identidad::{cargar_ca_desde_almacen, cargar_registro_desde_almacen};
use sak_core::libro::cargar_libro_desde_almacen;
use sak_core::monitor::EpocaMonotonica;
use sak_core::reloj::Ticks;
use sak_domain::obs::{
    addr_escucha_es_local, atender_stream_con_ops, in_process, in_process_con_ops,
    listener_loopback, ObsVista,
};
use sak_domain::ops::EstadoOps;
use std::sync::Mutex;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "uso:\n  sak-domain init <dominio_id>\n  sak-domain status <dominio_id>\n  sak-domain run <dominio_id>\n  sak-domain obs <dominio_id>   # una línea JSON stdin → JSON stdout (in-process)\n\n\
         Datos: %LOCALAPPDATA%\\SovereignAIKernel\\domains\\<id>\\evidencia\\\n\
         Canal obs.*: loopback 127.0.0.1 en `run`, o stdio en `obs`. Sin UI/red pública/telemetría."
    );
    process::exit(2);
}

fn local_app_data() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| {
            env::var_os("USERPROFILE").map(|u| PathBuf::from(u).join("AppData").join("Local"))
        })
        .unwrap_or_else(|| env::temp_dir())
}

fn evidencia_dir(dominio_id: &str) -> PathBuf {
    local_app_data()
        .join("SovereignAIKernel")
        .join("domains")
        .join(dominio_id)
        .join("evidencia")
}

fn validar_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn cmd_init(dominio_id: &str) -> i32 {
    if !validar_id(dominio_id) {
        eprintln!("dominio_id inválido");
        return 1;
    }
    let dir = evidencia_dir(dominio_id);
    match AlmacenDiscoLocal::abrir(&dir) {
        Ok(a) => {
            println!("dominio_inicializado={}", dominio_id);
            println!("evidencia={}", a.root().display());
            0
        }
        Err(e) => {
            eprintln!("init: {e}");
            1
        }
    }
}

fn construir_vista(
    dominio_id: &str,
    dir: &std::path::Path,
    ledger: &LedgerEvidencia<AlmacenDiscoLocal>,
) -> ObsVista {
    let gob = cargar_gobernanza_desde_almacen(ledger.almacen());
    let reg = cargar_registro_desde_almacen(ledger.almacen());
    let ca = cargar_ca_desde_almacen(ledger.almacen());
    let libro = cargar_libro_desde_almacen(ledger.almacen()).ok();
    let n_pasaportes = reg.as_ref().map(|r| r.n_versiones()).unwrap_or(0);
    let (n_certs, perfil) = match &ca {
        Ok(Some(c)) => (c.n_emitidos(), c.perfil().to_string()),
        _ => (0, "-".into()),
    };
    let hash_activo = gob
        .as_ref()
        .ok()
        .and_then(|g| g.hash_activo())
        .map(|h| {
            h.bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .unwrap_or_else(|| "-".into());
    let ahora: Ticks = ledger.epoca().saturating_mul(1_000);
    ObsVista::desde_ledger(
        dominio_id,
        dir,
        ledger,
        libro.as_ref(),
        n_pasaportes,
        n_certs,
        &perfil,
        &hash_activo,
        ahora,
    )
}

fn cmd_status(dominio_id: &str) -> i32 {
    if !validar_id(dominio_id) {
        eprintln!("dominio_id inválido");
        return 1;
    }
    let dir = evidencia_dir(dominio_id);
    if !dir.is_dir() {
        eprintln!("dominio_no_inicializado path={}", dir.display());
        return 1;
    }
    let mut almacen = match AlmacenDiscoLocal::abrir(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("status: {e}");
            return 1;
        }
    };
    let epoca = match EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("epoca: {e}");
            return 1;
        }
    };
    let n_archivos = fs::read_dir(&dir).map(|rd| rd.count()).unwrap_or(0);
    let (corpus_ok, hash_activo) = match cargar_gobernanza_desde_almacen(&almacen) {
        Ok(g) => (
            true,
            g.hash_activo()
                .map(|h| {
                    h.bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                })
                .unwrap_or_else(|| "-".into()),
        ),
        Err(_) => (false, "IRRESOLUBLE".into()),
    };
    let (registro_ok, n_pasaportes) = match cargar_registro_desde_almacen(&almacen) {
        Ok(r) => (true, r.n_versiones()),
        Err(_) => (false, 0),
    };
    let (ca_ok, n_certs, perfil) = match cargar_ca_desde_almacen(&almacen) {
        Ok(Some(ca)) => (true, ca.n_emitidos(), ca.perfil().to_string()),
        Ok(None) => (true, 0, "-".into()),
        Err(_) => (false, 0, "fallo".into()),
    };
    let (libro_ok, n_hechos) = match cargar_libro_desde_almacen(&almacen) {
        Ok(l) => (true, l.n_hechos()),
        Err(_) => (false, 0),
    };
    println!("dominio_id={dominio_id}");
    println!("evidencia={}", dir.display());
    println!("epoca={}", epoca.actual());
    println!("suelo_epoca={}", epoca.suelo());
    println!("objetos_almacen≈{n_archivos}");
    println!("corpus_carga={}", if corpus_ok { "ok" } else { "fallo" });
    println!("paquete_activo={hash_activo}");
    println!("registro_carga={}", if registro_ok { "ok" } else { "fallo" });
    println!("pasaportes_versiones={n_pasaportes}");
    println!("ca_carga={}", if ca_ok { "ok" } else { "fallo" });
    println!("certificados_emitidos={n_certs}");
    println!("identidad_perfil={perfil}");
    println!("libro_carga={}", if libro_ok { "ok" } else { "fallo" });
    println!("libro_hechos={n_hechos}");
    println!("proceso=sak-domain");
    println!("canal_obs=D3");
    println!("matriz=E+INV-07+INV-03/G.5+INV-04+INV-05+INV-09+obs.*");
    0
}

fn cmd_obs(dominio_id: &str) -> i32 {
    if !validar_id(dominio_id) {
        eprintln!("dominio_id inválido");
        return 1;
    }
    let dir = evidencia_dir(dominio_id);
    let mut almacen = match AlmacenDiscoLocal::abrir(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("obs: {e}");
            return 1;
        }
    };
    let _epoca = match EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("epoca: {e}");
            return 1;
        }
    };
    let gob_res = cargar_gobernanza_desde_almacen(&almacen);
    let mut ledger = match LedgerEvidencia::nuevo(almacen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ledger: {e}");
            return 1;
        }
    };
    match &gob_res {
        Ok(gob) => {
            if let Some(h) = gob.hash_activo() {
                let _ = exigir_cita_o_suspender(&mut ledger, h);
            }
        }
        Err(_) => ledger.suspender_por_cita_irresoluble(),
    }
    let estado_ops = match EstadoOps::abrir_disco(&dir, dominio_id) {
        Ok(mut e) => {
            if std::env::var("SAK_SEED_DEMO").ok().as_deref() == Some("1") {
                if let Err(err) = e.aplicar_seed_demo_alcanzables() {
                    eprintln!("seed_demo: {err}");
                }
            }
            Arc::new(Mutex::new(e))
        }
        Err(e) => {
            eprintln!("ops_estado: {e}");
            return 1;
        }
    };
    let vista = construir_vista(dominio_id, &dir, &ledger);
    let stdin = io::stdin();
    let mut linea = String::new();
    match stdin.lock().read_line(&mut linea) {
        Ok(0) => return 0,
        Ok(_) => {}
        Err(e) => {
            eprintln!("stdin: {e}");
            return 1;
        }
    }
    let out = in_process_con_ops(&vista, &estado_ops, linea.trim());
    println!("{out}");
    0
}

fn cmd_run(dominio_id: &str) -> i32 {
    if !validar_id(dominio_id) {
        eprintln!("dominio_id inválido");
        return 1;
    }
    let dominio_id = dominio_id.to_string();
    let handle = thread::Builder::new()
        .name("sak-domain-run".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(move || cmd_run_inner(&dominio_id))
        .expect("spawn sak-domain-run");
    handle.join().expect("join sak-domain-run")
}

fn cmd_run_inner(dominio_id: &str) -> i32 {
    let dir = evidencia_dir(dominio_id);
    let mut almacen = match AlmacenDiscoLocal::abrir(&dir) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("run: {e}");
            return 1;
        }
    };
    let epoca = match EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("epoca: {e}");
            return 1;
        }
    };
    let gob_res = cargar_gobernanza_desde_almacen(&almacen);
    let reg_res = cargar_registro_desde_almacen(&almacen);
    let ca_res = cargar_ca_desde_almacen(&almacen);
    let libro_res = cargar_libro_desde_almacen(&almacen);
    let n_pasaportes = reg_res.as_ref().map(|r| r.n_versiones()).unwrap_or(0);
    let (n_certs, perfil) = match &ca_res {
        Ok(Some(ca)) => (ca.n_emitidos(), ca.perfil()),
        _ => (0, "-"),
    };
    let n_hechos = libro_res.as_ref().map(|l| l.n_hechos()).unwrap_or(0);
    let mut ledger = match LedgerEvidencia::nuevo(almacen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ledger: {e}");
            return 1;
        }
    };
    match &gob_res {
        Ok(gob) => {
            if let Some(h) = gob.hash_activo() {
                if let Err(e) = exigir_cita_o_suspender(&mut ledger, h) {
                    eprintln!("corpus_cita: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!("corpus_carga: {e}");
            ledger.suspender_por_cita_irresoluble();
        }
    }
    let hash_activo = gob_res
        .as_ref()
        .ok()
        .and_then(|g| g.hash_activo())
        .map(|h| {
            h.bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        })
        .unwrap_or_else(|| "-".into());

    let estado_ops = match EstadoOps::abrir_disco(&dir, dominio_id) {
        Ok(mut e) => {
            if std::env::var("SAK_SEED_DEMO").ok().as_deref() == Some("1") {
                if let Err(err) = e.aplicar_seed_demo_alcanzables() {
                    eprintln!("seed_demo: {err}");
                }
            }
            Arc::new(Mutex::new(e))
        }
        Err(e) => {
            eprintln!("ops_estado: {e}");
            return 1;
        }
    };

    // Tras seed/ops libro en disco: Observar lee el snapshot actual.
    let vista = Arc::new(construir_vista(dominio_id, &dir, &ledger));

    let listener = match listener_loopback(0) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("obs_bind: {e}");
            return 1;
        }
    };
    let local = match listener.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("obs_addr: {e}");
            return 1;
        }
    };
    if !addr_escucha_es_local(local) {
        eprintln!("obs_bind: dirección no local — abortando");
        return 1;
    }

    println!("sak-domain run dominio={dominio_id}");
    println!("evidencia={}", dir.display());
    println!("epoca={}", epoca.actual());
    println!("suelo_epoca={}", epoca.suelo());
    println!("ledger_estado={:?}", ledger.estado());
    println!("ledger_epoca_mem={}", ledger.epoca());
    println!("paquete_activo={hash_activo}");
    println!("pasaportes_versiones={n_pasaportes}");
    println!("certificados_emitidos={n_certs}");
    println!("identidad_perfil={perfil}");
    println!("libro_hechos={n_hechos}");
    if ledger.estado() == EstadoDominio::Suspended {
        println!("dominio=SUSPENDED (cita corpus irresoluble)");
    }
    println!("obs_loopback={local}");
    println!("obs_familia=Observar");
    println!("escucha=loopback_obs + stdin quit");

    let vista_srv = Arc::clone(&vista);
    let ops_srv = Arc::clone(&estado_ops);
    let _obs_thread = thread::spawn(move || {
        let _ = listener.set_nonblocking(false);
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    if !sak_domain::obs::es_peer_local(peer) {
                        continue;
                    }
                    let v = Arc::clone(&vista_srv);
                    let o = Arc::clone(&ops_srv);
                    let _ = thread::spawn(move || {
                        let _ = atender_stream_con_ops(&v, Some(o), stream);
                    });
                }
                Err(_) => thread::sleep(Duration::from_millis(50)),
            }
        }
    });

    let _ = (reg_res, ca_res, libro_res, vista, estado_ops);
    if std::env::var("SAK_DAEMON").ok().as_deref() == Some("1") {
        println!("daemon=1 (sin quit por stdin; detener con señal/proceso)");
        loop {
            thread::sleep(Duration::from_secs(3600));
        }
    }
    let stdin = io::stdin();
    let mut linea = String::new();
    loop {
        linea.clear();
        match stdin.read_line(&mut linea) {
            Ok(0) => break,
            Ok(_) => {
                if linea.trim().eq_ignore_ascii_case("quit") {
                    break;
                }
            }
            Err(e) => {
                eprintln!("stdin: {e}");
                return 1;
            }
        }
    }
    println!("sak-domain detenido dominio={dominio_id}");
    let _ = ledger;
    0
}

fn main() {
    let mut args = env::args().skip(1);
    let cmd = match args.next() {
        Some(c) => c,
        None => usage(),
    };
    let id = match args.next() {
        Some(i) => i,
        None => usage(),
    };
    if args.next().is_some() {
        usage();
    }
    let code = match cmd.as_str() {
        "init" => cmd_init(&id),
        "status" => cmd_status(&id),
        "run" => cmd_run(&id),
        "obs" => cmd_obs(&id),
        _ => usage(),
    };
    process::exit(code);
}
