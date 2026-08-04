//! Binario consola operador local — solo Observar vía canal obs.*.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use sak_ops_ui::cliente::{parse_obs_addr, ClienteCanalTcp};
use sak_ops_ui::servidor::{servir_loopback, validar_bind_ui};

fn usage() -> ! {
    eprintln!(
        "uso: sak-ops-ui --dominio <id> --obs 127.0.0.1:<port> [--bind 127.0.0.1:<port>]\n\
         Solo loopback. Solo GET → obs.*. Sin telemetría. Sin autoridad."
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut dominio = None::<String>;
    let mut obs = None::<String>;
    let mut bind = "127.0.0.1:8790".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--dominio" => {
                i += 1;
                dominio = args.get(i).cloned();
            }
            "--obs" => {
                i += 1;
                obs = args.get(i).cloned();
            }
            "--bind" => {
                i += 1;
                bind = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
        i += 1;
    }
    let dominio = dominio.unwrap_or_else(|| usage());
    let obs_s = obs.unwrap_or_else(|| usage());
    let obs_addr = parse_obs_addr(&obs_s).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    let bind_addr: SocketAddr = bind.parse().unwrap_or_else(|_| usage());
    if let Err(e) = validar_bind_ui(bind_addr) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let cliente = Arc::new(
        ClienteCanalTcp::nuevo(obs_addr, &dominio).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        }),
    );
    if let Err(e) = servir_loopback(bind_addr, cliente, dominio, obs_s) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
