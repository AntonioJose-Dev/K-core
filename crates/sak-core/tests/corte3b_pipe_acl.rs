//! Corte 3B — transporte pipe (env) sin tocar sujeto; ACL multi-usuario = harness perfil.

use sak_core::pep::{pipe_desde_env, ENV_LOOPBACK_PIPE};

#[test]
fn pipe_env_ausente_none() {
    let prev = std::env::var(ENV_LOOPBACK_PIPE).ok();
    std::env::remove_var(ENV_LOOPBACK_PIPE);
    assert!(pipe_desde_env().is_none());
    match prev {
        Some(v) => std::env::set_var(ENV_LOOPBACK_PIPE, v),
        None => std::env::remove_var(ENV_LOOPBACK_PIPE),
    }
}

#[test]
fn pipe_env_vacio_none() {
    let prev = std::env::var(ENV_LOOPBACK_PIPE).ok();
    std::env::set_var(ENV_LOOPBACK_PIPE, "   ");
    assert!(pipe_desde_env().is_none());
    match prev {
        Some(v) => std::env::set_var(ENV_LOOPBACK_PIPE, v),
        None => std::env::remove_var(ENV_LOOPBACK_PIPE),
    }
}

#[test]
fn pipe_env_path_leido() {
    let prev = std::env::var(ENV_LOOPBACK_PIPE).ok();
    let p = r"\\.\pipe\sak-ef1-pm-test";
    std::env::set_var(ENV_LOOPBACK_PIPE, p);
    assert_eq!(pipe_desde_env().as_deref(), Some(p));
    match prev {
        Some(v) => std::env::set_var(ENV_LOOPBACK_PIPE, v),
        None => std::env::remove_var(ENV_LOOPBACK_PIPE),
    }
}

#[cfg(windows)]
#[test]
fn pipe_inexistente_abrir_falla() {
    use sak_core::pep::intentar_abrir_pipe;
    let err = intentar_abrir_pipe(r"\\.\pipe\sak-ef1-pm-no-existe-corte3b").expect_err("debe fallar");
    assert!(err.contains("os_error="), "{err}");
}
