//! A2 + A4 — checklist Auditoría y disclaimer de alcance Bloque A.
//!
//! Artefacto: confirma marcadores HTML de aceptación humana.
//! Afirmación permitida: UI guía auditoría Bloque A sin autoridad.
//! Afirmación NO permitida: mediación E2E / conformidad certificada.

use sak_ops_ui::pantallas::html_auditar;
use std::fs;
use std::path::PathBuf;

fn artefacto_dir() -> PathBuf {
    let base = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    let base = if base.is_absolute() {
        base
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").join(base)
    };
    let p = base.join("artefactos").join("bloque_a");
    fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn a2_a4_checklist_y_disclaimer_auditar() {
    let aud = html_auditar("demo-a2", "127.0.0.1:1");
    let checks = [
        "checklist-bloque-a",
        "data-check=\"latido\"",
        "data-check=\"sistema\"",
        "data-check=\"pep\"",
        "data-check=\"alcanzables\"",
        "data-check=\"custodia\"",
        "data-check=\"libro\"",
        "data-check=\"evidencia\"",
        "data-check=\"deny\"",
        "data-alcance=\"bloque-a\"",
        "No afirma",
        "efectos del agente",
    ];
    let mut missing = Vec::new();
    for c in checks {
        if !aud.contains(c) {
            missing.push(c);
        }
    }
    assert!(
        missing.is_empty(),
        "faltan marcadores A2/A4: {missing:?}"
    );

    let cuerpo = format!(
        "{{\n  \"fase\": \"A2+A4\",\n  \"marcadores_ok\": {n},\n  \"afirmacion_permitida\": \"UI muestra checklist Bloque A y disclaimer de no-mediacion; sin autoridad.\",\n  \"afirmacion_no_permitida\": \"Mediacion end-to-end ni conformidad certificada.\",\n  \"doc_checklist\": \"docs/ACEPTACION-BLOQUE-A.md\"\n}}\n",
        n = checks.len()
    );
    let path = artefacto_dir().join("a2_a4_checklist_ui.json");
    fs::write(&path, cuerpo).unwrap();
    assert!(path.is_file());
}
