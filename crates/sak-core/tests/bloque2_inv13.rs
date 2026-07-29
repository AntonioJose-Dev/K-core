//! INV-13: el crate autoritativo no contiene identificadores de instrumentos legales.

use std::fs;
use std::path::PathBuf;

fn fragmentos_prohibidos() -> Vec<String> {
    // Construidos por partes para que este propio archivo no introduzca el token completo
    // en el árbol de fuentes como cita embebida.
    vec![
        format!("{}{}", "GD", "PR"),
        format!("{}{}", "RG", "PD"),
        format!("{}{}", "AI ", "Act"),
        format!("{}{}", "LOPD", "GDD"),
        format!("{}{}", "Reglamento (UE) 2016/", "679"),
        format!("{}{}", "Reglamento (UE) 2024/", "1689"),
        format!("{}{}", "Artificial Intelligence ", "Act"),
    ]
}

#[test]
fn crate_autoritativo_sin_instrumentos_legales() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hallazgos = Vec::new();
    let prohibidos = fragmentos_prohibidos();
    visit(&root, &prohibidos, &mut hallazgos);
    assert!(
        hallazgos.is_empty(),
        "INV-13 violado; coincidencias: {hallazgos:?}"
    );
}

fn visit(dir: &PathBuf, prohibidos: &[String], out: &mut Vec<String>) {
    let entries = fs::read_dir(dir).expect("leer src");
    for e in entries.flatten() {
        let path = e.path();
        if path.is_dir() {
            visit(&path, prohibidos, out);
            continue;
        }
        if path.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap_or_default();
        for p in prohibidos {
            if text.contains(p) {
                out.push(format!("{}: contiene '{p}'", path.display()));
            }
        }
    }
}
