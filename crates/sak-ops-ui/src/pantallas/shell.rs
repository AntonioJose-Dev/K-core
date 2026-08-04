//! Shell de navegación: Observar | Conectar | Custodiar | Gobernar.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamiliaNav {
    Auditar,
    Observar,
    Conectar,
    Custodiar,
    Gobernar,
}

impl FamiliaNav {
    pub fn path(self) -> &'static str {
        match self {
            FamiliaNav::Auditar => "/",
            FamiliaNav::Observar => "/observar",
            FamiliaNav::Conectar => "/conectar",
            FamiliaNav::Custodiar => "/custodiar",
            FamiliaNav::Gobernar => "/gobernar",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            FamiliaNav::Auditar => "Auditoría",
            FamiliaNav::Observar => "Observar",
            FamiliaNav::Conectar => "Conectar",
            FamiliaNav::Custodiar => "Custodiar",
            FamiliaNav::Gobernar => "Gobernar",
        }
    }
}

pub fn html_shell(
    dominio_id: &str,
    canal_addr: &str,
    activa: FamiliaNav,
    titulo: &str,
    cuerpo: &str,
) -> String {
    let mut nav = String::new();
    for f in [
        FamiliaNav::Auditar,
        FamiliaNav::Observar,
        FamiliaNav::Conectar,
        FamiliaNav::Custodiar,
        FamiliaNav::Gobernar,
    ] {
        let cls = if f == activa { " class=\"activa\"" } else { "" };
        nav.push_str(&format!(
            r#"<a href="{}"{}>{}</a>"#,
            f.path(),
            cls,
            f.label()
        ));
    }
    let (h1, sub) = if activa == FamiliaNav::Auditar {
        (
            format!("Verificación del Kernel"),
            format!(
                "dominio <strong>{}</strong> · canal <code>{}</code> · solo lectura de auditoría",
                esc(dominio_id),
                esc(canal_addr)
            ),
        )
    } else if activa == FamiliaNav::Conectar || activa == FamiliaNav::Custodiar {
        (
            format!("Operar — {}", esc(titulo)),
            format!(
                "dominio <strong>{}</strong> · canal <code>{}</code> · UI transporta; Kernel valida · sin emitir caps",
                esc(dominio_id),
                esc(canal_addr)
            ),
        )
    } else if activa == FamiliaNav::Observar {
        (
            format!("Auditar — Observar"),
            format!(
                "dominio <strong>{}</strong> · canal <code>{}</code> · Libro · Evidencia · solo lectura",
                esc(dominio_id),
                esc(canal_addr)
            ),
        )
    } else {
        (
            format!("Consola operador — {}", esc(titulo)),
            format!(
                "dominio <strong>{}</strong> · canal <code>{}</code> · loopback",
                esc(dominio_id),
                esc(canal_addr)
            ),
        )
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>SAK Operador — {titulo}</title>
<style>
:root {{ --bg:#0f1419; --fg:#e7ecf1; --muted:#8b9aab; --accent:#3d8bfd; --warn:#a67c2a; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font:15px/1.45 system-ui,sans-serif; background:var(--bg); color:var(--fg); }}
header {{ padding:1rem 1.25rem; border-bottom:1px solid #243044; }}
header h1 {{ margin:0; font-size:1.15rem; font-weight:600; }}
header p {{ margin:.35rem 0 0; color:var(--muted); font-size:.85rem; }}
.auth-banner {{ background:#2a2210; color:#e8d9a8; padding:.5rem 1.25rem; font-size:.85rem; border-bottom:1px solid #4a3c18; }}
nav.fam {{ display:flex; gap:.5rem; padding:.75rem 1.25rem; border-bottom:1px solid #243044; flex-wrap:wrap; }}
nav.fam a {{ color:var(--muted); text-decoration:none; padding:.35rem .65rem; border:1px solid #2c3c52; border-radius:6px; }}
nav.fam a.activa {{ color:var(--fg); border-color:var(--accent); }}
nav.ops {{ display:flex; flex-wrap:wrap; gap:.4rem; padding:0 0 1rem; }}
button {{ background:#1a2332; color:var(--fg); border:1px solid #2c3c52; border-radius:6px; padding:.45rem .7rem; cursor:pointer; }}
main {{ padding:1.25rem 1.25rem 2.5rem; }}
.banner {{ color:var(--muted); }}
#meta {{ color:var(--muted); font-size:.8rem; margin-bottom:.75rem; }}
pre, pre.canon {{ background:#121a24; border:1px solid #243044; border-radius:8px; padding:1rem; overflow:auto; white-space:pre-wrap; word-break:break-word; }}
.badge {{ display:inline-block; padding:.1rem .4rem; border-radius:4px; font-size:.75rem; }}
.ok {{ background:#1a3; }} .deny {{ background:#522; }}
.anti-engano {{ border:1px solid #3d4a5c; border-radius:8px; padding:1rem; margin-top:1rem; }}
.anti-engano dt {{ color:var(--muted); margin-top:.5rem; }}
.stub {{ border:1px dashed #3d4a5c; border-radius:8px; padding:1.25rem; color:var(--muted); }}
</style>
</head>
<body>
<div class="auth-banner">UI sin autoridad — el Kernel Rust es el único emisor. UI muestra; Kernel valida. No firma capacidades. No eleva Libro. No certifica conformidad. Sin telemetría. Solo loopback. DENY fijo: <code>cap.emitir</code> · <code>libro.elevar</code> · <code>cus.reveal</code> · <code>obs.diagnostico.*</code> (desde UI).</div>
<header>
  <h1>{h1}</h1>
  <p>{sub}</p>
</header>
<nav class="fam">{nav}</nav>
<main>
{cuerpo}
</main>
</body>
</html>
"#,
        titulo = esc(titulo),
        h1 = h1,
        sub = sub,
        nav = nav,
        cuerpo = cuerpo,
    )
}

pub fn html_stub_familia(
    dominio_id: &str,
    canal_addr: &str,
    fam: FamiliaNav,
    ops_mvp: &[&str],
) -> String {
    let lista: String = ops_mvp
        .iter()
        .map(|o| format!("<li><code>{o}</code> → <span class=\"badge deny\">FASE0_SIN_HANDLER</span></li>"))
        .collect::<Vec<_>>()
        .join("\n");
    let cuerpo = format!(
        r#"<div class="stub">
  <p><strong>{label}</strong> — allowlist MVP reconocida; handlers de negocio en Fase 1+.</p>
  <p>No hay formularios de mutación en Fase 0. El canal responde <code>FASE0_SIN_HANDLER</code>.</p>
  <ul>{lista}</ul>
  <p><a href="/observar">Volver a Observar (lectura)</a> · <a href="/anti-engano">Ver panel anti-engaño</a></p>
</div>"#,
        label = fam.label(),
        lista = lista,
    );
    html_shell(dominio_id, canal_addr, fam, fam.label(), &cuerpo)
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
