//! Pantallas HTML: shell + Auditoría + Observar paneles + Conectar/Custodiar/Gobernar.

mod auditar;
mod conectar;
mod custodiar;
mod gobernar;
mod shell;

pub use auditar::html_auditar;
pub use conectar::html_conectar;
pub use custodiar::html_custodiar;
pub use gobernar::html_gobernar;
pub use shell::{html_shell, html_stub_familia, FamiliaNav};

use sak_domain::obs::contiene_secreto_prohibido;

use crate::allowlist::PANEL_OPS;
use crate::anti_engano::VistaAntiEngano;

/// Si la respuesta del canal contuviera patrón de secreto, no se muestra.
pub fn scrub_secreto_ui(respuesta: &str) -> Result<String, String> {
    if contiene_secreto_prohibido(respuesta) {
        return Err(
            "UI DENY: respuesta del canal contenía patrón de secreto; no se muestra".into(),
        );
    }
    const BAD: &[&str] = &[
        "begin private",
        "private_key",
        "secret_key",
        "\"seed\"",
        "\"pem\"",
    ];
    let lower = respuesta.to_ascii_lowercase();
    for b in BAD {
        if lower.contains(b) {
            return Err("UI DENY: patrón de material de clave".into());
        }
    }
    Ok(respuesta.to_string())
}

/// Consola Observar (paneles lectura crudos) — complemento de Auditoría.
pub fn html_consola(dominio_id: &str, obs_addr: &str) -> String {
    let mut botones = String::new();
    for (panel, op) in PANEL_OPS {
        let label = panel.replace('_', " ");
        botones.push_str(&format!(
            r#"<button type="button" data-op="{op}" data-panel="{panel}">{label}</button>"#
        ));
        botones.push('\n');
    }
    let cuerpo = format!(
        r#"<p class="banner">Familia <strong>Observar</strong> — paneles de lectura. Preferir <a href="/">Auditoría</a> para latido/custodia. UI sin autoridad: no decide, no ejerce, no eleva.</p>
<section class="obs-groups">
  <p><strong>Libro / control:</strong> paneles <em>libro</em>, <em>hechos</em>, <em>limites</em>, <em>incidentes</em>.</p>
  <p><strong>Evidencia:</strong> <em>evidencia_exportar</em> (confirmación en canal) · <em>evidencia_verificar</em> · <em>expediente</em>.</p>
  <p><strong>DENY desde UI:</strong> <code>libro.elevar</code>, <code>cap.emitir</code>, <code>cus.reveal</code>, <code>obs.diagnostico.*</code> — sin botones; el cliente los rechaza.</p>
</section>
<nav class="ops">
{botones}
</nav>
<div id="meta">Seleccione un panel Observar.</div>
<pre id="out">{{}}</pre>
<script>
const out = document.getElementById('out');
const meta = document.getElementById('meta');
document.querySelectorAll('button[data-op]').forEach(btn => {{
  btn.addEventListener('click', async () => {{
    const op = btn.getAttribute('data-op');
    const panel = btn.getAttribute('data-panel');
    meta.textContent = 'Solicitando ' + op + ' …';
    out.textContent = '';
    try {{
      let url = '/obs?op=' + encodeURIComponent(op) + '&panel=' + encodeURIComponent(panel);
      if (op === 'obs.evidencia.exportar') url += '&confirmacion_explicita=true';
      const r = await fetch(url, {{ method: 'GET' }});
      const t = await r.text();
      out.textContent = t;
      meta.innerHTML = r.ok
        ? '<span class="badge ok">OK canal · KERNEL VALIDA · UI MUESTRA</span> ' + op
        : '<span class="badge deny">DENY/ERROR</span> ' + op;
    }} catch (e) {{
      out.textContent = String(e);
      meta.innerHTML = '<span class="badge deny">fallo</span>';
    }}
  }});
}});
(function() {{
  const p = new URLSearchParams(location.search).get('panel');
  if (!p) return;
  const btn = document.querySelector('button[data-panel="' + p + '"]');
  if (btn) btn.click();
  else meta.textContent = 'panel deep-link desconocido: ' + p;
}})();
</script>"#,
        botones = botones,
    );
    html_shell(
        dominio_id,
        obs_addr,
        FamiliaNav::Observar,
        "Observar",
        &cuerpo,
    )
}

/// Demo del panel anti-engaño (sin acción de autoridad).
pub fn html_anti_engano_demo(dominio_id: &str, obs_addr: &str) -> String {
    let v = VistaAntiEngano {
        objeto_canonico: "{\n  \"ejemplo\": \"auditoria\",\n  \"sin_autoridad\": true\n}".into(),
        digest: "00000000".into(),
        identidad: "operador-ui-local".into(),
        rol: "operador".into(),
        consecuencias: "Ninguna: vista de demostración. No envía propuestas.".into(),
        epoca: "1".into(),
        confirmacion_independiente: false,
    };
    let cuerpo = format!(
        r#"<p class="banner">Componente anti-engaño (IPC §1) — la UI muestra; el Kernel valida.</p>
{}"#,
        v.html_panel()
    );
    html_shell(
        dominio_id,
        obs_addr,
        FamiliaNav::Observar,
        "Anti-engaño",
        &cuerpo,
    )
}
