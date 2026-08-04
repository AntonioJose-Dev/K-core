//! Pantallas Custodiar — referencias + rotación IRREVERSIBLE (Fase 5.1).

use crate::allowlist::ops_mvp_custodiar;
use crate::anti_engano::VistaAntiEngano;
use crate::pantallas::shell::{html_shell, FamiliaNav};

const CONSECUENCIAS: &str =
    "Registra solo handle/ref opaco. NO revela material. NO exporta raíz.";

const CONSECUENCIAS_ROTAR: &str =
    "IRREVERSIBLE: sustituye handle; conserva huella/historial anterior. NO material antiguo/nuevo. NO reveal/export_raiz.";

pub fn html_custodiar(dominio_id: &str, canal: &str) -> String {
    let anti = VistaAntiEngano {
        objeto_canonico: "alias | clase_ef | handle (KMS/PKCS#11) + firma_operador_hex".into(),
        digest: "(huella = SHA-384 dominio CUSTODIA del cuerpo canónico)".into(),
        identidad: "operador (firmante)".into(),
        rol: "operador-custodia".into(),
        consecuencias: CONSECUENCIAS.into(),
        epoca: "(epoca_vista del dominio)".into(),
        confirmacion_independiente: false,
    };
    let anti_rotar = VistaAntiEngano {
        objeto_canonico: "SAK-CUS-ROTAR-v1|secreto_id|huella_anterior|nuevo_handle|epoca|rol".into(),
        digest: "(digest visible en respuesta Kernel tras verificar firma)".into(),
        identidad: "operador (firmante)".into(),
        rol: "operador-custodia".into(),
        consecuencias: CONSECUENCIAS_ROTAR.into(),
        epoca: "(epoca_vista obligatoria)".into(),
        confirmacion_independiente: true,
    };
    let ops: String = ops_mvp_custodiar()
        .iter()
        .map(|o| format!("<li><code>{o}</code></li>"))
        .collect::<Vec<_>>()
        .join("");
    let cuerpo = format!(
        r#"<p class="banner"><strong>Custodiar</strong> — referencias y metadatos. Sin material de clave. UI no revela ni exporta raíz. <code>cus.rotar</code> = IRREVERSIBLE (Kernel valida).</p>
<p class="banner muted">Bloque A: alta de handle/huella · estado · DENY <code>cus.reveal</code>/<code>export_raiz</code>. La UI no posee credencial de efector.</p>
<section>
  <h2>Estado dominio</h2>
  <button type="button" id="btn-estado">cus.estado (lista)</button>
  <pre id="estado-out">{{}}</pre>
</section>
<section>
  <h2>Alta de referencia</h2>
  <p>Solo <code>alias</code>, <code>clase_ef</code>, <code>handle</code> + firma operador. PEM/raw/seed → DENY.</p>
  {anti}
  <textarea id="alta-json" rows="8" style="width:100%" placeholder='{{"alias":"kms-demo","clase_ef":"EF-1","handle":"kms:proj/key-1","firma_operador_hex":"...","pk_operador_hex":"..."}}'></textarea>
  <button type="button" id="btn-alta">Enviar cus.alta_referencia</button>
  <pre id="alta-out">{{}}</pre>
</section>
<section>
  <h2>Estado por id/alias</h2>
  <label>secreto_id <input id="sec-id"/></label>
  <label>alias <input id="sec-alias"/></label>
  <button type="button" id="btn-get">Consultar</button>
  <pre id="get-out">{{}}</pre>
</section>
<section>
  <h2>Rotar handle (IRREVERSIBLE)</h2>
  <p>Nuevo handle opaco + firma sobre objeto canónico. Conserva huella/historial. Cero bytes de material.</p>
  {anti_rotar}
  <textarea id="rotar-json" rows="8" style="width:100%" placeholder='{{"secreto_id":"…","nuevo_handle":"kms:proj/key-2","epoca_vista":1,"rol":"operador-custodia","identidad":"operador","confirmacion_independiente":true,"firma_operador_hex":"…","pk_operador_hex":"…"}}'></textarea>
  <button type="button" id="btn-rotar">Enviar cus.rotar</button>
  <pre id="rotar-out">{{}}</pre>
</section>
<p class="muted">Ops allowlist: <ul>{ops}</ul> · DENY fijo: <code>cus.reveal</code>, <code>cus.export_raiz</code></p>
<script>
async function postOps(op, extraObj) {{
  const body = Object.assign({{op, req_id:'ui-'+Date.now(), schema_v:1, operador_id:'operador-ui-local'}}, extraObj||{{}});
  const r = await fetch('/ops', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  return r.text();
}}
document.getElementById('btn-estado').onclick = async () => {{
  document.getElementById('estado-out').textContent = await postOps('cus.estado', {{}});
}};
document.getElementById('btn-alta').onclick = async () => {{
  let extra = {{}};
  try {{ extra = JSON.parse(document.getElementById('alta-json').value || '{{}}'); }} catch(e) {{ alert(e); return; }}
  document.getElementById('alta-out').textContent = await postOps('cus.alta_referencia', extra);
}};
document.getElementById('btn-get').onclick = async () => {{
  const extra = {{}};
  const id = document.getElementById('sec-id').value;
  const alias = document.getElementById('sec-alias').value;
  if (id) extra.secreto_id = id;
  if (alias) extra.alias = alias;
  document.getElementById('get-out').textContent = await postOps('cus.estado', extra);
}};
document.getElementById('btn-rotar').onclick = async () => {{
  let extra = {{}};
  try {{ extra = JSON.parse(document.getElementById('rotar-json').value || '{{}}'); }} catch(e) {{ alert(e); return; }}
  document.getElementById('rotar-out').textContent = await postOps('cus.rotar', extra);
}};
</script>"#,
        anti = anti.html_panel(),
        anti_rotar = anti_rotar.html_panel(),
        ops = ops,
    );
    html_shell(dominio_id, canal, FamiliaNav::Custodiar, "Custodiar", &cuerpo)
}
