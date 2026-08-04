//! Pantallas Gobernar — G.5 completo hasta revocar/revertir (Fase 5.4).

use crate::allowlist::ops_mvp_gobernar;
use crate::anti_engano::VistaAntiEngano;
use crate::pantallas::shell::{html_shell, FamiliaNav};

const CONSECUENCIAS: &str =
    "Registra propuesta, diff y firmas. NO activa época. NO revoca. NO certifica conformidad.";

const CONSECUENCIAS_SOMBRA: &str =
    "NO activa época. NO aplica como vivo. NO certifica conformidad. Ventana 7d: evalúa sin ALLOW reales.";

const CONSECUENCIAS_ACTIVAR: &str =
    "IRREVERSIBLE: avanza época y marca paquete activo vivo; conserva historial/paquete anterior. NO certifica conformidad. NO revoca.";

const CONSECUENCIAS_REVOCAR: &str =
    "IRREVERSIBLE: deja de ser activo vivo. NO borra historial/expediente/firmas/diff. NO invalida decisiones pasadas. NO certifica conformidad.";

const CONSECUENCIAS_REVERTIR: &str =
    "IRREVERSIBLE: reabre FIRMADA del hash histórico; exige sombra+activar. Conserva firmas/diff. NO borra ni salta trazabilidad. NO certifica conformidad.";

pub fn html_gobernar(dominio_id: &str, canal: &str) -> String {
    let anti = VistaAntiEngano {
        objeto_canonico: "hash_paquete + borrador (identificador|fuente|veredicto)".into(),
        digest: "(hash_paquete SHA-384 del paquete normativo)".into(),
        identidad: "proponente / revisor / firmantes juridico+tecnico".into(),
        rol: "gobernanza".into(),
        consecuencias: CONSECUENCIAS.into(),
        epoca: "(epoca_vista; sin activar)".into(),
        confirmacion_independiente: false,
    };
    let anti_sombra = VistaAntiEngano {
        objeto_canonico: "SAK-GOB-SOMBRA-v1|hash_paquete|ventana_ms=604800000".into(),
        digest: "(digest Kernel tras gob.entrar_sombra)".into(),
        identidad: "operador gobernanza".into(),
        rol: "gobernanza-sombra".into(),
        consecuencias: CONSECUENCIAS_SOMBRA.into(),
        epoca: "(epoca_vista obligatoria)".into(),
        confirmacion_independiente: true,
    };
    let anti_activar = VistaAntiEngano {
        objeto_canonico: "SAK-GOB-ACTIVAR-v1|hash_paquete|epoca_vista|rol".into(),
        digest: "(digest Kernel tras verificar firma)".into(),
        identidad: "operador gobernanza".into(),
        rol: "gobernanza-activar".into(),
        consecuencias: CONSECUENCIAS_ACTIVAR.into(),
        epoca: "(epoca_vista + en_limite_epoca=true)".into(),
        confirmacion_independiente: true,
    };
    let anti_revocar = VistaAntiEngano {
        objeto_canonico: "SAK-GOB-REVOCAR-v1|hash_paquete (+ firmas 2-de-N)".into(),
        digest: "(digest Kernel tras verificar umbral jurídico+técnico)".into(),
        identidad: "firmantes juridico+tecnico".into(),
        rol: "gobernanza-revocar".into(),
        consecuencias: CONSECUENCIAS_REVOCAR.into(),
        epoca: "(epoca_vista obligatoria)".into(),
        confirmacion_independiente: true,
    };
    let anti_revertir = VistaAntiEngano {
        objeto_canonico: "SAK-GOB-REVERTIR-v1|hash_paquete (+ firmas 2-de-N)".into(),
        digest: "(digest Kernel; no salta sombra)".into(),
        identidad: "firmantes juridico+tecnico".into(),
        rol: "gobernanza-revertir".into(),
        consecuencias: CONSECUENCIAS_REVERTIR.into(),
        epoca: "(epoca_vista obligatoria)".into(),
        confirmacion_independiente: true,
    };
    let ops: String = ops_mvp_gobernar()
        .iter()
        .map(|o| format!("<li><code>{o}</code></li>"))
        .collect::<Vec<_>>()
        .join("");
    let cuerpo = format!(
        r#"<p class="banner"><strong>Gobernar</strong> — G.5: propuesta → sombra → activar → revocar/revertir. Sin auto-certificación de conformidad. Sin borrar historia.</p>
<section>
  <h2>Propuesta</h2>
  {anti}
  <textarea id="prop-json" rows="10" style="width:100%" placeholder='JSON gob.proponer (identificador, fuente, interpretacion, firmas aprobacion+proponente…)'></textarea>
  <button type="button" id="btn-prop">gob.proponer</button>
  <pre id="prop-out">{{}}</pre>
</section>
<section>
  <h2>Revisión / Diff / Reconocer / Doble firma</h2>
  <label>hash_paquete <input id="hash" style="width:70%"/></label>
  <button type="button" id="btn-rev">revision_juridica</button>
  <button type="button" id="btn-diff">diff_conformidad</button>
  <textarea id="ack-json" rows="4" style="width:100%" placeholder='campos extra reconocer_diff / doble_firma'></textarea>
  <button type="button" id="btn-ack">reconocer_diff</button>
  <button type="button" id="btn-df">doble_firma</button>
  <pre id="flujo-out">{{}}</pre>
</section>
<section>
  <h2>Sombra (7 días — evalúa sin aplicar en vivo)</h2>
  <p class="banner">Registro visible: <strong>no activa</strong> · <strong>no aplica como vivo</strong> · <strong>no certifica conformidad</strong>.</p>
  {anti_sombra}
  <textarea id="sombra-json" rows="5" style="width:100%" placeholder='{{"identidad":"op","rol":"gobernanza-sombra","epoca_vista":"1","confirmacion_independiente":true}}'></textarea>
  <button type="button" id="btn-sombra">gob.entrar_sombra</button>
  <button type="button" id="btn-estado-sombra">gob.estado_sombra (lectura)</button>
  <pre id="sombra-out">{{}}</pre>
</section>
<section>
  <h2>Activar época (IRREVERSIBLE)</h2>
  <p class="banner">Solo <code>EN_SOMBRA</code> + ventana completa + <code>en_limite_epoca:true</code>. <strong>NO</strong> certifica conformidad.</p>
  {anti_activar}
  <textarea id="activar-json" rows="6" style="width:100%" placeholder='{{"identidad":"op","rol":"gobernanza-activar","epoca_vista":1,"en_limite_epoca":true,"confirmacion_independiente":true,"firma_operador_hex":"…","pk_operador_hex":"…"}}'></textarea>
  <button type="button" id="btn-activar">gob.activar_epoca</button>
  <pre id="activar-out">{{}}</pre>
</section>
<section>
  <h2>Revocar / Revertir (IRREVERSIBLE)</h2>
  <p class="banner">Revocar no borra historia. Revertir reabre FIRMADA y exige sombra+activar (sin saltos). Firmas 2-de-N.</p>
  {anti_revocar}
  {anti_revertir}
  <textarea id="rev-json" rows="6" style="width:100%" placeholder='{{"identidad":"op","rol":"gobernanza-revocar","epoca_vista":1,"confirmacion_independiente":true,"id_juridico":"…","firma_juridico_hex":"…","pk_juridico_hex":"…","id_tecnico":"…","firma_tecnico_hex":"…","pk_tecnico_hex":"…"}}'></textarea>
  <button type="button" id="btn-revocar">gob.revocar</button>
  <button type="button" id="btn-revertir">gob.revertir</button>
  <pre id="rev-out">{{}}</pre>
</section>
<p class="muted">Ops: <ul>{ops}</ul> · <code>conformidad_certificada</code> siempre false · DENY: borrar historia / saltar trazabilidad / auto-certificar</p>
<script>
async function postOps(op, extraObj) {{
  const body = Object.assign({{op, req_id:'ui-'+Date.now(), schema_v:1, operador_id:'operador-ui-local'}}, extraObj||{{}});
  const r = await fetch('/ops', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  return r.text();
}}
function parseExtra(id) {{
  try {{ return JSON.parse(document.getElementById(id).value || '{{}}'); }} catch(e) {{ alert(e); return null; }}
}}
document.getElementById('btn-prop').onclick = async () => {{
  const extra = parseExtra('prop-json'); if (!extra) return;
  const t = await postOps('gob.proponer', extra);
  document.getElementById('prop-out').textContent = t;
  try {{
    const j = JSON.parse(t);
    const h = j.cuerpo && j.cuerpo.hash_paquete;
    if (h) document.getElementById('hash').value = h;
  }} catch(_) {{}}
}};
document.getElementById('btn-rev').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value, revisor_id:'revisor-mvp', competencia_registrada:true}}, parseExtra('ack-json')||{{}});
  document.getElementById('flujo-out').textContent = await postOps('gob.revision_juridica', extra);
}};
document.getElementById('btn-diff').onclick = async () => {{
  document.getElementById('flujo-out').textContent = await postOps('gob.diff_conformidad', {{hash_paquete: document.getElementById('hash').value}});
}};
document.getElementById('btn-ack').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value}}, parseExtra('ack-json')||{{}});
  document.getElementById('flujo-out').textContent = await postOps('gob.reconocer_diff', extra);
}};
document.getElementById('btn-df').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value}}, parseExtra('ack-json')||{{}});
  document.getElementById('flujo-out').textContent = await postOps('gob.doble_firma', extra);
}};
document.getElementById('btn-sombra').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value, confirmacion_independiente:true}}, parseExtra('sombra-json')||{{}});
  document.getElementById('sombra-out').textContent = await postOps('gob.entrar_sombra', extra);
}};
document.getElementById('btn-estado-sombra').onclick = async () => {{
  document.getElementById('sombra-out').textContent = await postOps('gob.estado_sombra', {{hash_paquete: document.getElementById('hash').value}});
}};
document.getElementById('btn-activar').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value, confirmacion_independiente:true, en_limite_epoca:true}}, parseExtra('activar-json')||{{}});
  document.getElementById('activar-out').textContent = await postOps('gob.activar_epoca', extra);
}};
document.getElementById('btn-revocar').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value, confirmacion_independiente:true}}, parseExtra('rev-json')||{{}});
  document.getElementById('rev-out').textContent = await postOps('gob.revocar', extra);
}};
document.getElementById('btn-revertir').onclick = async () => {{
  const extra = Object.assign({{hash_paquete: document.getElementById('hash').value, confirmacion_independiente:true}}, parseExtra('rev-json')||{{}});
  document.getElementById('rev-out').textContent = await postOps('gob.revertir', extra);
}};
</script>"#,
        anti = anti.html_panel(),
        anti_sombra = anti_sombra.html_panel(),
        anti_activar = anti_activar.html_panel(),
        anti_revocar = anti_revocar.html_panel(),
        anti_revertir = anti_revertir.html_panel(),
        ops = ops,
    );
    html_shell(dominio_id, canal, FamiliaNav::Gobernar, "Gobernar", &cuerpo)
}
