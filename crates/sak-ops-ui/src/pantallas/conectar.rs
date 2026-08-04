//! Pantallas Conectar C1–C5 (Fase 4: ALCANZABLES + deep-links Observar).

use crate::allowlist::ops_mvp_conectar;
use crate::anti_engano::VistaAntiEngano;
use crate::pantallas::shell::{html_shell, FamiliaNav};

const CONSECUENCIAS_ALTA: &str =
    "Registra el sistema y su declaración. NO autoriza efectos. NO emite capacidades.";

const CONSECUENCIAS_ALC: &str =
    "Registra inventario firmado con caducidad. NO afirma completitud. NO autoriza efectos.";

/// C1–C5: sistemas, alta, pasaporte, PEPs, ALCANZABLES.
pub fn html_conectar(dominio_id: &str, canal: &str) -> String {
    let anti = VistaAntiEngano {
        objeto_canonico: "declaracion_responsable (campos + firma hex)".into(),
        digest: "(se calcula en Kernel tras verificar firma)".into(),
        identidad: "responsable (firmante)".into(),
        rol: "responsable".into(),
        consecuencias: CONSECUENCIAS_ALTA.into(),
        epoca: "(epoca_vista del dominio)".into(),
        confirmacion_independiente: false,
    };
    let anti_alc = VistaAntiEngano {
        objeto_canonico: "inventario ALCANZABLES (efectores/rutas/digests + firma productor)".into(),
        digest: "(digest dominio LIBRO del cuerpo canónico)".into(),
        identidad: "productor_id (detector instrumentado)".into(),
        rol: "inventario_alcanzables".into(),
        consecuencias: CONSECUENCIAS_ALC.into(),
        epoca: "(epoca del inventario)".into(),
        confirmacion_independiente: false,
    };
    let ops: String = ops_mvp_conectar()
        .iter()
        .map(|o| format!("<li><code>{o}</code></li>"))
        .collect::<Vec<_>>()
        .join("");
    let cuerpo = format!(
        r#"<p class="banner"><strong>Conectar</strong> — registra identidad e inventario; <em>no autoriza efectos</em>. UI no firma capacidades ni eleva Libro. Kernel valida firmas.</p>
<p class="banner muted">Bloque A (operar/auditar): alta · pasaporte · PEP vista · ALCANZABLES · DENY de secretos/autorizar. Mediación de efectos (decidir/ejercer) = Bloque B, <strong>fuera de esta UI</strong>.</p>
<section>
  <h2>C1 — Sistemas</h2>
  <button type="button" id="btn-listar">Listar (con.sistemas.listar)</button>
  <pre id="lista">{{}}</pre>
</section>
<section>
  <h2>C2 — Alta de sistema</h2>
  <p>Campos de declaración + <code>firma_responsable_hex</code> + <code>pk_responsable_hex</code>. Sin API keys.</p>
  {anti}
  <textarea id="alta-json" rows="8" style="width:100%" placeholder='JSON parcial o completo para POST /ops'></textarea>
  <button type="button" id="btn-alta">Enviar con.sistema.alta</button>
  <pre id="alta-out">{{}}</pre>
</section>
<section>
  <h2>C3 — Pasaporte</h2>
  <label>pasaporte_id <input id="pass-id"/></label>
  <label>version <input id="pass-ver" value="1"/></label>
  <button type="button" id="btn-emitir">Emitir (requiere JSON con firma en #alta-json)</button>
  <button type="button" id="btn-get">Get</button>
  <pre id="pass-out">{{}}</pre>
</section>
<section>
  <h2>C4 — PEPs (declarativo)</h2>
  <button type="button" id="btn-pep-vista">Vista</button>
  <textarea id="pep-json" rows="4" style="width:100%" placeholder='mapa_json opcional'></textarea>
  <button type="button" id="btn-pep-cfg">Configurar</button>
  <pre id="pep-out">{{}}</pre>
</section>
<section>
  <h2>C5 — Inventario ALCANZABLES</h2>
  <p>Productor, caducidad (<code>antiguedad_max</code>), límites INV-11. Credenciales solo como <code>cred:digest:…</code>. Sin material exportable. Sin afirmar completitud.</p>
  {anti_alc}
  <p class="deep-links">Deep-links Observar (solo lectura):
    <a href="/observar?panel=libro">Libro</a> ·
    <a href="/observar?panel=hechos">Hechos</a> ·
    <a href="/observar?panel=limites">Límites</a>
  </p>
  <textarea id="alc-json" rows="8" style="width:100%" placeholder='{{"sistema_id":"…","productor_id":"detector-…","efectores":"EF-1,EF-4","credenciales_detectadas":"cred:digest:aabb","firma_productor_hex":"…","pk_productor_hex":"…","incompleto_declarado":true}}'></textarea>
  <button type="button" id="btn-alc">Registrar con.inventario.alcanzables</button>
  <button type="button" id="btn-alc-vista">Vista / listar</button>
  <pre id="alc-out">{{}}</pre>
</section>
<p class="muted">Ops allowlist: <ul>{ops}</ul></p>
<script>
async function postOps(op, extraObj) {{
  const body = Object.assign({{op, req_id:'ui-'+Date.now(), schema_v:1, operador_id:'operador-ui-local'}}, extraObj||{{}});
  const r = await fetch('/ops', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  return r.text();
}}
document.getElementById('btn-listar').onclick = async () => {{
  document.getElementById('lista').textContent = await postOps('con.sistemas.listar', {{}});
}};
document.getElementById('btn-alta').onclick = async () => {{
  let extra = {{}};
  try {{ extra = JSON.parse(document.getElementById('alta-json').value || '{{}}'); }} catch(e) {{ alert(e); return; }}
  document.getElementById('alta-out').textContent = await postOps('con.sistema.alta', extra);
}};
document.getElementById('btn-emitir').onclick = async () => {{
  let extra = {{}};
  try {{ extra = JSON.parse(document.getElementById('alta-json').value || '{{}}'); }} catch(e) {{ alert(e); return; }}
  extra.pasaporte_id = document.getElementById('pass-id').value || extra.pasaporte_id || extra.sistema_id;
  extra.version = parseInt(document.getElementById('pass-ver').value||'1',10);
  document.getElementById('pass-out').textContent = await postOps('con.pasaporte.emitir', extra);
}};
document.getElementById('btn-get').onclick = async () => {{
  const id = document.getElementById('pass-id').value;
  const ver = parseInt(document.getElementById('pass-ver').value||'1',10);
  document.getElementById('pass-out').textContent = await postOps('con.pasaporte.get', {{pasaporte_id:id, version:ver}});
}};
document.getElementById('btn-pep-vista').onclick = async () => {{
  document.getElementById('pep-out').textContent = await postOps('con.pep.vista', {{}});
}};
document.getElementById('btn-pep-cfg').onclick = async () => {{
  const mapa_json = document.getElementById('pep-json').value || '{{}}';
  document.getElementById('pep-out').textContent = await postOps('con.pep.configurar', {{mapa_json}});
}};
document.getElementById('btn-alc').onclick = async () => {{
  let extra = {{}};
  try {{ extra = JSON.parse(document.getElementById('alc-json').value || '{{}}'); }} catch(e) {{ alert(e); return; }}
  document.getElementById('alc-out').textContent = await postOps('con.inventario.alcanzables', extra);
}};
document.getElementById('btn-alc-vista').onclick = async () => {{
  document.getElementById('alc-out').textContent = await postOps('con.inventario.alcanzables', {{vista:true}});
}};
</script>"#,
        anti = anti.html_panel(),
        anti_alc = anti_alc.html_panel(),
        ops = ops,
    );
    html_shell(dominio_id, canal, FamiliaNav::Conectar, "Conectar", &cuerpo)
}
