//! Pantalla Auditoría — verificación operativa del Kernel (vivo, sistemas, custodia).
//! Claridad de lectura de operador; UI sin autoridad; no certifica conformidad.

use crate::allowlist::ops_deny_fijo;
use crate::pantallas::shell::{html_shell, FamiliaNav};

pub fn html_auditar(dominio_id: &str, canal: &str) -> String {
    let bloqueados: String = ops_deny_fijo()
        .iter()
        .chain(["obs.diagnostico.decidir", "obs.diagnostico.ejercer"].iter())
        .map(|o| format!("<li><code>{o}</code></li>"))
        .collect::<Vec<_>>()
        .join("");

    let cuerpo = format!(
        r#"<header class="aud-hero" data-alcance="bloque-a">
  <p class="aud-kicker">Superficie de verificación · no de mando</p>
  <h1 class="aud-title">¿Está el Kernel vivo y custodiando bien?</h1>
  <p class="aud-lead">Esta pantalla sirve para <strong>comprobar</strong> tres cosas: que el dominio responde, que ve sistemas e identidades registradas, y que las referencias de custodia existen como metadatos — sin material de clave. No es una consola de operaciones genérica.</p>
  <p class="aud-lead muted">La UI <strong>no valida</strong>, <strong>no emite autoridad</strong> y <strong>no certifica cumplimiento</strong>. Solo pide lecturas al Kernel y muestra la respuesta.</p>
  <aside class="aud-alcance" id="alcance-bloque-a" data-fase="A4">
    <p><strong>Alcance Bloque A (A4):</strong> registro + custodia de referencias + DENY en canal operador. <strong>No afirma</strong> frontera única de efectos del agente (modelo/herramientas/datos mediadas por Kernel).</p>
  </aside>
</header>

<section class="aud-checklist" id="checklist-bloque-a" aria-label="Checklist aceptación Bloque A" data-fase="A2">
  <h2 class="aud-h2">Checklist de aceptación (Bloque A)</h2>
  <p class="aud-sub">Marca operativa tras el harness A1. La UI no firma conformidad; solo guía la auditoría humana.</p>
  <ol class="check-list">
    <li data-check="latido">Latido: dominio responde (<code>obs.salud</code> / <code>obs.estado</code>)</li>
    <li data-check="sistema">Sistema listado tras alta + pasaporte <code>firma_valida</code></li>
    <li data-check="pep">PEP vista sin secretos (solo nombres/egreso)</li>
    <li data-check="alcanzables">ALCANZABLES con <code>incompleto_declarado:true</code></li>
    <li data-check="custodia">Custodia: handle/huella y <code>material:null</code></li>
    <li data-check="libro">Libro/hechos visibles; sin elevar</li>
    <li data-check="evidencia">Evidencia export/verificar con <code>no_comprobado</code></li>
    <li data-check="deny">DENYs de autoridad siguen cerrados</li>
  </ol>
</section>

<section class="aud-howto" aria-label="Cómo leer esta pantalla">
  <h2 class="aud-h2">Cómo leer cada bloque</h2>
  <div class="role-cards">
    <article class="role-card">
      <span class="pill kernel">KERNEL VALIDA</span>
      <p>El dominio comprueba schema, allowlist, firmas cuando aplican y aplica DENY. Si algo es verdad operativa, lo dice el Kernel — no esta interfaz.</p>
    </article>
    <article class="role-card">
      <span class="pill muestra">UI MUESTRA</span>
      <p>La interfaz solo presenta campos y JSON. No añade veredicto, no completa datos, no “aprueba” nada.</p>
    </article>
    <article class="role-card">
      <span class="pill bloqueado">BLOQUEADO</span>
      <p>Operaciones prohibidas por diseño (revelar claves, elevar Libro, emitir caps, telemetría…). No hay atajo desde aquí.</p>
    </article>
  </div>
</section>

<article class="aud-block" id="latido">
  <div class="block-head">
    <span class="step">1</span>
    <div>
      <h2 class="aud-h2">Latido del dominio</h2>
      <p class="aud-sub">¿Responde el Kernel ahora mismo?</p>
    </div>
    <div class="role-line"><span class="pill kernel">KERNEL VALIDA</span><span class="pill muestra">UI MUESTRA</span></div>
  </div>
  <div class="summary">
    <p><strong>Qué comprueba:</strong> estado operativo, salud/latido, versión del crate, época y suelo, familia de canal.</p>
    <p><strong>Qué no es:</strong> no demuestra conformidad ni calidad del despliegue; solo que el proceso local contesta.</p>
  </div>
  <div class="grid-stats" id="latido-stats">
    <div class="stat" id="st-estado"><span class="k">Estado del dominio</span><span class="v">…</span></div>
    <div class="stat" id="st-salud"><span class="k">Salud / latido</span><span class="v">…</span></div>
    <div class="stat" id="st-epoca"><span class="k">Época actual</span><span class="v">…</span></div>
    <div class="stat" id="st-suelo"><span class="k">Suelo de época</span><span class="v">…</span></div>
    <div class="stat" id="st-version"><span class="k">Versión Kernel</span><span class="v">…</span></div>
    <div class="stat" id="st-canal"><span class="k">Canal operador</span><span class="v">…</span></div>
  </div>
  <div class="actions">
    <button type="button" id="btn-latido">Comprobar latido otra vez</button>
    <button type="button" class="ghost" id="btn-latido-raw" aria-expanded="false">Ver respuesta completa</button>
  </div>
  <pre id="latido-raw" class="raw hidden">{{}}</pre>
</article>

<article class="aud-block" id="sistemas">
  <div class="block-head">
    <span class="step">2</span>
    <div>
      <h2 class="aud-h2">Sistemas e identidades</h2>
      <p class="aud-sub">¿Qué sistemas conoce el Kernel y con qué pasaporte?</p>
    </div>
    <div class="role-line"><span class="pill kernel">KERNEL VALIDA</span><span class="pill muestra">UI MUESTRA</span></div>
  </div>
  <div class="summary">
    <p><strong>Qué comprueba:</strong> existencia en el registro soberano y consulta de pasaporte por <code>sistema_id</code>.</p>
    <p><strong>Qué no es:</strong> listar no autoriza efectos. Emitir o dar de alta sistemas se hace en <a href="/conectar">Conectar</a>, no aquí.</p>
  </div>
  <div class="actions">
    <button type="button" id="btn-sistemas">Ver sistemas registrados</button>
    <label class="field">sistema_id <input id="pas-id" placeholder="id del sistema"/></label>
    <button type="button" id="btn-pasaporte">Ver pasaporte</button>
  </div>
  <pre id="sistemas-out" class="raw">Pulse «Ver sistemas registrados» para pedir la lista al Kernel.</pre>
</article>

<article class="aud-block" id="custodia">
  <div class="block-head">
    <span class="step">3</span>
    <div>
      <h2 class="aud-h2">Custodia</h2>
      <p class="aud-sub">¿Hay referencias de clave (handles / huellas), sin ver el material?</p>
    </div>
    <div class="role-line">
      <span class="pill kernel">KERNEL VALIDA</span>
      <span class="pill muestra">UI MUESTRA</span>
      <span class="pill bloqueado">sin material</span>
    </div>
  </div>
  <div class="summary">
    <p><strong>Qué comprueba:</strong> que el Kernel conserva metadatos de custodia (alias, handle opaco, huella, estado).</p>
    <p><strong>Qué no es:</strong> no es un vault abierto. PEM, raw, seed o «reveal» están bloqueados. Rotar handles es <a href="/custodiar">Custodiar</a>.</p>
  </div>
  <div class="actions">
    <button type="button" id="btn-cus-lista">Ver referencias custodiadas</button>
    <label class="field">secreto_id <input id="cus-id"/></label>
    <label class="field">alias <input id="cus-alias"/></label>
    <button type="button" id="btn-cus-get">Consultar una referencia</button>
  </div>
  <pre id="cus-out" class="raw">Pulse «Ver referencias custodiadas» para pedir metadatos al Kernel.</pre>
</article>

<article class="aud-block" id="control">
  <div class="block-head">
    <span class="step">4</span>
    <div>
      <h2 class="aud-h2">Control real</h2>
      <p class="aud-sub">¿Qué alcance declarado y qué hechos/límites ve el operador?</p>
    </div>
    <div class="role-line"><span class="pill kernel">KERNEL VALIDA</span><span class="pill muestra">UI MUESTRA</span></div>
  </div>
  <div class="summary">
    <p><strong>Qué comprueba:</strong> inventario ALCANZABLES (con caducidad y productor), hechos del Libro, matriz de niveles, límites e incidentes declarados.</p>
    <p><strong>Qué no es:</strong> ALCANZABLES <strong>no afirma completitud</strong>. Elevar el Libro está bloqueado. Esto es lectura de control, no mando.</p>
  </div>
  <div class="control-grid">
    <div class="control-card">
      <h3>ALCANZABLES</h3>
      <p class="muted">Inventario alcanzado declarado — no inventario “completo”.</p>
      <button type="button" id="btn-alc">Ver inventario ALCANZABLES</button>
    </div>
    <div class="control-card">
      <h3>Hechos y Libro</h3>
      <p class="muted">Hechos con productor · matriz C0–C5 de lectura.</p>
      <button type="button" data-obs="obs.hechos.listar" data-target="control-out">Hechos</button>
      <button type="button" data-obs="obs.libro.matriz" data-target="control-out">Libro (matriz)</button>
    </div>
    <div class="control-card">
      <h3>Límites y señales</h3>
      <p class="muted">Límites DESP/VAL-EXT/GOB · incidentes · decisiones (lectura).</p>
      <button type="button" data-obs="obs.limites" data-target="control-out">Límites</button>
      <button type="button" data-obs="obs.incidentes" data-target="control-out">Incidentes</button>
      <button type="button" data-obs="obs.decisiones.listar" data-target="control-out">Decisiones</button>
    </div>
  </div>
  <p class="muted deep">También en paneles crudos: <a href="/observar?panel=libro">Libro</a> · <a href="/observar?panel=hechos">Hechos</a> · <a href="/observar?panel=limites">Límites</a></p>
  <pre id="alc-out" class="raw hidden"></pre>
  <pre id="control-out" class="raw">Elija ALCANZABLES, hechos, Libro o límites. La respuesta del Kernel aparece aquí.</pre>
</article>

<article class="aud-block" id="evidencia">
  <div class="block-head">
    <span class="step">5</span>
    <div>
      <h2 class="aud-h2">Evidencia verificable</h2>
      <p class="aud-sub">¿Puede exportarse y comprobarse un rastro sin secretos?</p>
    </div>
    <div class="role-line"><span class="pill kernel">KERNEL VALIDA</span><span class="pill muestra">UI MUESTRA</span></div>
  </div>
  <div class="summary">
    <p><strong>Qué comprueba:</strong> paquete con digests / raíces Merkle / inclusiones; informe de verificación con <code>no_comprobado[]</code>; expediente etiquetado.</p>
    <p><strong>Qué no es:</strong> exportar no entrega secreto raíz. Verificar no es un certificado de conformidad — la UI no interpreta el informe como “aprobado”.</p>
  </div>
  <div class="actions">
    <button type="button" id="btn-ev-exp">Exportar evidencia (digests)</button>
    <button type="button" id="btn-ev-ver">Verificar evidencia</button>
    <label class="field">expediente_id <input id="exp-id"/></label>
    <button type="button" id="btn-exp">Ver expediente</button>
  </div>
  <pre id="ev-out" class="raw">Las respuestas de exportar / verificar / expediente aparecen aquí.</pre>
</article>

<article class="aud-block aud-block-deny" id="bloqueos">
  <div class="block-head">
    <span class="step">6</span>
    <div>
      <h2 class="aud-h2">Bloqueos por diseño</h2>
      <p class="aud-sub">Qué no podrá hacer nunca esta superficie (ni el canal operador)</p>
    </div>
    <div class="role-line"><span class="pill bloqueado">BLOQUEADO</span></div>
  </div>
  <div class="summary">
    <p><strong>Por qué existen:</strong> proteger material de clave, impedir elevación del Libro, impedir emisión de capacidades desde UI, impedir telemetría y bind público, impedir diagnóstico sujeto fuera de allowlist.</p>
    <p><strong>Qué no son:</strong> no son “funciones pendientes”. Son denegaciones fijas de esquema.</p>
  </div>
  <ul class="deny-list">{bloqueados}</ul>
</article>

<footer class="aud-foot">
  <p>Para <strong>declarar</strong> sistemas, <strong>rotar</strong> custodia o <strong>gobernar</strong> corpus: use Conectar, Custodiar o Gobernar. Esta pantalla solo verifica.</p>
</footer>

<script>
async function getObs(op, extraQs) {{
  let q = '/obs?op=' + encodeURIComponent(op);
  if (extraQs) q += '&' + extraQs;
  const r = await fetch(q, {{ method:'GET' }});
  return {{ ok: r.ok, status: r.status, text: await r.text() }};
}}
async function postOps(op, extra) {{
  const body = Object.assign({{op, req_id:'aud-'+Date.now(), schema_v:1, operador_id:'operador-ui-local'}}, extra||{{}});
  const r = await fetch('/ops', {{ method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body) }});
  return {{ ok: r.ok, status: r.status, text: await r.text() }};
}}
function setStat(id, val) {{
  const el = document.querySelector('#'+id+' .v');
  if (el) el.textContent = (val === undefined || val === null || val === '') ? '—' : String(val);
}}
function parseCuerpo(text) {{
  try {{ const j = JSON.parse(text); return j.cuerpo || j; }} catch(_) {{ return null; }}
}}
function tryJson(t) {{ try {{ return JSON.parse(t); }} catch(_) {{ return t; }} }}
function showRaw(id, text) {{
  const el = document.getElementById(id);
  el.textContent = text;
  el.classList.remove('hidden');
}}
async function refrescarLatido() {{
  const [est, sal, ver, can, lim] = await Promise.all([
    getObs('obs.estado'), getObs('obs.salud'), getObs('obs.version'),
    getObs('obs.describir_canal'), getObs('obs.limites'),
  ]);
  const ce = parseCuerpo(est.text) || {{}};
  const cs = parseCuerpo(sal.text) || {{}};
  const cv = parseCuerpo(ver.text) || {{}};
  const cc = parseCuerpo(can.text) || {{}};
  setStat('st-estado', ce.estado || (est.ok ? 'OK' : 'FALLA'));
  setStat('st-salud', cs.salud || cs.latido || (sal.ok ? 'OK' : 'FALLA'));
  setStat('st-epoca', ce.epoca);
  setStat('st-suelo', ce.suelo_epoca);
  setStat('st-version', cv.version_crate || cv.version);
  setStat('st-canal', cc.familia || (can.ok ? 'loopback obs' : 'FALLA'));
  document.getElementById('latido-raw').textContent = JSON.stringify({{
    estado: tryJson(est.text), salud: tryJson(sal.text), version: tryJson(ver.text),
    canal: tryJson(can.text), limites: tryJson(lim.text),
    nota: 'Respuesta del Kernel. La UI no certifica ni interpreta conformidad.'
  }}, null, 2);
}}
document.getElementById('btn-latido').onclick = () => refrescarLatido();
document.getElementById('btn-latido-raw').onclick = function() {{
  const pre = document.getElementById('latido-raw');
  const open = pre.classList.toggle('hidden') === false;
  this.setAttribute('aria-expanded', open ? 'true' : 'false');
  this.textContent = open ? 'Ocultar respuesta completa' : 'Ver respuesta completa';
}};
document.getElementById('btn-sistemas').onclick = async () => {{
  showRaw('sistemas-out', (await postOps('con.sistemas.listar', {{}})).text);
}};
document.getElementById('btn-pasaporte').onclick = async () => {{
  const id = document.getElementById('pas-id').value.trim();
  showRaw('sistemas-out', (await postOps('con.pasaporte.get', {{ sistema_id: id }})).text);
}};
document.getElementById('btn-cus-lista').onclick = async () => {{
  showRaw('cus-out', (await postOps('cus.estado', {{}})).text);
}};
document.getElementById('btn-cus-get').onclick = async () => {{
  const extra = {{}};
  const id = document.getElementById('cus-id').value.trim();
  const alias = document.getElementById('cus-alias').value.trim();
  if (id) extra.secreto_id = id;
  if (alias) extra.alias = alias;
  showRaw('cus-out', (await postOps('cus.estado', extra)).text);
}};
document.getElementById('btn-alc').onclick = async () => {{
  const t = (await postOps('con.inventario.alcanzables', {{ vista: true }})).text;
  showRaw('control-out', t);
  document.getElementById('alc-out').textContent = t;
}};
document.querySelectorAll('button[data-obs]').forEach(btn => {{
  btn.onclick = async () => {{
    const op = btn.getAttribute('data-obs');
    const target = btn.getAttribute('data-target') || 'control-out';
    showRaw(target, (await getObs(op)).text);
  }};
}});
document.getElementById('btn-ev-exp').onclick = async () => {{
  showRaw('ev-out', (await getObs('obs.evidencia.exportar', 'confirmacion_explicita=true')).text);
}};
document.getElementById('btn-ev-ver').onclick = async () => {{
  showRaw('ev-out', (await getObs('obs.evidencia.verificar')).text);
}};
document.getElementById('btn-exp').onclick = async () => {{
  const id = document.getElementById('exp-id').value.trim();
  showRaw('ev-out', (await getObs('obs.expediente.get', 'expediente_id='+encodeURIComponent(id))).text);
}};
refrescarLatido();
(async function() {{
  const p = new URLSearchParams(location.search).get('panel');
  if (!p) return;
  const map = {{ hechos:'obs.hechos.listar', libro:'obs.libro.matriz', limites:'obs.limites' }};
  const op = map[p];
  if (!op) return;
  showRaw('control-out', (await getObs(op)).text);
  document.getElementById('control').scrollIntoView({{ behavior:'smooth', block:'start' }});
}})();
</script>"#,
        bloqueados = bloqueados,
    );

    let cuerpo_con_estilo = format!(
        r#"<style>
.aud-hero {{ margin:0 0 1.75rem; max-width:42rem; }}
.aud-alcance {{ margin:1rem 0 0; padding:.75rem 1rem; border:1px solid #3d4a5c; border-radius:8px; background:#121820; }}
.aud-alcance p {{ margin:0; font-size:.9rem; line-height:1.45; color:var(--muted); }}
.aud-alcance strong {{ color:var(--fg); }}
.aud-checklist {{ margin:0 0 2rem; max-width:52rem; }}
.check-list {{ margin:.75rem 0 0; padding-left:1.25rem; color:var(--muted); font-size:.9rem; line-height:1.55; }}
.check-list code {{ color:var(--fg); }}
.aud-kicker {{ margin:0 0 .5rem; font-size:.75rem; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); }}
.aud-title {{ margin:0 0 .75rem; font-size:1.55rem; font-weight:650; line-height:1.25; }}
.aud-lead {{ margin:0 0 .6rem; font-size:1rem; line-height:1.5; }}
.aud-lead.muted {{ color:var(--muted); font-size:.92rem; }}
.aud-howto {{ margin-bottom:2rem; }}
.aud-h2 {{ margin:0; font-size:1.15rem; font-weight:650; }}
.aud-sub {{ margin:.2rem 0 0; color:var(--muted); font-size:.95rem; }}
.role-cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:.75rem; margin-top:.85rem; }}
.role-card {{ border:1px solid #2a384c; border-radius:8px; padding:.85rem 1rem; background:#121820; }}
.role-card p {{ margin:.5rem 0 0; color:var(--muted); font-size:.88rem; line-height:1.45; }}
.pill {{ display:inline-block; font-size:.68rem; font-weight:650; letter-spacing:.03em; padding:.18rem .5rem; border-radius:4px; }}
.pill.kernel {{ background:#152820; color:#9ddeb8; border:1px solid #2d5a40; }}
.pill.muestra {{ background:#152030; color:#9ab8d8; border:1px solid #2c4a62; }}
.pill.bloqueado {{ background:#2a1818; color:#e0a0a0; border:1px solid #5a2c2c; }}
.aud-block {{ margin:0 0 2rem; padding:0 0 1.75rem; border-bottom:1px solid #1e2a3a; max-width:52rem; }}
.aud-block-deny {{ border-bottom:none; }}
.block-head {{ display:grid; grid-template-columns:auto 1fr; gap:.65rem 1rem; align-items:start; margin-bottom:.85rem; }}
.block-head .role-line {{ grid-column:2; display:flex; flex-wrap:wrap; gap:.35rem; }}
.step {{ display:inline-flex; align-items:center; justify-content:center; width:1.75rem; height:1.75rem; border-radius:50%; border:1px solid #3d4a5c; color:var(--fg); font-size:.85rem; font-weight:650; margin-top:.15rem; }}
.summary {{ border-left:3px solid #3d4a5c; padding:.15rem 0 .15rem 1rem; margin:0 0 1rem; }}
.summary p {{ margin:0 0 .45rem; font-size:.9rem; line-height:1.45; color:var(--muted); }}
.summary p strong {{ color:var(--fg); font-weight:600; }}
.summary a {{ color:var(--accent); }}
.grid-stats {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(148px,1fr)); gap:.55rem; margin:0 0 1rem; }}
.stat {{ background:#121a24; border:1px solid #243044; border-radius:8px; padding:.7rem .8rem; }}
.stat .k {{ display:block; color:var(--muted); font-size:.68rem; text-transform:uppercase; letter-spacing:.04em; }}
.stat .v {{ display:block; font-size:1.05rem; font-weight:650; margin-top:.25rem; word-break:break-all; }}
.actions {{ display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; margin-bottom:.75rem; }}
.field {{ display:inline-flex; align-items:center; gap:.35rem; color:var(--muted); font-size:.85rem; }}
.field input {{ background:#121a24; border:1px solid #2c3c52; color:var(--fg); border-radius:6px; padding:.4rem .55rem; min-width:10rem; }}
button.ghost {{ background:transparent; }}
.control-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:.75rem; margin-bottom:.75rem; }}
.control-card {{ border:1px solid #2a384c; border-radius:8px; padding:.85rem 1rem; background:#121820; }}
.control-card h3 {{ margin:0 0 .35rem; font-size:.95rem; }}
.control-card .muted {{ margin:0 0 .65rem; }}
.control-card button {{ margin:0 .35rem .35rem 0; }}
.muted {{ color:var(--muted); font-size:.88rem; }}
.deep a {{ color:var(--accent); margin-right:.75rem; }}
.raw {{ background:#121a24; border:1px solid #243044; border-radius:8px; padding:1rem; overflow:auto; white-space:pre-wrap; word-break:break-word; max-height:16rem; font-size:.82rem; }}
.raw.hidden {{ display:none; }}
.deny-list {{ columns:2; color:var(--muted); font-size:.82rem; margin:.5rem 0 0; }}
.aud-foot {{ max-width:42rem; color:var(--muted); font-size:.88rem; padding-top:.5rem; }}
.aud-foot strong {{ color:var(--fg); }}
@media (max-width:640px) {{
  .block-head {{ grid-template-columns:auto 1fr; }}
  .deny-list {{ columns:1; }}
}}
</style>
{cuerpo}"#,
        cuerpo = cuerpo,
    );

    html_shell(
        dominio_id,
        canal,
        FamiliaNav::Auditar,
        "Verificación del Kernel",
        &cuerpo_con_estilo,
    )
}
