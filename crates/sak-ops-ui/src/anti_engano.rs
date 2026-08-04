//! Anti-engaño de interfaz (IPC §1) — componente reutilizable Fase 0.
//!
//! La UI no firma ni autoriza: solo exige campos visibles antes de enviar
//! una PROPUESTA_HUMANA / IRREVERSIBLE al Kernel (Fase 1+).

/// Campos mínimos anti-engaño (contrato IPC §1).
#[derive(Debug, Clone)]
pub struct VistaAntiEngano {
    pub objeto_canonico: String,
    pub digest: String,
    pub identidad: String,
    pub rol: String,
    pub consecuencias: String,
    pub epoca: String,
    pub confirmacion_independiente: bool,
}

impl VistaAntiEngano {
    pub fn validar_completo(&self) -> Result<(), String> {
        if self.objeto_canonico.trim().is_empty() {
            return Err("anti-engaño: falta objeto canónico".into());
        }
        if self.digest.trim().is_empty() {
            return Err("anti-engaño: falta digest".into());
        }
        if self.identidad.trim().is_empty() {
            return Err("anti-engaño: falta identidad".into());
        }
        if self.rol.trim().is_empty() {
            return Err("anti-engaño: falta rol".into());
        }
        if self.consecuencias.trim().is_empty() {
            return Err("anti-engaño: faltan consecuencias".into());
        }
        if self.epoca.trim().is_empty() {
            return Err("anti-engaño: falta época".into());
        }
        Ok(())
    }

    /// Fragmento HTML de solo lectura (sin botón que conceda autoridad).
    pub fn html_panel(&self) -> String {
        format!(
            r#"<section class="anti-engano" data-anti-engano="1">
  <h2>Confirmación anti-engaño</h2>
  <p class="muted">La UI no emite autoridad. El Kernel valida digest, identidad, rol y firmas.</p>
  <dl>
    <dt>Objeto canónico</dt><dd><pre class="canon">{objeto}</pre></dd>
    <dt>Digest</dt><dd><code class="digest">{digest}</code></dd>
    <dt>Identidad</dt><dd>{ident}</dd>
    <dt>Rol</dt><dd>{rol}</dd>
    <dt>Consecuencias</dt><dd>{cons}</dd>
    <dt>Época</dt><dd>{epoca}</dd>
    <dt>Confirmación independiente</dt><dd>{conf}</dd>
  </dl>
</section>"#,
            objeto = esc(&self.objeto_canonico),
            digest = esc(&self.digest),
            ident = esc(&self.identidad),
            rol = esc(&self.rol),
            cons = esc(&self.consecuencias),
            epoca = esc(&self.epoca),
            conf = if self.confirmacion_independiente {
                "requerida / pendiente de canal distinto"
            } else {
                "no exigida en este borrador de vista"
            },
        )
    }
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Detecta material de clave en payload de petición UI.
pub fn payload_contiene_secreto(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    const BAD: &[&str] = &[
        "begin private",
        "begin rsa private",
        "private_key",
        "secret_key",
        "\"seed\"",
        "\"pem\"",
        "-----begin",
    ];
    BAD.iter().any(|b| lower.contains(b))
}
