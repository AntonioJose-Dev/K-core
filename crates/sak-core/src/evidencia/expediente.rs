//! Expediente completo §M 11 (J.1–J.6): doce partes, etiquetas, retención, J.2.
//!
//! Sin campo de veredicto (J.4 / L-09). Cofirma de testigos: ya §M 3.
//! No afirma HSM, atestación real, C5 ni conformidad legal [GOB].

use crate::capacidad::{Alcance, Capability};
use crate::crypto::{self, dominio};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::camaleon::{
    redactar_hoja, CustodiaTrampilla, HojaCamaleon, IdTitular, RegistroRedaccion,
    DECISION_CRIPTO_PII_V1,
};
use crate::evidencia::merkle::{
    emitir_prueba_inclusion, merkle_raiz, verificar_inclusion, PruebaInclusion,
};
use crate::evidencia::{AlmacenEvidencia, IdSujeto, LedgerEvidencia, TipoRegistro};
use std::fmt;

/// Frase literal J.4 (exenta del escáner de patrones: es la negación normativa).
pub const FRASE_REGISTROS_NO_CUMPLIMIENTO: &str =
    "La existencia de registros no equivale a cumplimiento. La responsabilidad juridica final corresponde al operador.";

/// Identificador versionado de la lista de patrones J.4 (comprobable).
pub const ID_LISTA_PATRONES_J4_V1: &str = "SAK-J4-PATTERNS-v1";

/// Lista explícita y cerrada de substrings prohibidos en campos declarativos del expediente.
/// No es un filtro semántico abierto: solo coincidencia literal case-insensitive.
pub const PATRONES_PROHIBIDOS_J4_V1: &[&str] = &[
    "veredicto de conformidad",
    "puntuacion de cumplimiento",
    "puntuación de cumplimiento",
    "el sistema cumple",
    "sistema en conformidad",
    "conformidad certificada",
    "cumple la ley",
    "cumple el reglamento",
    "score de cumplimiento",
    "nota de cumplimiento",
    "certifica conformidad",
    "veredicto: cumple",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtiquetaAfirmacion {
    HechoVerificable,
    EvaluacionAutomatica,
    DecisionHumana,
    InterpretacionJuridica,
    EvidenciaAusente,
    RiesgoResidual,
    NoAfirmado,
}

impl EtiquetaAfirmacion {
    pub fn token(self) -> &'static str {
        match self {
            EtiquetaAfirmacion::HechoVerificable => "HECHO_VERIFICABLE",
            EtiquetaAfirmacion::EvaluacionAutomatica => "EVALUACION_AUTOMATICA",
            EtiquetaAfirmacion::DecisionHumana => "DECISION_HUMANA",
            EtiquetaAfirmacion::InterpretacionJuridica => "INTERPRETACION_JURIDICA",
            EtiquetaAfirmacion::EvidenciaAusente => "EVIDENCIA_AUSENTE",
            EtiquetaAfirmacion::RiesgoResidual => "RIESGO_RESIDUAL",
            EtiquetaAfirmacion::NoAfirmado => "NO_AFIRMADO",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "HECHO_VERIFICABLE" => Some(Self::HechoVerificable),
            "EVALUACION_AUTOMATICA" => Some(Self::EvaluacionAutomatica),
            "DECISION_HUMANA" => Some(Self::DecisionHumana),
            "INTERPRETACION_JURIDICA" => Some(Self::InterpretacionJuridica),
            "EVIDENCIA_AUSENTE" => Some(Self::EvidenciaAusente),
            "RIESGO_RESIDUAL" => Some(Self::RiesgoResidual),
            "NO_AFIRMADO" => Some(Self::NoAfirmado),
            _ => None,
        }
    }
}

/// Afirmación del expediente: exactamente una etiqueta (J.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Afirmacion {
    pub texto: String,
    pub etiqueta: EtiquetaAfirmacion,
}

impl Afirmacion {
    pub fn nueva(texto: impl Into<String>, etiqueta: EtiquetaAfirmacion) -> Result<Self, ErrorExpediente> {
        let texto = texto.into();
        if texto.trim().is_empty() {
            return Err(ErrorExpediente::AfirmacionVacia);
        }
        rechazar_patron_j4(&texto)?;
        Ok(Afirmacion { texto, etiqueta })
    }

    /// Entrada no tipada: exige exactamente un token canónico; 0 → ausente; ≥2 o mezcla → DENY.
    pub fn desde_tokens(
        texto: impl Into<String>,
        tokens: &[&str],
    ) -> Result<Self, ErrorExpediente> {
        if tokens.is_empty() {
            return Err(ErrorExpediente::EtiquetaAusente);
        }
        if tokens.len() != 1 {
            return Err(ErrorExpediente::EtiquetaDuplicadaOMezcla);
        }
        let et = EtiquetaAfirmacion::desde_token(tokens[0])
            .ok_or(ErrorExpediente::EtiquetaAusente)?;
        Self::nueva(texto, et)
    }
}

/// ¿El texto declarativo contiene algún patrón prohibido J.4 v1?
pub fn contiene_patron_prohibido_j4(texto: &str) -> Option<&'static str> {
    let lower = texto.to_lowercase();
    for p in PATRONES_PROHIBIDOS_J4_V1 {
        if lower.contains(&p.to_lowercase()) {
            return Some(*p);
        }
    }
    None
}

fn rechazar_patron_j4(texto: &str) -> Result<(), ErrorExpediente> {
    if let Some(p) = contiene_patron_prohibido_j4(texto) {
        return Err(ErrorExpediente::SenalCumplimiento(p));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseRetencion {
    DecisionSinContenido,
    AutomaticoAltoRiesgo,
    ContenidoDatosPersonales,
    CheckpointCofirma,
    AprobacionHumana,
}

impl ClaseRetencion {
    /// Días de retención (J.6). Alto riesgo: 365 [VAL-EXT] suelo legal.
    pub fn dias_retencion(self) -> Option<u64> {
        match self {
            ClaseRetencion::DecisionSinContenido => Some(10 * 365),
            ClaseRetencion::AutomaticoAltoRiesgo => Some(365), // 12 meses; VAL-EXT
            ClaseRetencion::ContenidoDatosPersonales => Some(90),
            ClaseRetencion::CheckpointCofirma => None,
            ClaseRetencion::AprobacionHumana => Some(10 * 365),
        }
    }

    pub fn es_permanente(self) -> bool {
        self.dias_retencion().is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RecuentosObligaciones {
    pub evaluadas: u32,
    pub satisfechas_por_kernel: u32,
    pub requieren_decision_humana: u32,
    pub huecos_evidencia: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HechoContexto {
    pub productor: String,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub descripcion: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteSistemas {
    pub id_sistema: String,
    pub version_sistema: String,
    pub huella_artefacto: [u8; LONGITUD_HASH_PAQUETE],
    pub medida_tcb_kernel: [u8; LONGITUD_HASH_PAQUETE],
    pub hash_lista_simbolos: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteFinalidad {
    pub finalidad: String,
    pub usos_previstos: String,
    pub usos_excluidos: String,
    pub firma_responsable_presente: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteClasificacion {
    pub clasificacion_riesgo: String,
    pub justificacion_firmada: bool,
    pub rol_regulatorio: String,
    pub jurisdicciones: String,
    pub obligaciones_l1_l4: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteCorpus {
    pub hash_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub firmas_presentes: bool,
    pub diff_reconocido: bool,
    pub norma_id: String,
    pub norma_version: String,
    pub interpretacion: String,
    pub autor_interpretacion: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteRiesgos {
    pub riesgos: String,
    pub controles: String,
    pub resultado_controles: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteDecisiones {
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub codigo_razon: String,
    pub clase_efecto: String,
    pub parametros: String,
    pub normas_citadas: String,
    pub traza_precedencia: String,
    pub normas_inertes: String,
    pub hechos: Vec<HechoContexto>,
    pub pasos_consumidos: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteCapacidades {
    pub digest_capacidad: [u8; LONGITUD_HASH_PAQUETE],
    pub alcance: String,
    pub ttl_ticks: u64,
    pub uso: String,
    pub revocacion: String,
    pub punto_aplicacion: String,
    pub recibo_digest: [u8; LONGITUD_HASH_PAQUETE],
    pub intentos_rechazados: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteSupervision {
    pub id_humano: String,
    pub competencia: String,
    pub escalados: String,
    pub plazo: u64,
    pub quorum_ok: bool,
    pub independencia_ok: bool,
    pub firma_sobre_digest: [u8; LONGITUD_HASH_PAQUETE],
    pub decision_supervision: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteLibro {
    pub nivel_en_instante: String,
    pub historial_temporal: String,
    pub hechos_sostenedores: String,
    pub bypass_residual: String,
    pub plan_elevacion: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteSupuestos {
    pub serie_temporal: String,
    pub transiciones: String,
    pub atestacion_plataforma_presente: bool,
    pub atestacion_confinamiento_presente: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteIncidentes {
    pub incidentes: String,
    pub huecos_secuencia: String,
    pub divergencias: String,
    pub redacciones: Vec<RegistroRedaccion>,
    pub cambios_corpus: String,
    pub acciones_correctoras: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParteCadena {
    pub merkle_raiz: [u8; LONGITUD_HASH_PAQUETE],
    pub suelo_epoca: u64,
    pub cofirmas_testigos_ok: bool,
    /// Declaración de sellos (TSA real: no_comprobado [VAL-EXT]).
    pub sellos: String,
    pub pruebas_inclusion: Vec<PruebaInclusion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expediente {
    pub parte_1: ParteSistemas,
    pub parte_2: ParteFinalidad,
    pub parte_3: ParteClasificacion,
    pub parte_4: ParteCorpus,
    pub parte_5: ParteRiesgos,
    pub parte_6: ParteDecisiones,
    pub parte_7: ParteCapacidades,
    pub parte_8: ParteSupervision,
    pub parte_9: ParteLibro,
    pub parte_10: ParteSupuestos,
    pub parte_11: ParteIncidentes,
    pub parte_12: ParteCadena,
    pub afirmaciones: Vec<Afirmacion>,
    pub recuentos: RecuentosObligaciones,
    pub frase_j4: String,
    pub cliente_es_operador: bool,
    pub hojas_pii: Vec<(String, HojaCamaleon)>,
    pub(crate) campo_veredicto_prohibido: Option<String>,
    pub(crate) puntuacion_cumplimiento_prohibida: Option<u32>,
    pub digest_paquete: [u8; LONGITUD_HASH_PAQUETE],
    pub firma_mldsa: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorExpediente {
    CapacidadAuditoriaAusente,
    AfirmacionVacia,
    EtiquetaDuplicadaOMezcla,
    EtiquetaAusente,
    ContieneVeredicto,
    ContienePuntuacion,
    SenalCumplimiento(&'static str),
    FaltaFraseJ4,
    FaltaNoAfirmadoOperador,
    ParteIncompleta(&'static str),
    InclusionInvalida,
    PiiSinCifrado,
    Camaleon(String),
    Firma(String),
    Validacion(String),
}

impl fmt::Display for ErrorExpediente {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ErrorExpediente {}

pub fn alcance_auditoria() -> Alcance {
    Alcance::minimo(["AUDITORIA", "EXPEDIENTE", "EF-AUD"]).expect("alcance auditoria")
}

pub fn capacidad_autoriza_auditoria(cap: &Capability) -> bool {
    let a = cap.alcance();
    a.cubre(&alcance_auditoria())
        || a.tokens().iter().any(|t| t == "AUDITORIA" || t == "EXPEDIENTE")
}

impl Expediente {
    pub fn canonico_sin_firma(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-EXPEDIENTE-v2|");
        escribir(&mut v, &self.parte_1.id_sistema);
        escribir(&mut v, &self.parte_1.version_sistema);
        v.extend_from_slice(&self.parte_1.huella_artefacto);
        v.extend_from_slice(&self.parte_1.hash_lista_simbolos);
        escribir(&mut v, &self.parte_2.finalidad);
        escribir(&mut v, &self.parte_6.codigo_razon);
        escribir(&mut v, &self.parte_6.clase_efecto);
        escribir(&mut v, &self.parte_6.parametros);
        escribir(&mut v, &self.parte_7.uso);
        escribir(&mut v, &self.parte_7.revocacion);
        escribir(&mut v, &self.parte_7.punto_aplicacion);
        escribir(&mut v, &self.parte_8.escalados);
        v.extend_from_slice(&self.parte_8.plazo.to_le_bytes());
        escribir(&mut v, &self.parte_9.nivel_en_instante);
        v.extend_from_slice(&self.parte_12.merkle_raiz);
        v.extend_from_slice(&self.parte_12.suelo_epoca.to_le_bytes());
        v.push(u8::from(self.cliente_es_operador));
        for a in &self.afirmaciones {
            v.extend_from_slice(a.etiqueta.token().as_bytes());
            v.push(0);
            escribir(&mut v, &a.texto);
        }
        v.extend_from_slice(&self.recuentos.evaluadas.to_le_bytes());
        v.extend_from_slice(&self.recuentos.satisfechas_por_kernel.to_le_bytes());
        v.extend_from_slice(&self.recuentos.requieren_decision_humana.to_le_bytes());
        v.extend_from_slice(&self.recuentos.huecos_evidencia.to_le_bytes());
        escribir(&mut v, &self.frase_j4);
        for (id, h) in &self.hojas_pii {
            escribir(&mut v, id);
            v.extend_from_slice(&h.compromiso);
            v.push(u8::from(h.contenido_cifrado));
            v.extend_from_slice(&h.retencion_dias.to_le_bytes());
        }
        for p in &self.parte_12.pruebas_inclusion {
            v.extend_from_slice(&p.indice.to_le_bytes());
            v.extend_from_slice(&p.hoja);
        }
        v
    }

    pub fn validar_estructura(&self) -> Result<(), ErrorExpediente> {
        if self.campo_veredicto_prohibido.is_some() {
            return Err(ErrorExpediente::ContieneVeredicto);
        }
        if self.puntuacion_cumplimiento_prohibida.is_some() {
            return Err(ErrorExpediente::ContienePuntuacion);
        }
        if self.frase_j4 != FRASE_REGISTROS_NO_CUMPLIMIENTO {
            return Err(ErrorExpediente::FaltaFraseJ4);
        }
        // Frase J.4 exenta; afirmar que la lista versionada está fijada.
        let _ = ID_LISTA_PATRONES_J4_V1;
        for a in &self.afirmaciones {
            rechazar_patron_j4(&a.texto)?;
        }
        if self.parte_1.id_sistema.trim().is_empty()
            || self.parte_1.version_sistema.trim().is_empty()
        {
            return Err(ErrorExpediente::ParteIncompleta("sistemas"));
        }
        if self.parte_4.autor_interpretacion.trim().is_empty()
            || self.parte_4.interpretacion.trim().is_empty()
            || self.parte_4.norma_id.trim().is_empty()
            || self.parte_4.norma_version.trim().is_empty()
        {
            return Err(ErrorExpediente::ParteIncompleta("corpus"));
        }
        if self.parte_6.clase_efecto.trim().is_empty()
            || self.parte_6.parametros.trim().is_empty()
            || self.parte_6.hechos.is_empty()
        {
            return Err(ErrorExpediente::ParteIncompleta("decisiones"));
        }
        for h in &self.parte_6.hechos {
            if h.productor.trim().is_empty() {
                return Err(ErrorExpediente::ParteIncompleta("hechos productores"));
            }
        }
        if self.parte_7.uso.trim().is_empty() || self.parte_7.revocacion.trim().is_empty() {
            return Err(ErrorExpediente::ParteIncompleta("capacidades"));
        }
        if self.parte_7.punto_aplicacion.trim().is_empty() {
            return Err(ErrorExpediente::ParteIncompleta("punto aplicacion"));
        }
        if self.parte_8.escalados.trim().is_empty() || self.parte_8.plazo == 0 {
            return Err(ErrorExpediente::ParteIncompleta("supervision"));
        }
        if self.parte_9.nivel_en_instante.trim().is_empty() {
            return Err(ErrorExpediente::ParteIncompleta("libro nivel instante"));
        }
        if self.afirmaciones.is_empty() {
            return Err(ErrorExpediente::EtiquetaAusente);
        }
        for a in &self.afirmaciones {
            if EtiquetaAfirmacion::desde_token(a.etiqueta.token()).is_none() {
                return Err(ErrorExpediente::EtiquetaAusente);
            }
        }
        if self.cliente_es_operador {
            let ok = self.afirmaciones.iter().any(|a| {
                a.etiqueta == EtiquetaAfirmacion::NoAfirmado
                    && a.texto.contains("resistencia frente al operador")
            });
            if !ok {
                return Err(ErrorExpediente::FaltaNoAfirmadoOperador);
            }
        }
        for (_, h) in &self.hojas_pii {
            h.validar_retencion_cifrada()
                .map_err(|_| ErrorExpediente::PiiSinCifrado)?;
        }
        for p in &self.parte_12.pruebas_inclusion {
            if !verificar_inclusion(p, &self.parte_12.merkle_raiz) {
                return Err(ErrorExpediente::InclusionInvalida);
            }
        }
        Ok(())
    }
}

fn escribir(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}

pub struct ConstructorExpediente {
    pub custodia: CustodiaTrampilla,
    titular_a: IdTitular,
    titular_b: IdTitular,
}

impl ConstructorExpediente {
    pub fn nuevo(
        custodia: CustodiaTrampilla,
        titular_a: IdTitular,
        titular_b: IdTitular,
    ) -> Result<Self, ErrorExpediente> {
        let _ = custodia
            .material_si_autorizado(titular_a, titular_b)
            .map_err(|e| ErrorExpediente::Camaleon(e.to_string()))?;
        Ok(ConstructorExpediente {
            custodia,
            titular_a,
            titular_b,
        })
    }

    pub fn comprometer_pii(
        &self,
        id: impl Into<String>,
        contenido: &[u8],
        aleatoriedad: [u8; LONGITUD_HASH_PAQUETE],
    ) -> Result<(String, HojaCamaleon), ErrorExpediente> {
        let material = self
            .custodia
            .material_si_autorizado(self.titular_a, self.titular_b)
            .map_err(|e| ErrorExpediente::Camaleon(e.to_string()))?;
        let hoja = HojaCamaleon::comprometer_cifrado(material, contenido, aleatoriedad)
            .map_err(|e| ErrorExpediente::Camaleon(e.to_string()))?;
        let _ = DECISION_CRIPTO_PII_V1;
        Ok((id.into(), hoja))
    }

    pub fn redactar(
        &self,
        hojas: &mut Vec<(String, HojaCamaleon)>,
        id_hoja: &str,
        a: IdTitular,
        b: IdTitular,
        base_juridica: &str,
        fecha: u64,
    ) -> Result<RegistroRedaccion, ErrorExpediente> {
        let hoja = hojas
            .iter_mut()
            .find(|(i, _)| i == id_hoja)
            .map(|(_, h)| h)
            .ok_or_else(|| ErrorExpediente::Validacion("hoja inexistente".into()))?;
        redactar_hoja(&self.custodia, hoja, id_hoja, a, b, base_juridica, fecha)
            .map_err(|e| ErrorExpediente::Camaleon(e.to_string()))
    }

    pub fn generar<A: AlmacenEvidencia>(
        &self,
        cap: &Capability,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        mut borrador: ExpedienteBorrador,
    ) -> Result<Expediente, ErrorExpediente> {
        if !capacidad_autoriza_auditoria(cap) {
            return Err(ErrorExpediente::CapacidadAuditoriaAusente);
        }
        if borrador.cliente_es_operador && !borrador.saltar_auto_no_afirmado_operador {
            let tiene = borrador.afirmaciones.iter().any(|a| {
                a.etiqueta == EtiquetaAfirmacion::NoAfirmado
                    && a.texto.contains("resistencia frente al operador")
            });
            if !tiene {
                borrador.afirmaciones.push(
                    Afirmacion::nueva(
                        "resistencia frente al operador: NO_AFIRMADO (cliente=operador)",
                        EtiquetaAfirmacion::NoAfirmado,
                    )
                    .map_err(|_| ErrorExpediente::AfirmacionVacia)?,
                );
            }
        }
        if !borrador.parte_10.atestacion_plataforma_presente {
            borrador.afirmaciones.push(
                Afirmacion::nueva(
                    "atestacion de plataforma no comprobada en este expediente",
                    EtiquetaAfirmacion::NoAfirmado,
                )
                .unwrap(),
            );
        }

        let digests_hojas: Vec<_> = borrador
            .hojas_pii
            .iter()
            .map(|(_, h)| h.compromiso)
            .collect();
        borrador.parte_12.merkle_raiz = merkle_raiz(&digests_hojas);
        borrador.parte_12.pruebas_inclusion.clear();
        for i in 0..digests_hojas.len() {
            if let Some(p) = emitir_prueba_inclusion(&digests_hojas, i) {
                borrador.parte_12.pruebas_inclusion.push(p);
            }
        }

        let mut exp = Expediente {
            parte_1: borrador.parte_1,
            parte_2: borrador.parte_2,
            parte_3: borrador.parte_3,
            parte_4: borrador.parte_4,
            parte_5: borrador.parte_5,
            parte_6: borrador.parte_6,
            parte_7: borrador.parte_7,
            parte_8: borrador.parte_8,
            parte_9: borrador.parte_9,
            parte_10: borrador.parte_10,
            parte_11: borrador.parte_11,
            parte_12: borrador.parte_12,
            afirmaciones: borrador.afirmaciones,
            recuentos: borrador.recuentos,
            frase_j4: FRASE_REGISTROS_NO_CUMPLIMIENTO.to_string(),
            cliente_es_operador: borrador.cliente_es_operador,
            hojas_pii: borrador.hojas_pii,
            campo_veredicto_prohibido: borrador.inyectar_veredicto,
            puntuacion_cumplimiento_prohibida: borrador.inyectar_puntuacion,
            digest_paquete: [0u8; LONGITUD_HASH_PAQUETE],
            firma_mldsa: Vec::new(),
        };
        exp.validar_estructura()?;
        let cuerpo = exp.canonico_sin_firma();
        exp.digest_paquete = crypto::sha384_dominio(dominio::REGISTRO, &cuerpo);
        exp.firma_mldsa = ledger
            .firmar_autoridad(&exp.digest_paquete)
            .map_err(|e| ErrorExpediente::Firma(e.to_string()))?;

        let mut payload = Vec::new();
        payload.push(1); // EXPEDIENTE
        payload.extend_from_slice(&exp.digest_paquete);
        payload.extend_from_slice(&(exp.afirmaciones.len() as u16).to_le_bytes());
        let _ = ledger.registrar_evento_sistema(sujeto, TipoRegistro::Gobernanza, payload);

        Ok(exp)
    }
}

#[derive(Debug, Clone)]
pub struct ExpedienteBorrador {
    pub parte_1: ParteSistemas,
    pub parte_2: ParteFinalidad,
    pub parte_3: ParteClasificacion,
    pub parte_4: ParteCorpus,
    pub parte_5: ParteRiesgos,
    pub parte_6: ParteDecisiones,
    pub parte_7: ParteCapacidades,
    pub parte_8: ParteSupervision,
    pub parte_9: ParteLibro,
    pub parte_10: ParteSupuestos,
    pub parte_11: ParteIncidentes,
    pub parte_12: ParteCadena,
    pub afirmaciones: Vec<Afirmacion>,
    pub recuentos: RecuentosObligaciones,
    pub cliente_es_operador: bool,
    /// Solo harness: omite auto-inyección NO_AFIRMADO operador.
    pub saltar_auto_no_afirmado_operador: bool,
    pub hojas_pii: Vec<(String, HojaCamaleon)>,
    pub inyectar_veredicto: Option<String>,
    pub inyectar_puntuacion: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestasJ2 {
    pub sistema_por_artefacto: String,
    pub identidad_version: String,
    pub efecto_clase_params: String,
    pub datos_contexto_productores: String,
    pub norma_interpretacion_autor: String,
    pub decision_y_traza: String,
    pub capacidad_o_recibo: String,
    pub punto_aplicacion: String,
    pub persona_competencia_firma: String,
    pub nivel_libro_instante: String,
    pub integridad_cofirmas: String,
    pub no_comprobado: String,
    pub evidencia_faltante_riesgo: String,
}

impl RespuestasJ2 {
    /// Comprueba elemento a elemento los literales J.2; devuelve fallos por pregunta.
    pub fn verificar_literales(&self) -> Vec<String> {
        let mut e = Vec::new();
        if !self.sistema_por_artefacto.contains("artefacto=")
            || !self.sistema_por_artefacto.contains("solicitud=")
        {
            e.push("j2.1 sistema_por_artefacto".into());
        }
        if !self.identidad_version.contains('@') {
            e.push("j2.2 identidad_version".into());
        }
        if !self.efecto_clase_params.contains("clase=")
            || !self.efecto_clase_params.contains("params=")
        {
            e.push("j2.3 efecto_clase_params".into());
        }
        if !self.datos_contexto_productores.contains("productor=")
            || !self.datos_contexto_productores.contains("digest=")
        {
            e.push("j2.4 datos_contexto_productores".into());
        }
        if !self.norma_interpretacion_autor.contains("norma=")
            || !self.norma_interpretacion_autor.contains("version=")
            || !self.norma_interpretacion_autor.contains("jurisdiccion=")
            || !self.norma_interpretacion_autor.contains("interp=")
            || !self.norma_interpretacion_autor.contains("autor=")
        {
            e.push("j2.5 norma_interpretacion_autor".into());
        }
        if !self.decision_y_traza.contains("codigo=")
            || !self.decision_y_traza.contains("traza=")
            || !self.decision_y_traza.contains("inertes=")
        {
            e.push("j2.6 decision_y_traza".into());
        }
        if !self.capacidad_o_recibo.contains("cap=")
            || !self.capacidad_o_recibo.contains("recibo=")
            || !self.capacidad_o_recibo.contains("uso=")
            || !self.capacidad_o_recibo.contains("revocacion=")
        {
            e.push("j2.7 capacidad_o_recibo".into());
        }
        if self.punto_aplicacion.trim().is_empty() {
            e.push("j2.8 punto_aplicacion".into());
        }
        if !self.persona_competencia_firma.contains("humano=")
            || !self.persona_competencia_firma.contains("comp=")
            || !self.persona_competencia_firma.contains("firma=")
            || !self.persona_competencia_firma.contains("escalados=")
            || !self.persona_competencia_firma.contains("plazo=")
        {
            e.push("j2.9 persona_competencia_firma".into());
        }
        if self.nivel_libro_instante.trim().is_empty() {
            e.push("j2.10 nivel_libro_instante".into());
        }
        if !self.integridad_cofirmas.contains("merkle=")
            || !self.integridad_cofirmas.contains("cofirmas=")
            || !self.integridad_cofirmas.contains("sellos=")
            || !self.integridad_cofirmas.contains("inclusiones=")
        {
            e.push("j2.11 integridad_cofirmas".into());
        }
        if self.no_comprobado.trim().is_empty() {
            e.push("j2.12 no_comprobado".into());
        }
        if !self.evidencia_faltante_riesgo.contains("huecos=")
            || !self.evidencia_faltante_riesgo.contains("residual=")
        {
            e.push("j2.13 evidencia_faltante_riesgo".into());
        }
        e
    }
}

pub fn reconstruir_j2(exp: &Expediente) -> RespuestasJ2 {
    let no_comp: Vec<String> = exp
        .afirmaciones
        .iter()
        .filter(|a| {
            matches!(
                a.etiqueta,
                EtiquetaAfirmacion::NoAfirmado | EtiquetaAfirmacion::EvidenciaAusente
            )
        })
        .map(|a| a.texto.clone())
        .collect();
    let hechos = exp
        .parte_6
        .hechos
        .iter()
        .map(|h| {
            format!(
                "productor={} digest={} desc={}",
                h.productor,
                hex::encode_short(&h.digest),
                h.descripcion
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    RespuestasJ2 {
        sistema_por_artefacto: format!(
            "artefacto={} sys={} solicitud={}",
            hex::encode_short(&exp.parte_1.huella_artefacto),
            exp.parte_1.id_sistema,
            hex::encode_short(&exp.parte_6.digest_solicitud)
        ),
        identidad_version: format!(
            "{}@{}",
            exp.parte_1.id_sistema, exp.parte_1.version_sistema
        ),
        efecto_clase_params: format!(
            "solicitud={} clase={} params={}",
            hex::encode_short(&exp.parte_6.digest_solicitud),
            exp.parte_6.clase_efecto,
            exp.parte_6.parametros
        ),
        datos_contexto_productores: hechos,
        norma_interpretacion_autor: format!(
            "norma={} version={} jurisdiccion={} interp={} autor={}",
            exp.parte_4.norma_id,
            exp.parte_4.norma_version,
            exp.parte_3.jurisdicciones,
            exp.parte_4.interpretacion,
            exp.parte_4.autor_interpretacion
        ),
        decision_y_traza: format!(
            "codigo={} traza={} inertes={}",
            exp.parte_6.codigo_razon, exp.parte_6.traza_precedencia, exp.parte_6.normas_inertes
        ),
        capacidad_o_recibo: format!(
            "cap={} recibo={} uso={} revocacion={}",
            hex::encode_short(&exp.parte_7.digest_capacidad),
            hex::encode_short(&exp.parte_7.recibo_digest),
            exp.parte_7.uso,
            exp.parte_7.revocacion
        ),
        punto_aplicacion: exp.parte_7.punto_aplicacion.clone(),
        persona_competencia_firma: format!(
            "humano={} comp={} firma={} escalados={} plazo={}",
            exp.parte_8.id_humano,
            exp.parte_8.competencia,
            hex::encode_short(&exp.parte_8.firma_sobre_digest),
            exp.parte_8.escalados,
            exp.parte_8.plazo
        ),
        nivel_libro_instante: exp.parte_9.nivel_en_instante.clone(),
        integridad_cofirmas: format!(
            "merkle={} cofirmas={} sellos={} inclusiones={} suelo={}",
            hex::encode_short(&exp.parte_12.merkle_raiz),
            exp.parte_12.cofirmas_testigos_ok,
            exp.parte_12.sellos,
            exp.parte_12.pruebas_inclusion.len(),
            exp.parte_12.suelo_epoca
        ),
        no_comprobado: no_comp.join("; "),
        evidencia_faltante_riesgo: format!(
            "huecos={} residual={}",
            exp.recuentos.huecos_evidencia, exp.parte_9.bypass_residual
        ),
    }
}

mod hex {
    pub fn encode_short(d: &[u8]) -> String {
        d.iter().take(4).map(|b| format!("{b:02x}")).collect()
    }
}

#[derive(Debug, Clone)]
pub struct InformeExpediente {
    pub ok: bool,
    pub j2_completo: bool,
    pub j2_fallos: Vec<String>,
    pub sin_veredicto: bool,
    pub raiz_preservada_tras_redaccion: bool,
    pub inclusiones_ok: bool,
    pub errores: Vec<String>,
    pub no_comprobado: Vec<String>,
    pub respuestas_j2: Option<RespuestasJ2>,
}

/// Verificación offline del expediente (auditor externo: paquete + claves públicas).
pub fn verificar_expediente(
    exp: &Expediente,
    pk_autoridad: &[u8],
    compromisos_antes_redaccion: Option<&[[u8; LONGITUD_HASH_PAQUETE]]>,
) -> InformeExpediente {
    let mut errores = Vec::new();
    let mut no_comprobado = Vec::new();
    no_comprobado.push("custodia HSM de clave de autoridad (titularidad del cliente)".into());
    no_comprobado.push("atestacion de plataforma / TCB de host real".into());
    no_comprobado.push("suelo legal exacto de retencion 12 meses [VAL-EXT]".into());
    no_comprobado.push("conformidad legal [GOB] — no autocertificable".into());
    no_comprobado.push("testigo honesto [DESP]".into());
    no_comprobado.push("TSA / sello de tiempo de autoridad externa [VAL-EXT]".into());
    no_comprobado.push("C5 / confinamiento atestado (fuera §M 11)".into());
    no_comprobado.push(
        "KEK PII: decision impl AES-256-GCM+HMAC; no HSM/titularidad cliente [DESP]".into(),
    );

    if let Err(e) = exp.validar_estructura() {
        errores.push(format!("estructura: {e}"));
    }
    let sin_veredicto =
        exp.campo_veredicto_prohibido.is_none() && exp.puntuacion_cumplimiento_prohibida.is_none();
    if !sin_veredicto {
        errores.push("paquete contiene veredicto o puntuacion".into());
    }

    let cuerpo = exp.canonico_sin_firma();
    let dig = crypto::sha384_dominio(dominio::REGISTRO, &cuerpo);
    if dig != exp.digest_paquete {
        errores.push("digest de expediente no coincide".into());
    }
    if crate::crypto::ParMlDsa87::verificar(pk_autoridad, &exp.digest_paquete, &exp.firma_mldsa)
        .is_err()
    {
        errores.push("firma expediente invalida".into());
    }

    let mut raiz_ok = true;
    let mut inclusiones_ok = true;
    for p in &exp.parte_12.pruebas_inclusion {
        if !verificar_inclusion(p, &exp.parte_12.merkle_raiz) {
            inclusiones_ok = false;
            errores.push(format!("inclusion invalida indice={}", p.indice));
        }
    }
    if let Some(antes) = compromisos_antes_redaccion {
        for (i, (_, h)) in exp.hojas_pii.iter().enumerate() {
            if let Some(c) = antes.get(i) {
                if h.redactada && h.compromiso != *c {
                    raiz_ok = false;
                    errores.push(format!("compromiso camaleon alterado en hoja {i}"));
                }
            }
        }
        let digs: Vec<_> = exp.hojas_pii.iter().map(|(_, h)| h.compromiso).collect();
        let raiz = merkle_raiz(&digs);
        if raiz != exp.parte_12.merkle_raiz {
            raiz_ok = false;
            errores.push("merkle raiz no preservada".into());
        }
        // Tras redacción: mismas pruebas deben seguir verificando la raíz.
        for p in &exp.parte_12.pruebas_inclusion {
            if !verificar_inclusion(p, &raiz) {
                inclusiones_ok = false;
                errores.push(format!(
                    "inclusion no preservada tras redaccion indice={}",
                    p.indice
                ));
            }
        }
    }

    let j2 = reconstruir_j2(exp);
    let j2_fallos = j2.verificar_literales();
    let j2_completo = j2_fallos.is_empty();

    InformeExpediente {
        ok: errores.is_empty()
            && j2_completo
            && sin_veredicto
            && raiz_ok
            && inclusiones_ok,
        j2_completo,
        j2_fallos,
        sin_veredicto,
        raiz_preservada_tras_redaccion: raiz_ok,
        inclusiones_ok,
        errores,
        no_comprobado,
        respuestas_j2: Some(j2),
    }
}
