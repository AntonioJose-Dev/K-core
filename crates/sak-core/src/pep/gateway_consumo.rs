//! Gateway de consumo de decisión sobre personas (EF-8).
//!
//! No certifica equidad, ausencia de sesgo, legalidad ni competencia material.
//! Verifica presencia/firma/vigencia/enlace de hechos GOB/VAL-EXT. Custodia
//! demostrada solo en el adaptador instrumentado.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_consumo::{
    AdaptadorConsumoDecision, ErrorAdaptadorConsumo, EstadoConsumo, ResultadoConsumo,
};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_consumo::{
    alcance_ef8, digest_solicitud_consumo, AlcanceAutorizadoConsumo, HechoDecisionExigido,
    PrecondicionesPepEf8, SolicitudConsumoCruda, SolicitudConsumoDecisionPersona,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaConsumoDecision {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub recibo: ReciboEfecto,
    pub id_externo: String,
    pub estado: EstadoConsumo,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

/// PEP en el punto de consumo del resultado (no de cálculo).
pub struct GatewayConsumoDecisionPersona {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayConsumoDecisionPersona {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayConsumoDecisionPersona {
            verificador: VerificadorCapacidades::nuevo(suelo_epoca),
            intentos: Vec::new(),
            incidentes: Vec::new(),
        }
    }

    pub fn verificador_mut(&mut self) -> &mut VerificadorCapacidades {
        &mut self.verificador
    }

    pub fn intentos(&self) -> &[RegistroIntentoPep] {
        &self.intentos
    }

    pub fn incidentes(&self) -> &[IncidenteMediacion] {
        &self.incidentes
    }

    pub const fn puede_emitir_capacidad() -> bool {
        false
    }

    pub const fn posee_artefacto_consumo_expuesto() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudConsumoCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf8,
        hechos_presentes: &[HechoDecisionExigido],
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorConsumoDecision,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        ticks_ahora: Option<u64>,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepConsumo {
        let ticks = reloj.ahora();
        let ahora = ticks_ahora.unwrap_or(ticks);

        if !precondiciones.identidad_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::IdentidadNoVigente);
        }
        if !precondiciones.pasaporte_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::PasaporteNoVigente);
        }
        if !precondiciones.libro_c3 {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::ControlInsuficiente);
        }
        if !precondiciones.monitor_permisivo {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::MonitorNoPermisivo);
        }
        if !precondiciones.exclusividad_canal {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::ExclusividadCanalFalsa,
            );
        }
        if !precondiciones.hechos_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::HechoDecisionAusente);
        }

        let solicitud = match cruda {
            SolicitudConsumoCruda::NoTipificable | SolicitudConsumoCruda::Malformada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudConsumoCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudConsumoCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_consumo(solicitud);

        if ahora < solicitud.validez_desde || ahora > solicitud.validez_hasta {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PeriodoValidezNoAutorizado,
            );
        }
        if let Err(c) = comprobar_hechos(solicitud, hechos_presentes, ahora) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), c);
        }

        let Some(cap) = capacidad else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadAusente,
            );
        };

        if cap.decision().normas_citadas().is_empty() {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::Evidencia("decision sin normas citadas".into()),
            );
        }
        if *cap.decision().hash_paquete().bytes() != solicitud.hash_paquete {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PaqueteNoAutorizado,
            );
        }

        if let Err(codigo) = validar_contra_alcance(cap, solicitud) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo);
        }

        let intento = IntentoUso {
            sistema: sistema.clone(),
            digest_efecto: digest_sol,
            alcance: alcance_ef8(solicitud),
            epoca_actual,
        };

        // Irreversible / personas / datos personales ⇒ consulta síncrona.
        let exige_sincrona =
            !solicitud.reversible || solicitud.datos_personales || solicitud.categorias_especiales;
        let vista = if forzar_silencio_revocacion && exige_sincrona {
            VistaRevocacion::Silencio
        } else {
            self.verificador.vista_sincrona(reloj)
        };

        let antiguedad = match self.verificador.verificar_uso(cap, &intento, &vista, reloj) {
            ResultadoVerificacion::Denegado { causa } => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Capacidad(causa),
                );
            }
            ResultadoVerificacion::Permitido { antiguedad_vista_ms } => antiguedad_vista_ms,
        };

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::DecisionPersona,
            serializar_hechos(solicitud),
        );

        let resp = match adaptador.consumir_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptadorConsumo::AccionNoAutorizada) => {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::DivergenciaParametros,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: digest_sol,
                    ticks,
                });
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::AccionConsumoNoAutorizada,
                );
            }
            Err(ErrorAdaptadorConsumo::NoPuedeDemostrarExactitud)
            | Err(ErrorAdaptadorConsumo::DivergenciaConsumo) => {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::DivergenciaParametros,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: digest_sol,
                    ticks,
                });
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IncidenteMediacion,
                );
            }
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.to_string()),
                );
            }
        };

        if let Err(codigo) = comprobar_exactitud(solicitud, &resp, digest_sol, cap.digest_efecto()) {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::DivergenciaParametros,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_solicitud_ejecutada,
                ticks,
            });
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo);
        }

        self.cerrar_con_recibo(
            solicitud,
            digest_sol,
            cap,
            sistema,
            sujeto,
            ledger,
            &resp,
            antiguedad,
            ticks,
        )
    }

    fn cerrar_con_recibo<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudConsumoDecisionPersona,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoConsumo,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepConsumo {
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_recibo_interno,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: solicitud.digest_contexto,
        };

        if let Err(e) = ledger.registrar_recibo(sujeto, &recibo) {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::EvidenciaIncompleta,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_recibo_interno,
                ticks,
            });
            let _ = matches!(
                e,
                ErrorEvidencia::EscrituraFallida | ErrorEvidencia::DominioSuspendido
            );
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::Evidencia(e.to_string()),
            );
        }

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::DecisionPersona,
            serializar_consumo(digest_sol, resp),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepConsumo::Permitido(RespuestaConsumoDecision {
            digest_resultado: resp.digest_recibo_interno,
            recibo,
            id_externo: resp.id_externo.clone(),
            estado: resp.estado,
            digest_solicitud: digest_sol,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPepConsumo {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepConsumo::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepConsumo {
    Permitido(RespuestaConsumoDecision),
    Denegado { codigo: CodigoPep },
}

fn comprobar_hechos(
    sol: &SolicitudConsumoDecisionPersona,
    presentes: &[HechoDecisionExigido],
    ahora: u64,
) -> Result<(), CodigoPep> {
    for exigido in &sol.hechos_exigidos {
        let ok = presentes.iter().any(|p| {
            p.tipo == exigido.tipo
                && p.etiqueta == exigido.etiqueta
                && p.digest == exigido.digest
                && p.vigente_hasta >= ahora
                && exigido.vigente_hasta >= ahora
        });
        if !ok {
            if presentes.iter().any(|p| {
                p.tipo == exigido.tipo
                    && p.etiqueta == exigido.etiqueta
                    && p.digest == exigido.digest
                    && p.vigente_hasta < ahora
            }) {
                return Err(CodigoPep::HechoDecisionVencido);
            }
            return Err(CodigoPep::HechoDecisionAusente);
        }
    }
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudConsumoDecisionPersona,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoConsumo::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.id_sujeto_afectado != sol.id_sujeto_afectado {
        return Err(CodigoPep::SujetoDecisionNoAutorizado);
    }
    if auth.clase != sol.clase.token() {
        return Err(CodigoPep::ClaseDecisionNoAutorizada);
    }
    if auth.sistema_canal != sol.sistema_canal {
        return Err(CodigoPep::CanalConsumoNoAutorizado);
    }
    if auth.destinatario != sol.destinatario {
        return Err(CodigoPep::DestinatarioConsumoNoAutorizado);
    }
    if auth.accion_habilitada != sol.accion_habilitada {
        return Err(CodigoPep::AccionConsumoNoAutorizada);
    }
    if auth.digest_resultado != sol.digest_resultado {
        return Err(CodigoPep::ResultadoDecisionNoAutorizado);
    }
    if auth.finalidad != sol.finalidad {
        return Err(CodigoPep::FinalidadConsumoNoAutorizada);
    }
    if auth.version_resultado != sol.version_resultado {
        return Err(CodigoPep::VersionResultadoNoAutorizada);
    }
    if auth.validez_desde != sol.validez_desde || auth.validez_hasta != sol.validez_hasta {
        return Err(CodigoPep::PeriodoValidezNoAutorizado);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if !cap.alcance().cubre(&alcance_ef8(sol)) {
        return Err(CodigoPep::ResultadoDecisionNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudConsumoDecisionPersona,
    resp: &ResultadoConsumo,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.digest_resultado_consumido != sol.digest_resultado
        || resp.canal_efectivo != sol.sistema_canal
        || resp.destinatario_efectivo != sol.destinatario
        || resp.accion_efectiva != sol.accion_habilitada
        || resp.sujeto_efectivo != sol.id_sujeto_afectado
        || resp.clase_efectiva != sol.clase.token()
        || resp.finalidad_efectiva != sol.finalidad
        || resp.version_efectiva != sol.version_resultado
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if matches!(resp.estado, EstadoConsumo::Indeterminado) {
        return Err(CodigoPep::IncidenteMediacion);
    }
    Ok(())
}

fn serializar_hechos(sol: &SolicitudConsumoDecisionPersona) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0); // HECHOS
    for h in &sol.hechos_exigidos {
        v.extend_from_slice(h.tipo.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(h.etiqueta.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(&h.digest);
        v.extend_from_slice(&h.vigente_hasta.to_le_bytes());
    }
    v
}

fn serializar_consumo(dig: [u8; LONGITUD_HASH_PAQUETE], resp: &ResultadoConsumo) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // CONSUMO
    v.extend_from_slice(&dig);
    v.extend_from_slice(&resp.digest_recibo_interno);
    v.push(resp.estado as u8);
    v.extend_from_slice(&(resp.id_externo.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.id_externo.as_bytes());
    v
}

pub fn preparar_solicitud_consumo(
    s: SolicitudConsumoDecisionPersona,
) -> (SolicitudConsumoDecisionPersona, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_consumo(&s);
    (s, d)
}
