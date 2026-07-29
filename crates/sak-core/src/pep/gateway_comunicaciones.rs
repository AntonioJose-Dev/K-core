//! Gateway de comunicaciones EF-6: ejecución delegada (C4).
//!
//! No decide consentimiento, base jurídica ni vulnerabilidad; solo exige hechos
//! firmados etiquetados GOB/VAL-EXT. Custodia demostrada en adaptador instrumentado.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_comunicacion::{
    AdaptadorComunicacion, ErrorAdaptadorComunicacion, EstadoDestinatario, ResultadoComunicacion,
    ResultadoPorDestinatario,
};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_comunicacion::{
    alcance_ef6, digest_condiciones_comunicacion, digest_solicitud_comunicacion,
    AlcanceAutorizadoComunicacion, PrecondicionesPepEf6, SolicitudComunicacion,
    SolicitudComunicacionCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaComunicacion {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub recibo: ReciboEfecto,
    pub por_destinatario: Vec<ResultadoPorDestinatario>,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

/// Gateway EF-6. No decide, no emite, no entrega credencial ni identidad de remitente.
pub struct GatewayComunicaciones {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayComunicaciones {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayComunicaciones {
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

    pub const fn posee_credencial_envio_expuesta() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudComunicacionCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf6,
        hechos_presentes: &[crate::pep::solicitud_comunicacion::HechoContactoExigido],
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorComunicacion,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        ticks_ahora: Option<u64>,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepComunicacion {
        let ticks = reloj.ahora();
        let ahora = ticks_ahora.unwrap_or(ticks);

        if !precondiciones.identidad_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::IdentidadNoVigente);
        }
        if !precondiciones.pasaporte_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::PasaporteNoVigente);
        }
        if !precondiciones.libro_c4 {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::ControlInsuficiente);
        }
        if !precondiciones.monitor_permisivo {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::MonitorNoPermisivo);
        }
        if !precondiciones.hechos_contacto_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::HechoContactoAusente);
        }
        if precondiciones.cruza_dominio && !precondiciones.egreso_ef10_autorizado {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::EgresoEf10Requerido,
            );
        }
        if precondiciones.presenta_orden_fisica {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::EfectoFisicoEf11Requerido,
            );
        }

        let solicitud = match cruda {
            SolicitudComunicacionCruda::NoTipificable | SolicitudComunicacionCruda::Malformada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudComunicacionCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudComunicacionCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_comunicacion(solicitud);

        if let Err(c) = comprobar_hechos(solicitud, hechos_presentes) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), c);
        }
        if let Err(c) = aplicar_condiciones(solicitud, ahora) {
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
            alcance: alcance_ef6(solicitud),
            epoca_actual,
        };

        let vista = if forzar_silencio_revocacion {
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
            TipoRegistro::Comunicacion,
            serializar_hechos(solicitud),
        );

        let resp = match adaptador.enviar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptadorComunicacion::ResultadoIndeterminado)
            | Err(ErrorAdaptadorComunicacion::EntregaParcial) => {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::ResultadoIndeterminado,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: digest_sol,
                    ticks,
                });
                let _ = ledger.registrar_evento_sistema(
                    sujeto,
                    TipoRegistro::Comunicacion,
                    serializar_incidente(digest_sol, b"PARCIAL_O_INDETERMINADO"),
                );
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IncidenteMediacion,
                );
            }
            Err(ErrorAdaptadorComunicacion::NoPuedeDemostrarExactitud)
            | Err(ErrorAdaptadorComunicacion::DivergenciaEntrega) => {
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
        solicitud: &SolicitudComunicacion,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoComunicacion,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepComunicacion {
        let digest_cond = digest_condiciones_comunicacion(&solicitud.condiciones);
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: digest_cond,
        };

        if let Err(e) = ledger.registrar_recibo(sujeto, &recibo) {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::EvidenciaIncompleta,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_resultado,
                ticks,
            });
            let _ = matches!(
                e,
                ErrorEvidencia::EscrituraFallida | ErrorEvidencia::DominioSuspendido
            );
            // Tras envío: incidente; no afirmar entrega.
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::Evidencia(e.to_string()),
            );
        }

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Comunicacion,
            serializar_envio(digest_sol, resp),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepComunicacion::Permitido(RespuestaComunicacion {
            digest_resultado: resp.digest_resultado,
            recibo,
            por_destinatario: resp.por_destinatario.clone(),
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
    ) -> ResultadoPepComunicacion {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepComunicacion::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepComunicacion {
    Permitido(RespuestaComunicacion),
    Denegado { codigo: CodigoPep },
}

fn comprobar_hechos(
    sol: &SolicitudComunicacion,
    presentes: &[crate::pep::solicitud_comunicacion::HechoContactoExigido],
) -> Result<(), CodigoPep> {
    for exigido in &sol.hechos_exigidos {
        let ok = presentes.iter().any(|p| {
            p.tipo == exigido.tipo && p.etiqueta == exigido.etiqueta && p.digest == exigido.digest
        });
        if !ok {
            return Err(CodigoPep::HechoContactoAusente);
        }
    }
    Ok(())
}

fn aplicar_condiciones(sol: &SolicitudComunicacion, ahora: u64) -> Result<(), CodigoPep> {
    let c = &sol.condiciones;
    if c.plantilla_obligatoria && sol.id_plantilla.trim().is_empty() {
        return Err(CodigoPep::CondicionComunicacion);
    }
    if ahora < sol.ventana_desde_ticks || ahora > sol.ventana_hasta_ticks {
        return Err(CodigoPep::HorarioNoAutorizado);
    }
    // Franja horaria tipada: hora del día simulada como (ahora / 3600) % 24.
    let hora = ((ahora / 3600) % 24) as u8;
    if hora < c.hora_desde || hora >= c.hora_hasta {
        return Err(CodigoPep::HorarioNoAutorizado);
    }
    if sol.frecuencia_periodo > c.frecuencia_max_periodo {
        return Err(CodigoPep::FrecuenciaNoAutorizada);
    }
    let _marcado = c.marcado_obligatorio;
    let _baja = c.enlace_baja;
    let _ret = c.retencion_minima_dias;
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudComunicacion,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoComunicacion::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.canal != sol.canal.token() {
        return Err(CodigoPep::CanalNoAutorizado);
    }
    if auth.proveedor != sol.proveedor {
        return Err(CodigoPep::EfectorNoAutorizado);
    }
    if auth.identidad_remitente != sol.identidad_remitente {
        return Err(CodigoPep::RemitenteNoAutorizado);
    }
    if auth.digest_destinatarios != sol.destinatarios.digest {
        return Err(CodigoPep::DestinatarioNoAutorizado);
    }
    if auth.id_plantilla != sol.id_plantilla {
        return Err(CodigoPep::PlantillaNoAutorizada);
    }
    if auth.digest_cuerpo != sol.digest_cuerpo {
        return Err(CodigoPep::CuerpoNoAutorizado);
    }
    if auth.digest_adjuntos != sol.digest_adjuntos {
        return Err(CodigoPep::AdjuntoNoAutorizado);
    }
    if auth.idioma != sol.idioma {
        return Err(CodigoPep::IdiomaNoAutorizado);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if auth.ventana_desde_ticks != sol.ventana_desde_ticks
        || auth.ventana_hasta_ticks != sol.ventana_hasta_ticks
    {
        return Err(CodigoPep::HorarioNoAutorizado);
    }
    if auth.frecuencia_periodo != sol.frecuencia_periodo {
        return Err(CodigoPep::FrecuenciaNoAutorizada);
    }
    if !cap.alcance().cubre(&alcance_ef6(sol)) {
        return Err(CodigoPep::DestinatarioNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudComunicacion,
    resp: &ResultadoComunicacion,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.digest_contenido_entregado != sol.digest_cuerpo
        || resp.digest_destinatarios_efectivos != sol.destinatarios.digest
        || resp.canal_efectivo != sol.canal.token()
        || resp.remitente_efectivo != sol.identidad_remitente
        || resp.plantilla_efectiva != sol.id_plantilla
        || resp.idioma_efectivo != sol.idioma
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.por_destinatario.len() != sol.destinatarios.destinatarios.len() {
        return Err(CodigoPep::IncidenteMediacion);
    }
    for r in &resp.por_destinatario {
        if !sol.destinatarios.destinatarios.contains(&r.destinatario) {
            return Err(CodigoPep::IncidenteMediacion);
        }
        if matches!(
            r.estado,
            EstadoDestinatario::Indeterminado | EstadoDestinatario::Omitido
        ) {
            return Err(CodigoPep::IncidenteMediacion);
        }
    }
    Ok(())
}

fn serializar_hechos(sol: &SolicitudComunicacion) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0); // HECHOS
    for h in &sol.hechos_exigidos {
        v.extend_from_slice(h.tipo.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(h.etiqueta.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(&h.digest);
    }
    v
}

fn serializar_envio(dig: [u8; LONGITUD_HASH_PAQUETE], resp: &ResultadoComunicacion) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // ENVIO
    v.extend_from_slice(&dig);
    v.extend_from_slice(&resp.digest_resultado);
    for r in &resp.por_destinatario {
        v.extend_from_slice(&(r.destinatario.len() as u16).to_le_bytes());
        v.extend_from_slice(r.destinatario.as_bytes());
        v.push(r.estado as u8);
    }
    v
}

fn serializar_incidente(dig: [u8; LONGITUD_HASH_PAQUETE], etiqueta: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(2); // INCIDENTE
    v.extend_from_slice(&dig);
    v.extend_from_slice(etiqueta);
    v
}

pub fn preparar_solicitud_comunicacion(
    s: SolicitudComunicacion,
) -> (SolicitudComunicacion, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_comunicacion(&s);
    (s, d)
}
