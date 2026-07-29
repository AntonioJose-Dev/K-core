//! Gateway EF-11: efecto físico / ciberfísico vía módulo interpuesto.
//!
//! Sin módulo interpuesto o con ruta alternativa ⇒ C0 / DENY (no degradación
//! permisiva). No certifica seguridad industrial/médica ni ausencia de bypass
//! físico desconocido.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::modulo_fisico::{
    ErrorModuloFisico, FaseEjecucionFisica, ModuloFisicoInterpuesto, ResultadoFisico,
};
use crate::pep::solicitud_fisico::{
    alcance_ef11, digest_solicitud_fisica, AlcanceAutorizadoFisico, AprobacionHumanaFisica,
    HechoFisicoExigido, PrecondicionesPepEf11, SolicitudEfectoFisico, SolicitudFisicaCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaFisica {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub recibo: ReciboEfecto,
    pub id_externo: String,
    pub fase: FaseEjecucionFisica,
    pub estado_observado: String,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

pub struct GatewayEfectoFisico {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayEfectoFisico {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayEfectoFisico {
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

    pub const fn posee_autoridad_bus_expuesta() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudFisicaCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf11,
        hechos_presentes: &[HechoFisicoExigido],
        aprobacion: Option<&AprobacionHumanaFisica>,
        ledger: &mut LedgerEvidencia<A>,
        modulo: Option<&mut ModuloFisicoInterpuesto>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        ticks_ahora: Option<u64>,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepFisico {
        let ticks = reloj.ahora();
        let ahora = ticks_ahora.unwrap_or(ticks);

        if !precondiciones.identidad_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::IdentidadNoVigente);
        }
        if !precondiciones.pasaporte_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::PasaporteNoVigente);
        }
        // Sin módulo / ruta alternativa ⇒ C0: DENY (no modo observado).
        if precondiciones.clasificacion_c0() || modulo.is_none() {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::ModuloFisicoAusente,
            );
        }
        if !precondiciones.libro_c4 {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::ControlInsuficiente);
        }
        if !precondiciones.monitor_permisivo {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::MonitorNoPermisivo);
        }
        if !precondiciones.hechos_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::HechoFisicoAusente);
        }
        if !precondiciones.latido_modulo {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::LatidoModuloAusente);
        }

        let solicitud = match cruda {
            SolicitudFisicaCruda::NoTipificable | SolicitudFisicaCruda::Malformada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudFisicaCruda::OrdenLibre => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::OrdenFisicaLibre,
                );
            }
            SolicitudFisicaCruda::CompuestaNoDeclarada => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::OrdenFisicaCompuesta,
                );
            }
            SolicitudFisicaCruda::BusAlternativo => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::BusFisicoNoAutorizado,
                );
            }
            SolicitudFisicaCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudFisicaCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_fisica(solicitud);

        if let Err(c) = comprobar_hechos(solicitud, hechos_presentes) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), c);
        }
        if ahora < solicitud.ventana_desde || ahora > solicitud.ventana_hasta {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::VentanaFisicaNoAutorizada,
            );
        }

        if solicitud.exige_supervision {
            match aprobacion {
                None => {
                    return self.denegar(
                        ticks,
                        Some(sistema.clone()),
                        Some(digest_sol),
                        CodigoPep::AprobacionHumanaAusente,
                    );
                }
                Some(a) => {
                    if let Err(motivo) = a.valida_para(
                        &digest_sol,
                        &solicitud.digest_contexto,
                        ahora,
                        &solicitud.competencia_requerida,
                    ) {
                        let codigo = match motivo {
                            "competencia inadecuada" => CodigoPep::AprobacionHumanaIncompetente,
                            "no independiente" => CodigoPep::AprobacionHumanaNoIndependiente,
                            "fuera de plazo" => CodigoPep::AprobacionHumanaFueraPlazo,
                            "digest divergente" => CodigoPep::AprobacionHumanaDigestDivergente,
                            _ => CodigoPep::AprobacionHumanaAusente,
                        };
                        return self.denegar(
                            ticks,
                            Some(sistema.clone()),
                            Some(digest_sol),
                            codigo,
                        );
                    }
                }
            }
            if !precondiciones.supervision_ok {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::SupervisionAusente,
                );
            }
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
            alcance: alcance_ef11(solicitud),
            epoca_actual,
        };

        // EF-11: siempre consulta síncrona (efecto físico).
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

        let Some(modulo) = modulo else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::ModuloFisicoAusente,
            );
        };

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::EfectoFisico,
            serializar_hechos(solicitud),
        );

        let resp = match modulo.ejecutar_delegado(solicitud, cap.digest_efecto(), ahora) {
            Ok(r) => r,
            Err(e) => {
                return self.manejar_error_modulo(
                    e,
                    solicitud,
                    cap,
                    sistema,
                    sujeto,
                    ledger,
                    modulo,
                    digest_sol,
                    ticks,
                );
            }
        };

        if matches!(
            resp.fase,
            FaseEjecucionFisica::Parcial | FaseEjecucionFisica::Indeterminada
        ) || resp.digest_solicitud_ejecutada != digest_sol
        {
            return self.incidente_parcial(
                solicitud,
                cap,
                sistema,
                sujeto,
                ledger,
                modulo,
                &resp,
                digest_sol,
                ticks,
            );
        }

        if let Err(_codigo) = comprobar_exactitud(solicitud, &resp, digest_sol, cap.digest_efecto()) {
            return self.incidente_parcial(
                solicitud,
                cap,
                sistema,
                sujeto,
                ledger,
                modulo,
                &resp,
                digest_sol,
                ticks,
            );
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

    fn manejar_error_modulo<A: AlmacenEvidencia>(
        &mut self,
        e: ErrorModuloFisico,
        solicitud: &SolicitudEfectoFisico,
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        modulo: &mut ModuloFisicoInterpuesto,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        ticks: Ticks,
    ) -> ResultadoPepFisico {
        let codigo = match e {
            ErrorModuloFisico::SinLatido => CodigoPep::LatidoModuloAusente,
            ErrorModuloFisico::Interlock => CodigoPep::InterlockFisico,
            ErrorModuloFisico::EnvolventeLocal => CodigoPep::EnvolventeFisicaLocal,
            ErrorModuloFisico::Replay => CodigoPep::OrdenFisicaReplay,
            ErrorModuloFisico::BusNoDeclarado => CodigoPep::BusFisicoNoAutorizado,
            ErrorModuloFisico::EstadoIncompatible => CodigoPep::EstadoFisicoIncompatible,
            ErrorModuloFisico::ActuadorBloqueado => CodigoPep::ActuadorFisicoBloqueado,
            ErrorModuloFisico::TimeoutTelemetria
            | ErrorModuloFisico::EstadoIncierto
            | ErrorModuloFisico::ParadaNoConfirmable => {
                return self.incidente_parcial_sin_resp(
                    solicitud,
                    cap,
                    sistema,
                    sujeto,
                    ledger,
                    modulo,
                    digest_sol,
                    ticks,
                    CodigoPep::IncidenteMediacion,
                );
            }
            _ => CodigoPep::Evidencia(e.to_string()),
        };
        // Denegación del módulo = resultado real del efector, no reevaluación normativa.
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::EfectoFisico,
            serializar_denegacion_modulo(digest_sol, &e),
        );
        self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
    }

    fn incidente_parcial_sin_resp<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudEfectoFisico,
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        modulo: &mut ModuloFisicoInterpuesto,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        ticks: Ticks,
        codigo: CodigoPep,
    ) -> ResultadoPepFisico {
        self.incidentes.push(IncidenteMediacion {
            tipo: TipoIncidente::DivergenciaParametros,
            id_capacidad: Some(*cap.id()),
            digest_autorizado: *cap.digest_efecto(),
            digest_ejecutado: digest_sol,
            ticks,
        });
        modulo.bloquear_actuador(&solicitud.id_actuador);
        let _ = modulo.ejecutar_parada_segura(
            &solicitud.id_actuador,
            &solicitud.procedimiento_parada,
        );
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::EfectoFisico,
            serializar_incidente(digest_sol),
        );
        self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
    }

    fn incidente_parcial<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudEfectoFisico,
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        modulo: &mut ModuloFisicoInterpuesto,
        resp: &ResultadoFisico,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        ticks: Ticks,
    ) -> ResultadoPepFisico {
        let _ = resp;
        self.incidente_parcial_sin_resp(
            solicitud,
            cap,
            sistema,
            sujeto,
            ledger,
            modulo,
            digest_sol,
            ticks,
            CodigoPep::IncidenteMediacion,
        )
    }

    fn cerrar_con_recibo<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudEfectoFisico,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoFisico,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepFisico {
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: solicitud.digest_contexto,
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
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::Evidencia(e.to_string()),
            );
        }

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::EfectoFisico,
            serializar_ejecucion(digest_sol, resp),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepFisico::Permitido(RespuestaFisica {
            digest_resultado: resp.digest_resultado,
            recibo,
            id_externo: resp.id_externo.clone(),
            fase: resp.fase,
            estado_observado: resp.estado_observado.clone(),
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
    ) -> ResultadoPepFisico {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepFisico::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepFisico {
    Permitido(RespuestaFisica),
    Denegado { codigo: CodigoPep },
}

fn comprobar_hechos(
    sol: &SolicitudEfectoFisico,
    presentes: &[HechoFisicoExigido],
) -> Result<(), CodigoPep> {
    for exigido in &sol.hechos_exigidos {
        let ok = presentes.iter().any(|p| {
            p.tipo == exigido.tipo && p.etiqueta == exigido.etiqueta && p.digest == exigido.digest
        });
        if !ok {
            return Err(CodigoPep::HechoFisicoAusente);
        }
    }
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudEfectoFisico,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoFisico::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.id_actuador != sol.id_actuador {
        return Err(CodigoPep::ActuadorFisicoNoAutorizado);
    }
    if auth.id_controlador != sol.id_controlador {
        return Err(CodigoPep::ControladorFisicoNoAutorizado);
    }
    if auth.id_bus != sol.id_bus {
        return Err(CodigoPep::BusFisicoNoAutorizado);
    }
    if auth.operacion != sol.operacion.token() {
        return Err(CodigoPep::OperacionFisicaNoAutorizada);
    }
    if auth.magnitud != sol.parametros.magnitud
        || auth.velocidad != sol.parametros.velocidad
        || auth.duracion_ms != sol.parametros.duracion_ms
        || auth.energia != sol.parametros.energia
        || auth.unidad_magnitud != sol.parametros.unidad_magnitud
    {
        return Err(CodigoPep::ParametroFisicoNoAutorizado);
    }
    if auth.instalacion_zona != sol.instalacion_zona {
        return Err(CodigoPep::ZonaFisicaNoAutorizada);
    }
    if auth.modo != sol.modo.token() {
        return Err(CodigoPep::ModoFisicoNoAutorizado);
    }
    if auth.ventana_desde != sol.ventana_desde || auth.ventana_hasta != sol.ventana_hasta {
        return Err(CodigoPep::VentanaFisicaNoAutorizada);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if !cap.alcance().cubre(&alcance_ef11(sol)) {
        return Err(CodigoPep::ActuadorFisicoNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudEfectoFisico,
    resp: &ResultadoFisico,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.estado_observado != sol.estado_objetivo
        && !matches!(resp.fase, FaseEjecucionFisica::EstadoObservado)
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if matches!(
        resp.fase,
        FaseEjecucionFisica::Parcial | FaseEjecucionFisica::Indeterminada
    ) {
        return Err(CodigoPep::IncidenteMediacion);
    }
    Ok(())
}

fn serializar_hechos(sol: &SolicitudEfectoFisico) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0);
    for h in &sol.hechos_exigidos {
        v.extend_from_slice(h.tipo.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(h.etiqueta.token().as_bytes());
        v.push(b'|');
        v.extend_from_slice(&h.digest);
    }
    v
}

fn serializar_ejecucion(dig: [u8; LONGITUD_HASH_PAQUETE], resp: &ResultadoFisico) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // EJECUCION
    v.extend_from_slice(&dig);
    v.extend_from_slice(&resp.digest_resultado);
    v.push(resp.fase as u8);
    v.extend_from_slice(&(resp.estado_observado.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.estado_observado.as_bytes());
    v.extend_from_slice(&(resp.id_externo.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.id_externo.as_bytes());
    v
}

fn serializar_denegacion_modulo(dig: [u8; LONGITUD_HASH_PAQUETE], e: &ErrorModuloFisico) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(2); // DENEGACION_MODULO
    v.extend_from_slice(&dig);
    let s = e.to_string();
    v.extend_from_slice(&(s.len() as u16).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
    v
}

fn serializar_incidente(dig: [u8; LONGITUD_HASH_PAQUETE]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(3); // INCIDENTE
    v.extend_from_slice(&dig);
    v
}

pub fn preparar_solicitud_fisica(
    s: SolicitudEfectoFisico,
) -> (SolicitudEfectoFisico, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_fisica(&s);
    (s, d)
}
