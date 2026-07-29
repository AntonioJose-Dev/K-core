//! Gateway de escritura EF-3: punto de aplicación con ejecución delegada.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto,
};
use crate::identidad::IdSistema;
use crate::pep::ejecutor::{ErrorEjecutor, EjecutorEscritura};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_escritura::{
    alcance_ef3, digest_condiciones_escritura, digest_solicitud_escritura,
    AlcanceAutorizadoEscritura, CondicionesEscritura, PrecondicionesPepEf3, SolicitudEscritura,
    SolicitudEscrituraCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaEscritura {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    pub recibo: ReciboEfecto,
    pub digest_cambio_autorizado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_cambio_aplicado: [u8; LONGITUD_HASH_PAQUETE],
    pub version_previa: Option<u64>,
    pub version_posterior: Option<u64>,
    pub filas_afectadas: u32,
    pub antiguedad_vista_ms: Ticks,
}

/// Gateway EF-3. No decide, no emite, no posee credencial de escritura.
pub struct GatewayEscritura {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayEscritura {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayEscritura {
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

    pub const fn posee_credencial_escritura() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudEscrituraCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf3,
        ledger: &mut LedgerEvidencia<A>,
        ejecutor: &mut dyn EjecutorEscritura,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        // Si es true, fuerza vista de revocación en silencio (harness).
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepEscritura {
        let ticks = reloj.ahora();

        if !precondiciones.identidad_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::IdentidadNoVigente);
        }
        if !precondiciones.pasaporte_vigente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::PasaporteNoVigente);
        }
        if !precondiciones.libro_suficiente {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::ControlInsuficiente);
        }
        if !precondiciones.monitor_permisivo {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::MonitorNoPermisivo);
        }

        let solicitud = match cruda {
            SolicitudEscrituraCruda::NoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudEscrituraCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudEscrituraCruda::Tipada(s) => s,
        };

        // Escritura que materializa decisión sobre personas ⇒ exige cadena EF-8.
        if solicitud
            .campos
            .contains(crate::pep::solicitud_consumo::CAMPO_CONSECUENCIA_EF8)
            && !precondiciones.consumo_ef8_autorizado
        {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_solicitud_escritura(solicitud)),
                CodigoPep::ConsumoEf8Requerido,
            );
        }

        let digest_sol = digest_solicitud_escritura(solicitud);

        let Some(cap) = capacidad else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadAusente,
            );
        };

        // Decisión normativa vigente: hash + normas citadas (INV-03).
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

        let alcance_intento = alcance_ef3(solicitud);
        let intento = IntentoUso {
            sistema: sistema.clone(),
            digest_efecto: digest_sol,
            alcance: alcance_intento,
            epoca_actual,
        };

        // Irreversible o datos personales ⇒ vista síncrona; silencio ⇒ DENY.
        let exige_sincrona = cap.irreversible() || solicitud.datos_personales || !solicitud.reversible;
        let vista = if forzar_silencio_revocacion && exige_sincrona {
            VistaRevocacion::Silencio
        } else if exige_sincrona {
            self.verificador.vista_sincrona(reloj)
        } else {
            self.verificador.vista_sincrona(reloj)
        };

        let veredicto = self.verificador.verificar_uso(cap, &intento, &vista, reloj);
        let antiguedad = match veredicto {
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

        let resp = match ejecutor.mutar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorEjecutor::ConflictoCas) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::ConflictoCas,
                );
            }
            Err(ErrorEjecutor::NoPuedeDemostrarExactitud) => {
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

        // Debe demostrar mutación exactamente autorizada.
        if resp.digest_solicitud_ejecutada != digest_sol
            || resp.digest_solicitud_ejecutada != *cap.digest_efecto()
            || resp.digest_cambio_aplicado != resp.digest_cambio_autorizado
            || resp.filas_afectadas > solicitud.limite_filas
        {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::DivergenciaParametros,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_solicitud_ejecutada,
                ticks,
            });
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::IncidenteMediacion,
            );
        }

        let condiciones = CondicionesEscritura::desde_solicitud(solicitud);
        let digest_cond = digest_condiciones_escritura(&condiciones);
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: digest_cond,
        };

        if let Err(e) = ledger.registrar_recibo(sujeto, &recibo) {
            // Efecto ya ocurrió: incidente, nunca éxito silencioso.
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::EvidenciaIncompleta,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_cambio_aplicado,
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

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepEscritura::Permitido(RespuestaEscritura {
            digest_resultado: resp.digest_resultado,
            referencia_minima: resp.referencia_minima,
            recibo,
            digest_cambio_autorizado: resp.digest_cambio_autorizado,
            digest_cambio_aplicado: resp.digest_cambio_aplicado,
            version_previa: resp.version_previa,
            version_posterior: resp.version_posterior,
            filas_afectadas: resp.filas_afectadas,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPepEscritura {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepEscritura::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepEscritura {
    Permitido(RespuestaEscritura),
    Denegado { codigo: CodigoPep },
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudEscritura,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoEscritura::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;

    if auth.recurso != sol.recurso {
        return Err(CodigoPep::RecursoNoAutorizado);
    }
    if auth.operacion != sol.operacion.token() {
        return Err(CodigoPep::OperacionNoAutorizada);
    }
    if auth.digest_selector != sol.digest_selector {
        return Err(CodigoPep::SelectorNoAutorizado);
    }
    if auth.version_precondicion != sol.version_precondicion {
        return Err(CodigoPep::SelectorNoAutorizado);
    }
    if auth.digest_valores != sol.digest_valores {
        return Err(CodigoPep::ValorNoAutorizado);
    }
    if !sol.campos.is_subset(&auth.campos) {
        return Err(CodigoPep::CampoNoAutorizado);
    }
    if sol.limite_filas > auth.limite_filas {
        return Err(CodigoPep::LimiteFilasExcedido);
    }
    if auth.destinatario != sol.destinatario {
        return Err(CodigoPep::RecursoNoAutorizado);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if auth.reversible != sol.reversible || auth.datos_personales != sol.datos_personales {
        return Err(CodigoPep::OperacionNoAutorizada);
    }
    let intento = alcance_ef3(sol);
    if !cap.alcance().cubre(&intento) {
        return Err(CodigoPep::CampoNoAutorizado);
    }
    Ok(())
}

/// Prepara solicitud tipada y digest para ligar la capacidad.
pub fn preparar_solicitud_escritura(
    s: SolicitudEscritura,
) -> (SolicitudEscritura, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_escritura(&s);
    (s, d)
}
