//! Ejecutor de negocio EF-5: punto de aplicación con ejecución delegada (C4).
//!
//! No decide, no emite capacidades, no entrega credenciales al sujeto.
//! Demostración de custodia/ejecución solo en el adaptador instrumentado.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_negocio::{
    AdaptadorNegocio, ErrorAdaptadorNegocio, EstadoLiquidacion, ResultadoNegocio,
};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_negocio::{
    alcance_ef5, digest_condiciones_negocio, digest_solicitud_negocio, AlcanceAutorizadoNegocio,
    CondicionesNegocio, PrecondicionesPepEf5, SolicitudNegocioCruda, SolicitudOperacionNegocio,
};
use crate::reloj::{RelojMonotonico, Ticks};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaNegocio {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_externa: String,
    pub recibo: ReciboEfecto,
    pub estado_liquidacion: EstadoLiquidacion,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_operacion_enviada: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

/// Ejecutor EF-5. Credencial raíz permanece en custodia del adaptador; el Kernel ejecuta.
pub struct EjecutorNegocio {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
    /// Claves de idempotencia fijadas tras consumir nonce (antes del efector).
    claves_idempotencia: BTreeSet<[u8; 32]>,
}

impl EjecutorNegocio {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        EjecutorNegocio {
            verificador: VerificadorCapacidades::nuevo(suelo_epoca),
            intentos: Vec::new(),
            incidentes: Vec::new(),
            claves_idempotencia: BTreeSet::new(),
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

    pub fn clave_idempotencia_fijada(&self, key: &[u8; 32]) -> bool {
        self.claves_idempotencia.contains(key)
    }

    pub const fn puede_emitir_capacidad() -> bool {
        false
    }

    pub const fn posee_credencial_negocio_expuesta() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudNegocioCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf5,
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorNegocio,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepNegocio {
        let ticks = reloj.ahora();

        if !precondiciones.decision_permitida {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::DecisionDenegada);
        }
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
        if !precondiciones.supervision_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::SupervisionAusente);
        }
        if precondiciones.ordena_egreso_datos && !precondiciones.egreso_ef10_autorizado {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::EgresoEf10Requerido,
            );
        }
        if precondiciones.ordena_efecto_fisico && !precondiciones.efecto_fisico_ef11_autorizado {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::EfectoFisicoEf11Requerido,
            );
        }

        let solicitud = match cruda {
            SolicitudNegocioCruda::NoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudNegocioCruda::Malformada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudNegocioCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudNegocioCruda::Tipada(s) => s,
        };

        if solicitud.exige_supervision && !precondiciones.supervision_ok {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::SupervisionAusente,
            );
        }

        let digest_sol = digest_solicitud_negocio(solicitud);

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
            alcance: alcance_ef5(solicitud),
            epoca_actual,
        };

        // EF-5: consulta síncrona de revocación obligatoria.
        let vista = if forzar_silencio_revocacion {
            VistaRevocacion::Silencio
        } else {
            self.verificador.vista_sincrona(reloj)
        };

        // Consumir nonce y fijar idempotency key ANTES de invocar al efector.
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

        // Fijar clave de idempotencia ANTES de invocar al efector (sin reintento auto).
        self.claves_idempotencia.insert(solicitud.idempotency_key);

        let resp = match adaptador.ejecutar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptadorNegocio::ResultadoIndeterminado) => {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::ResultadoIndeterminado,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: digest_sol,
                    ticks,
                });
                let _ = ledger.registrar_evento_sistema(
                    sujeto,
                    TipoRegistro::Negocio,
                    serializar_incidente(digest_sol, b"INDETERMINADO"),
                );
                // Nunca reintentar automáticamente una operación irreversible.
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IncidenteMediacion,
                );
            }
            Err(ErrorAdaptadorNegocio::IdempotenciaDuplicada) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IdempotenciaDuplicada,
                );
            }
            Err(ErrorAdaptadorNegocio::IdempotenciaIncompatible) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IdempotenciaIncompatible,
                );
            }
            Err(ErrorAdaptadorNegocio::ConflictoPrecondicion) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::ConflictoPrecondicion,
                );
            }
            Err(ErrorAdaptadorNegocio::NoPuedeDemostrarExactitud)
            | Err(ErrorAdaptadorNegocio::DivergenciaOperacion) => {
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
        solicitud: &SolicitudOperacionNegocio,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoNegocio,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepNegocio {
        let condiciones = CondicionesNegocio::desde_solicitud(solicitud);
        let digest_cond = digest_condiciones_negocio(&condiciones);
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
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::Evidencia(e.to_string()),
            );
        }

        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Negocio,
            serializar_ejecucion(
                digest_sol,
                &resp.id_externo,
                resp.estado_liquidacion,
                &solicitud.sistema_efector,
                solicitud.tipo.token(),
            ),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepNegocio::Permitido(RespuestaNegocio {
            digest_resultado: resp.digest_resultado,
            referencia_externa: resp.id_externo.clone(),
            recibo,
            estado_liquidacion: resp.estado_liquidacion,
            digest_solicitud: digest_sol,
            digest_operacion_enviada: resp.digest_operacion_enviada,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPepNegocio {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepNegocio::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepNegocio {
    Permitido(RespuestaNegocio),
    Denegado { codigo: CodigoPep },
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudOperacionNegocio,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoNegocio::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.tipo != sol.tipo.token() {
        return Err(CodigoPep::TipoOperacionNoAutorizado);
    }
    if auth.sistema_efector != sol.sistema_efector {
        return Err(CodigoPep::EfectorNoAutorizado);
    }
    if auth.cuenta != sol.cuenta {
        return Err(CodigoPep::ContraparteNoAutorizada);
    }
    if auth.contraparte != sol.contraparte {
        return Err(CodigoPep::ContraparteNoAutorizada);
    }
    if auth.moneda != sol.moneda {
        return Err(CodigoPep::MonedaNoAutorizada);
    }
    if auth.importe != sol.importe.unidades_menores {
        return Err(CodigoPep::ImporteNoAutorizado);
    }
    if auth.digest_objeto != sol.digest_objeto {
        return Err(CodigoPep::ObjetoNoAutorizado);
    }
    if auth.idempotency_key != sol.idempotency_key {
        return Err(CodigoPep::IdempotenciaIncompatible);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if auth.epoca != sol.epoca {
        return Err(CodigoPep::OperacionNoAutorizada);
    }
    if !cap.alcance().cubre(&alcance_ef5(sol)) {
        return Err(CodigoPep::ObjetoNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudOperacionNegocio,
    resp: &ResultadoNegocio,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
        || resp.digest_operacion_enviada != digest_sol
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.tipo_efectivo != sol.tipo.token()
        || resp.contraparte_efectiva != sol.contraparte
        || resp.moneda_efectiva != sol.moneda
        || resp.importe_efectivo != sol.importe.unidades_menores
        || resp.efector_efectivo != sol.sistema_efector
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if matches!(resp.estado_liquidacion, EstadoLiquidacion::Indeterminada) {
        return Err(CodigoPep::IncidenteMediacion);
    }
    Ok(())
}

fn serializar_ejecucion(
    dig: [u8; LONGITUD_HASH_PAQUETE],
    id_ext: &str,
    estado: EstadoLiquidacion,
    efector: &str,
    tipo: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // EJECUCION
    v.extend_from_slice(&dig);
    v.push(estado as u8);
    v.extend_from_slice(&(id_ext.len() as u16).to_le_bytes());
    v.extend_from_slice(id_ext.as_bytes());
    v.extend_from_slice(&(efector.len() as u16).to_le_bytes());
    v.extend_from_slice(efector.as_bytes());
    v.extend_from_slice(&(tipo.len() as u16).to_le_bytes());
    v.extend_from_slice(tipo.as_bytes());
    v
}

fn serializar_incidente(dig: [u8; LONGITUD_HASH_PAQUETE], etiqueta: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(2); // INCIDENTE
    v.extend_from_slice(&dig);
    v.extend_from_slice(etiqueta);
    v
}

/// Prepara solicitud tipada y digest para ligar la capacidad.
pub fn preparar_solicitud_negocio(
    s: SolicitudOperacionNegocio,
) -> (SolicitudOperacionNegocio, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_negocio(&s);
    (s, d)
}
