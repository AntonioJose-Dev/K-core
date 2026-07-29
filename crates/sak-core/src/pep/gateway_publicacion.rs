//! Gateway de publicación EF-7: ejecución delegada (C4).
//!
//! No determina veracidad, licitud, riesgo reputacional ni adecuación editorial;
//! solo exige hechos firmados GOB/VAL-EXT. Custodia demostrada en adaptador instrumentado.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_publicacion::{
    AdaptadorPublicacion, ErrorAdaptadorPublicacion, EstadoPublicacion, ResultadoPublicacion,
};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_publicacion::{
    alcance_ef7, digest_condiciones_publicacion, digest_solicitud_publicacion,
    AlcanceAutorizadoPublicacion, HechoPublicacionExigido, PrecondicionesPepEf7,
    SolicitudPublicacion, SolicitudPublicacionCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaPublicacion {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub recibo: ReciboEfecto,
    pub id_externo: String,
    pub estado: EstadoPublicacion,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

pub struct GatewayPublicacion {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayPublicacion {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayPublicacion {
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

    pub const fn posee_credencial_publicacion_expuesta() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudPublicacionCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf7,
        hechos_presentes: &[HechoPublicacionExigido],
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorPublicacion,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        ticks_ahora: Option<u64>,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepPublicacion {
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
        if !precondiciones.hechos_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::HechoPublicacionAusente);
        }
        if !precondiciones.supervision_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::SupervisionAusente);
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
            SolicitudPublicacionCruda::NoTipificable | SolicitudPublicacionCruda::Malformada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudPublicacionCruda::ContenidoActivo => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ContenidoNoCanonico,
                );
            }
            SolicitudPublicacionCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudPublicacionCruda::Tipada(s) => s,
        };

        if solicitud.exige_supervision && !precondiciones.supervision_ok {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::SupervisionAusente,
            );
        }
        if !solicitud.contenido_canonico {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::ContenidoNoCanonico,
            );
        }

        let digest_sol = digest_solicitud_publicacion(solicitud);

        if let Err(c) = comprobar_hechos(solicitud, hechos_presentes) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), c);
        }
        if ahora < solicitud.ventana_desde || ahora > solicitud.ventana_hasta {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::VentanaPublicacionNoAutorizada,
            );
        }
        if let Err(c) = aplicar_condiciones(solicitud) {
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
            alcance: alcance_ef7(solicitud),
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
            TipoRegistro::Publicacion,
            serializar_hechos(solicitud),
        );

        let resp = match adaptador.publicar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptadorPublicacion::ResultadoIndeterminado)
            | Err(ErrorAdaptadorPublicacion::ConfirmacionParcial) => {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::ResultadoIndeterminado,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: digest_sol,
                    ticks,
                });
                let _ = ledger.registrar_evento_sistema(
                    sujeto,
                    TipoRegistro::Publicacion,
                    serializar_incidente(digest_sol, b"PARCIAL_O_INDETERMINADO"),
                );
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::IncidenteMediacion,
                );
            }
            Err(ErrorAdaptadorPublicacion::RetiradaFueraAlcance) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::RetiradaFueraAlcance,
                );
            }
            Err(ErrorAdaptadorPublicacion::NoPuedeDemostrarExactitud)
            | Err(ErrorAdaptadorPublicacion::DivergenciaPublicacion) => {
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
        solicitud: &SolicitudPublicacion,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoPublicacion,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepPublicacion {
        let digest_cond = digest_condiciones_publicacion(&solicitud.condiciones);
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
            TipoRegistro::Publicacion,
            serializar_publicacion(digest_sol, resp),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepPublicacion::Permitido(RespuestaPublicacion {
            digest_resultado: resp.digest_resultado,
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
    ) -> ResultadoPepPublicacion {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepPublicacion::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepPublicacion {
    Permitido(RespuestaPublicacion),
    Denegado { codigo: CodigoPep },
}

fn comprobar_hechos(
    sol: &SolicitudPublicacion,
    presentes: &[HechoPublicacionExigido],
) -> Result<(), CodigoPep> {
    for exigido in &sol.hechos_exigidos {
        let ok = presentes.iter().any(|p| {
            p.tipo == exigido.tipo && p.etiqueta == exigido.etiqueta && p.digest == exigido.digest
        });
        if !ok {
            return Err(CodigoPep::HechoPublicacionAusente);
        }
    }
    Ok(())
}

fn aplicar_condiciones(sol: &SolicitudPublicacion) -> Result<(), CodigoPep> {
    let c = &sol.condiciones;
    if c.plantilla_obligatoria && sol.titulo.trim().is_empty() {
        return Err(CodigoPep::CondicionPublicacion);
    }
    if c.audiencia_limitada && (sol.audiencia == "*" || sol.visibilidad == "publica-total") {
        return Err(CodigoPep::AudienciaNoAutorizada);
    }
    let _ = (c.marcado_obligatorio, c.retencion_dias, c.revision_humana);
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudPublicacion,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoPublicacion::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.canal != sol.canal.token() {
        return Err(CodigoPep::CanalPublicacionNoAutorizado);
    }
    if auth.proveedor != sol.proveedor {
        return Err(CodigoPep::EfectorNoAutorizado);
    }
    if auth.cuenta_publicadora != sol.cuenta_publicadora {
        return Err(CodigoPep::CuentaPublicacionNoAutorizada);
    }
    if auth.destino != sol.destino {
        return Err(CodigoPep::DestinoPublicacionNoAutorizado);
    }
    if auth.operacion != sol.operacion.token() {
        return Err(CodigoPep::OperacionPublicacionNoAutorizada);
    }
    if auth.digest_contenido != sol.digest_contenido {
        return Err(CodigoPep::ContenidoPublicacionNoAutorizado);
    }
    if auth.digest_medios != sol.digest_medios {
        return Err(CodigoPep::MedioPublicacionNoAutorizado);
    }
    if auth.idioma != sol.idioma {
        return Err(CodigoPep::IdiomaNoAutorizado);
    }
    if auth.etiquetas != sol.etiquetas {
        return Err(CodigoPep::EtiquetaNoAutorizada);
    }
    if auth.audiencia != sol.audiencia {
        return Err(CodigoPep::AudienciaNoAutorizada);
    }
    if auth.visibilidad != sol.visibilidad {
        return Err(CodigoPep::VisibilidadNoAutorizada);
    }
    if auth.ventana_desde != sol.ventana_desde || auth.ventana_hasta != sol.ventana_hasta {
        return Err(CodigoPep::VentanaPublicacionNoAutorizada);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if !cap.alcance().cubre(&alcance_ef7(sol)) {
        return Err(CodigoPep::ContenidoPublicacionNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudPublicacion,
    resp: &ResultadoPublicacion,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.digest_contenido_publicado != sol.digest_contenido
        || resp.digest_medios_publicados != sol.digest_medios
        || resp.canal_efectivo != sol.canal.token()
        || resp.cuenta_efectiva != sol.cuenta_publicadora
        || resp.destino_efectivo != sol.destino
        || resp.operacion_efectiva != sol.operacion.token()
        || resp.audiencia_efectiva != sol.audiencia
        || resp.visibilidad_efectiva != sol.visibilidad
        || resp.idioma_efectivo != sol.idioma
        || resp.etiquetas_efectivas != sol.etiquetas
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if matches!(resp.estado, EstadoPublicacion::Indeterminado) {
        return Err(CodigoPep::IncidenteMediacion);
    }
    Ok(())
}

fn serializar_hechos(sol: &SolicitudPublicacion) -> Vec<u8> {
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

fn serializar_publicacion(dig: [u8; LONGITUD_HASH_PAQUETE], resp: &ResultadoPublicacion) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // PUBLICACION
    v.extend_from_slice(&dig);
    v.extend_from_slice(&resp.digest_resultado);
    v.push(resp.estado as u8);
    v.extend_from_slice(&(resp.id_externo.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.id_externo.as_bytes());
    v.extend_from_slice(&(resp.destino_efectivo.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.destino_efectivo.as_bytes());
    v
}

fn serializar_incidente(dig: [u8; LONGITUD_HASH_PAQUETE], etiqueta: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(2); // INCIDENTE
    v.extend_from_slice(&dig);
    v.extend_from_slice(etiqueta);
    v
}

pub fn preparar_solicitud_publicacion(
    s: SolicitudPublicacion,
) -> (SolicitudPublicacion, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_publicacion(&s);
    (s, d)
}
