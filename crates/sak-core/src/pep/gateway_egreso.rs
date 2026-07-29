//! Gateway de egreso de datos EF-10: ejecución delegada entre dominios.
//!
//! No certifica licitud internacional, consentimiento, adecuación contractual,
//! exclusividad ni no-elusión global. Exige hechos GOB/VAL-EXT; custodia solo
//! en el adaptador instrumentado. EF-2/EF-3 no autorizan EF-10 por sí mismos.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_egreso::{
    AdaptadorEgreso, ErrorAdaptadorEgreso, EstadoEgreso, ResultadoEgreso,
};
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_egreso::{
    alcance_ef10, digest_condiciones_egreso, digest_solicitud_egreso, AlcanceAutorizadoEgreso,
    HechoEgresoExigido, PrecondicionesPepEf10, SolicitudEgresoCruda, SolicitudEgresoDatos,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaEgreso {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub recibo: ReciboEfecto,
    pub id_externo: String,
    pub estado: EstadoEgreso,
    pub endpoint_logico: String,
    pub ruta_efectiva: String,
    pub destino_efectivo: String,
    pub bytes_transferidos: u64,
    pub digest_solicitud: [u8; LONGITUD_HASH_PAQUETE],
    pub antiguedad_vista_ms: Ticks,
}

pub struct GatewayEgresoDatos {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayEgresoDatos {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayEgresoDatos {
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

    pub const fn posee_credencial_egreso_expuesta() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudEgresoCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf10,
        hechos_presentes: &[HechoEgresoExigido],
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorEgreso,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        _ticks_ahora: Option<u64>,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepEgreso {
        let ticks = reloj.ahora();

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
        if !precondiciones.hechos_ok {
            return self.denegar(ticks, Some(sistema.clone()), None, CodigoPep::HechoEgresoAusente);
        }

        let solicitud = match cruda {
            SolicitudEgresoCruda::NoTipificable
            | SolicitudEgresoCruda::Malformada(_)
            | SolicitudEgresoCruda::FormatoNoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudEgresoCruda::Wildcard => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::DestinoEgresoNoAutorizado,
                );
            }
            SolicitudEgresoCruda::Redireccion => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::RedireccionNoDeclarada,
                );
            }
            SolicitudEgresoCruda::ProxyNoDeclarado => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ProxyEgresoNoDeclarado,
                );
            }
            SolicitudEgresoCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudEgresoCruda::Tipada(s) => s,
        };

        if precondiciones.exige_c4(solicitud) && !precondiciones.libro_c4 {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::ControlInsuficiente,
            );
        }

        let digest_sol = digest_solicitud_egreso(solicitud);

        if let Err(c) = comprobar_hechos(solicitud, hechos_presentes) {
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
            alcance: alcance_ef10(solicitud),
            epoca_actual,
        };

        let exige_sincrona = !solicitud.reversible
            || solicitud.datos_personales
            || solicitud.categorias_especiales;
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
            TipoRegistro::EgresoDatos,
            serializar_hechos(solicitud),
        );

        let resp = match adaptador.transferir_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptadorEgreso::CanalEncubierto)
            | Err(ErrorAdaptadorEgreso::FragmentacionEvasiva)
            | Err(ErrorAdaptadorEgreso::Redireccion)
            | Err(ErrorAdaptadorEgreso::ProxyNoDeclarado)
            | Err(ErrorAdaptadorEgreso::DestinoNoAutorizado)
            | Err(ErrorAdaptadorEgreso::VolumenAcumuladoExcedido) => {
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
            Err(ErrorAdaptadorEgreso::NoPuedeDemostrarExactitud)
            | Err(ErrorAdaptadorEgreso::DivergenciaTransferencia) => {
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
        solicitud: &SolicitudEgresoDatos,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        resp: &ResultadoEgreso,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepEgreso {
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: digest_condiciones_egreso(&solicitud.condiciones),
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
            TipoRegistro::EgresoDatos,
            serializar_transferencia(digest_sol, resp),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepEgreso::Permitido(RespuestaEgreso {
            digest_resultado: resp.digest_resultado,
            recibo,
            id_externo: resp.id_externo.clone(),
            estado: resp.estado,
            endpoint_logico: resp.endpoint_logico.clone(),
            ruta_efectiva: resp.ruta_efectiva.clone(),
            destino_efectivo: resp.destino_efectivo.clone(),
            bytes_transferidos: resp.bytes_transferidos,
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
    ) -> ResultadoPepEgreso {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepEgreso::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepEgreso {
    Permitido(RespuestaEgreso),
    Denegado { codigo: CodigoPep },
}

fn comprobar_hechos(
    sol: &SolicitudEgresoDatos,
    presentes: &[HechoEgresoExigido],
) -> Result<(), CodigoPep> {
    for exigido in &sol.hechos_exigidos {
        let ok = presentes.iter().any(|p| {
            p.tipo == exigido.tipo && p.etiqueta == exigido.etiqueta && p.digest == exigido.digest
        });
        if !ok {
            return Err(CodigoPep::HechoEgresoAusente);
        }
    }
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudEgresoDatos,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoEgreso::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.dominio_origen != sol.dominio_origen {
        return Err(CodigoPep::OrigenEgresoNoAutorizado);
    }
    if auth.dominio_destino != sol.dominio_destino {
        return Err(CodigoPep::DestinoEgresoNoAutorizado);
    }
    if auth.proveedor != sol.proveedor {
        return Err(CodigoPep::ProveedorEgresoNoAutorizado);
    }
    if auth.endpoint != sol.endpoint || auth.ruta_canonica != sol.ruta_canonica {
        return Err(CodigoPep::EndpointEgresoNoAutorizado);
    }
    if auth.jurisdiccion_destino != sol.jurisdiccion_destino {
        return Err(CodigoPep::JurisdiccionEgresoNoAutorizada);
    }
    if auth.protocolo != sol.protocolo.token() {
        return Err(CodigoPep::ProtocoloEgresoNoAutorizado);
    }
    if auth.destinatario_tenant != sol.destinatario_tenant {
        return Err(CodigoPep::TenantEgresoNoAutorizado);
    }
    if auth.clasificacion != sol.clasificacion {
        return Err(CodigoPep::ClasificacionEgresoNoAutorizada);
    }
    if auth.digest_contenido != sol.digest_contenido {
        return Err(CodigoPep::ManifiestoEgresoNoAutorizado);
    }
    if auth.volumen_max_bytes != sol.volumen_max_bytes {
        return Err(CodigoPep::VolumenEgresoExcedido);
    }
    if auth.finalidad != sol.finalidad {
        return Err(CodigoPep::FinalidadEgresoNoAutorizada);
    }
    if auth.cifrado_exigido != sol.cifrado_exigido {
        return Err(CodigoPep::CifradoEgresoNoAutorizado);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if !cap.alcance().cubre(&alcance_ef10(sol)) {
        return Err(CodigoPep::DestinoEgresoNoAutorizado);
    }
    Ok(())
}

fn comprobar_exactitud(
    sol: &SolicitudEgresoDatos,
    resp: &ResultadoEgreso,
    digest_sol: [u8; LONGITUD_HASH_PAQUETE],
    digest_cap: &[u8; LONGITUD_HASH_PAQUETE],
) -> Result<(), CodigoPep> {
    if resp.digest_solicitud_ejecutada != digest_sol
        || resp.digest_solicitud_ejecutada != *digest_cap
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if resp.digest_manifiesto_efectivo != sol.digest_contenido
        || resp.endpoint_logico != sol.endpoint
        || resp.ruta_efectiva != sol.ruta_canonica
        || resp.destino_efectivo != sol.dominio_destino
        || resp.protocolo_efectivo != sol.protocolo.token()
        || resp.tenant_efectivo != sol.destinatario_tenant
        || resp.cifrado_aplicado != sol.cifrado_exigido
        || resp.bytes_transferidos > sol.volumen_max_bytes
        || resp.objetos_transferidos > sol.max_objetos
    {
        return Err(CodigoPep::IncidenteMediacion);
    }
    if matches!(resp.estado, EstadoEgreso::Indeterminado) {
        return Err(CodigoPep::IncidenteMediacion);
    }
    Ok(())
}

fn serializar_hechos(sol: &SolicitudEgresoDatos) -> Vec<u8> {
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

fn serializar_transferencia(dig: [u8; LONGITUD_HASH_PAQUETE], resp: &ResultadoEgreso) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // TRANSFERENCIA
    v.extend_from_slice(&dig);
    v.extend_from_slice(&resp.digest_resultado);
    v.push(resp.estado as u8);
    v.extend_from_slice(&resp.bytes_transferidos.to_le_bytes());
    v.extend_from_slice(&(resp.ruta_efectiva.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.ruta_efectiva.as_bytes());
    v.extend_from_slice(&(resp.id_externo.len() as u16).to_le_bytes());
    v.extend_from_slice(resp.id_externo.as_bytes());
    v
}

pub fn preparar_solicitud_egreso(
    s: SolicitudEgresoDatos,
) -> (SolicitudEgresoDatos, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_egreso(&s);
    (s, d)
}
