//! Gateway de datos EF-2: punto de aplicación con ejecución delegada.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto,
};
use crate::identidad::IdSistema;
use crate::pep::almacen::AlmacenDatos;
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::solicitud_datos::{
    alcance_ef2, digest_condiciones_min, digest_solicitud_datos, AlcanceAutorizadoDatos,
    CondicionesMinimizacion, SolicitudDatos, SolicitudDatosCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaDatos {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    pub recibo: ReciboEfecto,
    pub campos_devueltos: Vec<String>,
    pub volumen_devuelto: u32,
    pub antiguedad_vista_ms: Ticks,
}

/// Gateway EF-2. No decide, no emite, no posee credencial de datos.
pub struct GatewayDatos {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayDatos {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayDatos {
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

    pub const fn posee_credencial_datos() -> bool {
        false
    }

    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudDatosCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        almacen: &mut dyn AlmacenDatos,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
    ) -> ResultadoPepDatos {
        let ticks = reloj.ahora();

        let solicitud = match cruda {
            SolicitudDatosCruda::NoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudDatosCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudDatosCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_datos(solicitud);

        let Some(cap) = capacidad else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadAusente,
            );
        };

        if let Err(codigo) = validar_contra_alcance(cap, solicitud) {
            return self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo);
        }

        let alcance_intento = alcance_ef2(solicitud);
        let intento = IntentoUso {
            sistema: sistema.clone(),
            digest_efecto: digest_sol,
            alcance: alcance_intento,
            epoca_actual,
        };

        let vista = self.verificador.vista_sincrona(reloj);
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

        let resp = match almacen.consultar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.to_string()),
                );
            }
        };

        // Minimización: solo campos ⊆ autorizados y volumen ≤ límite.
        if resp.campos_devueltos.iter().any(|c| !solicitud.campos.contains(c))
            || resp.volumen_devuelto > solicitud.limite_volumen
            || resp.digest_consulta_ejecutada != digest_sol
            || resp.digest_consulta_ejecutada != *cap.digest_efecto()
        {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::DivergenciaParametros,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_consulta_ejecutada,
                ticks,
            });
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::IncidenteMediacion,
            );
        }

        let condiciones = CondicionesMinimizacion::desde_solicitud(solicitud);
        let digest_cond = digest_condiciones_min(&condiciones);
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: resp.digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: digest_cond,
        };

        if let Err(e) = ledger.registrar_recibo(sujeto, &recibo) {
            if matches!(
                e,
                ErrorEvidencia::EscrituraFallida | ErrorEvidencia::DominioSuspendido
            ) {
                self.incidentes.push(IncidenteMediacion {
                    tipo: TipoIncidente::EvidenciaIncompleta,
                    id_capacidad: Some(*cap.id()),
                    digest_autorizado: *cap.digest_efecto(),
                    digest_ejecutado: resp.digest_consulta_ejecutada,
                    ticks,
                });
            }
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

        ResultadoPepDatos::Permitido(RespuestaDatos {
            digest_resultado: resp.digest_resultado,
            referencia_minima: resp.referencia_minima,
            recibo,
            campos_devueltos: resp.campos_devueltos,
            volumen_devuelto: resp.volumen_devuelto,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPepDatos {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepDatos::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepDatos {
    Permitido(RespuestaDatos),
    Denegado { codigo: CodigoPep },
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudDatos,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoDatos::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;

    if auth.recurso != sol.recurso {
        return Err(CodigoPep::RecursoNoAutorizado);
    }
    if auth.operacion != sol.operacion.token() {
        return Err(CodigoPep::RecursoNoAutorizado);
    }
    if auth.digest_filtro != sol.digest_filtro {
        return Err(CodigoPep::FiltroNoAutorizado);
    }
    if !sol.campos.is_subset(&auth.campos) {
        return Err(CodigoPep::CampoNoAutorizado);
    }
    if sol.limite_volumen > auth.limite_volumen {
        return Err(CodigoPep::VolumenExcedido);
    }
    if auth.destinatario != sol.destinatario {
        return Err(CodigoPep::RecursoNoAutorizado);
    }
    // Sin ampliación de alcance: el intento exacto debe estar cubierto.
    let intento = alcance_ef2(sol);
    if !cap.alcance().cubre(&intento) {
        return Err(CodigoPep::CampoNoAutorizado);
    }
    Ok(())
}

/// Prepara solicitud tipada y digest para ligar la capacidad.
pub fn preparar_solicitud_datos(s: SolicitudDatos) -> (SolicitudDatos, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_datos(&s);
    (s, d)
}
