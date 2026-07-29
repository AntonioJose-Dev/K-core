//! Broker de herramientas y MCP (EF-4): única superficie visible para sujetos.

use crate::capacidad::{
    Capability, IntentoUso, ResultadoVerificacion, VerificadorCapacidades, VistaRevocacion,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto, TipoRegistro,
};
use crate::identidad::IdSistema;
use crate::pep::adaptador_comunicacion::AdaptadorComunicacion;
use crate::pep::adaptador_egreso::AdaptadorEgreso;
use crate::pep::adaptador_herramienta::{AdaptadorHerramientas, ErrorAdaptador};
use crate::pep::adaptador_negocio::AdaptadorNegocio;
use crate::pep::adaptador_publicacion::AdaptadorPublicacion;
use crate::pep::catalogo::CatalogoHerramientas;
use crate::pep::ejecutor::EjecutorEscritura;
use crate::pep::ejecutor_negocio::EjecutorNegocio;
use crate::pep::gateway::{CodigoPep, RegistroIntentoPep, ResultadoIntento};
use crate::pep::gateway_comunicaciones::GatewayComunicaciones;
use crate::pep::gateway_egreso::GatewayEgresoDatos;
use crate::pep::gateway_escritura::GatewayEscritura;
use crate::pep::gateway_fisico::GatewayEfectoFisico;
use crate::pep::gateway_publicacion::GatewayPublicacion;
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::modulo_fisico::ModuloFisicoInterpuesto;
use crate::pep::solicitud::ClaseEfecto;
use crate::pep::solicitud_comunicacion::{
    traducir_comunicacion_desde_herramienta, PrecondicionesPepEf6, SolicitudComunicacionCruda,
};
use crate::pep::solicitud_egreso::{
    traducir_egreso_desde_herramienta, PrecondicionesPepEf10, SolicitudEgresoCruda,
};
use crate::pep::solicitud_fisico::{
    traducir_fisico_desde_herramienta, AprobacionHumanaFisica, PrecondicionesPepEf11,
    SolicitudFisicaCruda,
};
use crate::pep::solicitud_escritura::{
    PrecondicionesPepEf3, SolicitudEscritura, SolicitudEscrituraCruda,
};
use crate::pep::solicitud_herramienta::{
    alcance_ef4, digest_condiciones_herramienta, digest_solicitud_herramienta,
    AlcanceAutorizadoHerramienta, CondicionesHerramienta, PrecondicionesPepEf4,
    SolicitudHerramienta, SolicitudHerramientaCruda,
};
use crate::pep::solicitud_negocio::{
    traducir_desde_herramienta, PrecondicionesPepEf5, SolicitudNegocioCruda,
};
use crate::pep::solicitud_publicacion::{
    traducir_publicacion_desde_herramienta, PrecondicionesPepEf7, SolicitudPublicacionCruda,
};
use crate::reloj::{RelojMonotonico, Ticks};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaHerramienta {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    pub recibo: ReciboEfecto,
    pub id_herramienta: String,
    pub version: String,
    pub servidor: String,
    pub destino_efectivo: String,
    pub delegado_a: Option<ClaseEfecto>,
    pub antiguedad_vista_ms: Ticks,
}

/// Broker EF-4. No decide, no emite, no posee credenciales de EF-3/5/6/7.
pub struct BrokerHerramientas {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
    delegaciones: Vec<RegistroDelegacion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroDelegacion {
    pub ticks: Ticks,
    pub desde_ef4: [u8; LONGITUD_HASH_PAQUETE],
    pub hacia: ClaseEfecto,
    pub digest_solicitud_subyacente: [u8; LONGITUD_HASH_PAQUETE],
}

impl BrokerHerramientas {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        BrokerHerramientas {
            verificador: VerificadorCapacidades::nuevo(suelo_epoca),
            intentos: Vec::new(),
            incidentes: Vec::new(),
            delegaciones: Vec::new(),
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

    pub fn delegaciones(&self) -> &[RegistroDelegacion] {
        &self.delegaciones
    }

    pub const fn puede_emitir_capacidad() -> bool {
        false
    }

    pub const fn posee_credencial_herramienta_expuesta() -> bool {
        false
    }

    /// Invoca una herramienta tipada. Composición conservadora hacia PEPs subyacentes.
    pub fn invocar<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudHerramientaCruda,
        capacidad_ef4: Option<&Capability>,
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf4,
        catalogo: &CatalogoHerramientas,
        ledger: &mut LedgerEvidencia<A>,
        adaptador: &mut dyn AdaptadorHerramientas,
        // Solo usados si efecto_subyacente == EF-3.
        gateway_ef3: Option<&mut GatewayEscritura>,
        ejecutor_ef3: Option<&mut dyn EjecutorEscritura>,
        // Solo usados si efecto_subyacente == EF-5.
        ejecutor_ef5: Option<&mut EjecutorNegocio>,
        adaptador_ef5: Option<&mut dyn AdaptadorNegocio>,
        precondiciones_ef5: Option<&PrecondicionesPepEf5>,
        // Solo usados si efecto_subyacente == EF-6.
        gateway_ef6: Option<&mut GatewayComunicaciones>,
        adaptador_ef6: Option<&mut dyn AdaptadorComunicacion>,
        precondiciones_ef6: Option<&PrecondicionesPepEf6>,
        // Solo usados si efecto_subyacente == EF-7.
        gateway_ef7: Option<&mut GatewayPublicacion>,
        adaptador_ef7: Option<&mut dyn AdaptadorPublicacion>,
        precondiciones_ef7: Option<&PrecondicionesPepEf7>,
        // Solo usados si efecto_subyacente == EF-10.
        gateway_ef10: Option<&mut GatewayEgresoDatos>,
        adaptador_ef10: Option<&mut dyn AdaptadorEgreso>,
        precondiciones_ef10: Option<&PrecondicionesPepEf10>,
        // Solo usados si efecto_subyacente == EF-11.
        gateway_ef11: Option<&mut GatewayEfectoFisico>,
        modulo_ef11: Option<&mut ModuloFisicoInterpuesto>,
        precondiciones_ef11: Option<&PrecondicionesPepEf11>,
        aprobacion_ef11: Option<&AprobacionHumanaFisica>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio_revocacion: bool,
    ) -> ResultadoPepHerramienta {
        let ticks = reloj.ahora();

        if let Err(c) = comprobar_precondiciones(precondiciones) {
            return self.denegar(ticks, Some(sistema.clone()), None, c);
        }

        if catalogo.verificar_firma().is_err() {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                None,
                CodigoPep::Evidencia("catalogo firma invalida".into()),
            );
        }

        let solicitud = match cruda {
            SolicitudHerramientaCruda::NoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudHerramientaCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudHerramientaCruda::Redireccion => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::RedireccionNoDeclarada,
                );
            }
            SolicitudHerramientaCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_herramienta(solicitud);

        // Catálogo: herramienta/versión/servidor/operación registrados.
        let entrada = match catalogo.obtener(
            &solicitud.id_herramienta,
            &solicitud.version,
            &solicitud.servidor,
            &solicitud.operacion,
        ) {
            Some(e) => e,
            None => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::HerramientaNoRegistrada,
                );
            }
        };

        if entrada.digest_esquema_args != solicitud.digest_esquema_args {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::ArgumentosNoAutorizados,
            );
        }
        if entrada.efecto_subyacente != solicitud.efecto_subyacente {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::OperacionNoAutorizada,
            );
        }
        if entrada.destinos_permitidos.is_empty() {
            if !solicitud.destino.is_empty() && solicitud.destino != "local" {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::DestinoNoAutorizado,
                );
            }
        } else if !entrada
            .destinos_permitidos
            .iter()
            .any(|d| d == &solicitud.destino)
        {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::DestinoNoAutorizado,
            );
        }
        if *catalogo.hash_paquete_normativo() != solicitud.hash_paquete {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PaqueteNoAutorizado,
            );
        }

        let Some(cap) = capacidad_ef4 else {
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
            alcance: alcance_ef4(solicitud),
            epoca_actual,
        };

        let exige_sincrona =
            cap.irreversible() || solicitud.datos_personales || !solicitud.reversible;
        let vista = if forzar_silencio_revocacion && exige_sincrona {
            VistaRevocacion::Silencio
        } else {
            self.verificador.vista_sincrona(reloj)
        };

        // Consumir nonce ANTES de entregar la llamada.
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

        // Composición conservadora.
        match solicitud.efecto_subyacente {
            ClaseEfecto::Ef11 => {
                return self.delegar_ef11(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    ledger,
                    gateway_ef11,
                    modulo_ef11,
                    precondiciones_ef11,
                    aprobacion_ef11,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef10 => {
                return self.delegar_ef10(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    ledger,
                    gateway_ef10,
                    adaptador_ef10,
                    precondiciones_ef10,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef7 => {
                return self.delegar_ef7(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    ledger,
                    gateway_ef7,
                    adaptador_ef7,
                    precondiciones_ef7,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef6 => {
                return self.delegar_ef6(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    ledger,
                    gateway_ef6,
                    adaptador_ef6,
                    precondiciones_ef6,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef5 => {
                return self.delegar_ef5(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    ledger,
                    ejecutor_ef5,
                    adaptador_ef5,
                    precondiciones_ef5,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef3 => {
                return self.delegar_ef3(
                    solicitud,
                    digest_sol,
                    capacidad_subyacente,
                    sistema,
                    sujeto,
                    precondiciones,
                    ledger,
                    gateway_ef3,
                    ejecutor_ef3,
                    reloj,
                    epoca_actual,
                    forzar_silencio_revocacion,
                    antiguedad,
                    ticks,
                );
            }
            ClaseEfecto::Ef1 | ClaseEfecto::Ef2 => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::PepSubyacenteInexistente,
                );
            }
            _ => {}
        }

        let resp = match adaptador.invocar_delegado(solicitud, cap.digest_efecto()) {
            Ok(r) => r,
            Err(ErrorAdaptador::NoPuedeDemostrarExactitud) => {
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

        if resp.digest_solicitud_ejecutada != digest_sol
            || resp.digest_solicitud_ejecutada != *cap.digest_efecto()
            || resp.digest_argumentos_usados != solicitud.digest_argumentos
            || resp.id_herramienta != solicitud.id_herramienta
            || resp.version != solicitud.version
            || resp.servidor != solicitud.servidor
            || resp.destino_efectivo != solicitud.destino
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

        self.cerrar_con_recibo(
            solicitud,
            digest_sol,
            cap,
            sistema,
            sujeto,
            ledger,
            &resp.digest_resultado,
            &resp.referencia_minima,
            &resp.id_herramienta,
            &resp.version,
            &resp.servidor,
            &resp.destino_efectivo,
            None,
            antiguedad,
            ticks,
        )
    }

    fn delegar_ef3<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        precondiciones: &PrecondicionesPepEf4,
        ledger: &mut LedgerEvidencia<A>,
        gateway_ef3: Option<&mut GatewayEscritura>,
        ejecutor_ef3: Option<&mut dyn EjecutorEscritura>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let Some(gw) = gateway_ef3 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(exe) = ejecutor_ef3 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap3) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };

        // Traducción tipada a EF-3 (sin ejecutar escritura en el broker).
        let sol3 = match SolicitudEscritura::nueva(
            crate::pep::solicitud_escritura::OperacionEscritura::Update,
            format!("tool:{}", solicitud.id_herramienta),
            solicitud.digest_argumentos,
            None,
            ["payload"],
            solicitud.digest_argumentos,
            solicitud.cuota.max(1),
            &solicitud.destino,
            solicitud.reversible,
            solicitud.datos_personales,
            solicitud.hash_paquete,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let digest_sub = crate::pep::solicitud_escritura::digest_solicitud_escritura(&sol3);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef3,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef3, digest_sub),
        );

        let pre3 = PrecondicionesPepEf3 {
            identidad_vigente: precondiciones.identidad_vigente,
            pasaporte_vigente: precondiciones.pasaporte_vigente,
            libro_suficiente: precondiciones.libro_suficiente,
            monitor_permisivo: precondiciones.monitor_permisivo,
            // EF-4→EF-3 no autoriza por sí el consumo EF-8; exige cadena propia.
            consumo_ef8_autorizado: false,
        };

        match gw.ejercer(
            &SolicitudEscrituraCruda::Tipada(sol3),
            Some(cap3),
            sistema,
            sujeto,
            &pre3,
            ledger,
            exe,
            reloj,
            epoca_actual,
            forzar_silencio,
        ) {
            crate::pep::gateway_escritura::ResultadoPepEscritura::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r.referencia_minima,
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef3),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::gateway_escritura::ResultadoPepEscritura::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn delegar_ef5<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        ejecutor_ef5: Option<&mut EjecutorNegocio>,
        adaptador_ef5: Option<&mut dyn AdaptadorNegocio>,
        precondiciones_ef5: Option<&PrecondicionesPepEf5>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let Some(exe) = ejecutor_ef5 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(adap) = adaptador_ef5 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap5) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };
        let pre5 = precondiciones_ef5
            .copied()
            .unwrap_or_else(PrecondicionesPepEf5::todas_ok);

        let sol5 = match traducir_desde_herramienta(
            &solicitud.id_herramienta,
            &solicitud.servidor,
            &solicitud.operacion,
            &solicitud.destino,
            solicitud.digest_argumentos,
            solicitud.digest_condiciones,
            solicitud.hash_paquete,
            solicitud.datos_personales,
            solicitud.reversible,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let digest_sub = crate::pep::solicitud_negocio::digest_solicitud_negocio(&sol5);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef5,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef5, digest_sub),
        );

        match exe.ejercer(
            &SolicitudNegocioCruda::Tipada(sol5),
            Some(cap5),
            sistema,
            sujeto,
            &pre5,
            ledger,
            adap,
            reloj,
            epoca_actual,
            forzar_silencio,
        ) {
            crate::pep::ejecutor_negocio::ResultadoPepNegocio::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r.referencia_externa,
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef5),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::ejecutor_negocio::ResultadoPepNegocio::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn delegar_ef6<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        gateway_ef6: Option<&mut GatewayComunicaciones>,
        adaptador_ef6: Option<&mut dyn AdaptadorComunicacion>,
        precondiciones_ef6: Option<&PrecondicionesPepEf6>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let Some(gw) = gateway_ef6 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(adap) = adaptador_ef6 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap6) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };
        let pre6 = precondiciones_ef6
            .copied()
            .unwrap_or_else(PrecondicionesPepEf6::todas_ok);

        let sol6 = match traducir_comunicacion_desde_herramienta(
            &solicitud.id_herramienta,
            &solicitud.servidor,
            &solicitud.operacion,
            &solicitud.destino,
            solicitud.digest_argumentos,
            solicitud.hash_paquete,
            solicitud.datos_personales,
            solicitud.reversible,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let hechos = sol6.hechos_exigidos.clone();
        let digest_sub = crate::pep::solicitud_comunicacion::digest_solicitud_comunicacion(&sol6);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef6,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef6, digest_sub),
        );

        // Hora dentro de franja tipica (08–20) para no denegar por horario en delegación.
        let ticks_hora = 10 * 3600;
        match gw.ejercer(
            &SolicitudComunicacionCruda::Tipada(sol6),
            Some(cap6),
            sistema,
            sujeto,
            &pre6,
            &hechos,
            ledger,
            adap,
            reloj,
            epoca_actual,
            Some(ticks_hora),
            forzar_silencio,
        ) {
            crate::pep::gateway_comunicaciones::ResultadoPepComunicacion::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r
                        .por_destinatario
                        .first()
                        .map(|d| d.id_externo.clone())
                        .unwrap_or_default(),
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef6),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::gateway_comunicaciones::ResultadoPepComunicacion::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn delegar_ef7<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        gateway_ef7: Option<&mut GatewayPublicacion>,
        adaptador_ef7: Option<&mut dyn AdaptadorPublicacion>,
        precondiciones_ef7: Option<&PrecondicionesPepEf7>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let Some(gw) = gateway_ef7 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(adap) = adaptador_ef7 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap7) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };
        let pre7 = precondiciones_ef7
            .copied()
            .unwrap_or_else(PrecondicionesPepEf7::todas_ok);

        let sol7 = match traducir_publicacion_desde_herramienta(
            &solicitud.id_herramienta,
            &solicitud.servidor,
            &solicitud.operacion,
            &solicitud.destino,
            solicitud.digest_argumentos,
            solicitud.hash_paquete,
            solicitud.datos_personales,
            solicitud.reversible,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let hechos = sol7.hechos_exigidos.clone();
        let digest_sub = crate::pep::solicitud_publicacion::digest_solicitud_publicacion(&sol7);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef7,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef7, digest_sub),
        );

        match gw.ejercer(
            &SolicitudPublicacionCruda::Tipada(sol7),
            Some(cap7),
            sistema,
            sujeto,
            &pre7,
            &hechos,
            ledger,
            adap,
            reloj,
            epoca_actual,
            Some(ticks),
            forzar_silencio,
        ) {
            crate::pep::gateway_publicacion::ResultadoPepPublicacion::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r.id_externo,
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef7),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::gateway_publicacion::ResultadoPepPublicacion::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn delegar_ef10<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        gateway_ef10: Option<&mut GatewayEgresoDatos>,
        adaptador_ef10: Option<&mut dyn AdaptadorEgreso>,
        precondiciones_ef10: Option<&PrecondicionesPepEf10>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let Some(gw) = gateway_ef10 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(adap) = adaptador_ef10 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap10) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };
        let pre10 = precondiciones_ef10
            .copied()
            .unwrap_or_else(PrecondicionesPepEf10::todas_ok);

        let sol10 = match traducir_egreso_desde_herramienta(
            &solicitud.id_herramienta,
            &solicitud.servidor,
            &solicitud.operacion,
            &solicitud.destino,
            solicitud.digest_argumentos,
            solicitud.hash_paquete,
            solicitud.datos_personales,
            solicitud.reversible,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let hechos = sol10.hechos_exigidos.clone();
        let digest_sub = crate::pep::solicitud_egreso::digest_solicitud_egreso(&sol10);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef10,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef10, digest_sub),
        );
        // Referencia cruzada EF-4 → EF-10 en ledger de egreso.
        let mut xref = Vec::new();
        xref.push(2); // XREF
        xref.extend_from_slice(&digest_sol);
        xref.extend_from_slice(&digest_sub);
        let _ = ledger.registrar_evento_sistema(sujeto, TipoRegistro::EgresoDatos, xref);

        match gw.ejercer(
            &SolicitudEgresoCruda::Tipada(sol10),
            Some(cap10),
            sistema,
            sujeto,
            &pre10,
            &hechos,
            ledger,
            adap,
            reloj,
            epoca_actual,
            Some(ticks),
            forzar_silencio,
        ) {
            crate::pep::gateway_egreso::ResultadoPepEgreso::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r.id_externo,
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef10),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::gateway_egreso::ResultadoPepEgreso::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn delegar_ef11<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        capacidad_subyacente: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        gateway_ef11: Option<&mut GatewayEfectoFisico>,
        modulo_ef11: Option<&mut ModuloFisicoInterpuesto>,
        precondiciones_ef11: Option<&PrecondicionesPepEf11>,
        aprobacion_ef11: Option<&AprobacionHumanaFisica>,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
        forzar_silencio: bool,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        // El broker nunca emite credenciales de controlador ni capacidades de bus.
        let Some(gw) = gateway_ef11 else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::PepSubyacenteInexistente,
            );
        };
        let Some(cap11) = capacidad_subyacente else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadSubyacenteAusente,
            );
        };
        let pre11 = precondiciones_ef11
            .copied()
            .unwrap_or_else(PrecondicionesPepEf11::todas_ok);

        let sol11 = match traducir_fisico_desde_herramienta(
            &solicitud.id_herramienta,
            &solicitud.servidor,
            &solicitud.operacion,
            &solicitud.destino,
            solicitud.digest_argumentos,
            solicitud.hash_paquete,
            solicitud.datos_personales,
            solicitud.reversible,
        ) {
            Ok(s) => s,
            Err(e) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    Some(digest_sol),
                    CodigoPep::Evidencia(e.into()),
                );
            }
        };
        let hechos = sol11.hechos_exigidos.clone();
        let digest_sub = crate::pep::solicitud_fisico::digest_solicitud_fisica(&sol11);
        self.delegaciones.push(RegistroDelegacion {
            ticks,
            desde_ef4: digest_sol,
            hacia: ClaseEfecto::Ef11,
            digest_solicitud_subyacente: digest_sub,
        });
        let _ = ledger.registrar_evento_sistema(
            sujeto,
            TipoRegistro::Herramienta,
            serializar_delegacion(digest_sol, ClaseEfecto::Ef11, digest_sub),
        );
        let mut xref = Vec::new();
        xref.push(2); // XREF
        xref.extend_from_slice(&digest_sol);
        xref.extend_from_slice(&digest_sub);
        let _ = ledger.registrar_evento_sistema(sujeto, TipoRegistro::EfectoFisico, xref);

        match gw.ejercer(
            &SolicitudFisicaCruda::Tipada(sol11),
            Some(cap11),
            sistema,
            sujeto,
            &pre11,
            &hechos,
            aprobacion_ef11,
            ledger,
            modulo_ef11,
            reloj,
            epoca_actual,
            Some(ticks),
            forzar_silencio,
        ) {
            crate::pep::gateway_fisico::ResultadoPepFisico::Permitido(r) => {
                self.intentos.push(RegistroIntentoPep {
                    ticks,
                    sistema: Some(sistema.clone()),
                    resultado: ResultadoIntento::Permitido,
                    digest_solicitud: Some(digest_sol),
                });
                ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
                    digest_resultado: r.digest_resultado,
                    referencia_minima: r.id_externo,
                    recibo: r.recibo,
                    id_herramienta: solicitud.id_herramienta.clone(),
                    version: solicitud.version.clone(),
                    servidor: solicitud.servidor.clone(),
                    destino_efectivo: solicitud.destino.clone(),
                    delegado_a: Some(ClaseEfecto::Ef11),
                    antiguedad_vista_ms: antiguedad,
                })
            }
            crate::pep::gateway_fisico::ResultadoPepFisico::Denegado { codigo } => {
                self.denegar(ticks, Some(sistema.clone()), Some(digest_sol), codigo)
            }
        }
    }

    fn cerrar_con_recibo<A: AlmacenEvidencia>(
        &mut self,
        solicitud: &SolicitudHerramienta,
        digest_sol: [u8; LONGITUD_HASH_PAQUETE],
        cap: &Capability,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        digest_resultado: &[u8; LONGITUD_HASH_PAQUETE],
        referencia: &str,
        id_herramienta: &str,
        version: &str,
        servidor: &str,
        destino: &str,
        delegado_a: Option<ClaseEfecto>,
        antiguedad: Ticks,
        ticks: Ticks,
    ) -> ResultadoPepHerramienta {
        let condiciones = CondicionesHerramienta::desde_solicitud(solicitud);
        let digest_cond = digest_condiciones_herramienta(&condiciones);
        let recibo = ReciboEfecto {
            digest_parametros: digest_sol,
            digest_resultado: *digest_resultado,
            digest_decision: *cap.compromiso_evidencia().digest(),
            digest_condiciones: digest_cond,
        };

        if let Err(e) = ledger.registrar_recibo(sujeto, &recibo) {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::EvidenciaIncompleta,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: *digest_resultado,
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
            TipoRegistro::Herramienta,
            serializar_invocacion(digest_sol, id_herramienta, version, servidor, destino),
        );

        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema: Some(sistema.clone()),
            resultado: ResultadoIntento::Permitido,
            digest_solicitud: Some(digest_sol),
        });

        ResultadoPepHerramienta::Permitido(RespuestaHerramienta {
            digest_resultado: *digest_resultado,
            referencia_minima: referencia.to_string(),
            recibo,
            id_herramienta: id_herramienta.to_string(),
            version: version.to_string(),
            servidor: servidor.to_string(),
            destino_efectivo: destino.to_string(),
            delegado_a,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPepHerramienta {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPepHerramienta::Denegado { codigo }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPepHerramienta {
    Permitido(RespuestaHerramienta),
    Denegado { codigo: CodigoPep },
}

fn comprobar_precondiciones(p: &PrecondicionesPepEf4) -> Result<(), CodigoPep> {
    if !p.identidad_vigente {
        return Err(CodigoPep::IdentidadNoVigente);
    }
    if !p.pasaporte_vigente {
        return Err(CodigoPep::PasaporteNoVigente);
    }
    if !p.libro_suficiente {
        return Err(CodigoPep::ControlInsuficiente);
    }
    if !p.monitor_permisivo {
        return Err(CodigoPep::MonitorNoPermisivo);
    }
    Ok(())
}

fn validar_contra_alcance(
    cap: &Capability,
    sol: &SolicitudHerramienta,
) -> Result<(), CodigoPep> {
    let auth = AlcanceAutorizadoHerramienta::desde_alcance(cap.alcance())
        .map_err(|e| CodigoPep::Evidencia(e.into()))?;
    if auth.id_herramienta != sol.id_herramienta {
        return Err(CodigoPep::HerramientaNoRegistrada);
    }
    if auth.version != sol.version {
        return Err(CodigoPep::VersionHerramientaNoAutorizada);
    }
    if auth.servidor != sol.servidor {
        return Err(CodigoPep::ServidorNoRegistrado);
    }
    if auth.operacion != sol.operacion {
        return Err(CodigoPep::OperacionNoAutorizada);
    }
    if auth.digest_esquema_args != sol.digest_esquema_args
        || auth.digest_argumentos != sol.digest_argumentos
    {
        return Err(CodigoPep::ArgumentosNoAutorizados);
    }
    if auth.destino != sol.destino {
        return Err(CodigoPep::DestinoNoAutorizado);
    }
    if auth.efecto_subyacente != sol.efecto_subyacente.token() {
        return Err(CodigoPep::OperacionNoAutorizada);
    }
    if auth.hash_paquete != sol.hash_paquete {
        return Err(CodigoPep::PaqueteNoAutorizado);
    }
    if !cap.alcance().cubre(&alcance_ef4(sol)) {
        return Err(CodigoPep::ArgumentosNoAutorizados);
    }
    Ok(())
}

fn serializar_delegacion(
    dig_ef4: [u8; LONGITUD_HASH_PAQUETE],
    hacia: ClaseEfecto,
    dig_sub: [u8; LONGITUD_HASH_PAQUETE],
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(2); // DELEGACION
    v.extend_from_slice(&dig_ef4);
    v.push(hacia as u8);
    v.extend_from_slice(&dig_sub);
    v
}

fn serializar_invocacion(
    dig: [u8; LONGITUD_HASH_PAQUETE],
    id: &str,
    ver: &str,
    srv: &str,
    dest: &str,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(1); // INVOCACION
    v.extend_from_slice(&dig);
    for s in [id, ver, srv, dest] {
        let b = s.as_bytes();
        v.extend_from_slice(&(b.len() as u16).to_le_bytes());
        v.extend_from_slice(b);
    }
    v
}

pub fn preparar_solicitud_herramienta(
    s: SolicitudHerramienta,
) -> (SolicitudHerramienta, [u8; LONGITUD_HASH_PAQUETE]) {
    let d = digest_solicitud_herramienta(&s);
    (s, d)
}
