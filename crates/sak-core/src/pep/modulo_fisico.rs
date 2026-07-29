//! Módulo físico interpuesto (simulado): único camino instrumentado al bus/actuador.
//!
//! Los tests prueban el módulo y las rutas instrumentadas; no prueban ausencia de
//! mando manual, bypass eléctrico o ruta física desconocida.

use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::pep::proveedor::ErrorEgreso;
use crate::pep::solicitud_fisico::{OperacionFisica, SolicitudEfectoFisico};
use crate::reloj::Ticks;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorModuloFisico {
    NoAutorizado,
    EnvolventeLocal,
    Interlock,
    ActuadorBloqueado,
    SinLatido,
    Replay,
    BusNoDeclarado,
    EstadoIncompatible,
    TimeoutTelemetria,
    EstadoIncierto,
    ParadaNoConfirmable,
    DivergenciaOrden,
    FalloInterno,
}

impl fmt::Display for ErrorModuloFisico {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorModuloFisico::NoAutorizado => write!(f, "modulo fisico no autorizado"),
            ErrorModuloFisico::EnvolventeLocal => write!(f, "envolvente de seguridad local"),
            ErrorModuloFisico::Interlock => write!(f, "interlock activo"),
            ErrorModuloFisico::ActuadorBloqueado => write!(f, "actuador bloqueado tras incidente"),
            ErrorModuloFisico::SinLatido => write!(f, "sin latido del modulo"),
            ErrorModuloFisico::Replay => write!(f, "orden replay"),
            ErrorModuloFisico::BusNoDeclarado => write!(f, "bus no declarado"),
            ErrorModuloFisico::EstadoIncompatible => write!(f, "estado observado incompatible"),
            ErrorModuloFisico::TimeoutTelemetria => write!(f, "timeout telemetria"),
            ErrorModuloFisico::EstadoIncierto => write!(f, "estado observado incierto"),
            ErrorModuloFisico::ParadaNoConfirmable => write!(f, "parada segura no confirmable"),
            ErrorModuloFisico::DivergenciaOrden => write!(f, "divergencia de orden"),
            ErrorModuloFisico::FalloInterno => write!(f, "fallo interno del modulo"),
        }
    }
}

impl std::error::Error for ErrorModuloFisico {}

/// Autoridad de bus/controlador en custodia. Nunca se expone al sujeto.
pub struct AutoridadBus {
    material: [u8; 32],
    id_bus: String,
}

impl AutoridadBus {
    pub fn desde_semilla(id_bus: impl Into<String>, semilla: [u8; 32]) -> Self {
        AutoridadBus {
            material: semilla,
            id_bus: id_bus.into(),
        }
    }

    pub fn id_bus(&self) -> &str {
        &self.id_bus
    }

    pub(crate) fn firmar_orden(&self, canon: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::hmac_sha384(&self.material, canon)
    }
}

impl fmt::Debug for AutoridadBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AutoridadBus(REDACTED)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FaseEjecucionFisica {
    AceptadaModulo = 1,
    TransmitidaControlador = 2,
    ConfirmadaControlador = 3,
    EstadoObservado = 4,
    Parcial = 5,
    Indeterminada = 6,
}

impl FaseEjecucionFisica {
    pub fn token(self) -> &'static str {
        match self {
            FaseEjecucionFisica::AceptadaModulo => "aceptada_modulo",
            FaseEjecucionFisica::TransmitidaControlador => "transmitida_controlador",
            FaseEjecucionFisica::ConfirmadaControlador => "confirmada_controlador",
            FaseEjecucionFisica::EstadoObservado => "estado_observado",
            FaseEjecucionFisica::Parcial => "parcial",
            FaseEjecucionFisica::Indeterminada => "indeterminada",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoFisico {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub digest_solicitud_ejecutada: [u8; LONGITUD_HASH_PAQUETE],
    pub fase: FaseEjecucionFisica,
    pub estado_observado: String,
    pub id_externo: String,
    pub parada_ejecutada: bool,
}

#[derive(Debug, Clone, Default)]
pub struct InterlocksLocales {
    pub paro_emergencia: bool,
    pub puerta_zona_abierta: bool,
    pub limite_energia_excedido: bool,
    pub presencia_humana_no_segura: bool,
    pub modo_incompatible: bool,
    pub perdida_comunicacion: bool,
    pub deriva_estado: bool,
}

/// Módulo interpuesto: único camino instrumentado. Sin exposición de autoridad.
pub struct ModuloFisicoInterpuesto {
    autoridad: AutoridadBus,
    pub ordenes_delegadas: u32,
    pub intentos_directos: u32,
    ultimo_latido: Ticks,
    latido_max_ms: Ticks,
    estados: BTreeMap<String, String>,
    buses_declarados: BTreeSet<String>,
    actuadores_bloqueados: BTreeSet<String>,
    digests_usados: BTreeSet<[u8; LONGITUD_HASH_PAQUETE]>,
    pub interlocks: InterlocksLocales,
    pub forzar_timeout: bool,
    pub forzar_estado_incierto: bool,
    pub forzar_divergencia: bool,
    pub forzar_sin_latido: bool,
}

impl ModuloFisicoInterpuesto {
    pub fn nuevo(autoridad: AutoridadBus, ahora: Ticks) -> Self {
        let mut buses = BTreeSet::new();
        buses.insert(autoridad.id_bus().to_string());
        let mut estados = BTreeMap::new();
        estados.insert("default".into(), "reposo".into());
        ModuloFisicoInterpuesto {
            autoridad,
            ordenes_delegadas: 0,
            intentos_directos: 0,
            ultimo_latido: ahora,
            latido_max_ms: 5_000,
            estados,
            buses_declarados: buses,
            actuadores_bloqueados: BTreeSet::new(),
            digests_usados: BTreeSet::new(),
            interlocks: InterlocksLocales::default(),
            forzar_timeout: false,
            forzar_estado_incierto: false,
            forzar_divergencia: false,
            forzar_sin_latido: false,
        }
    }

    pub fn declarar_bus(&mut self, bus: impl Into<String>) {
        self.buses_declarados.insert(bus.into());
    }

    pub fn set_estado(&mut self, actuador: impl Into<String>, estado: impl Into<String>) {
        self.estados.insert(actuador.into(), estado.into());
    }

    pub fn latido(&mut self, ahora: Ticks) {
        self.ultimo_latido = ahora;
    }

    pub fn latido_vigente(&self, ahora: Ticks) -> bool {
        !self.forzar_sin_latido
            && ahora.saturating_sub(self.ultimo_latido) <= self.latido_max_ms
    }

    pub fn autoridad_expuesta(&self) -> bool {
        false
    }

    pub fn llamar_directo(
        &mut self,
        _solicitud: &SolicitudEfectoFisico,
    ) -> Result<ResultadoFisico, ErrorEgreso> {
        self.intentos_directos += 1;
        let _ = &self.autoridad;
        Err(ErrorEgreso::BloqueadoSinPep)
    }

    pub fn ejecutar_parada_segura(
        &mut self,
        actuador: &str,
        procedimiento: &str,
    ) -> Result<(), ErrorModuloFisico> {
        if procedimiento.trim().is_empty() {
            return Err(ErrorModuloFisico::ParadaNoConfirmable);
        }
        if self.interlocks.perdida_comunicacion {
            return Err(ErrorModuloFisico::ParadaNoConfirmable);
        }
        self.estados.insert(actuador.to_string(), "parado_seguro".into());
        Ok(())
    }

    pub fn bloquear_actuador(&mut self, actuador: &str) {
        self.actuadores_bloqueados.insert(actuador.to_string());
    }

    /// Ejecuta orden con autorización efímera de alcance exacto + envolvente local.
    pub fn ejecutar_delegado(
        &mut self,
        solicitud: &SolicitudEfectoFisico,
        digest_autorizado: &[u8; LONGITUD_HASH_PAQUETE],
        ahora: Ticks,
    ) -> Result<ResultadoFisico, ErrorModuloFisico> {
        let digest = crate::pep::solicitud_fisico::digest_solicitud_fisica(solicitud);
        if digest != *digest_autorizado {
            return Err(ErrorModuloFisico::DivergenciaOrden);
        }
        if !self.latido_vigente(ahora) {
            return Err(ErrorModuloFisico::SinLatido);
        }
        if self.actuadores_bloqueados.contains(&solicitud.id_actuador) {
            return Err(ErrorModuloFisico::ActuadorBloqueado);
        }
        if self.digests_usados.contains(&digest) {
            return Err(ErrorModuloFisico::Replay);
        }
        if !self.buses_declarados.contains(&solicitud.id_bus)
            && self.autoridad.id_bus() != solicitud.id_bus
        {
            return Err(ErrorModuloFisico::BusNoDeclarado);
        }

        // Envolvente estática local (puede denegar aunque el Kernel autorice).
        if !solicitud.limites.contiene(&solicitud.parametros) {
            return Err(ErrorModuloFisico::EnvolventeLocal);
        }
        if ahora < solicitud.ventana_desde || ahora > solicitud.ventana_hasta {
            return Err(ErrorModuloFisico::EnvolventeLocal);
        }

        if self.interlocks.paro_emergencia
            || self.interlocks.puerta_zona_abierta
            || self.interlocks.limite_energia_excedido
            || self.interlocks.presencia_humana_no_segura
            || self.interlocks.modo_incompatible
            || self.interlocks.perdida_comunicacion
            || self.interlocks.deriva_estado
        {
            return Err(ErrorModuloFisico::Interlock);
        }

        let estado_actual = self
            .estados
            .get(&solicitud.id_actuador)
            .cloned()
            .unwrap_or_else(|| "reposo".into());
        if estado_actual != solicitud.estado_inicial && solicitud.operacion != OperacionFisica::ParadaSegura
        {
            return Err(ErrorModuloFisico::EstadoIncompatible);
        }

        if self.forzar_timeout {
            return Err(ErrorModuloFisico::TimeoutTelemetria);
        }
        if self.forzar_estado_incierto {
            return Err(ErrorModuloFisico::EstadoIncierto);
        }

        let sello = self.autoridad.firmar_orden(&solicitud.canonico());
        self.ordenes_delegadas += 1;
        self.digests_usados.insert(digest);

        let mut payload = Vec::new();
        payload.extend_from_slice(&sello);
        payload.extend_from_slice(&digest);
        let digest_resultado = crypto::sha384_dominio(b"SAK-PHYS-OUT-v1|", &payload);

        let (fase, estado_obs, dig_sol) = if self.forzar_divergencia {
            (
                FaseEjecucionFisica::Parcial,
                "incierto".to_string(),
                {
                    let mut d = digest;
                    d[0] ^= 0xff;
                    d
                },
            )
        } else {
            self.estados
                .insert(solicitud.id_actuador.clone(), solicitud.estado_objetivo.clone());
            (
                FaseEjecucionFisica::EstadoObservado,
                solicitud.estado_objetivo.clone(),
                digest,
            )
        };

        Ok(ResultadoFisico {
            digest_resultado,
            digest_solicitud_ejecutada: dig_sol,
            fase,
            estado_observado: estado_obs,
            id_externo: format!("ef11-{}", encode(&sello[..4])),
            parada_ejecutada: false,
        })
    }
}

fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
