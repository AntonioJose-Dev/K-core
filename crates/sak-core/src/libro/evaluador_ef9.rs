//! Régimen transversal EF-9: ejecución de código (rebanada repo EF-9; C / INV-11).
//!
//! EF-9 **no se media**: se prohíbe o se confina. Este módulo no autoriza
//! scripts, shells, nodos de código, despliegues ni cambios de infraestructura.
//!
//! C5 efectivo y atestación de plataforma real **no están implementados**
//! (cierre de atestación → §M 12).

use crate::contexto::ClaseEfecto;
use crate::crypto::ParMlDsa87;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{AlmacenEvidencia, IdSujeto, LedgerEvidencia, TipoRegistro};
use crate::identidad::IdSistema;
use crate::libro::hecho::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use crate::libro::libro_ctrl::LibroControl;
use crate::libro::minimo::minimo_exigido;
use crate::libro::nivel::NivelControl;
use crate::pep::CodigoPep;
use crate::reloj::Ticks;
use std::collections::BTreeSet;
use std::fmt;

/// Perfiles mutuamente excluyentes por sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerfilEf9 {
    /// Sin intérprete, shell, nodo, compilador, cargador dinámico, macros,
    /// despliegue ni autoridad ambiental para el sujeto.
    CodigoProhibido,
    /// Única ruta: runtime de perfil mínimo. **No** afirma C5 ni confinamiento efectivo.
    ConfinadoPendienteAtestacion,
}

impl PerfilEf9 {
    pub fn token(self) -> &'static str {
        match self {
            PerfilEf9::CodigoProhibido => "codigo_prohibido",
            PerfilEf9::ConfinadoPendienteAtestacion => "confinado_pendiente_atestacion",
        }
    }

    /// Siempre falso: C5 no está implementado (pendiente criterio §M 12).
    pub const fn afirma_c5(self) -> bool {
        false
    }

    /// Siempre falso hasta atestación real de plataforma.
    pub const fn afirma_confinamiento_efectivo(self) -> bool {
        false
    }
}

/// Señales que, salvo demostración contraria en entorno instrumentado, abren EF-9.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SenalEf9 {
    NodoCodigoAutomatizacion,
    InterpreteDisponible,
    ShellOComandoRemoto,
    EjecucionScript,
    PluginOMacroCargable,
    ContenedorPrivilegiadoOMontaje,
    DespliegueOModificacionInfra,
    CredencialAccesibleDesdeProceso,
    RedSalidaNoForzada,
    AccesoDirectoEfector(ClaseEfecto),
    CargaDinamica,
}

impl SenalEf9 {
    pub fn token(self) -> String {
        match self {
            SenalEf9::NodoCodigoAutomatizacion => "nodo_codigo".into(),
            SenalEf9::InterpreteDisponible => "interprete".into(),
            SenalEf9::ShellOComandoRemoto => "shell_remoto".into(),
            SenalEf9::EjecucionScript => "script".into(),
            SenalEf9::PluginOMacroCargable => "plugin_macro".into(),
            SenalEf9::ContenedorPrivilegiadoOMontaje => "contenedor_privilegiado".into(),
            SenalEf9::DespliegueOModificacionInfra => "despliegue_infra".into(),
            SenalEf9::CredencialAccesibleDesdeProceso => "credencial_accesible".into(),
            SenalEf9::RedSalidaNoForzada => "red_salida".into(),
            SenalEf9::AccesoDirectoEfector(c) => format!("efector_directo:{}", c.token()),
            SenalEf9::CargaDinamica => "carga_dinamica".into(),
        }
    }
}

/// Observación tipada del entorno instrumentado (no del host real completo).
#[derive(Debug, Clone, Default)]
pub struct ObservacionEntornoEf9 {
    pub senales: BTreeSet<SenalEf9>,
    /// Demostración instrumentada de que no hay vía de ejecución (solo CodigoProhibido).
    pub demostracion_codigo_ausente: bool,
    /// Runtime mínimo declarado (sin red/FS/syscalls/reloj/entropía/carga/credenciales).
    pub runtime_minimo_declarado: bool,
    /// Salida solo por funciones mediadas (declarado; no atestado).
    pub salida_solo_mediada: bool,
}

impl ObservacionEntornoEf9 {
    /// EF-9 abierto salvo demostración contraria en el entorno instrumentado.
    pub fn ef9_abierto(&self) -> bool {
        if self.demostracion_codigo_ausente && self.senales.is_empty() {
            return false;
        }
        !self.senales.is_empty() || !self.demostracion_codigo_ausente
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoEvaluacionEf9 {
    /// Perfil CodigoProhibido: intento denegado y registrado.
    DenegadoProhibido { codigo: CodigoPep },
    /// Perfil confinado pendiente: no hay mediación de ejecución; C5 no afirmado.
    DenegadoNoConfinado { codigo: CodigoPep },
    /// Estado registrado sin solicitud de ejecución (sincronización Libro).
    EstadoSincronizado {
        ef9_abierto: bool,
        perfil: PerfilEf9,
    },
}

impl fmt::Display for ResultadoEvaluacionEf9 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResultadoEvaluacionEf9::DenegadoProhibido { codigo } => {
                write!(f, "DENY({})", codigo.token())
            }
            ResultadoEvaluacionEf9::DenegadoNoConfinado { codigo } => {
                write!(f, "DENY({})", codigo.token())
            }
            ResultadoEvaluacionEf9::EstadoSincronizado {
                ef9_abierto,
                perfil,
            } => write!(
                f,
                "estado ef9_abierto={} perfil={}",
                ef9_abierto,
                perfil.token()
            ),
        }
    }
}

/// Evaluador transversal EF-9. No emite capacidades. No es un PEP de autorización.
pub struct EvaluadorEf9 {
    perfiles: std::collections::HashMap<String, PerfilEf9>,
    denegaciones: Vec<(IdSistema, CodigoPep, Ticks)>,
}

impl Default for EvaluadorEf9 {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl EvaluadorEf9 {
    pub fn nuevo() -> Self {
        EvaluadorEf9 {
            perfiles: std::collections::HashMap::new(),
            denegaciones: Vec::new(),
        }
    }

    pub const fn puede_emitir_capacidad() -> bool {
        false
    }

    pub const fn c5_implementado() -> bool {
        false
    }

    pub fn perfil_de(&self, sistema: &IdSistema) -> Option<PerfilEf9> {
        self.perfiles.get(sistema.como_str()).copied()
    }

    pub fn denegaciones(&self) -> &[(IdSistema, CodigoPep, Ticks)] {
        &self.denegaciones
    }

    /// Asigna un perfil. Sustituye el anterior (mutuamente excluyentes).
    pub fn asignar_perfil(&mut self, sistema: &IdSistema, perfil: PerfilEf9) {
        self.perfiles
            .insert(sistema.como_str().to_string(), perfil);
    }

    /// Detecta apertura a partir de la observación instrumentada.
    pub fn detectar_apertura(obs: &ObservacionEntornoEf9) -> bool {
        obs.ef9_abierto()
    }

    /// Sincroniza hechos EF9_ABIERTO / inventario en el Libro y opcionalmente el ledger.
    pub fn sincronizar_libro<A: AlmacenEvidencia>(
        &mut self,
        sistema: &IdSistema,
        perfil: PerfilEf9,
        obs: &ObservacionEntornoEf9,
        inventario: Option<&InventarioAlcanzables>,
        libro: &mut LibroControl,
        firmante: &ParMlDsa87,
        epoca: u64,
        ahora: Ticks,
        sujeto: Option<&IdSujeto>,
        ledger: Option<&mut LedgerEvidencia<A>>,
    ) -> Result<ResultadoEvaluacionEf9, crate::crypto::ErrorCrypto> {
        self.asignar_perfil(sistema, perfil);

        let abierto = match perfil {
            PerfilEf9::CodigoProhibido => {
                // Solo cerrado si la observación demuestra ausencia de código.
                !(obs.demostracion_codigo_ausente && obs.senales.is_empty())
            }
            PerfilEf9::ConfinadoPendienteAtestacion => {
                // Runtime mínimo declarado no basta: sin atestación, no se cierra EF-9
                // como confinamiento efectivo; se mantiene abierto salvo demostración.
                let _ = (obs.runtime_minimo_declarado, obs.salida_solo_mediada);
                // No registrar CONFINADO=true: C5 / confinamiento efectivo no implementados.
                true
            }
        };

        let hecho = HechoFirmadoLibro::firmar(
            TipoHecho::Ef9Abierto,
            sistema.clone(),
            None,
            abierto,
            1,
            epoca,
            ahora,
            InventarioAlcanzables::NO_DEMUESTRA,
            firmante,
        )?;
        libro.registrar_hecho(hecho);

        if let Some(inv) = inventario {
            libro.registrar_alcanzables(inv.clone());
        }

        // Persistir evaluación por clases relevantes para reconstrucción histórica.
        for clase in [
            ClaseEfecto::Ef1,
            ClaseEfecto::Ef2,
            ClaseEfecto::Ef3,
            ClaseEfecto::Ef4,
            ClaseEfecto::Ef5,
            ClaseEfecto::Ef6,
            ClaseEfecto::Ef7,
            ClaseEfecto::Ef8,
            ClaseEfecto::Ef9,
        ] {
            let eval = libro.evaluar(sistema, clase, ahora);
            libro.registrar_evaluacion_historica(
                sistema,
                clase,
                eval.nivel_vigente,
                eval.causa_degradacion
                    .clone()
                    .unwrap_or_else(|| format!("nivel_base={:?}", eval.nivel_base)),
                epoca,
            );
        }

        if let (Some(sujeto), Some(ledger)) = (sujeto, ledger) {
            let payload = serializar_estado_ef9(sistema, perfil, abierto, inventario, ahora);
            let _ = ledger.registrar_evento_sistema(sujeto, TipoRegistro::Ef9, payload);
        }

        Ok(ResultadoEvaluacionEf9::EstadoSincronizado {
            ef9_abierto: abierto,
            perfil,
        })
    }

    /// Toda solicitud de ejecución EF-9 se deniega con evidencia encadenada.
    pub fn evaluar_solicitud_ejecucion<A: AlmacenEvidencia>(
        &mut self,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        ahora: Ticks,
    ) -> ResultadoEvaluacionEf9 {
        let perfil = self
            .perfiles
            .get(sistema.como_str())
            .copied()
            .unwrap_or(PerfilEf9::CodigoProhibido);

        let (codigo, tag) = match perfil {
            PerfilEf9::CodigoProhibido => (CodigoPep::Ef9Prohibido, 2u8),
            PerfilEf9::ConfinadoPendienteAtestacion => (CodigoPep::Ef9NoConfinado, 3u8),
        };

        self.denegaciones
            .push((sistema.clone(), codigo.clone(), ahora));

        let mut payload = Vec::new();
        payload.push(tag); // DENEGACION
        payload.extend_from_slice(sistema.como_str().as_bytes());
        payload.push(0);
        payload.extend_from_slice(codigo.token().as_bytes());
        payload.push(0);
        payload.extend_from_slice(&ahora.to_le_bytes());
        payload.extend_from_slice(perfil.token().as_bytes());
        let _ = ledger.registrar_evento_sistema(sujeto, TipoRegistro::Ef9, payload);

        match perfil {
            PerfilEf9::CodigoProhibido => ResultadoEvaluacionEf9::DenegadoProhibido { codigo },
            PerfilEf9::ConfinadoPendienteAtestacion => {
                ResultadoEvaluacionEf9::DenegadoNoConfinado { codigo }
            }
        }
    }
}

fn serializar_estado_ef9(
    sistema: &IdSistema,
    perfil: PerfilEf9,
    abierto: bool,
    inventario: Option<&InventarioAlcanzables>,
    ahora: Ticks,
) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0); // ESTADO
    v.extend_from_slice(sistema.como_str().as_bytes());
    v.push(0);
    v.extend_from_slice(perfil.token().as_bytes());
    v.push(0);
    v.push(u8::from(abierto));
    v.push(u8::from(PerfilEf9::afirma_c5(perfil)));
    v.extend_from_slice(&ahora.to_le_bytes());
    if let Some(inv) = inventario {
        v.extend_from_slice(&inv.digest);
    } else {
        v.extend_from_slice(&[0u8; LONGITUD_HASH_PAQUETE]);
    }
    v
}

/// ¿El Libro alcanza el mínimo de la clase tras degradación EF-9?
pub fn control_alcanza_minimo(
    libro: &LibroControl,
    sistema: &IdSistema,
    clase: ClaseEfecto,
    datos_personales: bool,
    ahora: Ticks,
) -> bool {
    let eval = libro.evaluar(sistema, clase, ahora);
    eval.nivel_vigente >= minimo_exigido(clase, datos_personales)
}

/// ¿Nivel vigente ≥ C3 tras degradación EF-9?
pub fn libro_suficiente_c3(
    libro: &LibroControl,
    sistema: &IdSistema,
    clase: ClaseEfecto,
    ahora: Ticks,
) -> bool {
    libro.evaluar(sistema, clase, ahora).nivel_vigente >= NivelControl::C3
}

/// ¿Nivel vigente ≥ C4 tras degradación EF-9?
pub fn libro_suficiente_c4(
    libro: &LibroControl,
    sistema: &IdSistema,
    clase: ClaseEfecto,
    ahora: Ticks,
) -> bool {
    libro.evaluar(sistema, clase, ahora).nivel_vigente >= NivelControl::C4
}
