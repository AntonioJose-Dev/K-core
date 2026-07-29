//! Estado del Libro de Control firmado por par (sistema, clase).

use crate::contexto::ClaseEfecto;
use crate::identidad::IdSistema;
use crate::libro::calculo::{
    aplicar_degradacion_ef9, bypass_residual_de, calcular_nivel_base, vista_desde_hechos,
    EvaluacionNivel,
};
use crate::libro::hecho::{HechoFirmadoLibro, InventarioAlcanzables, TipoHecho};
use crate::libro::nivel::NivelControl;
use crate::reloj::Ticks;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParSistemaClase {
    pub sistema: IdSistema,
    pub clase: ClaseEfecto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorLibro {
    ElevacionProhibida,
    RebajaNoInferior,
    ClaseSuspendida,
}

impl fmt::Display for ErrorLibro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorLibro::ElevacionProhibida => {
                write!(f, "no existe interfaz que eleve el nivel del Libro")
            }
            ErrorLibro::RebajaNoInferior => {
                write!(f, "la rebaja manual debe ser estrictamente inferior al calculado")
            }
            ErrorLibro::ClaseSuspendida => write!(f, "clase suspendida por incidente de bypass"),
        }
    }
}

impl std::error::Error for ErrorLibro {}

/// Libro de Control. Sin API de elevación (INV-10).
pub struct LibroControl {
    hechos: Vec<HechoFirmadoLibro>,
    alcanzables: HashMap<String, InventarioAlcanzables>,
    /// Techos manuales del operador (solo rebaja).
    techos: HashMap<ParSistemaClase, NivelControl>,
    /// Clases suspendidas (trampa / sonda fallida).
    suspendidas: BTreeSet<ParSistemaClase>,
    /// Forzado a C0 (credencial trampa usada).
    forzar_c0: BTreeSet<ParSistemaClase>,
    historial: Vec<(ParSistemaClase, NivelControl, String, u64)>,
}

impl Default for LibroControl {
    fn default() -> Self {
        Self::nuevo()
    }
}

impl LibroControl {
    pub fn nuevo() -> Self {
        LibroControl {
            hechos: Vec::new(),
            alcanzables: HashMap::new(),
            techos: HashMap::new(),
            suspendidas: BTreeSet::new(),
            forzar_c0: BTreeSet::new(),
            historial: Vec::new(),
        }
    }

    pub fn registrar_hecho(&mut self, hecho: HechoFirmadoLibro) {
        self.hechos.push(hecho);
    }

    pub fn registrar_alcanzables(&mut self, inv: InventarioAlcanzables) {
        self.alcanzables
            .insert(inv.sistema.como_str().to_string(), inv);
    }

    /// Persiste el hecho causante / nivel vigente para reconstrucción histórica.
    pub fn registrar_evaluacion_historica(
        &mut self,
        sistema: &IdSistema,
        clase: ClaseEfecto,
        nivel: NivelControl,
        causa: impl Into<String>,
        epoca: u64,
    ) {
        self.historial.push((
            ParSistemaClase {
                sistema: sistema.clone(),
                clase,
            },
            nivel,
            causa.into(),
            epoca,
        ));
    }

    pub fn inventario(&self, sistema: &IdSistema) -> Option<&InventarioAlcanzables> {
        self.alcanzables.get(sistema.como_str())
    }

    /// Declara un efector alcanzable: degrada automáticamente esa clase (H-3).
    pub fn declarar_efector_alcanzable(
        &mut self,
        sistema: &IdSistema,
        clase: ClaseEfecto,
        ahora: Ticks,
        epoca: u64,
        firmante: &crate::crypto::ParMlDsa87,
    ) -> Result<(), crate::crypto::ErrorCrypto> {
        let key = sistema.como_str().to_string();
        let prev = self.alcanzables.get(&key);
        let mut set = prev.map(|i| i.efectores.clone()).unwrap_or_default();
        set.insert(clase);
        let version = prev.map(|i| i.version + 1).unwrap_or(1);
        let instancia = prev
            .map(|i| i.instancia.clone())
            .unwrap_or_else(|| "default".into());
        let rutas = prev.map(|i| i.rutas_red.clone()).unwrap_or_default();
        let creds = prev
            .map(|i| i.credenciales_detectadas.clone())
            .unwrap_or_default();
        let almacenes = prev.map(|i| i.almacenes.clone()).unwrap_or_default();
        let puntos = prev.map(|i| i.puntos_servicio.clone()).unwrap_or_default();
        let canales = prev.map(|i| i.canales_consumo.clone()).unwrap_or_default();
        let productor_id = prev
            .map(|i| i.productor_id.clone())
            .unwrap_or_else(|| "inventario-instrumentado".into());
        let inv = InventarioAlcanzables::firmar_completo(
            sistema.clone(),
            instancia,
            set,
            rutas,
            creds,
            almacenes,
            puntos,
            canales,
            false,
            version,
            epoca,
            ahora,
            productor_id,
            firmante,
        )?;
        self.alcanzables.insert(key, inv);
        self.historial.push((
            ParSistemaClase {
                sistema: sistema.clone(),
                clase,
            },
            NivelControl::C2,
            format!("declarado alcanzable ⇒ degradacion automatica de {}", clase.token()),
            epoca,
        ));
        Ok(())
    }

    /// Rebaja manual permitida. **No hay** método `elevar` (INV-10).
    pub fn rebajar(
        &mut self,
        sistema: &IdSistema,
        clase: ClaseEfecto,
        nuevo: NivelControl,
        ahora: Ticks,
        epoca: u64,
        causa: impl Into<String>,
    ) -> Result<(), ErrorLibro> {
        let eval = self.evaluar(sistema, clase, ahora);
        if nuevo > eval.nivel_vigente {
            return Err(ErrorLibro::ElevacionProhibida);
        }
        if nuevo >= eval.nivel_vigente {
            return Err(ErrorLibro::RebajaNoInferior);
        }
        let par = ParSistemaClase {
            sistema: sistema.clone(),
            clase,
        };
        self.techos.insert(par.clone(), nuevo);
        self.historial.push((par, nuevo, causa.into(), epoca));
        Ok(())
    }

    /// Credencial trampa usada ⇒ C0 + suspensión de clase (I.1).
    pub fn credencial_trampa_usada(&mut self, sistema: &IdSistema, clase: ClaseEfecto, epoca: u64) {
        let par = ParSistemaClase {
            sistema: sistema.clone(),
            clase,
        };
        self.forzar_c0.insert(par.clone());
        self.suspendidas.insert(par.clone());
        self.historial.push((
            par,
            NivelControl::C0,
            "credencial trampa usada ⇒ C0 y suspension de clase".into(),
            epoca,
        ));
    }

    pub fn clase_suspendida(&self, sistema: &IdSistema, clase: ClaseEfecto) -> bool {
        self.suspendidas.contains(&ParSistemaClase {
            sistema: sistema.clone(),
            clase,
        })
    }

    pub fn evaluar(
        &self,
        sistema: &IdSistema,
        clase: ClaseEfecto,
        ahora: Ticks,
    ) -> EvaluacionNivel {
        let par = ParSistemaClase {
            sistema: sistema.clone(),
            clase,
        };
        if self.forzar_c0.contains(&par) {
            return EvaluacionNivel {
                nivel_base: NivelControl::C0,
                nivel_vigente: NivelControl::C0,
                hechos_efectivos: vec![],
                hechos_caducados: vec![],
                bypass_residual: bypass_residual_de(NivelControl::C0),
                causa_degradacion: Some("credencial trampa / forzado C0".into()),
                techo_manual: self.techos.get(&par).copied(),
            };
        }

        let (vista, efectivos, caducados) =
            vista_desde_hechos(&self.hechos, sistema, clase, ahora);
        let nivel_base = calcular_nivel_base(vista);
        let inv = self.alcanzables.get(sistema.como_str());
        let (mut nivel, mut causa) =
            aplicar_degradacion_ef9(nivel_base, clase, vista.ef9_abierto, inv, ahora);

        let techo = self.techos.get(&par).copied();
        if let Some(t) = techo {
            if t < nivel {
                causa = Some(format!(
                    "rebaja manual del operador a {} (causa registrada)",
                    t.token()
                ));
                nivel = t;
            }
        }

        EvaluacionNivel {
            nivel_base,
            nivel_vigente: nivel,
            hechos_efectivos: efectivos,
            hechos_caducados: caducados,
            bypass_residual: bypass_residual_de(nivel),
            causa_degradacion: causa,
            techo_manual: techo,
        }
    }

    pub fn n_hechos(&self) -> usize {
        self.hechos.len()
    }

    pub fn historial(&self) -> &[(ParSistemaClase, NivelControl, String, u64)] {
        &self.historial
    }

    /// Hechos que un PEP EF-1/EF-2 instrumentado **puede** sostener (no CONFINADO).
    pub fn hechos_sostenibles_por_pep_ef1_ef2() -> &'static [TipoHecho] {
        &[
            TipoHecho::Custodia,
            TipoHecho::Delegado,
            TipoHecho::PepAtestado,
            TipoHecho::SondaOk,
            TipoHecho::Observable,
            TipoHecho::Exclusividad, // solo si bypass §I lo alimenta en el entorno
        ]
    }
}

/// Resumen firmable del Libro (digest de pares evaluados).
#[allow(dead_code)]
pub fn resumen_pares(
    evaluaciones: &BTreeMap<ParSistemaClase, NivelControl>,
) -> Vec<u8> {
    let mut v = Vec::new();
    for (par, niv) in evaluaciones {
        v.extend_from_slice(par.sistema.como_str().as_bytes());
        v.push(0);
        v.extend_from_slice(par.clase.token().as_bytes());
        v.push(0);
        v.push(*niv as u8);
    }
    v
}
