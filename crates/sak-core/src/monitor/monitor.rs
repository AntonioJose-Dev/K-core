//! Monitor de supuestos críticos y orquestación de la máquina de estados.

use crate::capacidad::{IdCapacidad, VerificadorCapacidades};
use crate::contexto::ClaseEfecto;
use crate::crypto;
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{AlmacenEvidencia, IdSujeto, LedgerEvidencia, MemoriaDurable};
use crate::identidad::IdSistema;
use crate::monitor::epoca::{EpocaMonotonica, ErrorEpoca};
use crate::monitor::estados::EstadoMaquina;
use crate::monitor::transicion::RegistroTransicion;
use crate::monitor::umbrales::{
    UMBRAL_COFIRMA_DEGRADED_MS, UMBRAL_COFIRMA_SUSPEND_MS, UMBRAL_PEP_SILENCIO_MS,
    UMBRAL_RECONCILIACION_SUSPEND_PCT,
};
use crate::reloj::Ticks;
use std::collections::{HashMap, HashSet};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupuestoCritico {
    CorreccionCriptografica,
    EntropiaEjecucion,
    CustodiaClaveFirma,
    CofirmaTestigos,
    AtestacionPlataforma,
    LatidoPep,
    HuecoSecuencia,
    ReconciliacionProveedor,
    EpocaAntiRollback,
}

impl SupuestoCritico {
    pub fn token(self) -> &'static str {
        match self {
            SupuestoCritico::CorreccionCriptografica => "CORRECCION_CRIPTOGRAFICA",
            SupuestoCritico::EntropiaEjecucion => "ENTROPIA_EJECUCION",
            SupuestoCritico::CustodiaClaveFirma => "CUSTODIA_CLAVE_FIRMA",
            SupuestoCritico::CofirmaTestigos => "COFIRMA_TESTIGOS",
            SupuestoCritico::AtestacionPlataforma => "ATESTACION_PLATAFORMA",
            SupuestoCritico::LatidoPep => "LATIDO_PEP",
            SupuestoCritico::HuecoSecuencia => "HUECO_SECUENCIA",
            SupuestoCritico::ReconciliacionProveedor => "RECONCILIACION_PROVEEDOR",
            SupuestoCritico::EpocaAntiRollback => "EPOCA_ANTI_ROLLBACK",
        }
    }
}

impl fmt::Display for SupuestoCritico {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlcanceAfectado {
    Dominio,
    Sistema,
    Clase,
}

impl AlcanceAfectado {
    pub fn token(self) -> &'static str {
        match self {
            AlcanceAfectado::Dominio => "DOMINIO",
            AlcanceAfectado::Sistema => "SISTEMA",
            AlcanceAfectado::Clase => "CLASE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorMonitor {
    EstadoNoPermiteAutorizacion { estado: EstadoMaquina },
    ClaseSuspendida,
    RecuperacionPendienteGobernanza,
    Terminal,
    Epoca(ErrorEpoca),
    AutotestFallido,
}

impl fmt::Display for ErrorMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorMonitor::EstadoNoPermiteAutorizacion { estado } => {
                write!(f, "autorizacion denegada en estado {}", estado.token())
            }
            ErrorMonitor::ClaseSuspendida => write!(f, "clase de efecto suspendida"),
            ErrorMonitor::RecuperacionPendienteGobernanza => write!(
                f,
                "recuperacion SUSPENDED→ARMED pendiente de gobernanza (no bypass tecnico)"
            ),
            ErrorMonitor::Terminal => write!(f, "dominio en FAIL_STATIC"),
            ErrorMonitor::Epoca(e) => write!(f, "epoca: {e}"),
            ErrorMonitor::AutotestFallido => write!(f, "autotest criptografico fallido"),
        }
    }
}

impl std::error::Error for ErrorMonitor {}

/// Monitor + máquina de estados del dominio.
pub struct MonitorDominio {
    estado: EstadoMaquina,
    epoca: EpocaMonotonica,
    transiciones: Vec<RegistroTransicion>,
    clases_suspendidas: HashSet<ClaseEfecto>,
    /// Capacidades a revocar en el verificador asociado.
    ids_a_revocar: Vec<IdCapacidad>,
    ultima_cofirma: Option<Ticks>,
    /// Atestación de plataforma (VAL-EXT / simulada).
    ultima_atestacion: Option<Ticks>,
    ultimo_latido_pep: HashMap<ClaseEfecto, Ticks>,
    /// Emisiones registradas por época (anti doble emisor).
    emisiones_por_epoca: HashMap<u64, u32>,
}

impl MonitorDominio {
    /// Arranque: persiste época, SELFTEST, y si pasa llega a ARMED.
    pub fn arrancar(
        almacen: &mut dyn AlmacenEvidencia,
        autotest_ok: bool,
        ahora: Ticks,
    ) -> Result<Self, ErrorMonitor> {
        let epoca = EpocaMonotonica::cargar_o_iniciar(almacen, 1).map_err(ErrorMonitor::Epoca)?;
        let mut m = MonitorDominio {
            estado: EstadoMaquina::Cold,
            epoca,
            transiciones: Vec::new(),
            clases_suspendidas: HashSet::new(),
            ids_a_revocar: Vec::new(),
            ultima_cofirma: Some(ahora),
            ultima_atestacion: Some(ahora),
            ultimo_latido_pep: HashMap::new(),
            emisiones_por_epoca: HashMap::new(),
        };
        m.transicionar(
            EstadoMaquina::Selftest,
            "arranque",
            None,
            [0u8; LONGITUD_HASH_PAQUETE],
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        if !autotest_ok {
            m.transicionar(
                EstadoMaquina::FailStatic,
                "autotest criptografico fallido en arranque",
                Some(SupuestoCritico::CorreccionCriptografica),
                digest_causa(b"autotest-fail"),
                AlcanceAfectado::Dominio,
                None,
                None,
                ahora,
            );
            return Err(ErrorMonitor::AutotestFallido);
        }
        m.transicionar(
            EstadoMaquina::Sealed,
            "autotest ok",
            None,
            digest_causa(b"autotest-ok"),
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        m.transicionar(
            EstadoMaquina::Armed,
            "corpus/PEP listos (arranque instrumentado)",
            None,
            digest_causa(b"armed"),
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        Ok(m)
    }

    pub fn estado(&self) -> EstadoMaquina {
        self.estado
    }

    pub fn epoca(&self) -> u64 {
        self.epoca.actual()
    }

    pub fn suelo_epoca(&self) -> u64 {
        self.epoca.suelo()
    }

    pub fn transiciones(&self) -> &[RegistroTransicion] {
        &self.transiciones
    }

    pub fn clase_suspendida(&self, clase: ClaseEfecto) -> bool {
        self.clases_suspendidas.contains(&clase)
    }

    /// Puerta de autorización (INV-12): sin caché permisiva.
    pub fn exigir_autorizacion(
        &self,
        clase: ClaseEfecto,
        irreversible: bool,
    ) -> Result<(), ErrorMonitor> {
        if self.estado.es_terminal() {
            return Err(ErrorMonitor::Terminal);
        }
        if self.clases_suspendidas.contains(&clase) {
            return Err(ErrorMonitor::ClaseSuspendida);
        }
        if !self.estado.permite_capacidad(irreversible) {
            return Err(ErrorMonitor::EstadoNoPermiteAutorizacion {
                estado: self.estado,
            });
        }
        Ok(())
    }

    /// Registra emisión en la época actual; segunda emisión válida en la misma
    /// época desde este monitor se deniega (invariante de un emisor).
    pub fn registrar_emision_epoca(&mut self) -> Result<(), ErrorMonitor> {
        self.exigir_autorizacion(ClaseEfecto::Ef1, false)?;
        let e = self.epoca.actual();
        let n = self.emisiones_por_epoca.entry(e).or_insert(0);
        *n += 1;
        if *n > 1 {
            return Err(ErrorMonitor::EstadoNoPermiteAutorizacion {
                estado: self.estado,
            });
        }
        Ok(())
    }

    pub fn n_emisiones_epoca(&self, epoca: u64) -> u32 {
        self.emisiones_por_epoca.get(&epoca).copied().unwrap_or(0)
    }

    /// Recuperación SUSPENDED→ARMED: **pendiente de gobernanza**, no bypass.
    pub fn intentar_recuperacion_automatica(&self) -> Result<(), ErrorMonitor> {
        if self.estado == EstadoMaquina::FailStatic {
            return Err(ErrorMonitor::Terminal);
        }
        if self.estado == EstadoMaquina::Suspended {
            return Err(ErrorMonitor::RecuperacionPendienteGobernanza);
        }
        Ok(())
    }

    pub fn aplicar_revocaciones(&self, verificador: &mut VerificadorCapacidades) {
        for id in &self.ids_a_revocar {
            verificador.revocar(*id);
        }
    }

    pub fn tomar_revocaciones(&mut self) -> Vec<IdCapacidad> {
        std::mem::take(&mut self.ids_a_revocar)
    }

    pub fn marcar_capacidad_viva(&mut self, id: IdCapacidad) {
        // Se acumula para revocar al suspender/terminal.
        if !self.ids_a_revocar.contains(&id) {
            // En operación normal no están "a revocar"; usamos set separado.
        }
        let _ = id;
    }

    // --- Respuestas I.1 ---

    pub fn evento_hueco_secuencia(&mut self, ahora: Ticks, digest: [u8; LONGITUD_HASH_PAQUETE]) {
        self.suspender_dominio(
            "hueco de secuencia en cadena de evidencia",
            SupuestoCritico::HuecoSecuencia,
            digest,
            ahora,
        );
    }

    pub fn evento_reconciliacion(
        &mut self,
        divergencia_pct: u32,
        ahora: Ticks,
    ) {
        if divergencia_pct > UMBRAL_RECONCILIACION_SUSPEND_PCT {
            self.suspender_dominio(
                format!("reconciliacion divergencia {divergencia_pct}% > 5%"),
                SupuestoCritico::ReconciliacionProveedor,
                digest_causa(&divergencia_pct.to_le_bytes()),
                ahora,
            );
        }
    }

    pub fn evento_latido_pep(&mut self, clase: ClaseEfecto, ahora: Ticks) {
        self.ultimo_latido_pep.insert(clase, ahora);
    }

    pub fn evaluar_silencio_pep(&mut self, clase: ClaseEfecto, ahora: Ticks) {
        let ultimo = self.ultimo_latido_pep.get(&clase).copied();
        let silencio = match ultimo {
            None => true,
            Some(t) => ahora.saturating_sub(t) > UMBRAL_PEP_SILENCIO_MS,
        };
        if silencio {
            self.clases_suspendidas.insert(clase);
            self.transicionar(
                self.estado, // puede permanecer ARMED a nivel dominio
                format!("PEP silencio >30s clase {}", clase.token()),
                Some(SupuestoCritico::LatidoPep),
                digest_causa(clase.token().as_bytes()),
                AlcanceAfectado::Clase,
                None,
                Some(clase),
                ahora,
            );
            // Si ya estábamos Armed, el registro documenta suspensión de clase
            // sin necesariamente bajar el dominio (I.1: suspensión de esa clase).
        }
    }

    pub fn evento_custodia_clave_inalcanzable(&mut self, ahora: Ticks) {
        self.suspender_dominio(
            "custodia de clave de firma no alcanzable",
            SupuestoCritico::CustodiaClaveFirma,
            digest_causa(b"custodia-key"),
            ahora,
        );
    }

    pub fn evento_cofirma_testigos(&mut self, obtenida_en: Ticks, ahora: Ticks) {
        self.ultima_cofirma = Some(obtenida_en);
        let ant = ahora.saturating_sub(obtenida_en);
        if ant > UMBRAL_COFIRMA_SUSPEND_MS {
            self.suspender_dominio(
                "cofirma de testigos obsoleta >3600s",
                SupuestoCritico::CofirmaTestigos,
                digest_causa(b"cofirma-suspend"),
                ahora,
            );
        } else if ant > UMBRAL_COFIRMA_DEGRADED_MS {
            self.degradar(
                "cofirma de testigos obsoleta >900s",
                SupuestoCritico::CofirmaTestigos,
                digest_causa(b"cofirma-degraded"),
                ahora,
            );
        }
    }

    /// Atestación de plataforma (VAL-EXT): misma política 900/3600 si se declara.
    pub fn evento_atestacion_plataforma(&mut self, obtenida_en: Ticks, ahora: Ticks) {
        self.ultima_atestacion = Some(obtenida_en);
        let ant = ahora.saturating_sub(obtenida_en);
        if ant > UMBRAL_COFIRMA_SUSPEND_MS {
            self.suspender_dominio(
                "atestacion de plataforma obsoleta >3600s [VAL-EXT]",
                SupuestoCritico::AtestacionPlataforma,
                digest_causa(b"attest-suspend"),
                ahora,
            );
        } else if ant > UMBRAL_COFIRMA_DEGRADED_MS {
            self.degradar(
                "atestacion de plataforma obsoleta >900s [VAL-EXT]",
                SupuestoCritico::AtestacionPlataforma,
                digest_causa(b"attest-degraded"),
                ahora,
            );
        }
    }

    pub fn evento_autotest_fallido(&mut self, ahora: Ticks) {
        if self.estado.es_terminal() {
            return;
        }
        self.transicionar(
            EstadoMaquina::FailStatic,
            "autotest criptografico fallido",
            Some(SupuestoCritico::CorreccionCriptografica),
            digest_causa(b"autotest-runtime"),
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        self.revocar_todas_vivas_marcadas();
    }

    pub fn evento_entropia_ejecucion_fallida(&mut self, ahora: Ticks) {
        self.suspender_dominio(
            "fallo de entropia en ejecucion",
            SupuestoCritico::EntropiaEjecucion,
            digest_causa(b"entropy"),
            ahora,
        );
    }

    pub fn evento_retroceso_epoca(
        &mut self,
        propuesto: u64,
        ahora: Ticks,
    ) -> Result<(), ErrorMonitor> {
        match self.epoca.validar_no_retroceso(propuesto) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.transicionar(
                    EstadoMaquina::FailStatic,
                    format!("perdida/retroceso de epoca: {e}"),
                    Some(SupuestoCritico::EpocaAntiRollback),
                    digest_causa(&propuesto.to_le_bytes()),
                    AlcanceAfectado::Dominio,
                    None,
                    None,
                    ahora,
                );
                self.revocar_todas_vivas_marcadas();
                Err(ErrorMonitor::Epoca(e))
            }
        }
    }

    pub fn avanzar_epoca(
        &mut self,
        almacen: &mut dyn AlmacenEvidencia,
        ahora: Ticks,
    ) -> Result<u64, ErrorMonitor> {
        let n = self
            .epoca
            .avanzar(almacen)
            .map_err(ErrorMonitor::Epoca)?;
        self.transicionar(
            self.estado,
            format!("avance de epoca a {n}"),
            None,
            digest_causa(&n.to_le_bytes()),
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        Ok(n)
    }

    /// Serializa transiciones para encadenar en evidencia offline.
    pub fn payload_transiciones(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1); // versión
        out.extend_from_slice(&(self.transiciones.len() as u32).to_le_bytes());
        for t in &self.transiciones {
            let cuerpo = t.cuerpo_canonico();
            out.extend_from_slice(&(cuerpo.len() as u32).to_le_bytes());
            out.extend_from_slice(&cuerpo);
            out.extend_from_slice(&t.digest());
        }
        out
    }

    fn suspender_dominio(
        &mut self,
        causa: impl Into<String>,
        supuesto: SupuestoCritico,
        digest: [u8; LONGITUD_HASH_PAQUETE],
        ahora: Ticks,
    ) {
        if self.estado.es_terminal() {
            return;
        }
        self.transicionar(
            EstadoMaquina::Suspended,
            causa,
            Some(supuesto),
            digest,
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
        self.revocar_todas_vivas_marcadas();
    }

    fn degradar(
        &mut self,
        causa: impl Into<String>,
        supuesto: SupuestoCritico,
        digest: [u8; LONGITUD_HASH_PAQUETE],
        ahora: Ticks,
    ) {
        if matches!(
            self.estado,
            EstadoMaquina::Suspended | EstadoMaquina::FailStatic | EstadoMaquina::Degraded
        ) {
            return;
        }
        if self.estado != EstadoMaquina::Armed {
            return;
        }
        self.transicionar(
            EstadoMaquina::Degraded,
            causa,
            Some(supuesto),
            digest,
            AlcanceAfectado::Dominio,
            None,
            None,
            ahora,
        );
    }

    fn revocar_todas_vivas_marcadas(&mut self) {
        // Las IDs se inyectan vía `programar_revocacion`.
    }

    pub fn programar_revocacion(&mut self, id: IdCapacidad) {
        self.ids_a_revocar.push(id);
    }

    fn transicionar(
        &mut self,
        hacia: EstadoMaquina,
        causa: impl Into<String>,
        supuesto: Option<SupuestoCritico>,
        digest_hecho: [u8; LONGITUD_HASH_PAQUETE],
        alcance: AlcanceAfectado,
        sistema: Option<IdSistema>,
        clase: Option<ClaseEfecto>,
        ahora: Ticks,
    ) {
        let desde = self.estado;
        // Permite registro de evento de clase sin cambiar estado de dominio
        // cuando hacia == desde (silencio PEP).
        if hacia != desde || supuesto.is_some() {
            let reg = RegistroTransicion {
                desde,
                hacia,
                causa: causa.into(),
                supuesto,
                epoca: self.epoca.actual(),
                ticks: ahora,
                digest_hecho,
                alcance,
                sistema,
                clase,
            };
            self.transiciones.push(reg);
            if hacia != desde {
                self.estado = hacia;
            }
        }
    }
}

fn digest_causa(msg: &[u8]) -> [u8; LONGITUD_HASH_PAQUETE] {
    crypto::sha384_dominio(b"SAK-MONITOR-v1|", msg)
}

/// Encadena el payload de transiciones en el ledger (sujeto de sistema).
pub fn encadenar_transiciones_en_ledger<A: AlmacenEvidencia>(
    ledger: &mut LedgerEvidencia<A>,
    monitor: &MonitorDominio,
) -> Result<(), crate::evidencia::ErrorEvidencia> {
    use crate::evidencia::TipoRegistro;
    ledger
        .registrar_evento_sistema(
            &IdSujeto::nuevo("dominio").unwrap(),
            TipoRegistro::TransicionEstado,
            monitor.payload_transiciones(),
        )
        .map(|_| ())
}

/// Helper de prueba: monitor + almacén en memoria ya ARMED.
pub fn monitor_armado_prueba(ahora: Ticks) -> (MonitorDominio, MemoriaDurable) {
    let mut store = MemoriaDurable::default();
    let m = MonitorDominio::arrancar(&mut store, true, ahora).expect("arrancar");
    (m, store)
}
