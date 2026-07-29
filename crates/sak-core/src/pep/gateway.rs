//! Gateway de modelos EF-1: punto de aplicación con ejecución delegada.

use crate::capacidad::{
    Alcance, Capability, CausaDenegacion, IntentoUso, ResultadoVerificacion,
    VerificadorCapacidades,
};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::evidencia::{
    AlmacenEvidencia, ErrorEvidencia, IdSujeto, LedgerEvidencia, ReciboEfecto,
};
use crate::identidad::IdSistema;
use crate::pep::incidente::{IncidenteMediacion, TipoIncidente};
use crate::pep::proveedor::ProveedorModelo;
use crate::pep::solicitud::{
    canon_condiciones, digest_solicitud_inferencia, CondicionesAplicadas, SolicitudCruda,
    SolicitudInferencia,
};
use crate::reloj::{RelojMonotonico, Ticks};
use std::fmt;

/// Códigos de denegación del PEP (cadena H; no amplían G.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodigoPep {
    /// H.1: efecto no tipificable.
    EfectoNoTipificado,
    /// Clase no admitida por este gateway.
    ClaseNoSoportada,
    /// Capacidad ausente.
    CapacidadAusente,
    /// Fallo de verificación INV-08 / H.13.
    Capacidad(CausaDenegacion),
    /// Divergencia autorizado/ejecutado ⇒ incidente, no éxito.
    IncidenteMediacion,
    /// Fallo al encadenar evidencia del recibo o del efector.
    Evidencia(String),
    /// EF-2: recurso o conjunto de datos distinto del autorizado.
    RecursoNoAutorizado,
    /// EF-2: filtro/digest de consulta alterado.
    FiltroNoAutorizado,
    /// EF-2: campo no permitido.
    CampoNoAutorizado,
    /// EF-2: exceso de volumen.
    VolumenExcedido,
    /// EF-3: selector o precondición distinta.
    SelectorNoAutorizado,
    /// EF-3: digest de valores alterado.
    ValorNoAutorizado,
    /// EF-3: límite de filas/objetos excedido.
    LimiteFilasExcedido,
    /// EF-3: operación distinta de la autorizada.
    OperacionNoAutorizada,
    /// EF-3: conflicto CAS / versión.
    ConflictoCas,
    /// EF-3: hash de paquete normativo distinto.
    PaqueteNoAutorizado,
    /// Precondiciones de cadena: identidad no vigente.
    IdentidadNoVigente,
    /// Pasaporte no vigente.
    PasaporteNoVigente,
    /// Libro de Control insuficiente (H.4).
    ControlInsuficiente,
    /// Monitor fuera de estado permisivo.
    MonitorNoPermisivo,
    /// EF-4: herramienta no registrada en catálogo.
    HerramientaNoRegistrada,
    /// EF-4: versión de herramienta distinta.
    VersionHerramientaNoAutorizada,
    /// EF-4: servidor MCP / proveedor no registrado.
    ServidorNoRegistrado,
    /// EF-4: destino/URL no declarado.
    DestinoNoAutorizado,
    /// EF-4: argumentos alterados o esquema distinto.
    ArgumentosNoAutorizados,
    /// EF-4: redirección no declarada.
    RedireccionNoDeclarada,
    /// EF-4: PEP subyacente inexistente (EF-6/7 u omitido).
    PepSubyacenteInexistente,
    /// EF-4: falta capacidad del efecto subyacente (p.ej. EF-3/EF-5).
    CapacidadSubyacenteAusente,
    /// EF-5: decisión normativa DENY (sin capacidad emitible).
    DecisionDenegada,
    /// EF-5: supervisión humana exigida pero ausente.
    SupervisionAusente,
    /// EF-5: importe distinto del autorizado.
    ImporteNoAutorizado,
    /// EF-5: moneda distinta.
    MonedaNoAutorizada,
    /// EF-5: contraparte / cuenta distinta.
    ContraparteNoAutorizada,
    /// EF-5: tipo de operación distinto.
    TipoOperacionNoAutorizado,
    /// EF-5: objeto contractual / de negocio distinto.
    ObjetoNoAutorizado,
    /// EF-5: efector / sistema distinto.
    EfectorNoAutorizado,
    /// EF-5: idempotency key repetida (mismo digest).
    IdempotenciaDuplicada,
    /// EF-5: idempotency key incompatible o reutilizada con otros parámetros.
    IdempotenciaIncompatible,
    /// EF-5: conflicto de precondición en el efector.
    ConflictoPrecondicion,
    /// EF-6: hecho de contacto exigido ausente.
    HechoContactoAusente,
    /// EF-6: canal distinto.
    CanalNoAutorizado,
    /// EF-6: remitente distinto.
    RemitenteNoAutorizado,
    /// EF-6: destinatario / conjunto distinto.
    DestinatarioNoAutorizado,
    /// EF-6: plantilla / asunto distinto.
    PlantillaNoAutorizada,
    /// EF-6: cuerpo distinto.
    CuerpoNoAutorizado,
    /// EF-6: adjunto distinto.
    AdjuntoNoAutorizado,
    /// EF-6: idioma distinto.
    IdiomaNoAutorizado,
    /// EF-6: fuera de franja horaria.
    HorarioNoAutorizado,
    /// EF-6: frecuencia excedida.
    FrecuenciaNoAutorizada,
    /// EF-6: cardinalidad / conjunto masivo inválido.
    CardinalidadExcedida,
    /// EF-6: condición normativa no aplicable (plantilla, marcado, baja…).
    CondicionComunicacion,
    /// EF-7: hecho de publicación exigido ausente.
    HechoPublicacionAusente,
    /// EF-7: canal distinto.
    CanalPublicacionNoAutorizado,
    /// EF-7: cuenta publicadora distinta.
    CuentaPublicacionNoAutorizada,
    /// EF-7: destino distinto.
    DestinoPublicacionNoAutorizado,
    /// EF-7: operación distinta.
    OperacionPublicacionNoAutorizada,
    /// EF-7: contenido distinto.
    ContenidoPublicacionNoAutorizado,
    /// EF-7: medio/adjunto distinto.
    MedioPublicacionNoAutorizado,
    /// EF-7: etiqueta distinta.
    EtiquetaNoAutorizada,
    /// EF-7: audiencia distinta o abierta.
    AudienciaNoAutorizada,
    /// EF-7: visibilidad distinta.
    VisibilidadNoAutorizada,
    /// EF-7: ventana de publicación fuera de alcance.
    VentanaPublicacionNoAutorizada,
    /// EF-7: contenido no canónico / HTML-script activo.
    ContenidoNoCanonico,
    /// EF-7: condición normativa no aplicable.
    CondicionPublicacion,
    /// EF-7: retirada fuera de alcance.
    RetiradaFueraAlcance,
    /// EF-8: hecho de decisión ausente.
    HechoDecisionAusente,
    /// EF-8: hecho de decisión vencido (plazo/quórum).
    HechoDecisionVencido,
    /// EF-8: sujeto afectado distinto.
    SujetoDecisionNoAutorizado,
    /// EF-8: clase de decisión distinta.
    ClaseDecisionNoAutorizada,
    /// EF-8: canal de consumo distinto.
    CanalConsumoNoAutorizado,
    /// EF-8: destinatario distinto.
    DestinatarioConsumoNoAutorizado,
    /// EF-8: acción habilitada distinta.
    AccionConsumoNoAutorizada,
    /// EF-8: digest de resultado distinto.
    ResultadoDecisionNoAutorizado,
    /// EF-8: finalidad distinta.
    FinalidadConsumoNoAutorizada,
    /// EF-8: versión distinta.
    VersionResultadoNoAutorizada,
    /// EF-8: periodo de validez fuera de alcance.
    PeriodoValidezNoAutorizado,
    /// EF-8: exclusividad del canal falsa (vía alternativa).
    ExclusividadCanalFalsa,
    /// EF-3 que materializa EF-8 sin pasar por el gateway de consumo.
    ConsumoEf8Requerido,
    /// EF-9: ejecución de código prohibida (perfil CodigoProhibido).
    Ef9Prohibido,
    /// EF-9: confinamiento no efectivo / pendiente de atestación (no C5).
    Ef9NoConfinado,
    /// EF-10: hecho de egreso ausente.
    HechoEgresoAusente,
    /// EF-10: dominio origen distinto.
    OrigenEgresoNoAutorizado,
    /// EF-10: dominio destino distinto.
    DestinoEgresoNoAutorizado,
    /// EF-10: proveedor distinto.
    ProveedorEgresoNoAutorizado,
    /// EF-10: endpoint/ruta distintos.
    EndpointEgresoNoAutorizado,
    /// EF-10: jurisdicción distinta.
    JurisdiccionEgresoNoAutorizada,
    /// EF-10: protocolo distinto.
    ProtocoloEgresoNoAutorizado,
    /// EF-10: tenant distinto.
    TenantEgresoNoAutorizado,
    /// EF-10: clasificación distinta.
    ClasificacionEgresoNoAutorizada,
    /// EF-10: manifiesto/digest distinto.
    ManifiestoEgresoNoAutorizado,
    /// EF-10: volumen no autorizado / excedido.
    VolumenEgresoExcedido,
    /// EF-10: finalidad distinta.
    FinalidadEgresoNoAutorizada,
    /// EF-10: cifrado distinto.
    CifradoEgresoNoAutorizado,
    /// EF-10: proxy no declarado.
    ProxyEgresoNoDeclarado,
    /// EF-5/6/7 cruzan dominio sin cadena EF-10.
    EgresoEf10Requerido,
    /// EF-11: módulo físico interpuesto ausente / C0.
    ModuloFisicoAusente,
    /// EF-11: hecho físico ausente.
    HechoFisicoAusente,
    /// EF-11: latido del módulo ausente.
    LatidoModuloAusente,
    /// EF-11: actuador no autorizado.
    ActuadorFisicoNoAutorizado,
    /// EF-11: controlador no autorizado.
    ControladorFisicoNoAutorizado,
    /// EF-11: bus no autorizado.
    BusFisicoNoAutorizado,
    /// EF-11: operación no autorizada.
    OperacionFisicaNoAutorizada,
    /// EF-11: parámetro/unidad no autorizado.
    ParametroFisicoNoAutorizado,
    /// EF-11: zona no autorizada.
    ZonaFisicaNoAutorizada,
    /// EF-11: modo no autorizado.
    ModoFisicoNoAutorizado,
    /// EF-11: ventana no autorizada.
    VentanaFisicaNoAutorizada,
    /// EF-11: orden libre.
    OrdenFisicaLibre,
    /// EF-11: orden compuesta no declarada.
    OrdenFisicaCompuesta,
    /// EF-11: replay.
    OrdenFisicaReplay,
    /// EF-11: interlock local.
    InterlockFisico,
    /// EF-11: envolvente local del módulo.
    EnvolventeFisicaLocal,
    /// EF-11: estado incompatible.
    EstadoFisicoIncompatible,
    /// EF-11: actuador bloqueado.
    ActuadorFisicoBloqueado,
    /// EF-11: aprobación humana ausente.
    AprobacionHumanaAusente,
    /// EF-11: aprobación incompetente.
    AprobacionHumanaIncompetente,
    /// EF-11: aprobación no independiente.
    AprobacionHumanaNoIndependiente,
    /// EF-11: aprobación fuera de plazo.
    AprobacionHumanaFueraPlazo,
    /// EF-11: digest de aprobación divergente.
    AprobacionHumanaDigestDivergente,
    /// EF-5 que ordena actuador sin cadena EF-11.
    EfectoFisicoEf11Requerido,
}

impl CodigoPep {
    pub fn token(&self) -> &'static str {
        match self {
            CodigoPep::EfectoNoTipificado => "EFECTO_NO_TIPIFICADO",
            CodigoPep::ClaseNoSoportada => "CLASE_NO_SOPORTADA",
            CodigoPep::CapacidadAusente => "CAPACIDAD_AUSENTE",
            CodigoPep::Capacidad(_) => "CAPACIDAD_INVALIDA",
            CodigoPep::IncidenteMediacion => "INCIDENTE_MEDIACION",
            CodigoPep::Evidencia(_) => "EVIDENCIA",
            CodigoPep::RecursoNoAutorizado => "RECURSO_NO_AUTORIZADO",
            CodigoPep::FiltroNoAutorizado => "FILTRO_NO_AUTORIZADO",
            CodigoPep::CampoNoAutorizado => "CAMPO_NO_AUTORIZADO",
            CodigoPep::VolumenExcedido => "VOLUMEN_EXCEDIDO",
            CodigoPep::SelectorNoAutorizado => "SELECTOR_NO_AUTORIZADO",
            CodigoPep::ValorNoAutorizado => "VALOR_NO_AUTORIZADO",
            CodigoPep::LimiteFilasExcedido => "LIMITE_FILAS_EXCEDIDO",
            CodigoPep::OperacionNoAutorizada => "OPERACION_NO_AUTORIZADA",
            CodigoPep::ConflictoCas => "CONFLICTO_CAS",
            CodigoPep::PaqueteNoAutorizado => "PAQUETE_NO_AUTORIZADO",
            CodigoPep::IdentidadNoVigente => "IDENTIDAD_NO_VIGENTE",
            CodigoPep::PasaporteNoVigente => "PASAPORTE_NO_VIGENTE",
            CodigoPep::ControlInsuficiente => "CONTROL_INSUFICIENTE",
            CodigoPep::MonitorNoPermisivo => "MONITOR_NO_PERMISIVO",
            CodigoPep::HerramientaNoRegistrada => "HERRAMIENTA_NO_REGISTRADA",
            CodigoPep::VersionHerramientaNoAutorizada => "VERSION_HERRAMIENTA_NO_AUTORIZADA",
            CodigoPep::ServidorNoRegistrado => "SERVIDOR_NO_REGISTRADO",
            CodigoPep::DestinoNoAutorizado => "DESTINO_NO_AUTORIZADO",
            CodigoPep::ArgumentosNoAutorizados => "ARGUMENTOS_NO_AUTORIZADOS",
            CodigoPep::RedireccionNoDeclarada => "REDIRECCION_NO_DECLARADA",
            CodigoPep::PepSubyacenteInexistente => "PEP_SUBYACENTE_INEXISTENTE",
            CodigoPep::CapacidadSubyacenteAusente => "CAPACIDAD_SUBYACENTE_AUSENTE",
            CodigoPep::DecisionDenegada => "DECISION_DENEGADA",
            CodigoPep::SupervisionAusente => "SUPERVISION_AUSENTE",
            CodigoPep::ImporteNoAutorizado => "IMPORTE_NO_AUTORIZADO",
            CodigoPep::MonedaNoAutorizada => "MONEDA_NO_AUTORIZADA",
            CodigoPep::ContraparteNoAutorizada => "CONTRAPARTE_NO_AUTORIZADA",
            CodigoPep::TipoOperacionNoAutorizado => "TIPO_OPERACION_NO_AUTORIZADO",
            CodigoPep::ObjetoNoAutorizado => "OBJETO_NO_AUTORIZADO",
            CodigoPep::EfectorNoAutorizado => "EFECTOR_NO_AUTORIZADO",
            CodigoPep::IdempotenciaDuplicada => "IDEMPOTENCIA_DUPLICADA",
            CodigoPep::IdempotenciaIncompatible => "IDEMPOTENCIA_INCOMPATIBLE",
            CodigoPep::ConflictoPrecondicion => "CONFLICTO_PRECONDICION",
            CodigoPep::HechoContactoAusente => "HECHO_CONTACTO_AUSENTE",
            CodigoPep::CanalNoAutorizado => "CANAL_NO_AUTORIZADO",
            CodigoPep::RemitenteNoAutorizado => "REMITENTE_NO_AUTORIZADO",
            CodigoPep::DestinatarioNoAutorizado => "DESTINATARIO_NO_AUTORIZADO",
            CodigoPep::PlantillaNoAutorizada => "PLANTILLA_NO_AUTORIZADA",
            CodigoPep::CuerpoNoAutorizado => "CUERPO_NO_AUTORIZADO",
            CodigoPep::AdjuntoNoAutorizado => "ADJUNTO_NO_AUTORIZADO",
            CodigoPep::IdiomaNoAutorizado => "IDIOMA_NO_AUTORIZADO",
            CodigoPep::HorarioNoAutorizado => "HORARIO_NO_AUTORIZADO",
            CodigoPep::FrecuenciaNoAutorizada => "FRECUENCIA_NO_AUTORIZADA",
            CodigoPep::CardinalidadExcedida => "CARDINALIDAD_EXCEDIDA",
            CodigoPep::CondicionComunicacion => "CONDICION_COMUNICACION",
            CodigoPep::HechoPublicacionAusente => "HECHO_PUBLICACION_AUSENTE",
            CodigoPep::CanalPublicacionNoAutorizado => "CANAL_PUBLICACION_NO_AUTORIZADO",
            CodigoPep::CuentaPublicacionNoAutorizada => "CUENTA_PUBLICACION_NO_AUTORIZADA",
            CodigoPep::DestinoPublicacionNoAutorizado => "DESTINO_PUBLICACION_NO_AUTORIZADO",
            CodigoPep::OperacionPublicacionNoAutorizada => "OPERACION_PUBLICACION_NO_AUTORIZADA",
            CodigoPep::ContenidoPublicacionNoAutorizado => "CONTENIDO_PUBLICACION_NO_AUTORIZADO",
            CodigoPep::MedioPublicacionNoAutorizado => "MEDIO_PUBLICACION_NO_AUTORIZADO",
            CodigoPep::EtiquetaNoAutorizada => "ETIQUETA_NO_AUTORIZADA",
            CodigoPep::AudienciaNoAutorizada => "AUDIENCIA_NO_AUTORIZADA",
            CodigoPep::VisibilidadNoAutorizada => "VISIBILIDAD_NO_AUTORIZADA",
            CodigoPep::VentanaPublicacionNoAutorizada => "VENTANA_PUBLICACION_NO_AUTORIZADA",
            CodigoPep::ContenidoNoCanonico => "CONTENIDO_NO_CANONICO",
            CodigoPep::CondicionPublicacion => "CONDICION_PUBLICACION",
            CodigoPep::RetiradaFueraAlcance => "RETIRADA_FUERA_ALCANCE",
            CodigoPep::HechoDecisionAusente => "HECHO_DECISION_AUSENTE",
            CodigoPep::HechoDecisionVencido => "HECHO_DECISION_VENCIDO",
            CodigoPep::SujetoDecisionNoAutorizado => "SUJETO_DECISION_NO_AUTORIZADO",
            CodigoPep::ClaseDecisionNoAutorizada => "CLASE_DECISION_NO_AUTORIZADA",
            CodigoPep::CanalConsumoNoAutorizado => "CANAL_CONSUMO_NO_AUTORIZADO",
            CodigoPep::DestinatarioConsumoNoAutorizado => "DESTINATARIO_CONSUMO_NO_AUTORIZADO",
            CodigoPep::AccionConsumoNoAutorizada => "ACCION_CONSUMO_NO_AUTORIZADA",
            CodigoPep::ResultadoDecisionNoAutorizado => "RESULTADO_DECISION_NO_AUTORIZADO",
            CodigoPep::FinalidadConsumoNoAutorizada => "FINALIDAD_CONSUMO_NO_AUTORIZADA",
            CodigoPep::VersionResultadoNoAutorizada => "VERSION_RESULTADO_NO_AUTORIZADA",
            CodigoPep::PeriodoValidezNoAutorizado => "PERIODO_VALIDEZ_NO_AUTORIZADO",
            CodigoPep::ExclusividadCanalFalsa => "EXCLUSIVIDAD_CANAL_FALSA",
            CodigoPep::ConsumoEf8Requerido => "CONSUMO_EF8_REQUERIDO",
            CodigoPep::Ef9Prohibido => "EF9_PROHIBIDO",
            CodigoPep::Ef9NoConfinado => "EF9_NO_CONFINADO",
            CodigoPep::HechoEgresoAusente => "HECHO_EGRESO_AUSENTE",
            CodigoPep::OrigenEgresoNoAutorizado => "ORIGEN_EGRESO_NO_AUTORIZADO",
            CodigoPep::DestinoEgresoNoAutorizado => "DESTINO_EGRESO_NO_AUTORIZADO",
            CodigoPep::ProveedorEgresoNoAutorizado => "PROVEEDOR_EGRESO_NO_AUTORIZADO",
            CodigoPep::EndpointEgresoNoAutorizado => "ENDPOINT_EGRESO_NO_AUTORIZADO",
            CodigoPep::JurisdiccionEgresoNoAutorizada => "JURISDICCION_EGRESO_NO_AUTORIZADA",
            CodigoPep::ProtocoloEgresoNoAutorizado => "PROTOCOLO_EGRESO_NO_AUTORIZADO",
            CodigoPep::TenantEgresoNoAutorizado => "TENANT_EGRESO_NO_AUTORIZADO",
            CodigoPep::ClasificacionEgresoNoAutorizada => "CLASIFICACION_EGRESO_NO_AUTORIZADA",
            CodigoPep::ManifiestoEgresoNoAutorizado => "MANIFIESTO_EGRESO_NO_AUTORIZADO",
            CodigoPep::VolumenEgresoExcedido => "VOLUMEN_EGRESO_EXCEDIDO",
            CodigoPep::FinalidadEgresoNoAutorizada => "FINALIDAD_EGRESO_NO_AUTORIZADA",
            CodigoPep::CifradoEgresoNoAutorizado => "CIFRADO_EGRESO_NO_AUTORIZADO",
            CodigoPep::ProxyEgresoNoDeclarado => "PROXY_EGRESO_NO_DECLARADO",
            CodigoPep::EgresoEf10Requerido => "EGRESO_EF10_REQUERIDO",
            CodigoPep::ModuloFisicoAusente => "MODULO_FISICO_AUSENTE",
            CodigoPep::HechoFisicoAusente => "HECHO_FISICO_AUSENTE",
            CodigoPep::LatidoModuloAusente => "LATIDO_MODULO_AUSENTE",
            CodigoPep::ActuadorFisicoNoAutorizado => "ACTUADOR_FISICO_NO_AUTORIZADO",
            CodigoPep::ControladorFisicoNoAutorizado => "CONTROLADOR_FISICO_NO_AUTORIZADO",
            CodigoPep::BusFisicoNoAutorizado => "BUS_FISICO_NO_AUTORIZADO",
            CodigoPep::OperacionFisicaNoAutorizada => "OPERACION_FISICA_NO_AUTORIZADA",
            CodigoPep::ParametroFisicoNoAutorizado => "PARAMETRO_FISICO_NO_AUTORIZADO",
            CodigoPep::ZonaFisicaNoAutorizada => "ZONA_FISICA_NO_AUTORIZADA",
            CodigoPep::ModoFisicoNoAutorizado => "MODO_FISICO_NO_AUTORIZADO",
            CodigoPep::VentanaFisicaNoAutorizada => "VENTANA_FISICA_NO_AUTORIZADA",
            CodigoPep::OrdenFisicaLibre => "ORDEN_FISICA_LIBRE",
            CodigoPep::OrdenFisicaCompuesta => "ORDEN_FISICA_COMPUESTA",
            CodigoPep::OrdenFisicaReplay => "ORDEN_FISICA_REPLAY",
            CodigoPep::InterlockFisico => "INTERLOCK_FISICO",
            CodigoPep::EnvolventeFisicaLocal => "ENVOLVENTE_FISICA_LOCAL",
            CodigoPep::EstadoFisicoIncompatible => "ESTADO_FISICO_INCOMPATIBLE",
            CodigoPep::ActuadorFisicoBloqueado => "ACTUADOR_FISICO_BLOQUEADO",
            CodigoPep::AprobacionHumanaAusente => "APROBACION_HUMANA_AUSENTE",
            CodigoPep::AprobacionHumanaIncompetente => "APROBACION_HUMANA_INCOMPETENTE",
            CodigoPep::AprobacionHumanaNoIndependiente => "APROBACION_HUMANA_NO_INDEPENDIENTE",
            CodigoPep::AprobacionHumanaFueraPlazo => "APROBACION_HUMANA_FUERA_PLAZO",
            CodigoPep::AprobacionHumanaDigestDivergente => "APROBACION_HUMANA_DIGEST_DIVERGENTE",
            CodigoPep::EfectoFisicoEf11Requerido => "EFECTO_FISICO_EF11_REQUERIDO",
        }
    }
}

impl fmt::Display for CodigoPep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodigoPep::Capacidad(c) => write!(f, "DENY({})/{}", self.token(), c),
            CodigoPep::Evidencia(s) => write!(f, "DENY({})/{}", self.token(), s),
            other => write!(f, "DENY({})", other.token()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoIntento {
    Permitido,
    Denegado(CodigoPep),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistroIntentoPep {
    pub ticks: Ticks,
    pub sistema: Option<IdSistema>,
    pub resultado: ResultadoIntento,
    pub digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RespuestaInferencia {
    pub digest_resultado: [u8; LONGITUD_HASH_PAQUETE],
    pub referencia_minima: String,
    pub recibo: ReciboEfecto,
    pub antiguedad_vista_ms: Ticks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultadoPep {
    Permitido(RespuestaInferencia),
    Denegado { codigo: CodigoPep },
}

/// Gateway EF-1. No decide, no emite capacidades, no posee credencial de proveedor.
pub struct GatewayModelos {
    verificador: VerificadorCapacidades,
    intentos: Vec<RegistroIntentoPep>,
    incidentes: Vec<IncidenteMediacion>,
}

impl GatewayModelos {
    pub fn nuevo(suelo_epoca: u64) -> Self {
        GatewayModelos {
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

    /// El PEP no autoriza por sí mismo: no hay API de emisión aquí.
    pub const fn puede_emitir_capacidad() -> bool {
        false
    }

    pub const fn posee_credencial_proveedor() -> bool {
        false
    }

    /// Ejercer EF-1: validar/consumir capacidad y solo entonces ejecutar delegado.
    pub fn ejercer<A: AlmacenEvidencia>(
        &mut self,
        cruda: &SolicitudCruda,
        capacidad: Option<&Capability>,
        sistema: &IdSistema,
        sujeto: &IdSujeto,
        ledger: &mut LedgerEvidencia<A>,
        proveedor: &mut dyn ProveedorModelo,
        reloj: &impl RelojMonotonico,
        epoca_actual: u64,
    ) -> ResultadoPep {
        let ticks = reloj.ahora();

        let solicitud = match cruda {
            SolicitudCruda::NoTipificable => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::EfectoNoTipificado,
                );
            }
            SolicitudCruda::ClaseNoSoportada(_) => {
                return self.denegar(
                    ticks,
                    Some(sistema.clone()),
                    None,
                    CodigoPep::ClaseNoSoportada,
                );
            }
            SolicitudCruda::Tipada(s) => s,
        };

        let digest_sol = digest_solicitud_inferencia(solicitud);

        let Some(cap) = capacidad else {
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::CapacidadAusente,
            );
        };

        let alcance_intento = Alcance::minimo(["EF-1"]).expect("EF-1");
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

        let resp = match proveedor.inferir_delegado(solicitud, cap.digest_efecto()) {
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

        if resp.digest_parametros_ejecutados != digest_sol
            || resp.digest_parametros_ejecutados != *cap.digest_efecto()
        {
            self.incidentes.push(IncidenteMediacion {
                tipo: TipoIncidente::DivergenciaParametros,
                id_capacidad: Some(*cap.id()),
                digest_autorizado: *cap.digest_efecto(),
                digest_ejecutado: resp.digest_parametros_ejecutados,
                ticks,
            });
            return self.denegar(
                ticks,
                Some(sistema.clone()),
                Some(digest_sol),
                CodigoPep::IncidenteMediacion,
            );
        }

        let condiciones = CondicionesAplicadas::desde_solicitud(solicitud);
        let digest_cond = canon_condiciones(&condiciones);
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
                    digest_ejecutado: resp.digest_parametros_ejecutados,
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

        ResultadoPep::Permitido(RespuestaInferencia {
            digest_resultado: resp.digest_resultado,
            referencia_minima: resp.referencia_minima,
            recibo,
            antiguedad_vista_ms: antiguedad,
        })
    }

    fn denegar(
        &mut self,
        ticks: Ticks,
        sistema: Option<IdSistema>,
        digest_solicitud: Option<[u8; LONGITUD_HASH_PAQUETE]>,
        codigo: CodigoPep,
    ) -> ResultadoPep {
        self.intentos.push(RegistroIntentoPep {
            ticks,
            sistema,
            resultado: ResultadoIntento::Denegado(codigo.clone()),
            digest_solicitud,
        });
        ResultadoPep::Denegado { codigo }
    }
}

/// Alcance mínimo típico para emitir capacidad EF-1.
pub fn alcance_ef1() -> Alcance {
    Alcance::minimo(["EF-1"]).expect("EF-1")
}

/// Construye solicitud tipada y su digest (para ligar la capacidad).
pub fn preparar_solicitud(
    modelo: &str,
    prompt_digest: [u8; LONGITUD_HASH_PAQUETE],
    max_tokens: u32,
    temperatura_millis: u32,
) -> (SolicitudInferencia, [u8; LONGITUD_HASH_PAQUETE]) {
    let s = SolicitudInferencia::nueva(modelo, prompt_digest, max_tokens, temperatura_millis)
        .expect("solicitud");
    let d = digest_solicitud_inferencia(&s);
    (s, d)
}
