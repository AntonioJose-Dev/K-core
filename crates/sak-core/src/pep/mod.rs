//! Puntos de aplicación (PEP).
//!
//! Rebanadas de repositorio (nombres `bloqueN_*` en tests = etiqueta de repo,
//! **no** filas §M). Mapa: ver `docs/TRAZABILIDAD-REBANADAS-EF3-EF11.md`.
//!
//! - §M 6 / EF-1: gateway de inferencia
//! - §M 7 / EF-2: gateway de datos
//! - EF-3: gateway de escritura (C; rebanada repo `bloque12`)
//! - EF-4: broker de herramientas/MCP (C/F.5; `bloque13`)
//! - EF-5: ejecutor de negocio (C; `bloque14`)
//! - EF-6: gateway de comunicaciones (C; `bloque15`)
//! - EF-7: gateway de publicación (C; `bloque16`)
//! - EF-8: PEP de consumo (C [V1.1-H1]; `bloque17`)
//! - EF-9: régimen prohibición/confinamiento — **no** PEP de mediación (C/INV-11; `bloque18`; atestación → §M 12)
//! - EF-10: gateway de egreso (C; `bloque19`)
//! - EF-11: PEP físico interpuesto simulado (C/F.9; `bloque20`)
//!
//! INV-06: el PEP aplica el veredicto de la capacidad; no decide, no crea
//! autoridad y no posee credencial de efector propia.

mod adaptador_comunicacion;
mod adaptador_consumo;
mod adaptador_egreso;
mod adaptador_herramienta;
mod adaptador_negocio;
mod adaptador_publicacion;
mod almacen;
mod broker;
mod catalogo;
mod ejecutor;
mod ejecutor_negocio;
mod gateway;
mod gateway_comunicaciones;
mod gateway_consumo;
mod gateway_datos;
mod gateway_egreso;
mod gateway_escritura;
mod gateway_fisico;
mod gateway_publicacion;
mod incidente;
mod modulo_fisico;
mod proveedor;
mod proveedor_loopback;
mod proveedor_nvidia_ef1;
mod solicitud;
mod solicitud_comunicacion;
mod solicitud_consumo;
mod solicitud_datos;
mod solicitud_egreso;
mod solicitud_escritura;
mod solicitud_fisico;
mod solicitud_herramienta;
mod solicitud_negocio;
mod solicitud_publicacion;

pub use adaptador_comunicacion::{
    AdaptadorComunicacion, AdaptadorComunicacionSimulado, CredencialEnvio,
    ErrorAdaptadorComunicacion, EstadoDestinatario, ResultadoComunicacion,
    ResultadoPorDestinatario,
};
pub use adaptador_consumo::{
    AdaptadorConsumoDecision, AdaptadorConsumoSimulado, ArtefactoConsumo, ErrorAdaptadorConsumo,
    EstadoConsumo, ResultadoConsumo,
};
pub use adaptador_egreso::{
    AdaptadorEgreso, AdaptadorEgresoSimulado, CredencialEgreso, ErrorAdaptadorEgreso, EstadoEgreso,
    ResultadoEgreso,
};
pub use adaptador_herramienta::{
    AdaptadorHerramientas, AdaptadorSimulado, CredencialHerramienta, ErrorAdaptador,
    ResultadoHerramienta,
};
pub use adaptador_negocio::{
    AdaptadorNegocio, AdaptadorNegocioSimulado, CredencialNegocio, ErrorAdaptadorNegocio,
    EstadoLiquidacion, ResultadoNegocio,
};
pub use adaptador_publicacion::{
    AdaptadorPublicacion, AdaptadorPublicacionSimulado, CredencialPublicacion,
    ErrorAdaptadorPublicacion, EstadoPublicacion, ResultadoPublicacion,
};
pub use almacen::{
    AlmacenDatos, AlmacenSimulado, CredencialDatos, ErrorAlmacen, ResultadoDatos,
};
pub use broker::{
    preparar_solicitud_herramienta, BrokerHerramientas, RegistroDelegacion, RespuestaHerramienta,
    ResultadoPepHerramienta,
};
pub use catalogo::{CatalogoHerramientas, EntradaHerramienta, ErrorCatalogo};
pub use ejecutor::{
    CredencialEscritura, EjecutorEscritura, EjecutorSimulado, ErrorEjecutor, ResultadoEscritura,
};
pub use ejecutor_negocio::{
    preparar_solicitud_negocio, EjecutorNegocio, RespuestaNegocio, ResultadoPepNegocio,
};
pub use gateway::{
    alcance_ef1, preparar_solicitud, CodigoPep, GatewayModelos, RegistroIntentoPep,
    RespuestaInferencia, ResultadoIntento, ResultadoPep,
};
pub use gateway_comunicaciones::{
    preparar_solicitud_comunicacion, GatewayComunicaciones, RespuestaComunicacion,
    ResultadoPepComunicacion,
};
pub use gateway_consumo::{
    preparar_solicitud_consumo, GatewayConsumoDecisionPersona, RespuestaConsumoDecision,
    ResultadoPepConsumo,
};
pub use gateway_datos::{
    preparar_solicitud_datos, GatewayDatos, RespuestaDatos, ResultadoPepDatos,
};
pub use gateway_egreso::{
    preparar_solicitud_egreso, GatewayEgresoDatos, RespuestaEgreso, ResultadoPepEgreso,
};
pub use gateway_escritura::{
    preparar_solicitud_escritura, GatewayEscritura, RespuestaEscritura, ResultadoPepEscritura,
};
pub use gateway_fisico::{
    preparar_solicitud_fisica, GatewayEfectoFisico, RespuestaFisica, ResultadoPepFisico,
};
pub use gateway_publicacion::{
    preparar_solicitud_publicacion, GatewayPublicacion, RespuestaPublicacion,
    ResultadoPepPublicacion,
};
pub use incidente::{IncidenteMediacion, TipoIncidente};
pub use modulo_fisico::{
    AutoridadBus, ErrorModuloFisico, FaseEjecucionFisica, InterlocksLocales,
    ModuloFisicoInterpuesto, ResultadoFisico,
};
pub use proveedor::{
    instalar_contexto_ejercicio_ef1, limpiar_contexto_ejercicio_ef1, tomar_contexto_ejercicio_ef1,
    ContextoEjercicioEf1, CredencialProveedor, ErrorEgreso, ErrorProveedor, ProveedorModelo,
    ProveedorSimulado, RespuestaModelo,
};
pub use proveedor_loopback::{
    atender_peticion_mock, construir_peticion_con_nonce, emitir_ticket_bytes, enviar_linea_mock,
    enviar_linea_pipe, generar_clave_efimera, generar_nonce_aleatorio, intentar_abrir_pipe,
    llamada_directa_sin_sello, parse_clave_hex, pipe_desde_env, sello_protocolo_antiguo,
    verificar_sello_con_nonce, verificar_ticket_v2, MockEf1Loopback, ProveedorLoopbackEf1,
    ENV_LOOPBACK_PIPE, HANDLE_EF1_PROBE_MEDIADO,
};
pub use proveedor_nvidia_ef1::{
    ultimo_diagnostico_nvidia, ClaseFallo, DiagnosticoProvider, ProveedorNvidiaEf1,
    HANDLE_EF1_PILOTO_NVIDIA, ENV_NVIDIA_KEY,
};
pub use solicitud::{
    canon_condiciones, digest_solicitud_inferencia, ClaseEfecto, CondicionesAplicadas,
    SolicitudCruda, SolicitudInferencia,
};
pub use solicitud_comunicacion::{
    alcance_ef6, digest_solicitud_comunicacion, traducir_comunicacion_desde_herramienta,
    AlcanceAutorizadoComunicacion, CanalComunicacion, CondicionesComunicacion,
    ConjuntoDestinatarios, EtiquetaHecho, HechoContactoExigido, PrecondicionesPepEf6,
    SolicitudComunicacion, SolicitudComunicacionCruda, TipoHechoContacto,
};
pub use solicitud_consumo::{
    alcance_ef8, digest_solicitud_consumo, AlcanceAutorizadoConsumo, CAMPO_CONSECUENCIA_EF8,
    ClaseDecisionPersona, HechoDecisionExigido, PrecondicionesPepEf8,
    SolicitudConsumoCruda, SolicitudConsumoDecisionPersona, TipoHechoDecision,
};
pub use solicitud_datos::{
    alcance_ef2, digest_solicitud_datos, AlcanceAutorizadoDatos, CondicionesMinimizacion,
    OperacionDatos, SolicitudDatos, SolicitudDatosCruda,
};
pub use solicitud_egreso::{
    alcance_ef10, digest_condiciones_egreso, digest_solicitud_egreso,
    traducir_egreso_desde_herramienta, AlcanceAutorizadoEgreso, CondicionesEgreso,
    HechoEgresoExigido, OperacionEgreso, PrecondicionesPepEf10, ProtocoloEgreso,
    SolicitudEgresoCruda, SolicitudEgresoDatos,
};
pub use solicitud_escritura::{
    alcance_ef3, digest_solicitud_escritura, AlcanceAutorizadoEscritura, CondicionesEscritura,
    OperacionEscritura, PrecondicionesPepEf3, SolicitudEscritura, SolicitudEscrituraCruda,
};
pub use solicitud_fisico::{
    alcance_ef11, digest_solicitud_fisica, traducir_fisico_desde_herramienta,
    AlcanceAutorizadoFisico, AprobacionHumanaFisica, HechoFisicoExigido, LimitesFisicos,
    ModoOperativo, OperacionFisica, ParametrosFisicos, PrecondicionesPepEf11,
    SolicitudEfectoFisico, SolicitudFisicaCruda,
};
pub use solicitud_herramienta::{
    alcance_ef4, digest_solicitud_herramienta, AlcanceAutorizadoHerramienta,
    CondicionesHerramienta, PrecondicionesPepEf4, SolicitudHerramienta, SolicitudHerramientaCruda,
};
pub use solicitud_negocio::{
    alcance_ef5, digest_solicitud_negocio, traducir_desde_herramienta, AlcanceAutorizadoNegocio,
    CondicionesNegocio, ImporteNormalizado, PrecondicionesPepEf5, SolicitudNegocioCruda,
    SolicitudOperacionNegocio, TipoOperacionNegocio,
};
pub use solicitud_publicacion::{
    alcance_ef7, digest_solicitud_publicacion, traducir_publicacion_desde_herramienta,
    AlcanceAutorizadoPublicacion, CanalPublicacion, CondicionesPublicacion,
    HechoPublicacionExigido, OperacionPublicacion, PrecondicionesPepEf7, SolicitudPublicacion,
    SolicitudPublicacionCruda,
};
