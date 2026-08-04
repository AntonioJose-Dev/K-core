//! Libro de Control (Bloque 8): INV-09, INV-10, INV-11; Matriz D.3 e I.
//!
//! El nivel se **calcula** a partir de hechos firmados con caducidad. El operador
//! puede rebajar; **no existe** interfaz que eleve. Hecho caducado ⇒ falso.
//! §M 12: confinamiento I.10, sonda EF-1…12, multiparte (perfiles avanzados).

mod bypass;
mod calculo;
mod confinamiento;
mod evaluador_ef9;
mod hecho;
mod libro_ctrl;
mod libro_durable;
mod minimo;
mod multiparte;
mod nivel;
mod puerta;
mod sonda_ef;

pub use bypass::{
    ejecutar_prueba, limite_no_demuestra, EntradaPrueba, ResultadoPruebaBypass, TipoPruebaBypass,
};
pub use calculo::{
    aplicar_degradacion_ef9, calcular_nivel_base, confinado_sin_custodia_exclusividad_no_es_c5,
    denominacion_si_c5_calculado, EvaluacionNivel, VistaHechos,
};
pub use confinamiento::{
    AtestacionConfinamiento, EntradaPredicadosI10, ErrorConfinamiento, IdPredicadoI10,
    PredicadoEvaluado, ANTIGUEDAD_CONFINADO_TICKS, PREDICADO6_SONDA_DIEZ_V1,
};
pub use evaluador_ef9::{
    control_alcanza_minimo, libro_suficiente_c3, libro_suficiente_c4, EvaluadorEf9,
    ObservacionEntornoEf9, PerfilEf9, ResultadoEvaluacionEf9, SenalEf9,
};
pub use hecho::{
    antigüedad_maxima, HechoFirmadoLibro, InventarioAlcanzables, ProductorHecho, TipoHecho,
};
pub use libro_ctrl::{ErrorLibro, LibroControl, ParSistemaClase};
pub use libro_durable::{
    cargar_libro_desde_almacen, conservar_libro, clave_almacen_libro, ErrorLibroDurable,
};
pub use minimo::minimo_exigido;
pub use multiparte::{
    aceptar_certificado, emitir_certificado_vista, quorum_dos_tercios_mas_uno,
    registrar_vista_si_compatible, CertificadoCambioVista, ErrorVista, IdNodo,
};
pub use nivel::{
    NivelControl, C5_CALCULADO_SOBRE_HECHOS_APORTADOS, C5_HOST_REAL_PROHIBIDO,
};
pub use puerta::{
    comprobar_puerta_control, decidir_con_libro, decidir_paquete_con_libro, DecisionConControl,
    ResultadoPuertaControl,
};
pub use sonda_ef::{
    denegar_ef12_siempre, es_deny_ef12, ejecutar_sonda_doce_sin_capacidad,
    recorrer_puerta_sin_capacidad, verificar_resultado_sonda, ErrorSonda, ReciboSondaClase,
    ResultadoIntentoSonda, ResultadoSondaDoce,
};
