//! Libro de Control (Bloque 8): INV-09, INV-10, INV-11; Matriz D.3 e I.
//!
//! El nivel se **calcula** a partir de hechos firmados con caducidad. El operador
//! puede rebajar; **no existe** interfaz que eleve. Hecho caducado ⇒ falso.

mod bypass;
mod calculo;
mod evaluador_ef9;
mod hecho;
mod libro_ctrl;
mod minimo;
mod nivel;
mod puerta;

pub use bypass::{
    ejecutar_prueba, limite_no_demuestra, EntradaPrueba, ResultadoPruebaBypass, TipoPruebaBypass,
};
pub use calculo::{
    aplicar_degradacion_ef9, calcular_nivel_base, confinado_sin_custodia_exclusividad_no_es_c5,
    EvaluacionNivel, VistaHechos,
};
pub use evaluador_ef9::{
    control_alcanza_minimo, libro_suficiente_c3, libro_suficiente_c4, EvaluadorEf9,
    ObservacionEntornoEf9, PerfilEf9, ResultadoEvaluacionEf9, SenalEf9,
};
pub use hecho::{
    antigüedad_maxima, HechoFirmadoLibro, InventarioAlcanzables, ProductorHecho, TipoHecho,
};
pub use libro_ctrl::{ErrorLibro, LibroControl, ParSistemaClase};
pub use minimo::minimo_exigido;
pub use nivel::NivelControl;
pub use puerta::{
    comprobar_puerta_control, decidir_con_libro, decidir_paquete_con_libro, DecisionConControl,
    ResultadoPuertaControl,
};
