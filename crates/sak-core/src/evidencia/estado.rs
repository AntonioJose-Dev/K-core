//! Estado del dominio respecto a la evidencia.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoDominio {
    Operative,
    Suspended,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorEvidencia {
    DominioSuspendido,
    EscrituraFallida,
    HuecoSecuencia { esperado: u64, encontrado: u64 },
    DecisionSinCita,
    DecisionYaComprometida,
    CapacidadYaEmitida,
    EmisionCapacidadRechazada,
    Firma(String),
    Verificacion(String),
    ReciboSinDecision,
    CitaPaqueteIrresoluble,
}

impl fmt::Display for ErrorEvidencia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorEvidencia::DominioSuspendido => f.write_str("dominio SUSPENDED"),
            ErrorEvidencia::EscrituraFallida => {
                f.write_str("evidencia no escribible; dominio suspendido")
            }
            ErrorEvidencia::HuecoSecuencia {
                esperado,
                encontrado,
            } => write!(
                f,
                "hueco de secuencia: esperado {esperado}, encontrado {encontrado}"
            ),
            ErrorEvidencia::DecisionSinCita => {
                f.write_str("decision sin hash de paquete o sin normas citadas")
            }
            ErrorEvidencia::DecisionYaComprometida => {
                f.write_str("decision permisiva ya tiene registro comprometido")
            }
            ErrorEvidencia::CapacidadYaEmitida => {
                f.write_str("ya se emitio capacidad para esta decision comprometida")
            }
            ErrorEvidencia::EmisionCapacidadRechazada => {
                f.write_str("emision de capacidad rechazada (epoca/ttl/ligadura)")
            }
            ErrorEvidencia::Firma(s) => write!(f, "firma: {s}"),
            ErrorEvidencia::Verificacion(s) => write!(f, "verificacion: {s}"),
            ErrorEvidencia::ReciboSinDecision => {
                f.write_str("recibo sin decision previa en la cadena")
            }
            ErrorEvidencia::CitaPaqueteIrresoluble => {
                f.write_str("cita de paquete normativo irresoluble; dominio SUSPENDED")
            }
        }
    }
}

impl std::error::Error for ErrorEvidencia {}
