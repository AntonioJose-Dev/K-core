//! Objeto de norma G.1: firma lógica, serialización determinista, carga.
//!
//! Un paquete con un solo campo obligatorio ausente **no es cargable**.
//! `interpretación` no puede estar vacía; autor identificado obligatorio (INV-16).
//!
//! Esquema publicado: `schemas/norma_v1.cddl`.

use crate::contexto::{ClaseEfecto, IdProductor};
use crate::decision::{HashPaqueteNormativo, IdNorma, LONGITUD_HASH_PAQUETE};
use crate::perfil::Rango;
use crate::predicado::{self, Predicado};
use sha2::{Digest, Sha384};
use std::fmt;

/// Esquema CDDL publicado (G.1). Incluido en el crate autoritativo como dato,
/// no como lógica jurídica (INV-13).
pub const ESQUEMA_NORMA_V1: &str = include_str!("../../../schemas/norma_v1.cddl");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Naturaleza {
    Prohibicion = 1,
    Obligacion = 2,
    Condicion = 3,
    Definicion = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Operacionalidad {
    L1 = 1,
    L2 = 2,
    L3 = 3,
    L4 = 4,
}

/// Materias reservadas (G.4): no codificables como L1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MateriaReservada {
    InterpretacionOperativa = 1,
    ClasificacionOperacionalidad = 2,
    ClasificacionRiesgoCasoNuevo = 3,
    ImpactoDerechosFundamentales = 4,
    EvaluacionConformidad = 5,
    CompetenciaAprobador = 6,
    ExcepcionOBaseJuridica = 7,
    CalificacionIncidenteGrave = 8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fecha {
    pub anio: u16,
    pub mes: u8,
    pub dia: u8,
}

impl Fecha {
    pub fn nueva(anio: u16, mes: u8, dia: u8) -> Result<Self, ErrorCarga> {
        if mes == 0 || mes > 12 || dia == 0 || dia > 31 {
            return Err(ErrorCarga::FechaInvalida);
        }
        Ok(Fecha { anio, mes, dia })
    }

    /// Días desde 1970-01-01 (aprox. civil, suficiente para vigencia).
    pub fn a_epoch_dias(self) -> u32 {
        let y = self.anio as i32;
        let m = self.mes as i32;
        let d = self.dia as i32;
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = (y - era * 400) as u32;
        let m = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * m + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy as u32;
        (era as u32)
            .wrapping_mul(146097)
            .wrapping_add(doe)
            .wrapping_sub(719468)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vigencia {
    pub entrada: Fecha,
    pub termino: Option<Fecha>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alcance {
    pub caso_de_uso: String,
    pub clase_riesgo: String,
    pub rol_regulatorio: String,
    pub sector: String,
    pub categorias_datos: String,
    pub autonomia: String,
    pub destinatarios: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequisitoEvidencia {
    pub productor: IdProductor,
    pub antiguedad_maxima_segundos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpretacion {
    pub texto: String,
    pub autor: String,
    /// Digest de la evidencia de aprobación (dato; verificación cripto en Bloque 3).
    pub digest_aprobacion: [u8; LONGITUD_HASH_PAQUETE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escalado {
    pub rol: String,
    pub competencia: String,
    pub quorum: u8,
    pub plazo_segundos: u64,
    pub exige_independencia: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monitorizacion {
    pub que: String,
    pub periodo_segundos: u64,
    pub umbral: String,
}

/// Norma cargada y validada. Campos privados; solo se obtiene vía `cargar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Norma {
    identificador: IdNorma,
    fuente: String,
    jurisdiccion: String,
    vigencia: Vigencia,
    alcance: Alcance,
    naturaleza: Naturaleza,
    operacionalidad: Operacionalidad,
    clase_de_efecto: ClaseEfecto,
    predicado: Predicado,
    evidencia_exigida: Vec<RequisitoEvidencia>,
    acciones_obligatorias: Vec<String>,
    condiciones_de_denegacion: Vec<String>,
    escalado: Option<Escalado>,
    monitorizacion: Option<Monitorizacion>,
    interpretacion: Interpretacion,
    ambigua: bool,
    rango: Rango,
    hash: HashPaqueteNormativo,
    pretende_resolver: Vec<MateriaReservada>,
}

/// Borrador previo a la validación y al sellado del hash.
#[derive(Debug, Clone)]
pub struct BorradorNorma {
    pub identificador: String,
    pub fuente: String,
    pub jurisdiccion: String,
    pub vigencia: Vigencia,
    pub alcance: Alcance,
    pub naturaleza: Naturaleza,
    pub operacionalidad: Operacionalidad,
    pub clase_de_efecto: ClaseEfecto,
    pub predicado: Predicado,
    pub evidencia_exigida: Vec<RequisitoEvidencia>,
    pub acciones_obligatorias: Vec<String>,
    pub condiciones_de_denegacion: Vec<String>,
    pub escalado: Option<Escalado>,
    pub monitorizacion: Option<Monitorizacion>,
    pub interpretacion: Interpretacion,
    pub ambigua: bool,
    pub rango: Rango,
    pub pretende_resolver: Vec<MateriaReservada>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCarga {
    CampoObligatorioAusente(&'static str),
    InterpretacionVacia,
    AutorNoIdentificado,
    IdInvalido,
    FechaInvalida,
    HashNoCoincide,
    MateriaReservadaComoL1(MateriaReservada),
    /// Firma del paquete inválida o ausente cuando se exige (G.5 / Bloque 11).
    FirmaInvalida,
    /// Versión de esquema distinta de la publicada.
    EsquemaDesconocido(u32),
    /// Cita jurídica no resoluble en el registro de citas (VAL-EXT / GOB).
    CitaNoResoluble,
    /// Interpretación sin evidencia de aprobación verificable (INV-16).
    InterpretacionSinAprobacion,
}

impl fmt::Display for ErrorCarga {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorCarga::CampoObligatorioAusente(c) => write!(f, "campo obligatorio ausente: {c}"),
            ErrorCarga::InterpretacionVacia => f.write_str("interpretacion operativa vacia"),
            ErrorCarga::AutorNoIdentificado => f.write_str("autor de interpretacion no identificado"),
            ErrorCarga::IdInvalido => f.write_str("identificador de norma invalido"),
            ErrorCarga::FechaInvalida => f.write_str("fecha de vigencia invalida"),
            ErrorCarga::HashNoCoincide => f.write_str("hash del objeto canonico no coincide"),
            ErrorCarga::MateriaReservadaComoL1(m) => {
                write!(f, "materia reservada codificada como L1: {m:?}")
            }
            ErrorCarga::FirmaInvalida => f.write_str("firma de paquete normativo invalida"),
            ErrorCarga::EsquemaDesconocido(v) => write!(f, "esquema normativo desconocido: {v}"),
            ErrorCarga::CitaNoResoluble => f.write_str("cita juridica no resoluble"),
            ErrorCarga::InterpretacionSinAprobacion => {
                f.write_str("interpretacion sin aprobacion verificable")
            }
        }
    }
}

impl std::error::Error for ErrorCarga {}

fn no_vacio(s: &str, campo: &'static str) -> Result<(), ErrorCarga> {
    if s.trim().is_empty() {
        Err(ErrorCarga::CampoObligatorioAusente(campo))
    } else {
        Ok(())
    }
}

impl Norma {
    /// Valida campos obligatorios, materias reservadas y sella el hash SHA-384.
    pub fn cargar(b: BorradorNorma) -> Result<Self, ErrorCarga> {
        no_vacio(&b.identificador, "identificador")?;
        no_vacio(&b.fuente, "fuente")?;
        no_vacio(&b.jurisdiccion, "jurisdiccion")?;
        no_vacio(&b.alcance.caso_de_uso, "alcance.caso_de_uso")?;
        no_vacio(&b.alcance.clase_riesgo, "alcance.clase_riesgo")?;
        no_vacio(&b.alcance.rol_regulatorio, "alcance.rol_regulatorio")?;
        no_vacio(&b.alcance.sector, "alcance.sector")?;
        no_vacio(&b.alcance.categorias_datos, "alcance.categorias_datos")?;
        no_vacio(&b.alcance.autonomia, "alcance.autonomia")?;
        no_vacio(&b.alcance.destinatarios, "alcance.destinatarios")?;
        if b.interpretacion.texto.trim().is_empty() {
            return Err(ErrorCarga::InterpretacionVacia);
        }
        if b.interpretacion.autor.trim().is_empty() {
            return Err(ErrorCarga::AutorNoIdentificado);
        }
        if b.operacionalidad == Operacionalidad::L1 {
            if let Some(m) = b.pretende_resolver.first() {
                return Err(ErrorCarga::MateriaReservadaComoL1(*m));
            }
        }
        let id = IdNorma::nueva(b.identificador).map_err(|_| ErrorCarga::IdInvalido)?;

        let mut n = Norma {
            identificador: id,
            fuente: b.fuente,
            jurisdiccion: b.jurisdiccion,
            vigencia: b.vigencia,
            alcance: b.alcance,
            naturaleza: b.naturaleza,
            operacionalidad: b.operacionalidad,
            clase_de_efecto: b.clase_de_efecto,
            predicado: b.predicado,
            evidencia_exigida: b.evidencia_exigida,
            acciones_obligatorias: b.acciones_obligatorias,
            condiciones_de_denegacion: b.condiciones_de_denegacion,
            escalado: b.escalado,
            monitorizacion: b.monitorizacion,
            interpretacion: b.interpretacion,
            ambigua: b.ambigua,
            rango: b.rango,
            hash: HashPaqueteNormativo::desde_bytes([0u8; LONGITUD_HASH_PAQUETE]),
            pretende_resolver: b.pretende_resolver,
        };
        let digest = n.digest_canonico();
        n.hash = HashPaqueteNormativo::desde_bytes(digest);
        Ok(n)
    }

    /// Rechaza si el hash declarado no coincide con el objeto canónico.
    pub fn cargar_con_hash_declarado(
        b: BorradorNorma,
        hash_declarado: HashPaqueteNormativo,
    ) -> Result<Self, ErrorCarga> {
        let n = Self::cargar(b)?;
        if n.hash != hash_declarado {
            return Err(ErrorCarga::HashNoCoincide);
        }
        Ok(n)
    }

    pub fn digest_canonico(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        let bytes = self.serializar_canonico_sin_hash();
        let mut hasher = Sha384::new();
        hasher.update(&bytes);
        let out = hasher.finalize();
        let mut arr = [0u8; LONGITUD_HASH_PAQUETE];
        arr.copy_from_slice(&out);
        arr
    }

    fn serializar_canonico_sin_hash(&self) -> Vec<u8> {
        let mut out = Vec::new();
        escribir(&mut out, self.identificador.como_str());
        escribir(&mut out, &self.fuente);
        escribir(&mut out, &self.jurisdiccion);
        out.extend_from_slice(&self.vigencia.entrada.anio.to_le_bytes());
        out.push(self.vigencia.entrada.mes);
        out.push(self.vigencia.entrada.dia);
        match self.vigencia.termino {
            None => out.push(0),
            Some(t) => {
                out.push(1);
                out.extend_from_slice(&t.anio.to_le_bytes());
                out.push(t.mes);
                out.push(t.dia);
            }
        }
        escribir(&mut out, &self.alcance.caso_de_uso);
        escribir(&mut out, &self.alcance.clase_riesgo);
        escribir(&mut out, &self.alcance.rol_regulatorio);
        escribir(&mut out, &self.alcance.sector);
        escribir(&mut out, &self.alcance.categorias_datos);
        escribir(&mut out, &self.alcance.autonomia);
        escribir(&mut out, &self.alcance.destinatarios);
        out.push(self.naturaleza as u8);
        out.push(self.operacionalidad as u8);
        out.push(self.clase_de_efecto as u8);
        predicado::serializar_canonico(&self.predicado, &mut out);
        out.extend_from_slice(&(self.evidencia_exigida.len() as u32).to_le_bytes());
        for e in &self.evidencia_exigida {
            escribir(&mut out, e.productor.como_str());
            out.extend_from_slice(&e.antiguedad_maxima_segundos.to_le_bytes());
        }
        out.extend_from_slice(&(self.acciones_obligatorias.len() as u32).to_le_bytes());
        for a in &self.acciones_obligatorias {
            escribir(&mut out, a);
        }
        out.extend_from_slice(&(self.condiciones_de_denegacion.len() as u32).to_le_bytes());
        for c in &self.condiciones_de_denegacion {
            escribir(&mut out, c);
        }
        match &self.escalado {
            None => out.push(0),
            Some(e) => {
                out.push(1);
                escribir(&mut out, &e.rol);
                escribir(&mut out, &e.competencia);
                out.push(e.quorum);
                out.extend_from_slice(&e.plazo_segundos.to_le_bytes());
                out.push(u8::from(e.exige_independencia));
            }
        }
        match &self.monitorizacion {
            None => out.push(0),
            Some(m) => {
                out.push(1);
                escribir(&mut out, &m.que);
                out.extend_from_slice(&m.periodo_segundos.to_le_bytes());
                escribir(&mut out, &m.umbral);
            }
        }
        escribir(&mut out, &self.interpretacion.texto);
        escribir(&mut out, &self.interpretacion.autor);
        out.extend_from_slice(&self.interpretacion.digest_aprobacion);
        out.push(u8::from(self.ambigua));
        out.push(self.rango as u8);
        out.extend_from_slice(&(self.pretende_resolver.len() as u32).to_le_bytes());
        for m in &self.pretende_resolver {
            out.push(*m as u8);
        }
        out
    }

    pub fn id(&self) -> &IdNorma {
        &self.identificador
    }
    pub fn fuente(&self) -> &str {
        &self.fuente
    }
    pub fn jurisdiccion(&self) -> &str {
        &self.jurisdiccion
    }
    pub fn vigencia(&self) -> &Vigencia {
        &self.vigencia
    }
    pub fn naturaleza(&self) -> Naturaleza {
        self.naturaleza
    }
    pub fn operacionalidad(&self) -> Operacionalidad {
        self.operacionalidad
    }
    pub fn clase_de_efecto(&self) -> ClaseEfecto {
        self.clase_de_efecto
    }
    pub fn predicado(&self) -> &Predicado {
        &self.predicado
    }
    pub fn evidencia_exigida(&self) -> &[RequisitoEvidencia] {
        &self.evidencia_exigida
    }
    pub fn escalado(&self) -> Option<&Escalado> {
        self.escalado.as_ref()
    }
    pub fn interpretacion(&self) -> &Interpretacion {
        &self.interpretacion
    }
    pub fn ambigua(&self) -> bool {
        self.ambigua
    }
    pub fn rango(&self) -> Rango {
        self.rango
    }
    pub fn hash(&self) -> &HashPaqueteNormativo {
        &self.hash
    }
}

fn escribir(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

/// Paquete normativo: conjunto de normas cargadas + hash del paquete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaqueteNormativo {
    normas: Vec<Norma>,
    hash: HashPaqueteNormativo,
}

impl PaqueteNormativo {
    pub fn cargar(normas: Vec<Norma>) -> Result<Self, ErrorCarga> {
        if normas.is_empty() {
            // Un paquete vacío es cargable como dato, pero no cubre casos:
            // el motor denegará por INV-02. No es error de carga.
        }
        let mut ordenadas = normas;
        ordenadas.sort_by(|a, b| a.id().como_str().cmp(b.id().como_str()));
        for w in ordenadas.windows(2) {
            if w[0].id() == w[1].id() {
                return Err(ErrorCarga::CampoObligatorioAusente("identificador_unico"));
            }
        }
        let mut hasher = Sha384::new();
        for n in &ordenadas {
            hasher.update(n.hash().bytes());
        }
        let out = hasher.finalize();
        let mut arr = [0u8; LONGITUD_HASH_PAQUETE];
        arr.copy_from_slice(&out);
        Ok(PaqueteNormativo {
            normas: ordenadas,
            hash: HashPaqueteNormativo::desde_bytes(arr),
        })
    }

    pub fn normas(&self) -> &[Norma] {
        &self.normas
    }

    pub fn hash(&self) -> &HashPaqueteNormativo {
        &self.hash
    }

    pub fn aplicables_a(&self, clase: ClaseEfecto) -> impl Iterator<Item = &Norma> {
        self.normas.iter().filter(move |n| n.clase_de_efecto() == clase)
    }

    /// Serialización canónica del paquete (hashes de normas ordenadas).
    pub fn serializar_canonico(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(self.normas.len() as u32).to_le_bytes());
        for n in &self.normas {
            out.extend_from_slice(n.hash().bytes());
        }
        out.extend_from_slice(self.hash.bytes());
        out
    }

    /// Mensaje firmable del paquete (dominio PAQUETE_NORMA).
    pub fn mensaje_firma(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crate::crypto::sha384_dominio(
            crate::crypto::dominio::PAQUETE_NORMA,
            &self.serializar_canonico(),
        )
    }
}

/// Versión publicada del esquema normativo (G.1 / CDDL v1).
pub const ESQUEMA_NORMA_VERSION: u32 = 1;
