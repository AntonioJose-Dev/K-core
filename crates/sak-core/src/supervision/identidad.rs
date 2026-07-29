//! Identidades humanas autenticadas por clave y competencias atestadas (VAL-EXT).

use crate::contexto::ClaseEfecto;
use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::reloj::Ticks;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdHumano(String);

impl IdHumano {
    pub fn nuevo(id: impl Into<String>) -> Result<Self, &'static str> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err("id humano vacio");
        }
        Ok(IdHumano(id))
    }

    pub fn como_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdHumano {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Etiqueta de dependencia: el Kernel no determina competencia; la consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EtiquetaCompetencia {
    /// Supuesto operativo consumido sin prueba interna de gobernanza.
    Supuesto = 1,
    /// Validación externa (VAL-EXT): atestación humana/externa firmada.
    ValExt = 2,
}

impl EtiquetaCompetencia {
    pub const fn token(self) -> &'static str {
        match self {
            EtiquetaCompetencia::Supuesto => "SUPUESTO",
            EtiquetaCompetencia::ValExt => "VAL-EXT",
        }
    }
}

/// Identidad humana registrada con clave pública ML-DSA-87.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentidadHumana {
    pub id: IdHumano,
    pub pk_mldsa: Vec<u8>,
}

/// Competencia / rol atestados. El Kernel no decide si «es competente».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompetenciaAtestada {
    pub id_humano: IdHumano,
    pub rol: String,
    pub competencia: String,
    pub clase: ClaseEfecto,
    pub vigente_desde: Ticks,
    pub vigente_hasta: Ticks,
    pub etiqueta: EtiquetaCompetencia,
    /// Digest de la atestación externa (VAL-EXT / gobernanza).
    pub digest_atestacion: [u8; LONGITUD_HASH_PAQUETE],
    /// Firma del atestador externo sobre `digest_atestacion` (dato VAL-EXT).
    pub firma_atestador: Vec<u8>,
    /// Clave pública del atestador externo (opcional en harnesses; verificación VAL-EXT).
    pub pk_atestador: Vec<u8>,
}

impl CompetenciaAtestada {
    pub fn vigente_en(&self, ahora: Ticks) -> bool {
        ahora >= self.vigente_desde && ahora <= self.vigente_hasta
    }

    pub fn cubre(
        &self,
        id: &IdHumano,
        rol: &str,
        competencia: &str,
        clase: ClaseEfecto,
        ahora: Ticks,
    ) -> bool {
        &self.id_humano == id
            && self.rol == rol
            && self.competencia == competencia
            && self.clase == clase
            && self.vigente_en(ahora)
            && !self.firma_atestador.is_empty()
            && self.digest_atestacion != [0u8; LONGITUD_HASH_PAQUETE]
    }
}

/// Registro de identidades humanas y competencias atestadas.
#[derive(Debug, Default, Clone)]
pub struct RegistroHumanos {
    identidades: BTreeMap<String, IdentidadHumana>,
    competencias: Vec<CompetenciaAtestada>,
}

impl RegistroHumanos {
    pub fn nuevo() -> Self {
        Self::default()
    }

    pub fn registrar_identidad(&mut self, id: IdentidadHumana) -> Result<(), &'static str> {
        if id.pk_mldsa.is_empty() {
            return Err("pk humana vacia");
        }
        self.identidades
            .insert(id.id.como_str().to_string(), id);
        Ok(())
    }

    pub fn registrar_competencia(&mut self, c: CompetenciaAtestada) -> Result<(), &'static str> {
        if c.rol.trim().is_empty() || c.competencia.trim().is_empty() {
            return Err("rol o competencia vacios");
        }
        if c.firma_atestador.is_empty() {
            return Err("atestacion sin firma");
        }
        if c.vigente_hasta < c.vigente_desde {
            return Err("vigencia invertida");
        }
        self.competencias.push(c);
        Ok(())
    }

    pub fn identidad(&self, id: &IdHumano) -> Option<&IdentidadHumana> {
        self.identidades.get(id.como_str())
    }

    pub fn competencia_vigente(
        &self,
        id: &IdHumano,
        rol: &str,
        competencia: &str,
        clase: ClaseEfecto,
        ahora: Ticks,
    ) -> Option<&CompetenciaAtestada> {
        self.competencias
            .iter()
            .find(|c| c.cubre(id, rol, competencia, clase, ahora))
    }

    /// Existe atestación coincidente (rol/competencia/clase) aunque esté vencida.
    pub fn tiene_atestacion(
        &self,
        id: &IdHumano,
        rol: &str,
        competencia: &str,
        clase: ClaseEfecto,
    ) -> bool {
        self.competencias.iter().any(|c| {
            &c.id_humano == id
                && c.rol == rol
                && c.competencia == competencia
                && c.clase == clase
                && !c.firma_atestador.is_empty()
        })
    }

    /// Construye una atestación firmada de prueba (harnesses). Etiqueta VAL-EXT.
    pub fn atestacion_prueba(
        atestador: &ParMlDsa87,
        id_humano: IdHumano,
        rol: impl Into<String>,
        competencia: impl Into<String>,
        clase: ClaseEfecto,
        desde: Ticks,
        hasta: Ticks,
    ) -> Result<CompetenciaAtestada, crate::crypto::ErrorCrypto> {
        let rol = rol.into();
        let competencia = competencia.into();
        let mut msg = Vec::new();
        msg.extend_from_slice(id_humano.como_str().as_bytes());
        msg.push(0);
        msg.extend_from_slice(rol.as_bytes());
        msg.push(0);
        msg.extend_from_slice(competencia.as_bytes());
        msg.push(0);
        msg.push(clase as u8);
        msg.extend_from_slice(&desde.to_le_bytes());
        msg.extend_from_slice(&hasta.to_le_bytes());
        let digest = crypto::sha384_dominio(dominio::SUPERVISION, &msg);
        let firma = atestador.firmar(&digest)?;
        Ok(CompetenciaAtestada {
            id_humano,
            rol,
            competencia,
            clase,
            vigente_desde: desde,
            vigente_hasta: hasta,
            etiqueta: EtiquetaCompetencia::ValExt,
            digest_atestacion: digest,
            firma_atestador: firma,
            pk_atestador: atestador.public.clone(),
        })
    }
}
