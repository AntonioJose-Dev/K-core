//! Hechos firmados del Libro (D.3) con productor, versión, caducidad y época.

use crate::contexto::ClaseEfecto;
use crate::crypto::{self, dominio, ParMlDsa87};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::IdSistema;
use crate::reloj::Ticks;
use std::collections::BTreeSet;
use std::fmt;

/// Tipos de hecho D.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TipoHecho {
    Custodia,
    Exclusividad,
    PepAtestado,
    SondaOk,
    Delegado,
    Confinado,
    Observable,
    Ef9Abierto,
    Alcanzables,
}

impl TipoHecho {
    pub fn token(self) -> &'static str {
        match self {
            TipoHecho::Custodia => "CUSTODIA",
            TipoHecho::Exclusividad => "EXCLUSIVIDAD",
            TipoHecho::PepAtestado => "PEP_ATESTADO",
            TipoHecho::SondaOk => "SONDA_OK",
            TipoHecho::Delegado => "DELEGADO",
            TipoHecho::Confinado => "CONFINADO",
            TipoHecho::Observable => "OBSERVABLE",
            TipoHecho::Ef9Abierto => "EF9_ABIERTO",
            TipoHecho::Alcanzables => "ALCANZABLES",
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "CUSTODIA" => Some(TipoHecho::Custodia),
            "EXCLUSIVIDAD" => Some(TipoHecho::Exclusividad),
            "PEP_ATESTADO" => Some(TipoHecho::PepAtestado),
            "SONDA_OK" => Some(TipoHecho::SondaOk),
            "DELEGADO" => Some(TipoHecho::Delegado),
            "CONFINADO" => Some(TipoHecho::Confinado),
            "OBSERVABLE" => Some(TipoHecho::Observable),
            "EF9_ABIERTO" => Some(TipoHecho::Ef9Abierto),
            "ALCANZABLES" => Some(TipoHecho::Alcanzables),
            _ => None,
        }
    }

    /// Hechos de detección de elusión (requieren prueba §I).
    pub fn es_elusion(self) -> bool {
        matches!(
            self,
            TipoHecho::Custodia
                | TipoHecho::Exclusividad
                | TipoHecho::PepAtestado
                | TipoHecho::SondaOk
                | TipoHecho::Ef9Abierto
                | TipoHecho::Confinado
        )
    }
}

impl fmt::Display for TipoHecho {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// Antigüedad máxima en ticks (1 tick ≡ 1 ms de política), Matriz D.3.
pub fn antigüedad_maxima(tipo: TipoHecho) -> Ticks {
    match tipo {
        TipoHecho::PepAtestado => 30_000,
        TipoHecho::SondaOk | TipoHecho::Confinado => 300_000,
        _ => 3_600_000,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductorHecho {
    CustodiaSecretos,
    DeteccionBypass,
    RegistroPep,
    SondaAdversarial,
    EmisorCapacidades,
    AtestacionConfinamiento,
    IngestaRegistros,
    InspeccionConfiguracion,
    InventarioAlcanzables,
}

impl ProductorHecho {
    pub fn token(self) -> &'static str {
        match self {
            ProductorHecho::CustodiaSecretos => "custodia_secretos",
            ProductorHecho::DeteccionBypass => "deteccion_bypass",
            ProductorHecho::RegistroPep => "registro_pep",
            ProductorHecho::SondaAdversarial => "sonda_adversarial",
            ProductorHecho::EmisorCapacidades => "emisor_capacidades",
            ProductorHecho::AtestacionConfinamiento => "atestacion_confinamiento",
            ProductorHecho::IngestaRegistros => "ingesta_registros",
            ProductorHecho::InspeccionConfiguracion => "inspeccion_configuracion",
            ProductorHecho::InventarioAlcanzables => "inventario_alcanzables",
        }
    }

    pub fn para_tipo(tipo: TipoHecho) -> Self {
        match tipo {
            TipoHecho::Custodia => ProductorHecho::CustodiaSecretos,
            TipoHecho::Exclusividad => ProductorHecho::DeteccionBypass,
            TipoHecho::PepAtestado => ProductorHecho::RegistroPep,
            TipoHecho::SondaOk => ProductorHecho::SondaAdversarial,
            TipoHecho::Delegado => ProductorHecho::EmisorCapacidades,
            TipoHecho::Confinado => ProductorHecho::AtestacionConfinamiento,
            TipoHecho::Observable => ProductorHecho::IngestaRegistros,
            TipoHecho::Ef9Abierto => ProductorHecho::InspeccionConfiguracion,
            TipoHecho::Alcanzables => ProductorHecho::InventarioAlcanzables,
        }
    }

    pub fn desde_token(s: &str) -> Option<Self> {
        match s {
            "custodia_secretos" => Some(ProductorHecho::CustodiaSecretos),
            "deteccion_bypass" => Some(ProductorHecho::DeteccionBypass),
            "registro_pep" => Some(ProductorHecho::RegistroPep),
            "sonda_adversarial" => Some(ProductorHecho::SondaAdversarial),
            "emisor_capacidades" => Some(ProductorHecho::EmisorCapacidades),
            "atestacion_confinamiento" => Some(ProductorHecho::AtestacionConfinamiento),
            "ingesta_registros" => Some(ProductorHecho::IngestaRegistros),
            "inspeccion_configuracion" => Some(ProductorHecho::InspeccionConfiguracion),
            "inventario_alcanzables" => Some(ProductorHecho::InventarioAlcanzables),
            _ => None,
        }
    }
}

/// Hecho firmado del Libro. Caducado ⇒ se evalúa como falso.
#[derive(Debug, Clone)]
pub struct HechoFirmadoLibro {
    pub tipo: TipoHecho,
    pub sistema: IdSistema,
    /// `None` solo para hechos de sistema (`CONFINADO`, `EF9_ABIERTO`, `ALCANZABLES`).
    pub clase: Option<ClaseEfecto>,
    pub valor: bool,
    pub productor: ProductorHecho,
    pub version: u32,
    pub epoca: u64,
    pub emitido_en: Ticks,
    pub antigüedad_max: Ticks,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub firma: Vec<u8>,
    /// PK del firmante (verificación offline de integridad).
    pub pk_firmante: Vec<u8>,
    /// Límite explícito de lo que la prueba **no** demuestra.
    pub no_demuestra: &'static str,
}

impl HechoFirmadoLibro {
    pub fn vigente(&self, ahora: Ticks) -> bool {
        ahora.saturating_sub(self.emitido_en) <= self.antigüedad_max
    }

    /// Verdadero solo si el hecho está vigente, íntegro y su valor es true.
    pub fn efectivo(&self, ahora: Ticks) -> bool {
        self.integridad_ok() && self.vigente(ahora) && self.valor
    }

    /// Alcance §D.3: hechos de sistema sin clase; el resto con clase.
    pub fn alcance_ok(&self) -> bool {
        match self.tipo {
            TipoHecho::Confinado | TipoHecho::Ef9Abierto | TipoHecho::Alcanzables => {
                self.clase.is_none()
            }
            _ => self.clase.is_some(),
        }
    }

    pub fn cuerpo_canonico_sin_firma(&self) -> Vec<u8> {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(self.tipo.token().as_bytes());
        cuerpo.push(0);
        cuerpo.extend_from_slice(self.sistema.como_str().as_bytes());
        cuerpo.push(0);
        if let Some(c) = self.clase {
            cuerpo.extend_from_slice(c.token().as_bytes());
        }
        cuerpo.push(0);
        cuerpo.push(u8::from(self.valor));
        cuerpo.extend_from_slice(self.productor.token().as_bytes());
        cuerpo.push(0);
        cuerpo.extend_from_slice(&self.version.to_le_bytes());
        cuerpo.extend_from_slice(&self.epoca.to_le_bytes());
        cuerpo.extend_from_slice(&self.emitido_en.to_le_bytes());
        cuerpo.extend_from_slice(&self.antigüedad_max.to_le_bytes());
        cuerpo
    }

    /// Productor asignado, alcance, digest y firma coherentes.
    pub fn integridad_ok(&self) -> bool {
        if self.productor != ProductorHecho::para_tipo(self.tipo) {
            return false;
        }
        if !self.alcance_ok() {
            return false;
        }
        let dig = crypto::sha384_dominio(dominio::LIBRO, &self.cuerpo_canonico_sin_firma());
        if dig != self.digest {
            return false;
        }
        if self.pk_firmante.is_empty() || self.firma.is_empty() {
            return false;
        }
        ParMlDsa87::verificar(&self.pk_firmante, &self.digest, &self.firma).is_ok()
    }

    pub fn firmar(
        tipo: TipoHecho,
        sistema: IdSistema,
        clase: Option<ClaseEfecto>,
        valor: bool,
        version: u32,
        epoca: u64,
        emitido_en: Ticks,
        no_demuestra: &'static str,
        firmante: &ParMlDsa87,
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let productor = ProductorHecho::para_tipo(tipo);
        let antigüedad_max = antigüedad_maxima(tipo);
        let mut h = HechoFirmadoLibro {
            tipo,
            sistema,
            clase,
            valor,
            productor,
            version,
            epoca,
            emitido_en,
            antigüedad_max,
            digest: [0u8; LONGITUD_HASH_PAQUETE],
            firma: vec![],
            pk_firmante: firmante.public.clone(),
            no_demuestra,
        };
        if !h.alcance_ok() {
            return Err(crate::crypto::ErrorCrypto::Clave);
        }
        h.digest = crypto::sha384_dominio(dominio::LIBRO, &h.cuerpo_canonico_sin_firma());
        h.firma = firmante.firmar(&h.digest)?;
        Ok(h)
    }
}

/// Inventario `ALCANZABLES(s)` firmado, versionado y con caducidad (H-3 / rebanada EF-9).
///
/// Declara expresamente: los tests prueban el uso correcto del inventario
/// instrumentado, **no** su completitud ante activos desconocidos o un host privilegiado.
#[derive(Debug, Clone)]
pub struct InventarioAlcanzables {
    pub sistema: IdSistema,
    /// Instancia / despliegue observado.
    pub instancia: String,
    pub efectores: BTreeSet<ClaseEfecto>,
    /// Rutas de red observadas (host:puerto o CIDR tipados).
    pub rutas_red: BTreeSet<String>,
    /// Identificadores/digests de credenciales o artefactos detectados (nunca material).
    pub credenciales_detectadas: BTreeSet<String>,
    pub almacenes: BTreeSet<String>,
    pub puntos_servicio: BTreeSet<String>,
    pub canales_consumo: BTreeSet<String>,
    /// Si true, el productor declara inventario incompleto ⇒ no sostiene ausencia de degradación.
    pub incompleto_declarado: bool,
    pub version: u32,
    pub epoca: u64,
    pub emitido_en: Ticks,
    pub antigüedad_max: Ticks,
    pub productor: ProductorHecho,
    pub productor_id: String,
    pub digest: [u8; LONGITUD_HASH_PAQUETE],
    pub firma: Vec<u8>,
    pub pk_firmante: Vec<u8>,
    pub no_demuestra: &'static str,
}

impl InventarioAlcanzables {
    pub const NO_DEMUESTRA: &'static str =
        "uso correcto del inventario instrumentado, no completitud frente a activos desconocidos ni host privilegiado (INV-11)";

    pub fn vigente(&self, ahora: Ticks) -> bool {
        !self.incompleto_declarado
            && ahora.saturating_sub(self.emitido_en) <= self.antigüedad_max
    }

    /// Vigencia estructural (firma/caducidad) sin exigir completitud.
    pub fn no_caducado(&self, ahora: Ticks) -> bool {
        ahora.saturating_sub(self.emitido_en) <= self.antigüedad_max
    }

    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(b"ALCANZABLES|");
        cuerpo.extend_from_slice(self.sistema.como_str().as_bytes());
        cuerpo.push(0);
        escribir_str(&mut cuerpo, &self.instancia);
        for e in &self.efectores {
            cuerpo.extend_from_slice(e.token().as_bytes());
            cuerpo.push(b',');
        }
        cuerpo.push(0);
        for r in &self.rutas_red {
            escribir_str(&mut cuerpo, r);
        }
        cuerpo.push(0);
        for c in &self.credenciales_detectadas {
            escribir_str(&mut cuerpo, c);
        }
        cuerpo.push(0);
        for a in &self.almacenes {
            escribir_str(&mut cuerpo, a);
        }
        cuerpo.push(0);
        for p in &self.puntos_servicio {
            escribir_str(&mut cuerpo, p);
        }
        cuerpo.push(0);
        for c in &self.canales_consumo {
            escribir_str(&mut cuerpo, c);
        }
        cuerpo.push(u8::from(self.incompleto_declarado));
        cuerpo.extend_from_slice(&self.version.to_le_bytes());
        cuerpo.extend_from_slice(&self.epoca.to_le_bytes());
        cuerpo.extend_from_slice(&self.emitido_en.to_le_bytes());
        escribir_str(&mut cuerpo, &self.productor_id);
        cuerpo
    }

    pub fn firmar(
        sistema: IdSistema,
        efectores: BTreeSet<ClaseEfecto>,
        version: u32,
        epoca: u64,
        emitido_en: Ticks,
        firmante: &ParMlDsa87,
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        Self::firmar_completo(
            sistema,
            "default",
            efectores,
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            false,
            version,
            epoca,
            emitido_en,
            "inventario-instrumentado",
            firmante,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn firmar_completo(
        sistema: IdSistema,
        instancia: impl Into<String>,
        efectores: BTreeSet<ClaseEfecto>,
        rutas_red: BTreeSet<String>,
        credenciales_detectadas: BTreeSet<String>,
        almacenes: BTreeSet<String>,
        puntos_servicio: BTreeSet<String>,
        canales_consumo: BTreeSet<String>,
        incompleto_declarado: bool,
        version: u32,
        epoca: u64,
        emitido_en: Ticks,
        productor_id: impl Into<String>,
        firmante: &ParMlDsa87,
    ) -> Result<Self, crate::crypto::ErrorCrypto> {
        let antigüedad_max = antigüedad_maxima(TipoHecho::Alcanzables);
        let mut inv = InventarioAlcanzables {
            sistema,
            instancia: instancia.into(),
            efectores,
            rutas_red,
            credenciales_detectadas,
            almacenes,
            puntos_servicio,
            canales_consumo,
            incompleto_declarado,
            version,
            epoca,
            emitido_en,
            antigüedad_max,
            productor: ProductorHecho::InventarioAlcanzables,
            productor_id: productor_id.into(),
            digest: [0u8; LONGITUD_HASH_PAQUETE],
            firma: Vec::new(),
            pk_firmante: firmante.public.clone(),
            no_demuestra: Self::NO_DEMUESTRA,
        };
        let digest = crypto::sha384_dominio(dominio::LIBRO, &inv.cuerpo_canonico());
        let firma = firmante.firmar(&digest)?;
        inv.digest = digest;
        inv.firma = firma;
        Ok(inv)
    }

    pub fn integridad_ok(&self) -> bool {
        if self.productor != ProductorHecho::InventarioAlcanzables {
            return false;
        }
        let digest = crypto::sha384_dominio(dominio::LIBRO, &self.cuerpo_canonico());
        if digest != self.digest {
            return false;
        }
        if self.pk_firmante.is_empty() || self.firma.is_empty() {
            return false;
        }
        ParMlDsa87::verificar(&self.pk_firmante, &self.digest, &self.firma).is_ok()
    }

    pub fn verificar_firma(&self, public: &[u8]) -> Result<(), crate::crypto::ErrorCrypto> {
        let digest = crypto::sha384_dominio(dominio::LIBRO, &self.cuerpo_canonico());
        if digest != self.digest {
            return Err(crate::crypto::ErrorCrypto::Verificacion);
        }
        ParMlDsa87::verificar(public, &self.digest, &self.firma)
    }

    /// Serialización para ledger TipoRegistro::Ef9.
    pub fn serializar_ledger(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(1); // INVENTARIO
        v.extend_from_slice(&self.digest);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(&self.epoca.to_le_bytes());
        v.push(u8::from(self.incompleto_declarado));
        v.extend_from_slice(&(self.efectores.len() as u16).to_le_bytes());
        for e in &self.efectores {
            v.extend_from_slice(e.token().as_bytes());
            v.push(b'|');
        }
        v
    }
}

fn escribir_str(v: &mut Vec<u8>, s: &str) {
    v.extend_from_slice(&(s.len() as u32).to_le_bytes());
    v.extend_from_slice(s.as_bytes());
}
