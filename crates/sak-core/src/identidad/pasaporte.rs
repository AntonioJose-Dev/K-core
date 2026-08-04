//! Pasaporte soberano firmado y versionado (INV-04 / §E Registro).

use crate::crypto::{self, dominio, ParMlDsa87, ErrorCrypto};
use crate::decision::LONGITUD_HASH_PAQUETE;
use crate::identidad::artefacto::IdSistema;

/// Declaración firmada del responsable (§E: entrada del Registro soberano).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaracionResponsable {
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    modelos: String,
    jurisdiccion: String,
    datos: String,
    autonomia_por_clase: String,
    herramientas: String,
    efectores: String,
    clasificacion_riesgo: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    firma_responsable: Vec<u8>,
    pk_responsable: Vec<u8>,
}

impl DeclaracionResponsable {
    /// Firma la declaración con la clave del responsable.
    pub fn firmar(
        par: &ParMlDsa87,
        sistema_id: IdSistema,
        responsable: impl Into<String>,
        finalidad: impl Into<String>,
        modelos: impl Into<String>,
        jurisdiccion: impl Into<String>,
        datos: impl Into<String>,
        autonomia_por_clase: impl Into<String>,
        herramientas: impl Into<String>,
        efectores: impl Into<String>,
        clasificacion_riesgo: impl Into<String>,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
    ) -> Result<Self, ErrorCrypto> {
        let mut d = DeclaracionResponsable {
            sistema_id,
            responsable: responsable.into(),
            finalidad: finalidad.into(),
            modelos: modelos.into(),
            jurisdiccion: jurisdiccion.into(),
            datos: datos.into(),
            autonomia_por_clase: autonomia_por_clase.into(),
            herramientas: herramientas.into(),
            efectores: efectores.into(),
            clasificacion_riesgo: clasificacion_riesgo.into(),
            vigente_desde_dias,
            vigente_hasta_dias,
            firma_responsable: vec![],
            pk_responsable: par.public.clone(),
        };
        d.firma_responsable = par.firmar(&d.cuerpo_canonico())?;
        Ok(d)
    }

    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-DECL-RESP-v1|");
        escribir_campo(&mut v, self.sistema_id.como_str());
        escribir_campo(&mut v, &self.responsable);
        escribir_campo(&mut v, &self.finalidad);
        escribir_campo(&mut v, &self.modelos);
        escribir_campo(&mut v, &self.jurisdiccion);
        escribir_campo(&mut v, &self.datos);
        escribir_campo(&mut v, &self.autonomia_por_clase);
        escribir_campo(&mut v, &self.herramientas);
        escribir_campo(&mut v, &self.efectores);
        escribir_campo(&mut v, &self.clasificacion_riesgo);
        v.extend_from_slice(&self.vigente_desde_dias.to_le_bytes());
        v.extend_from_slice(&self.vigente_hasta_dias.to_le_bytes());
        v
    }

    pub fn firma_valida(&self) -> bool {
        if self.firma_responsable.is_empty() || self.pk_responsable.is_empty() {
            return false;
        }
        ParMlDsa87::verificar(
            &self.pk_responsable,
            &self.cuerpo_canonico(),
            &self.firma_responsable,
        )
        .is_ok()
    }

    pub fn sistema_id(&self) -> &IdSistema {
        &self.sistema_id
    }
    pub fn responsable(&self) -> &str {
        &self.responsable
    }
    pub fn finalidad(&self) -> &str {
        &self.finalidad
    }
    pub fn modelos(&self) -> &str {
        &self.modelos
    }
    pub fn jurisdiccion(&self) -> &str {
        &self.jurisdiccion
    }
    pub fn datos(&self) -> &str {
        &self.datos
    }
    pub fn autonomia_por_clase(&self) -> &str {
        &self.autonomia_por_clase
    }
    pub fn herramientas(&self) -> &str {
        &self.herramientas
    }
    pub fn efectores(&self) -> &str {
        &self.efectores
    }
    pub fn clasificacion_riesgo(&self) -> &str {
        &self.clasificacion_riesgo
    }
    pub fn vigente_desde_dias(&self) -> u32 {
        self.vigente_desde_dias
    }
    pub fn vigente_hasta_dias(&self) -> u32 {
        self.vigente_hasta_dias
    }
    pub fn firma_responsable(&self) -> &[u8] {
        &self.firma_responsable
    }
    pub fn pk_responsable(&self) -> &[u8] {
        &self.pk_responsable
    }

    /// Reconstruye una declaración ya firmada (canal operador / IPC). Verifica la firma.
    pub fn reconstruir(
        sistema_id: IdSistema,
        responsable: impl Into<String>,
        finalidad: impl Into<String>,
        modelos: impl Into<String>,
        jurisdiccion: impl Into<String>,
        datos: impl Into<String>,
        autonomia_por_clase: impl Into<String>,
        herramientas: impl Into<String>,
        efectores: impl Into<String>,
        clasificacion_riesgo: impl Into<String>,
        vigente_desde_dias: u32,
        vigente_hasta_dias: u32,
        firma_responsable: Vec<u8>,
        pk_responsable: Vec<u8>,
    ) -> Result<Self, &'static str> {
        if firma_responsable.is_empty() || pk_responsable.is_empty() {
            return Err("firma o pk de responsable ausente");
        }
        let d = DeclaracionResponsable {
            sistema_id,
            responsable: responsable.into(),
            finalidad: finalidad.into(),
            modelos: modelos.into(),
            jurisdiccion: jurisdiccion.into(),
            datos: datos.into(),
            autonomia_por_clase: autonomia_por_clase.into(),
            herramientas: herramientas.into(),
            efectores: efectores.into(),
            clasificacion_riesgo: clasificacion_riesgo.into(),
            vigente_desde_dias,
            vigente_hasta_dias,
            firma_responsable,
            pk_responsable,
        };
        if !d.firma_valida() {
            return Err("firma de responsable invalida");
        }
        Ok(d)
    }

    /// Digest SHA-384 del cuerpo canónico (anti-engaño / IPC).
    pub fn digest_cuerpo(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, &self.cuerpo_canonico())
    }
}

/// Pasaporte de un sistema de IA (INV-04).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pasaporte {
    id: String,
    version: u32,
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    modelos: String,
    jurisdiccion: String,
    datos: String,
    autonomia_por_clase: String,
    herramientas: String,
    efectores: String,
    clasificacion_riesgo: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    /// Firma del registro soberano sobre el cuerpo canónico.
    firma: Vec<u8>,
    /// PK del registro que firmó (para verificación offline del propio objeto).
    pk_registro: Vec<u8>,
}

impl Pasaporte {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn sistema_id(&self) -> &str {
        self.sistema_id.como_str()
    }
    pub fn responsable(&self) -> &str {
        &self.responsable
    }
    pub fn finalidad(&self) -> &str {
        &self.finalidad
    }
    pub fn modelos(&self) -> &str {
        &self.modelos
    }
    pub fn jurisdiccion(&self) -> &str {
        &self.jurisdiccion
    }
    pub fn datos(&self) -> &str {
        &self.datos
    }
    pub fn autonomia_por_clase(&self) -> &str {
        &self.autonomia_por_clase
    }
    pub fn herramientas(&self) -> &str {
        &self.herramientas
    }
    pub fn efectores(&self) -> &str {
        &self.efectores
    }
    pub fn clasificacion_riesgo(&self) -> &str {
        &self.clasificacion_riesgo
    }
    pub fn vigente_desde_dias(&self) -> u32 {
        self.vigente_desde_dias
    }
    pub fn vigente_hasta_dias(&self) -> u32 {
        self.vigente_hasta_dias
    }
    pub fn firma(&self) -> &[u8] {
        &self.firma
    }
    pub fn pk_registro(&self) -> &[u8] {
        &self.pk_registro
    }

    pub fn cuerpo_canonico(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"SAK-PASSPORT-v1|");
        v.extend_from_slice(self.id.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.version.to_le_bytes());
        v.extend_from_slice(self.sistema_id.como_str().as_bytes());
        v.push(0);
        v.extend_from_slice(self.responsable.as_bytes());
        v.push(0);
        v.extend_from_slice(self.finalidad.as_bytes());
        v.push(0);
        // Campos §E (Registro soberano); vacíos en registros legados vía `registrar`.
        escribir_campo(&mut v, &self.modelos);
        escribir_campo(&mut v, &self.jurisdiccion);
        escribir_campo(&mut v, &self.datos);
        escribir_campo(&mut v, &self.autonomia_por_clase);
        escribir_campo(&mut v, &self.herramientas);
        escribir_campo(&mut v, &self.efectores);
        escribir_campo(&mut v, &self.clasificacion_riesgo);
        v.extend_from_slice(&self.vigente_desde_dias.to_le_bytes());
        v.extend_from_slice(&self.vigente_hasta_dias.to_le_bytes());
        v
    }

    pub fn digest(&self) -> [u8; LONGITUD_HASH_PAQUETE] {
        crypto::sha384_dominio(dominio::REGISTRO, &self.cuerpo_canonico())
    }

    pub fn firma_valida(&self) -> bool {
        if self.version == 0 || self.firma.is_empty() || self.pk_registro.is_empty() {
            return false;
        }
        ParMlDsa87::verificar(&self.pk_registro, &self.cuerpo_canonico(), &self.firma).is_ok()
    }

    pub fn vigente_en(&self, instante_epoch_dias: u32) -> bool {
        instante_epoch_dias >= self.vigente_desde_dias
            && instante_epoch_dias <= self.vigente_hasta_dias
    }
}

/// Pasaporte ya verificado como vigente, firmado y versionado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasaporteVigente {
    inner: Pasaporte,
}

impl PasaporteVigente {
    pub fn pasaporte(&self) -> &Pasaporte {
        &self.inner
    }
    pub fn id(&self) -> &str {
        self.inner.id()
    }
    pub fn version(&self) -> u32 {
        self.inner.version()
    }
    pub fn sistema_id(&self) -> &str {
        self.inner.sistema_id()
    }
}

fn escribir_campo(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    out.extend_from_slice(&(b.len() as u16).to_le_bytes());
    out.extend_from_slice(b);
}

/// Construcción interna por el registro (firma incluida).
pub(super) fn sellar_pasaporte(
    id: String,
    version: u32,
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    modelos: String,
    jurisdiccion: String,
    datos: String,
    autonomia_por_clase: String,
    herramientas: String,
    efectores: String,
    clasificacion_riesgo: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    firmante: &ParMlDsa87,
) -> Result<Pasaporte, ErrorCrypto> {
    let mut p = Pasaporte {
        id,
        version,
        sistema_id,
        responsable,
        finalidad,
        modelos,
        jurisdiccion,
        datos,
        autonomia_por_clase,
        herramientas,
        efectores,
        clasificacion_riesgo,
        vigente_desde_dias,
        vigente_hasta_dias,
        firma: vec![],
        pk_registro: firmante.public.clone(),
    };
    p.firma = firmante.firmar(&p.cuerpo_canonico())?;
    Ok(p)
}

/// Reconstitución desde almacén durable (firma ya presente).
pub(super) fn desde_almacen(
    id: String,
    version: u32,
    sistema_id: IdSistema,
    responsable: String,
    finalidad: String,
    modelos: String,
    jurisdiccion: String,
    datos: String,
    autonomia_por_clase: String,
    herramientas: String,
    efectores: String,
    clasificacion_riesgo: String,
    vigente_desde_dias: u32,
    vigente_hasta_dias: u32,
    firma: Vec<u8>,
    pk_registro: Vec<u8>,
) -> Pasaporte {
    Pasaporte {
        id,
        version,
        sistema_id,
        responsable,
        finalidad,
        modelos,
        jurisdiccion,
        datos,
        autonomia_por_clase,
        herramientas,
        efectores,
        clasificacion_riesgo,
        vigente_desde_dias,
        vigente_hasta_dias,
        firma,
        pk_registro,
    }
}

pub(super) fn como_vigente(p: Pasaporte) -> PasaporteVigente {
    PasaporteVigente { inner: p }
}
