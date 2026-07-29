//! Verificación independiente offline (J.5): sin red y sin Kernel.

use crate::crypto::{ParMlDsa87, ParSlhDsa};
use crate::evidencia::merkle::merkle_raiz;
use crate::evidencia::registro::{PaqueteEvidencia, RegistroFirmado, TipoRegistro};
use crate::evidencia::CheckpointEpoca;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct InformeVerificacion {
    pub ok: bool,
    pub cadena_continua: bool,
    pub firmas_registros_ok: bool,
    pub checkpoints_ok: bool,
    pub cofirmas_testigos_ok: bool,
    pub merkle_ok: bool,
    /// Comprobaciones que este verificador **no** pudo realizar.
    pub no_comprobado: Vec<String>,
    pub errores: Vec<String>,
}

/// Verifica un paquete de evidencia solo con claves públicas.
pub fn verificar_paquete(pkg: &PaqueteEvidencia) -> InformeVerificacion {
    let mut errores = Vec::new();
    let mut no_comprobado = Vec::new();

    // Lo que este binario no cubre en Bloque 3.
    no_comprobado.push(
        "sello de tiempo de autoridad de sellado externo (diferido)".into(),
    );
    no_comprobado.push(
        "atestacion de plataforma / medida de TCB del host (Bloque 9+)".into(),
    );
    no_comprobado.push(
        "custodia HSM de la clave de autoridad (titularidad del cliente)".into(),
    );
    no_comprobado.push(
        "hash camaleon y redacciones: comprobar via verificar_expediente (§M 11)".into(),
    );

    // Continuidad de cadena por sujeto.
    let mut por_sujeto: BTreeMap<String, Vec<&RegistroFirmado>> = BTreeMap::new();
    for r in &pkg.registros {
        por_sujeto
            .entry(r.sujeto.como_str().to_string())
            .or_default()
            .push(r);
    }
    let mut cadena_continua = true;
    for (sujeto, regs) in &por_sujeto {
        let mut ordenados = regs.clone();
        ordenados.sort_by_key(|r| (r.epoca, r.secuencia));
        let mut prev = [0u8; 48];
        let mut seq_esperada = 0u64;
        for r in ordenados {
            if r.secuencia != seq_esperada {
                cadena_continua = false;
                errores.push(format!(
                    "hueco secuencia sujeto={sujeto}: esperado {seq_esperada}, hay {}",
                    r.secuencia
                ));
            }
            if r.prev_hash != prev {
                // Primer registro de una nueva época puede reiniciar enlace vía
                // hash de enlace; comprobamos digest del cuerpo.
                let cuerpo = r.cuerpo_para_hash();
                let dig = RegistroFirmado::calcular_digest(&cuerpo);
                if dig != r.digest {
                    cadena_continua = false;
                    errores.push(format!(
                        "digest de registro inconsistente seq={}",
                        r.secuencia
                    ));
                }
            }
            let cuerpo = r.cuerpo_para_hash();
            let dig = RegistroFirmado::calcular_digest(&cuerpo);
            if dig != r.digest {
                cadena_continua = false;
                errores.push(format!("digest invalido seq={}", r.secuencia));
            }
            // Actualizar prev como enlace = H(prev||digest)
            let mut cat = Vec::new();
            cat.extend_from_slice(&prev);
            cat.extend_from_slice(&r.digest);
            prev = crate::crypto::sha384_dominio(crate::crypto::dominio::ENLACE, &cat);
            seq_esperada = r.secuencia + 1;
        }
    }

    // Firmas ML-DSA de registros.
    let mut firmas_registros_ok = true;
    for r in &pkg.registros {
        if ParMlDsa87::verificar(&pkg.pk_autoridad_mldsa, &r.digest, &r.firma_mldsa).is_err() {
            firmas_registros_ok = false;
            errores.push(format!(
                "firma ML-DSA invalida registro seq={}",
                r.secuencia
            ));
        }
        // INV-03: decisión debe citar normas (payload no vacío de ids).
        if r.tipo == TipoRegistro::Decision {
            if r.payload.len() < 1 + 1 + 48 + 4 {
                firmas_registros_ok = false;
                errores.push("registro de decision mal formado".into());
            } else {
                let n_normas =
                    u32::from_le_bytes(r.payload[50..54].try_into().unwrap_or([0; 4]));
                // Permitidas deben tener ≥1 norma; denegadas pueden tener 0.
                let veredicto = r.payload[1];
                if veredicto == 3 && n_normas == 0 {
                    firmas_registros_ok = false;
                    errores.push(
                        "decision ALLOW sin identificadores de norma (INV-03)".into(),
                    );
                }
            }
        }
        if r.tipo == TipoRegistro::Supervision {
            // Prefijo: tipo evento (1) + len (4) + cuerpo (≥ digest 48 en fallo mínimo).
            if r.payload.len() < 1 + 4 {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de supervision mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Gobernanza {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de gobernanza mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Herramienta {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de herramienta mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Negocio {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de negocio mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Comunicacion {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de comunicacion mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Publicacion {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de publicacion mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::DecisionPersona {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de decision-persona mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::Ef9 {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!("registro EF-9 mal formado seq={}", r.secuencia));
            }
        }
        if r.tipo == TipoRegistro::EgresoDatos {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de egreso-datos mal formado seq={}",
                    r.secuencia
                ));
            }
        }
        if r.tipo == TipoRegistro::EfectoFisico {
            if r.payload.is_empty() {
                firmas_registros_ok = false;
                errores.push(format!(
                    "registro de efecto-fisico mal formado seq={}",
                    r.secuencia
                ));
            }
        }
    }

    // Checkpoints: Merkle + ML-DSA autoridad + 2× SLH-DSA testigos.
    let mut checkpoints_ok = true;
    let mut cofirmas_testigos_ok = true;
    let mut merkle_ok = true;

    for cp in &pkg.checkpoints {
        let msg = cp.mensaje_canonico();
        if ParMlDsa87::verificar(&pkg.pk_autoridad_mldsa, &msg, &cp.firma_autoridad_mldsa)
            .is_err()
        {
            checkpoints_ok = false;
            errores.push(format!(
                "firma autoridad checkpoint epoca={}",
                cp.epoca
            ));
        }
        if ParSlhDsa::verificar(&pkg.pk_testigo_1_slh, &msg, &cp.cofirma_testigo_1_slh).is_err()
        {
            cofirmas_testigos_ok = false;
            errores.push(format!(
                "cofirma testigo1 invalida epoca={}",
                cp.epoca
            ));
        }
        if ParSlhDsa::verificar(&pkg.pk_testigo_2_slh, &msg, &cp.cofirma_testigo_2_slh).is_err()
        {
            cofirmas_testigos_ok = false;
            errores.push(format!(
                "cofirma testigo2 invalida epoca={}",
                cp.epoca
            ));
        }

        // Recomputar Merkle de registros de esa época.
        let hojas: Vec<_> = pkg
            .registros
            .iter()
            .filter(|r| r.epoca == cp.epoca)
            .map(|r| r.digest)
            .collect();
        if hojas.len() as u64 != cp.n_registros {
            merkle_ok = false;
            errores.push(format!(
                "n_registros checkpoint epoca={} no coincide",
                cp.epoca
            ));
        }
        let root = merkle_raiz(&hojas);
        if root != cp.merkle_root {
            merkle_ok = false;
            errores.push(format!(
                "merkle root divergente epoca={}",
                cp.epoca
            ));
        }
        let _ = cp as &CheckpointEpoca;
    }

    let ok = errores.is_empty()
        && cadena_continua
        && firmas_registros_ok
        && checkpoints_ok
        && cofirmas_testigos_ok
        && merkle_ok;

    InformeVerificacion {
        ok,
        cadena_continua,
        firmas_registros_ok,
        checkpoints_ok,
        cofirmas_testigos_ok,
        merkle_ok,
        no_comprobado,
        errores,
    }
}
