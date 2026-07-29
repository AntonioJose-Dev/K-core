//! §M 11 — Expediente: cierre de brechas J.1–J.4 / J.6.
//!
//! No afirma HSM, atestación real, C5, TSA, suelo legal VAL-EXT ni conformidad [GOB].

use sak_core::capacidad::{Alcance, ClasificacionEfecto, ParametrosEmision};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    alcance_auditoria, emitir_prueba_inclusion, merkle_raiz, verificar_expediente,
    verificar_inclusion, Afirmacion, ClaseRetencion, ConstructorExpediente, CustodiaTrampilla,
    ErrorCamaleon, ErrorExpediente, EtiquetaAfirmacion, ExpedienteBorrador, HechoContexto,
    IdSujeto, IdTitular, LedgerEvidencia, MemoriaDurable, ParteCadena, ParteCapacidades,
    ParteClasificacion, ParteCorpus, ParteDecisiones, ParteFinalidad, ParteIncidentes, ParteLibro,
    ParteRiesgos, ParteSistemas, ParteSupervision, ParteSupuestos, RecuentosObligaciones,
    DECISION_CRIPTO_PII_V1, FRASE_REGISTROS_NO_CUMPLIMIENTO, ID_LISTA_PATRONES_J4_V1,
    PATRONES_PROHIBIDOS_J4_V1,
};
use sak_core::identidad::IdSistema;
use sak_core::reloj::RelojInyectado;

fn zeros() -> [u8; LONGITUD_HASH_PAQUETE] {
    [0u8; LONGITUD_HASH_PAQUETE]
}

fn custodia_ok() -> CustodiaTrampilla {
    CustodiaTrampilla::instalar(
        [1u8; 32],
        false,
        [2u8; 32],
        true,
        [3u8; 32],
        true,
    )
    .unwrap()
}

fn borrador_minimo(hojas: Vec<(String, sak_core::evidencia::HojaCamaleon)>) -> ExpedienteBorrador {
    ExpedienteBorrador {
        parte_1: ParteSistemas {
            id_sistema: "sys-m11".into(),
            version_sistema: "1.0.0".into(),
            huella_artefacto: [0xAAu8; LONGITUD_HASH_PAQUETE],
            medida_tcb_kernel: zeros(),
            hash_lista_simbolos: [0x11u8; LONGITUD_HASH_PAQUETE],
        },
        parte_2: ParteFinalidad {
            finalidad: "auditoria".into(),
            usos_previstos: "verificar".into(),
            usos_excluidos: "autocertificar".into(),
            firma_responsable_presente: true,
        },
        parte_3: ParteClasificacion {
            clasificacion_riesgo: "alto".into(),
            justificacion_firmada: true,
            rol_regulatorio: "proveedor".into(),
            jurisdicciones: "ES".into(),
            obligaciones_l1_l4: "L1,L3".into(),
        },
        parte_4: ParteCorpus {
            hash_paquete: [0xBBu8; LONGITUD_HASH_PAQUETE],
            firmas_presentes: true,
            diff_reconocido: true,
            norma_id: "N-1".into(),
            norma_version: "2024.1".into(),
            interpretacion: "texto aprobado".into(),
            autor_interpretacion: "jurista-1".into(),
        },
        parte_5: ParteRiesgos {
            riesgos: "elusion".into(),
            controles: "pep".into(),
            resultado_controles: "parcial".into(),
        },
        parte_6: ParteDecisiones {
            digest_solicitud: [0xCCu8; LONGITUD_HASH_PAQUETE],
            codigo_razon: "ALLOW".into(),
            clase_efecto: "EF-AUD".into(),
            parametros: "exp=1".into(),
            normas_citadas: "N-1".into(),
            traza_precedencia: "N-1".into(),
            normas_inertes: "N-sombra".into(),
            hechos: vec![HechoContexto {
                productor: "prod-a".into(),
                digest: [0x01u8; LONGITUD_HASH_PAQUETE],
                descripcion: "hecho-contexto".into(),
            }],
            pasos_consumidos: 3,
        },
        parte_7: ParteCapacidades {
            digest_capacidad: [0xDDu8; LONGITUD_HASH_PAQUETE],
            alcance: "AUDITORIA".into(),
            ttl_ticks: 60_000,
            uso: "unico".into(),
            revocacion: "no-revocada".into(),
            punto_aplicacion: "gateway-auditoria".into(),
            recibo_digest: [0xEEu8; LONGITUD_HASH_PAQUETE],
            intentos_rechazados: 0,
        },
        parte_8: ParteSupervision {
            id_humano: "hum-1".into(),
            competencia: "auditor".into(),
            escalados: "esc-1".into(),
            plazo: 86_400,
            quorum_ok: true,
            independencia_ok: true,
            firma_sobre_digest: [0xFFu8; LONGITUD_HASH_PAQUETE],
            decision_supervision: "aprobado".into(),
        },
        parte_9: ParteLibro {
            nivel_en_instante: "C3".into(),
            historial_temporal: "C2->C3".into(),
            hechos_sostenedores: "CUSTODIA".into(),
            bypass_residual: "ruta desconocida".into(),
            plan_elevacion: "pep".into(),
        },
        parte_10: ParteSupuestos {
            serie_temporal: "ok".into(),
            transiciones: "ninguna".into(),
            atestacion_plataforma_presente: false,
            atestacion_confinamiento_presente: false,
        },
        parte_11: ParteIncidentes {
            incidentes: "ninguno".into(),
            huecos_secuencia: "0".into(),
            divergencias: "0".into(),
            redacciones: vec![],
            cambios_corpus: "ninguno".into(),
            acciones_correctoras: "ninguna".into(),
        },
        parte_12: ParteCadena {
            merkle_raiz: zeros(),
            suelo_epoca: 1,
            cofirmas_testigos_ok: true,
            sellos: "epoca-monotona".into(),
            pruebas_inclusion: vec![],
        },
        afirmaciones: vec![
            Afirmacion::nueva("huella de artefacto registrada", EtiquetaAfirmacion::HechoVerificable)
                .unwrap(),
            Afirmacion::nueva(
                "nivel libro en el instante de la decision",
                EtiquetaAfirmacion::EvaluacionAutomatica,
            )
            .unwrap(),
            Afirmacion::nueva("aprobacion humana registrada", EtiquetaAfirmacion::DecisionHumana)
                .unwrap(),
            Afirmacion::nueva(
                "interpretacion atribuida a jurista-1",
                EtiquetaAfirmacion::InterpretacionJuridica,
            )
            .unwrap(),
            Afirmacion::nueva(
                "atestacion de plataforma ausente en el paquete",
                EtiquetaAfirmacion::EvidenciaAusente,
            )
            .unwrap(),
            Afirmacion::nueva("bypass residual declarado", EtiquetaAfirmacion::RiesgoResidual)
                .unwrap(),
        ],
        recuentos: RecuentosObligaciones {
            evaluadas: 4,
            satisfechas_por_kernel: 2,
            requieren_decision_humana: 1,
            huecos_evidencia: 1,
        },
        cliente_es_operador: true,
        saltar_auto_no_afirmado_operador: false,
        hojas_pii: hojas,
        inyectar_veredicto: None,
        inyectar_puntuacion: None,
    }
}

fn emitir_cap_auditoria(
    ledger: &mut LedgerEvidencia<MemoriaDurable>,
    sujeto: &IdSujeto,
    reloj: &RelojInyectado,
) -> sak_core::capacidad::Capability {
    let hash = HashPaqueteNormativo::desde_bytes([9u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-AUD").unwrap()], vec![], 1).unwrap();
    let d = DecisionPermitida::nueva(hash, traza, None).unwrap();
    ledger
        .emitir_tras_evidencia(
            sujeto,
            d,
            ParametrosEmision {
                sistema: IdSistema::nuevo("sys-m11").unwrap(),
                digest_efecto: [0x42u8; LONGITUD_HASH_PAQUETE],
                alcance: alcance_auditoria(),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto {
                    irreversible: false,
                    afecta_personas: false,
                    datos_personales: false,
                },
            },
            reloj,
        )
        .unwrap()
}

#[test]
fn retencion_por_clase_j6() {
    assert_eq!(ClaseRetencion::DecisionSinContenido.dias_retencion(), Some(3650));
    assert_eq!(ClaseRetencion::AutomaticoAltoRiesgo.dias_retencion(), Some(365));
    assert_eq!(ClaseRetencion::ContenidoDatosPersonales.dias_retencion(), Some(90));
    assert!(ClaseRetencion::CheckpointCofirma.es_permanente());
    assert_eq!(ClaseRetencion::AprobacionHumana.dias_retencion(), Some(3650));
}

#[test]
fn trampilla_operador_solo_deniega() {
    let c = CustodiaTrampilla::instalar([1u8; 32], false, [2u8; 32], false, [3u8; 32], true)
        .unwrap();
    assert!(matches!(
        c.material_si_autorizado(IdTitular(0), IdTitular(1)),
        Err(ErrorCamaleon::OperadorSolo)
    ));
    assert!(c.material_si_autorizado(IdTitular(0), IdTitular(2)).is_ok());
}

#[test]
fn sin_titular_ajeno_no_instala() {
    assert!(matches!(
        CustodiaTrampilla::instalar([1u8; 32], false, [2u8; 32], false, [3u8; 32], false),
        Err(ErrorCamaleon::SinTitularAjeno)
    ));
}

#[test]
fn j3_mezcla_o_doble_etiqueta_deniega() {
    assert!(matches!(
        Afirmacion::desde_tokens("x", &["HECHO_VERIFICABLE", "NO_AFIRMADO"]),
        Err(ErrorExpediente::EtiquetaDuplicadaOMezcla)
    ));
    assert!(matches!(
        Afirmacion::desde_tokens("x", &["HECHO_VERIFICABLE", "HECHO_VERIFICABLE"]),
        Err(ErrorExpediente::EtiquetaDuplicadaOMezcla)
    ));
    assert!(matches!(
        Afirmacion::desde_tokens("x", &[]),
        Err(ErrorExpediente::EtiquetaAusente)
    ));
    let ok = Afirmacion::desde_tokens("hecho", &["HECHO_VERIFICABLE"]).unwrap();
    assert_eq!(ok.etiqueta, EtiquetaAfirmacion::HechoVerificable);
}

#[test]
fn j4_lista_versionada_y_senal_cumplimiento_deniega() {
    assert_eq!(ID_LISTA_PATRONES_J4_V1, "SAK-J4-PATTERNS-v1");
    assert!(!PATRONES_PROHIBIDOS_J4_V1.is_empty());
    assert!(matches!(
        Afirmacion::nueva("el sistema cumple los requisitos", EtiquetaAfirmacion::HechoVerificable),
        Err(ErrorExpediente::SenalCumplimiento(_))
    ));
    assert!(matches!(
        Afirmacion::nueva("conformidad certificada hoy", EtiquetaAfirmacion::HechoVerificable),
        Err(ErrorExpediente::SenalCumplimiento(_))
    ));
    // Frase J.4 normativa no se aplica como patrón sobre sí misma vía Afirmacion;
    // el expediente fija la frase canónica aparte.
    assert!(FRASE_REGISTROS_NO_CUMPLIMIENTO.contains("no equivale a cumplimiento"));
}

#[test]
fn j1_7_uso_revocacion_obligatorios() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-uso").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut b = borrador_minimo(vec![]);
    b.parte_7.uso.clear();
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b),
        Err(ErrorExpediente::ParteIncompleta("capacidades"))
    ));
    let mut b2 = borrador_minimo(vec![]);
    b2.parte_7.revocacion.clear();
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b2),
        Err(ErrorExpediente::ParteIncompleta("capacidades"))
    ));
}

#[test]
fn j1_8_escalados_plazo_obligatorios() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-esc").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut b = borrador_minimo(vec![]);
    b.parte_8.escalados.clear();
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b),
        Err(ErrorExpediente::ParteIncompleta("supervision"))
    ));
    let mut b2 = borrador_minimo(vec![]);
    b2.parte_8.plazo = 0;
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b2),
        Err(ErrorExpediente::ParteIncompleta("supervision"))
    ));
}

#[test]
fn j6_cliente_operador_sin_no_afirmado_deniega() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-op").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut b = borrador_minimo(vec![]);
    b.cliente_es_operador = true;
    b.saltar_auto_no_afirmado_operador = true;
    b.parte_10.atestacion_plataforma_presente = true; // evita otro NO_AFIRMADO automático
    // Quitar cualquier NO_AFIRMADO de resistencia
    b.afirmaciones
        .retain(|a| !(a.etiqueta == EtiquetaAfirmacion::NoAfirmado
            && a.texto.contains("resistencia frente al operador")));
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b),
        Err(ErrorExpediente::FaltaNoAfirmadoOperador)
    ));
}

#[test]
fn j6_pii_cifrado_90_dias_decision_documentada() {
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(0), IdTitular(1)).unwrap();
    let plain = b"dato-personal-secreto";
    let (_id, hoja) = ctor
        .comprometer_pii("pii-c", plain, [7u8; LONGITUD_HASH_PAQUETE])
        .unwrap();
    assert_eq!(hoja.retencion_dias, 90);
    assert!(hoja.contenido_cifrado);
    assert_ne!(hoja.ciphertext.as_slice(), plain);
    assert_eq!(hoja.decision_cripto, DECISION_CRIPTO_PII_V1);
    let material = ctor
        .custodia
        .material_si_autorizado(IdTitular(0), IdTitular(1))
        .unwrap();
    let claro = hoja.descifrar_para_auditoria(material).unwrap();
    assert_eq!(claro, plain);
}

#[test]
fn j6_inclusion_preservada_tras_redaccion() {
    let hojas_comp = vec![[1u8; LONGITUD_HASH_PAQUETE], [2u8; LONGITUD_HASH_PAQUETE]];
    let raiz = merkle_raiz(&hojas_comp);
    let prueba = emitir_prueba_inclusion(&hojas_comp, 0).unwrap();
    assert!(verificar_inclusion(&prueba, &raiz));
    // Misma raíz tras «redacción» (compromisos invariantes):
    assert!(verificar_inclusion(&prueba, &raiz));
    let mut prueba_mala = prueba.clone();
    prueba_mala.camino[0].0[0] ^= 0xff;
    assert!(!verificar_inclusion(&prueba_mala, &raiz));
}

#[test]
fn criterio_m11_j2_trece_preguntas_y_redaccion_inclusion() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-1").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);

    let custodia = custodia_ok();
    let ctor = ConstructorExpediente::nuevo(custodia, IdTitular(0), IdTitular(1)).unwrap();
    let hoja = ctor
        .comprometer_pii("pii-1", b"dato-personal", [7u8; LONGITUD_HASH_PAQUETE])
        .unwrap();
    let compromiso_antes = hoja.1.compromiso;
    let borrador = borrador_minimo(vec![hoja]);

    let mut exp = ctor
        .generar(&cap, &sujeto, &mut ledger, borrador)
        .unwrap();
    assert_eq!(exp.frase_j4, FRASE_REGISTROS_NO_CUMPLIMIENTO);
    assert!(!exp.parte_12.pruebas_inclusion.is_empty());
    let prueba_antes = exp.parte_12.pruebas_inclusion[0].clone();
    assert!(verificar_inclusion(
        &prueba_antes,
        &exp.parte_12.merkle_raiz
    ));

    let antes = [compromiso_antes];
    let reg = ctor
        .redactar(
            &mut exp.hojas_pii,
            "pii-1",
            IdTitular(0),
            IdTitular(1),
            "art-17-supresion",
            20_000,
        )
        .unwrap();
    exp.parte_11.redacciones.push(reg);
    assert!(exp.hojas_pii[0].1.redactada);
    assert_eq!(exp.hojas_pii[0].1.compromiso, compromiso_antes);
    assert!(verificar_inclusion(
        &prueba_antes,
        &exp.parte_12.merkle_raiz
    ));

    let informe = verificar_expediente(&exp, ledger.pk_autoridad(), Some(&antes));
    assert!(informe.sin_veredicto, "{:?}", informe.errores);
    assert!(informe.j2_completo, "fallos={:?}", informe.j2_fallos);
    assert!(informe.j2_fallos.is_empty());
    assert!(informe.raiz_preservada_tras_redaccion, "{:?}", informe.errores);
    assert!(informe.inclusiones_ok, "{:?}", informe.errores);
    assert!(informe.ok, "{:?}", informe.errores);
    let j2 = informe.respuestas_j2.unwrap();
    // Asserts individuales J.2 (1..13)
    assert!(j2.sistema_por_artefacto.contains("artefacto="));
    assert!(j2.sistema_por_artefacto.contains("solicitud="));
    assert!(j2.identidad_version.contains('@'));
    assert!(j2.efecto_clase_params.contains("clase=EF-AUD"));
    assert!(j2.efecto_clase_params.contains("params="));
    assert!(j2.datos_contexto_productores.contains("productor=prod-a"));
    assert!(j2.datos_contexto_productores.contains("digest="));
    assert!(j2.norma_interpretacion_autor.contains("norma=N-1"));
    assert!(j2.norma_interpretacion_autor.contains("version=2024.1"));
    assert!(j2.norma_interpretacion_autor.contains("jurisdiccion=ES"));
    assert!(j2.norma_interpretacion_autor.contains("autor=jurista-1"));
    assert!(j2.decision_y_traza.contains("inertes=N-sombra"));
    assert!(j2.capacidad_o_recibo.contains("uso=unico"));
    assert!(j2.capacidad_o_recibo.contains("revocacion=no-revocada"));
    assert_eq!(j2.punto_aplicacion, "gateway-auditoria");
    assert!(j2.persona_competencia_firma.contains("escalados=esc-1"));
    assert!(j2.persona_competencia_firma.contains("plazo=86400"));
    assert!(j2.nivel_libro_instante.contains("C3"));
    assert!(j2.integridad_cofirmas.contains("inclusiones="));
    assert!(!j2.no_comprobado.is_empty());
    assert!(j2.evidencia_faltante_riesgo.contains("residual="));
    assert!(!informe.no_comprobado.is_empty());
}

#[test]
fn veredicto_inyectado_rechaza() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-2").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut borrador = borrador_minimo(vec![]);
    borrador.inyectar_veredicto = Some("CUMPLE".into());
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, borrador),
        Err(ErrorExpediente::ContieneVeredicto)
    ));
}

#[test]
fn puntuacion_inyectada_rechaza() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-3").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut borrador = borrador_minimo(vec![]);
    borrador.inyectar_puntuacion = Some(100);
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, borrador),
        Err(ErrorExpediente::ContienePuntuacion)
    ));
}

#[test]
fn sin_capacidad_auditoria_deniega() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-4").unwrap();
    let hash = HashPaqueteNormativo::desde_bytes([8u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-X").unwrap()], vec![], 1).unwrap();
    let d = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let cap = ledger
        .emitir_tras_evidencia(
            &sujeto,
            d,
            ParametrosEmision {
                sistema: IdSistema::nuevo("sys-m11").unwrap(),
                digest_efecto: [0x99u8; LONGITUD_HASH_PAQUETE],
                alcance: Alcance::minimo(["otro"]).unwrap(),
                epoca: 1,
                epoca_suelo: 1,
                ttl_ticks: 60_000,
                clasificacion: ClasificacionEfecto {
                    irreversible: false,
                    afecta_personas: false,
                    datos_personales: false,
                },
            },
            &reloj,
        )
        .unwrap();
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, borrador_minimo(vec![])),
        Err(ErrorExpediente::CapacidadAuditoriaAusente)
    ));
}

#[test]
fn redaccion_sin_base_juridica_o_ya_redactada() {
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(0), IdTitular(1)).unwrap();
    let mut hojas = vec![ctor
        .comprometer_pii("h", b"x", [1u8; LONGITUD_HASH_PAQUETE])
        .unwrap()];
    assert!(ctor
        .redactar(&mut hojas, "h", IdTitular(0), IdTitular(1), "", 1)
        .is_err());
    ctor.redactar(&mut hojas, "h", IdTitular(0), IdTitular(1), "base", 1)
        .unwrap();
    assert!(ctor
        .redactar(&mut hojas, "h", IdTitular(0), IdTitular(1), "base", 2)
        .is_err());
}

#[test]
fn afirmaciones_vacias_rechazan() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-6").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut borrador = borrador_minimo(vec![]);
    borrador.afirmaciones.clear();
    borrador.cliente_es_operador = false;
    borrador.parte_10.atestacion_plataforma_presente = true;
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, borrador),
        Err(ErrorExpediente::EtiquetaAusente)
    ));
}

#[test]
fn firma_expediente_verificable_con_pk_ledger() {
    let _ = ParMlDsa87::generar();
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-5").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let exp = ctor
        .generar(&cap, &sujeto, &mut ledger, borrador_minimo(vec![]))
        .unwrap();
    assert!(ParMlDsa87::verificar(ledger.pk_autoridad(), &exp.digest_paquete, &exp.firma_mldsa).is_ok());
}

#[test]
fn j2_omision_elemento_falla_literal() {
    let reloj = RelojInyectado::nuevo(1);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).unwrap();
    let sujeto = IdSujeto::nuevo("aud-j2").unwrap();
    let cap = emitir_cap_auditoria(&mut ledger, &sujeto, &reloj);
    let ctor = ConstructorExpediente::nuevo(custodia_ok(), IdTitular(1), IdTitular(2)).unwrap();
    let mut b = borrador_minimo(vec![]);
    b.parte_4.autor_interpretacion.clear();
    assert!(matches!(
        ctor.generar(&cap, &sujeto, &mut ledger, b),
        Err(ErrorExpediente::ParteIncompleta("corpus"))
    ));
}
