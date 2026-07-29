//! Verificador independiente: sin red y sin Kernel (Matriz J.5).
//!
//! `sak-verify --self-test` construye un paquete mínimo, lo verifica offline
//! y enumera lo no comprobable.

use sak_core::capacidad::{
    digest_efecto_canonico, Alcance, ClasificacionEfecto, ParametrosEmision,
};
use sak_core::decision::{
    DecisionPermitida, HashPaqueteNormativo, IdNorma, TrazaPrecedencia, LONGITUD_HASH_PAQUETE,
};
use sak_core::evidencia::{
    alcance_auditoria, verificar_expediente, verificar_paquete, Afirmacion, ClaseRetencion,
    ConstructorExpediente, CustodiaTrampilla, EtiquetaAfirmacion, ExpedienteBorrador, HechoContexto,
    IdSujeto, IdTitular, LedgerEvidencia, MemoriaDurable, ParteCadena, ParteCapacidades,
    ParteClasificacion, ParteCorpus, ParteDecisiones, ParteFinalidad, ParteIncidentes, ParteLibro,
    ParteRiesgos, ParteSistemas, ParteSupervision, ParteSupuestos, ReciboEfecto,
    RecuentosObligaciones, TipoRegistro, FRASE_REGISTROS_NO_CUMPLIMIENTO,
};
use sak_core::identidad::IdSistema;
use sak_core::reloj::RelojInyectado;
use std::env;
use std::process;

fn self_test() -> i32 {
    let mut ledger = match LedgerEvidencia::nuevo(MemoriaDurable::default()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("init: {e}");
            return 1;
        }
    };
    let sujeto = IdSujeto::nuevo("sujeto-a").unwrap();
    let hash = HashPaqueteNormativo::desde_bytes([7u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-1").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let reloj = RelojInyectado::nuevo(100);
    let params = ParametrosEmision {
        sistema: IdSistema::nuevo("sys-verify").unwrap(),
        digest_efecto: digest_efecto_canonico("EF-VERIFY", b"p"),
        alcance: Alcance::minimo(["verify"]).unwrap(),
        epoca: 1,
        epoca_suelo: 1,
        ttl_ticks: 60_000,
        clasificacion: ClasificacionEfecto::irreversible(),
    };
    let cap = match ledger.emitir_tras_evidencia(&sujeto, decision, params, &reloj) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("emitir: {e}");
            return 1;
        }
    };
    // Snapshot mínimo de catálogo EF-4 (tipo Herramienta) para verificación offline.
    let mut cat_payload = Vec::new();
    cat_payload.push(0); // CATALOGO
    cat_payload.extend_from_slice(b"calc");
    cat_payload.extend_from_slice(&[1u8; LONGITUD_HASH_PAQUETE]);
    if let Err(e) = ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Herramienta, cat_payload)
    {
        eprintln!("catalogo: {e}");
        return 1;
    }
    let mut inv_payload = Vec::new();
    inv_payload.push(1); // INVOCACION
    inv_payload.extend_from_slice(cap.digest_efecto());
    inv_payload.extend_from_slice(b"calc|1.0|mcp-local|local");
    if let Err(e) = ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Herramienta, inv_payload)
    {
        eprintln!("invocacion: {e}");
        return 1;
    }
    let mut biz_payload = Vec::new();
    biz_payload.push(1); // EJECUCION
    biz_payload.extend_from_slice(cap.digest_efecto());
    biz_payload.push(1); // Confirmada
    biz_payload.extend_from_slice(&(3u16).to_le_bytes());
    biz_payload.extend_from_slice(b"ext");
    biz_payload.extend_from_slice(&(4u16).to_le_bytes());
    biz_payload.extend_from_slice(b"core");
    biz_payload.extend_from_slice(&(4u16).to_le_bytes());
    biz_payload.extend_from_slice(b"pago");
    if let Err(e) = ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Negocio, biz_payload) {
        eprintln!("negocio: {e}");
        return 1;
    }
    let mut comm_payload = Vec::new();
    comm_payload.push(1); // ENVIO
    comm_payload.extend_from_slice(cap.digest_efecto());
    comm_payload.extend_from_slice(&[3u8; LONGITUD_HASH_PAQUETE]);
    if let Err(e) =
        ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Comunicacion, comm_payload)
    {
        eprintln!("comunicacion: {e}");
        return 1;
    }
    let mut pub_payload = Vec::new();
    pub_payload.push(1); // PUBLICACION
    pub_payload.extend_from_slice(cap.digest_efecto());
    pub_payload.extend_from_slice(&[4u8; LONGITUD_HASH_PAQUETE]);
    pub_payload.push(1); // Publicado
    pub_payload.extend_from_slice(&(3u16).to_le_bytes());
    pub_payload.extend_from_slice(b"ext");
    pub_payload.extend_from_slice(&(2u16).to_le_bytes());
    pub_payload.extend_from_slice(b"/x");
    if let Err(e) = ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Publicacion, pub_payload)
    {
        eprintln!("publicacion: {e}");
        return 1;
    }
    let mut ef8_payload = Vec::new();
    ef8_payload.push(1); // CONSUMO
    ef8_payload.extend_from_slice(cap.digest_efecto());
    ef8_payload.extend_from_slice(&[5u8; LONGITUD_HASH_PAQUETE]);
    ef8_payload.push(1); // Entregado
    ef8_payload.extend_from_slice(&(3u16).to_le_bytes());
    ef8_payload.extend_from_slice(b"ext");
    if let Err(e) =
        ledger.registrar_evento_sistema(&sujeto, TipoRegistro::DecisionPersona, ef8_payload)
    {
        eprintln!("decision-persona: {e}");
        return 1;
    }
    let mut ef9_payload = Vec::new();
    ef9_payload.push(0); // ESTADO
    ef9_payload.extend_from_slice(b"sys-verify");
    ef9_payload.push(0);
    ef9_payload.extend_from_slice(b"codigo_prohibido");
    ef9_payload.push(0);
    ef9_payload.push(0); // cerrado
    ef9_payload.push(0); // no C5
    ef9_payload.extend_from_slice(&100u64.to_le_bytes());
    ef9_payload.extend_from_slice(&[6u8; LONGITUD_HASH_PAQUETE]);
    if let Err(e) = ledger.registrar_evento_sistema(&sujeto, TipoRegistro::Ef9, ef9_payload) {
        eprintln!("ef9: {e}");
        return 1;
    }
    let mut egreso_payload = Vec::new();
    egreso_payload.push(1); // TRANSFERENCIA
    egreso_payload.extend_from_slice(cap.digest_efecto());
    egreso_payload.extend_from_slice(&[7u8; LONGITUD_HASH_PAQUETE]);
    egreso_payload.push(1);
    egreso_payload.extend_from_slice(&100u64.to_le_bytes());
    egreso_payload.extend_from_slice(&(2u16).to_le_bytes());
    egreso_payload.extend_from_slice(b"/x");
    egreso_payload.extend_from_slice(&(3u16).to_le_bytes());
    egreso_payload.extend_from_slice(b"ext");
    if let Err(e) =
        ledger.registrar_evento_sistema(&sujeto, TipoRegistro::EgresoDatos, egreso_payload)
    {
        eprintln!("egreso: {e}");
        return 1;
    }
    let mut fisico_payload = Vec::new();
    fisico_payload.push(1); // EJECUCION
    fisico_payload.extend_from_slice(cap.digest_efecto());
    fisico_payload.extend_from_slice(&[8u8; LONGITUD_HASH_PAQUETE]);
    fisico_payload.push(4); // EstadoObservado
    fisico_payload.extend_from_slice(&(6u16).to_le_bytes());
    fisico_payload.extend_from_slice(b"activo");
    fisico_payload.extend_from_slice(&(5u16).to_le_bytes());
    fisico_payload.extend_from_slice(b"ef11x");
    if let Err(e) =
        ledger.registrar_evento_sistema(&sujeto, TipoRegistro::EfectoFisico, fisico_payload)
    {
        eprintln!("fisico: {e}");
        return 1;
    }
    let recibo = ReciboEfecto {
        digest_parametros: [1u8; LONGITUD_HASH_PAQUETE],
        digest_resultado: [2u8; LONGITUD_HASH_PAQUETE],
        digest_decision: *cap.compromiso_evidencia().digest(),
        digest_condiciones: [0u8; LONGITUD_HASH_PAQUETE],
    };
    if let Err(e) = ledger.registrar_recibo(&sujeto, &recibo) {
        eprintln!("recibo: {e}");
        return 1;
    }
    if let Err(e) = ledger.cerrar_epoca() {
        eprintln!("checkpoint: {e}");
        return 1;
    }
    let pkg = ledger.exportar_paquete();
    let tiene_herramienta = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Herramienta);
    if !tiene_herramienta {
        eprintln!("falta registro Herramienta en paquete");
        return 1;
    }
    let tiene_negocio = pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Negocio);
    if !tiene_negocio {
        eprintln!("falta registro Negocio en paquete");
        return 1;
    }
    let tiene_comm = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Comunicacion);
    if !tiene_comm {
        eprintln!("falta registro Comunicacion en paquete");
        return 1;
    }
    let tiene_pub = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::Publicacion);
    if !tiene_pub {
        eprintln!("falta registro Publicacion en paquete");
        return 1;
    }
    let tiene_ef8 = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::DecisionPersona);
    if !tiene_ef8 {
        eprintln!("falta registro DecisionPersona en paquete");
        return 1;
    }
    let tiene_ef9 = pkg.registros.iter().any(|r| r.tipo == TipoRegistro::Ef9);
    if !tiene_ef9 {
        eprintln!("falta registro Ef9 en paquete");
        return 1;
    }
    let tiene_egreso = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::EgresoDatos);
    if !tiene_egreso {
        eprintln!("falta registro EgresoDatos en paquete");
        return 1;
    }
    let tiene_fisico = pkg
        .registros
        .iter()
        .any(|r| r.tipo == TipoRegistro::EfectoFisico);
    if !tiene_fisico {
        eprintln!("falta registro EfectoFisico en paquete");
        return 1;
    }
    let informe = verificar_paquete(&pkg);
    println!("ok={}", informe.ok);
    println!("cadena_continua={}", informe.cadena_continua);
    println!("firmas_registros_ok={}", informe.firmas_registros_ok);
    println!("checkpoints_ok={}", informe.checkpoints_ok);
    println!("cofirmas_testigos_ok={}", informe.cofirmas_testigos_ok);
    println!("merkle_ok={}", informe.merkle_ok);
    println!("herramienta_registros_presentes=true");
    println!("negocio_registros_presentes=true");
    println!("comunicacion_registros_presentes=true");
    println!("publicacion_registros_presentes=true");
    println!("decision_persona_registros_presentes=true");
    println!("ef9_registros_presentes=true");
    println!("egreso_datos_registros_presentes=true");
    println!("efecto_fisico_registros_presentes=true");
    println!("no_comprobado:");
    for x in &informe.no_comprobado {
        println!("  - {x}");
    }
    for e in &informe.errores {
        println!("error: {e}");
    }
    if !informe.ok {
        return 1;
    }

    // §M 11 — expediente J.2 offline (paquete + claves públicas; sin veredicto).
    if self_test_expediente_m11().is_err() {
        return 1;
    }
    0
}

fn zeros() -> [u8; LONGITUD_HASH_PAQUETE] {
    [0u8; LONGITUD_HASH_PAQUETE]
}

fn self_test_expediente_m11() -> Result<(), ()> {
    let reloj = RelojInyectado::nuevo(200);
    let mut ledger = LedgerEvidencia::nuevo(MemoriaDurable::default()).map_err(|e| {
        eprintln!("m11 ledger: {e}");
    })?;
    let sujeto = IdSujeto::nuevo("aud-verify").map_err(|_| {
        eprintln!("m11 sujeto");
    })?;
    let hash = HashPaqueteNormativo::desde_bytes([11u8; LONGITUD_HASH_PAQUETE]);
    let traza =
        TrazaPrecedencia::nueva(vec![IdNorma::nueva("N-M11").unwrap()], vec![], 1).unwrap();
    let decision = DecisionPermitida::nueva(hash, traza, None).unwrap();
    let cap = ledger
        .emitir_tras_evidencia(
            &sujeto,
            decision,
            ParametrosEmision {
                sistema: IdSistema::nuevo("sys-m11-verify").unwrap(),
                digest_efecto: digest_efecto_canonico("EF-AUD", b"exp"),
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
            &reloj,
        )
        .map_err(|e| {
            eprintln!("m11 emitir: {e}");
        })?;

    let custodia = CustodiaTrampilla::instalar(
        [1u8; 32],
        false,
        [2u8; 32],
        true,
        [3u8; 32],
        true,
    )
    .map_err(|e| {
        eprintln!("m11 trampilla: {e}");
    })?;
    let ctor = ConstructorExpediente::nuevo(custodia, IdTitular(0), IdTitular(1)).map_err(|e| {
        eprintln!("m11 ctor: {e}");
    })?;
    let hoja = ctor
        .comprometer_pii("pii-v", b"dato", [9u8; LONGITUD_HASH_PAQUETE])
        .map_err(|e| {
            eprintln!("m11 pii: {e}");
        })?;
    let compromiso = hoja.1.compromiso;

    let borrador = ExpedienteBorrador {
        parte_1: ParteSistemas {
            id_sistema: "sys-m11-verify".into(),
            version_sistema: "1.0.0".into(),
            huella_artefacto: [0x11u8; LONGITUD_HASH_PAQUETE],
            medida_tcb_kernel: zeros(),
            hash_lista_simbolos: [0x22u8; LONGITUD_HASH_PAQUETE],
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
            obligaciones_l1_l4: "L1".into(),
        },
        parte_4: ParteCorpus {
            hash_paquete: [0x33u8; LONGITUD_HASH_PAQUETE],
            firmas_presentes: true,
            diff_reconocido: true,
            norma_id: "N-M11".into(),
            norma_version: "2024.1".into(),
            interpretacion: "texto".into(),
            autor_interpretacion: "jurista-v".into(),
        },
        parte_5: ParteRiesgos {
            riesgos: "r".into(),
            controles: "c".into(),
            resultado_controles: "parcial".into(),
        },
        parte_6: ParteDecisiones {
            digest_solicitud: [0x44u8; LONGITUD_HASH_PAQUETE],
            codigo_razon: "ALLOW".into(),
            clase_efecto: "EF-AUD".into(),
            parametros: "exp=1".into(),
            normas_citadas: "N-M11".into(),
            traza_precedencia: "N-M11".into(),
            normas_inertes: "N-sombra".into(),
            hechos: vec![HechoContexto {
                productor: "prod-v".into(),
                digest: [0x01u8; LONGITUD_HASH_PAQUETE],
                descripcion: "hecho".into(),
            }],
            pasos_consumidos: 1,
        },
        parte_7: ParteCapacidades {
            digest_capacidad: [0x55u8; LONGITUD_HASH_PAQUETE],
            alcance: "AUDITORIA".into(),
            ttl_ticks: 60_000,
            uso: "unico".into(),
            revocacion: "no-revocada".into(),
            punto_aplicacion: "gateway-auditoria".into(),
            recibo_digest: [0x66u8; LONGITUD_HASH_PAQUETE],
            intentos_rechazados: 0,
        },
        parte_8: ParteSupervision {
            id_humano: "hum-v".into(),
            competencia: "auditor".into(),
            escalados: "esc-v".into(),
            plazo: 86_400,
            quorum_ok: true,
            independencia_ok: true,
            firma_sobre_digest: [0x77u8; LONGITUD_HASH_PAQUETE],
            decision_supervision: "ok".into(),
        },
        parte_9: ParteLibro {
            nivel_en_instante: "C3".into(),
            historial_temporal: "C2->C3".into(),
            hechos_sostenedores: "CUSTODIA".into(),
            bypass_residual: "desconocido".into(),
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
            Afirmacion::nueva("artefacto", EtiquetaAfirmacion::HechoVerificable).unwrap(),
            Afirmacion::nueva("nivel libro", EtiquetaAfirmacion::EvaluacionAutomatica).unwrap(),
            Afirmacion::nueva("interp", EtiquetaAfirmacion::InterpretacionJuridica).unwrap(),
            Afirmacion::nueva("residual", EtiquetaAfirmacion::RiesgoResidual).unwrap(),
        ],
        recuentos: RecuentosObligaciones {
            evaluadas: 4,
            satisfechas_por_kernel: 2,
            requieren_decision_humana: 1,
            huecos_evidencia: 1,
        },
        cliente_es_operador: true,
        saltar_auto_no_afirmado_operador: false,
        hojas_pii: vec![hoja],
        inyectar_veredicto: None,
        inyectar_puntuacion: None,
    };

    let mut exp = ctor
        .generar(&cap, &sujeto, &mut ledger, borrador)
        .map_err(|e| {
            eprintln!("m11 generar: {e}");
        })?;
    if exp.frase_j4 != FRASE_REGISTROS_NO_CUMPLIMIENTO {
        eprintln!("m11 frase J.4 ausente o alterada");
        return Err(());
    }
    let _ = ClaseRetencion::ContenidoDatosPersonales.dias_retencion();

    let antes = [compromiso];
    let reg = ctor
        .redactar(
            &mut exp.hojas_pii,
            "pii-v",
            IdTitular(0),
            IdTitular(1),
            "base-juridica-verify",
            1,
        )
        .map_err(|e| {
            eprintln!("m11 redactar: {e}");
        })?;
    exp.parte_11.redacciones.push(reg);

    let informe = verificar_expediente(&exp, ledger.pk_autoridad(), Some(&antes));
    println!("m11_expediente_ok={}", informe.ok);
    println!("m11_j2_completo={}", informe.j2_completo);
    println!("m11_sin_veredicto={}", informe.sin_veredicto);
    println!("m11_raiz_preservada={}", informe.raiz_preservada_tras_redaccion);
    println!("m11_inclusiones_ok={}", informe.inclusiones_ok);
    println!("m11_redacciones={}", exp.parte_11.redacciones.len());
    if let Some(j2) = &informe.respuestas_j2 {
        println!("m11_j2_1={}", j2.sistema_por_artefacto);
        println!("m11_j2_2={}", j2.identidad_version);
        println!("m11_j2_3={}", j2.efecto_clase_params);
        println!("m11_j2_4={}", j2.datos_contexto_productores);
        println!("m11_j2_5={}", j2.norma_interpretacion_autor);
        println!("m11_j2_6={}", j2.decision_y_traza);
        println!("m11_j2_7={}", j2.capacidad_o_recibo);
        println!("m11_j2_8={}", j2.punto_aplicacion);
        println!("m11_j2_9={}", j2.persona_competencia_firma);
        println!("m11_j2_10={}", j2.nivel_libro_instante);
        println!("m11_j2_11={}", j2.integridad_cofirmas);
        println!("m11_j2_12={}", j2.no_comprobado);
        println!("m11_j2_13={}", j2.evidencia_faltante_riesgo);
    }
    for f in &informe.j2_fallos {
        println!("m11_j2_fallo: {f}");
    }
    println!("m11_no_comprobado:");
    for x in &informe.no_comprobado {
        println!("  - {x}");
    }
    for e in &informe.errores {
        println!("m11_error: {e}");
    }
    if informe.ok
        && informe.j2_completo
        && informe.sin_veredicto
        && informe.raiz_preservada_tras_redaccion
        && informe.inclusiones_ok
    {
        Ok(())
    } else {
        Err(())
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--self-test") {
        // SLH-DSA usa marcos de pila grandes en debug; aislar en hilo con 16 MiB.
        let handle = std::thread::Builder::new()
            .name("sak-verify-self-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(self_test)
            .expect("spawn self-test");
        let code = handle.join().expect("join self-test");
        process::exit(code);
    }
    eprintln!("uso: sak-verify --self-test");
    process::exit(2);
}
