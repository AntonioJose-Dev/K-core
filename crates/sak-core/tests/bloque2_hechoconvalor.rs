//! Fase 2 HechoConValor: presupuesto y ausencia de recursión (INV-17).
//!
//! Demuestra que `Predicado::HechoConValor(HechoConValor)` es una hoja pura:
//! consume exactamente 1 paso y no puede recurrir porque `HechoConValor`
//! no contiene `Predicado`.
//!
//! `Predicado::HechoVigente(IdProductor)` (tag 3) se preserva como variante
//! independiente: solo comprueba presencia/vigencia, sin exigir token.

use sak_core::contexto::{
    ClaseEfecto, Contexto, EfectoTipado, HechoConValor, HechoFirmado, IdProductor, ValorHecho,
};
use sak_core::decision::{Veredicto, LONGITUD_HASH_PAQUETE};
use sak_core::predicado::{evaluar, Predicado};
use sak_core::presupuesto::Presupuesto;

fn ctx_con_hecho(token: &str) -> Contexto {
    let prod = IdProductor::nuevo("prod-test").expect("productor");
    let valor = ValorHecho::token(token).expect("token no vacio");
    let _ = HechoConValor::nuevo(prod.clone(), valor.clone());
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    let hecho = sak_core::contexto::HechoFirmado::nuevo(
        prod,
        valor,
        [2u8; LONGITUD_HASH_PAQUETE],
        sak_core::contexto::FirmaProductor::nueva(vec![1, 2, 3]).unwrap(),
        10,
        100,
        hash_peticion,
    );
    Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho],
        hash_peticion,
    )
}

fn ctx_vacio() -> Contexto {
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![],
        hash_peticion,
    )
}

fn hecho_con_valor(token: &str) -> HechoConValor {
    let prod = IdProductor::nuevo("prod-test").expect("productor");
    let valor = ValorHecho::token(token).expect("token no vacio");
    HechoConValor::nuevo(prod, valor)
}

/// Un árbol idéntico con `HechoVigente` en la hoja consume exactamente el mismo
/// presupuesto que el mismo árbol con `Fijo(Allow)` en esa hoja.
/// Para evitar cortocircuitos, usamos un contexto donde `HechoVigente` es verdadero
/// y comparamos contra `Fijo(Allow)`.
#[test]
fn hecho_con_valor_consume_exactamente_un_paso_comparativa() {
    // Contexto con un hecho presente para que HechoConValor evalúe a true.
    let ctx = ctx_con_hecho("tok-a");

    // Árbol A: hoja = Fijo(Allow)
    let pred_a = Predicado::Y(vec![
        Predicado::Fijo(Veredicto::Allow),
        Predicado::No(Box::new(Predicado::Fijo(Veredicto::Deny))),
    ]);

    // Árbol B: idéntico, pero la primera hoja es HechoConValor (con hecho presente → true)
    let pred_b = Predicado::Y(vec![
        Predicado::HechoConValor(hecho_con_valor("tok-a")),
        Predicado::No(Box::new(Predicado::Fijo(Veredicto::Deny))),
    ]);

    // Árbol C: idéntico, pero la segunda hoja es HechoConValor
    let pred_c = Predicado::Y(vec![
        Predicado::Fijo(Veredicto::Allow),
        Predicado::No(Box::new(Predicado::HechoConValor(hecho_con_valor("tok-a")))),
    ]);

    let mut p1 = Presupuesto::nuevo();
    let _ = evaluar(&pred_a, &ctx, &mut p1);

    let mut p2 = Presupuesto::nuevo();
    let _ = evaluar(&pred_b, &ctx, &mut p2);

    let mut p3 = Presupuesto::nuevo();
    let _ = evaluar(&pred_c, &ctx, &mut p3);

    // Ambos árboles tienen 4 nodos: Y + hoja1 + No + Fijo = 4 pasos.
    assert_eq!(p1.consumidos(), 4, "árbol A: Y+Fijo+No+Fijo");
    assert_eq!(p2.consumidos(), 4, "árbol B: Y+HechoConValor+No+Fijo");
    assert_eq!(p3.consumidos(), 4, "árbol C: Y+Fijo+No+HechoConValor");
}

/// `HechoConValor` aislado consume exactamente 1 paso.
#[test]
fn hecho_con_valor_aislado_un_paso() {
    let pred = Predicado::HechoConValor(hecho_con_valor("tok-solitario"));
    let mut p = Presupuesto::nuevo();
    let _ = evaluar(&pred, &ctx_vacio(), &mut p);
    assert_eq!(p.consumidos(), 1);
}

/// Un árbol profundo con muchas hojas `HechoVigente` consume exactamente
/// N pasos (uno por nodo), demostrando que no hay recursión ni ramificación
/// oculta. Usamos un contexto donde todas las hojas son verdaderas para evitar
/// cortocircuitos, y comparamos contra el mismo árbol con `Fijo(Allow)`.
#[test]
fn hecho_con_valor_profundo_sin_recursion() {
    // Construimos: O( Fijo(Deny), Y(HechoVigente, HechoVigente) )
    // Con hechos presentes: O evalúa Fijo(Deny)=false, luego Y evalúa ambos HV=true.
    // Nodos: O + Fijo + Y + HV + HV = 5 pasos.
    let ctx = ctx_con_hecho("t1");

    let pred_hv = Predicado::O(vec![
        Predicado::Fijo(Veredicto::Deny),
        Predicado::Y(vec![
            Predicado::HechoConValor(hecho_con_valor("t1")),
            Predicado::HechoConValor(hecho_con_valor("t2")),
        ]),
    ]);

    // Mismo árbol pero con Fijo(Allow) en las hojas:
    let pred_fijo = Predicado::O(vec![
        Predicado::Fijo(Veredicto::Deny),
        Predicado::Y(vec![
            Predicado::Fijo(Veredicto::Allow),
            Predicado::Fijo(Veredicto::Allow),
        ]),
    ]);

    let mut p1 = Presupuesto::nuevo();
    let _ = evaluar(&pred_hv, &ctx, &mut p1);

    let mut p2 = Presupuesto::nuevo();
    let _ = evaluar(&pred_fijo, &ctx, &mut p2);

    assert_eq!(p1.consumidos(), 5, "árbol con HechoVigente: O+Fijo+Y+HV+HV");
    assert_eq!(p2.consumidos(), 5, "árbol con Fijo: O+Fijo+Y+Fijo+Fijo");
}

/// `HechoConValor` no es un `Predicado`, por lo que no puede alojar
/// subpredicados. La compilación impide la recursión por construcción de tipos.
#[test]
fn hecho_con_valor_no_contiene_predicado() {
    let hcv = HechoConValor::nuevo(
        IdProductor::nuevo("p").unwrap(),
        ValorHecho::token("v").unwrap(),
    );
    // Si HechoConValor tuviera un campo Predicado, podríamos construir recursión.
    // Al no tenerlo, lo siguiente es imposible de compilar si se intenta:
    //   Predicado::HechoConValor( ??? )  // solo acepta HechoConValor, no Predicado
    // El test documenta la invariante por construcción.
    assert_eq!(hcv.productor().como_str(), "p");
    assert_eq!(hcv.valor().como_str(), "v");
}

/// Compatibilidad hacia atrás: un corpus existente serializado con el tag 3
/// (formato anterior a Fase 2) se deserializa como `HechoVigente(IdProductor)`
/// y evalúa exactamente igual que antes: solo presencia/vigencia, sin exigir token.
#[test]
fn compatibilidad_hacia_atras_hechovigente_tag3() {
    // Reconstrucción manual del formato antiguo (tag 3 + productor sin token).
    // Formato: [3][u16 len][bytes productor]
    let productor_str = "prod-legacy";
    let mut bytes = Vec::new();
    bytes.push(3); // tag original de HechoVigente
    bytes.extend_from_slice(&(productor_str.len() as u16).to_le_bytes());
    bytes.extend_from_slice(productor_str.as_bytes());

    // Deserializar con el código actual.
    let pred = sak_core::gobernanza::corpus_durable::decode_predicado_from_bytes(&bytes)
        .expect("debe deserializar HechoVigente legacy");

    // Debe reconstruirse como HechoVigente(IdProductor), no como HechoConValor.
    match &pred {
        Predicado::HechoVigente(id) => {
            assert_eq!(id.como_str(), productor_str);
        }
        Predicado::HechoConValor(_) => {
            panic!("tag 3 legacy se deserializo como HechoConValor: cambio de formato incompatible");
        }
        _ => panic!("variante inesperada: {:?}", pred),
    }

    // Evaluación: solo presencia/vigencia, sin exigir token.
    // Contexto: el productor "prod-legacy" tiene un hecho caducado (no debe cumplir).
    let prod = IdProductor::nuevo(productor_str).expect("productor");
    let valor = ValorHecho::token("token-cualquiera").expect("token");
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    let hecho = sak_core::contexto::HechoFirmado::nuevo(
        prod.clone(),
        valor,
        [2u8; LONGITUD_HASH_PAQUETE],
        sak_core::contexto::FirmaProductor::nueva(vec![1, 2, 3]).unwrap(),
        200, // antiguedad_segundos
        100, // antiguedad_maxima_segundos (caducado)
        hash_peticion,
    );
    let ctx = Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho],
        hash_peticion,
    );
    let mut p = Presupuesto::nuevo();
    let resultado = evaluar(&pred, &ctx, &mut p);
    assert_eq!(resultado, Ok(Veredicto::Deny), "hecho caducado debe ser Deny");
}

// =============================================================================
// Fase 3 — Atado a petición (id_peticion)
// =============================================================================

use sak_core::contexto::FirmaProductor;

/// Test a) Replay entre peticiones DISTINTAS: un HechoFirmado con id_peticion
/// de la Petición A es RECHAZADO al evaluarse en el contexto de la Petición B.
///
/// Esto es lo que antes pasaba (aceptaba) y ahora no debe pasar.
#[test]
fn hecho_firmado_rechazado_en_peticion_distinta() {
    let prod = IdProductor::nuevo("prod-replay").expect("productor");
    let valor = ValorHecho::token("token-replay").expect("token");

    // Hecho firmado creado para la Petición A
    let hash_peticion_a = [0xAAu8; LONGITUD_HASH_PAQUETE];
    let hecho = HechoFirmado::nuevo(
        prod.clone(),
        valor,
        [0u8; LONGITUD_HASH_PAQUETE],
        FirmaProductor::nueva(vec![1, 2, 3]).unwrap(),
        10,
        100,
        hash_peticion_a,
    );

    // Contexto de la Petición B (hash distinto)
    let hash_peticion_b = [0xBBu8; LONGITUD_HASH_PAQUETE];
    let ctx = Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho],
        hash_peticion_b,
    );

    let pred = Predicado::HechoConValor(HechoConValor::nuevo(prod, ValorHecho::token("token-replay").unwrap()));
    let mut p = Presupuesto::nuevo();
    let resultado = evaluar(&pred, &ctx, &mut p);
    assert_eq!(resultado, Ok(Veredicto::Deny), "replay entre peticiones distintas debe ser Deny");
}

/// Test b) No-regresión: el mismo hecho SÍ es aceptado cuando id_peticion
/// coincide con la petición actual.
#[test]
fn hecho_firmado_aceptado_con_id_peticion_coincidente() {
    let prod = IdProductor::nuevo("prod-ok").expect("productor");
    let valor = ValorHecho::token("token-ok").expect("token");

    let hash_peticion = [0xCCu8; LONGITUD_HASH_PAQUETE];
    let hecho = HechoFirmado::nuevo(
        prod.clone(),
        valor.clone(),
        [0u8; LONGITUD_HASH_PAQUETE],
        FirmaProductor::nueva(vec![1, 2, 3]).unwrap(),
        10,
        100,
        hash_peticion,
    );

    let ctx = Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho],
        hash_peticion,
    );

    let pred = Predicado::HechoConValor(HechoConValor::nuevo(prod, valor));
    let mut p = Presupuesto::nuevo();
    let resultado = evaluar(&pred, &ctx, &mut p);
    assert_eq!(resultado, Ok(Veredicto::Allow), "id_peticion coincidente debe ser Allow");
}

/// Test d) Ataque real: falsificación de HechoFirmado sin verificación de firma.
///
/// Este test EJECUTA el ataque descrito: construye un HechoFirmado con
/// `id_peticion` copiado/adivinado del hash público de una petición objetivo,
/// SIN usar ninguna clave del productor legítimo, y demuestra que evaluar()
/// lo ACEPTA igualmente.
///
/// Esto prueba en código, no en prosa, que el mecanismo de `id_peticion`
/// bloquea replay estructural entre peticiones distintas, pero NO impide
/// que un atacante que conozca o elija el hash de la petición construya
/// un HechoFirmado falsificado que el motor aceptará.
///
/// La deuda conocida queda demostrada empíricamente: la protección real
/// contra replay requiere verificación criptográfica de FirmaProductor
/// contra el productor declarado (planeada para Bloques 3-4).
#[test]
fn ataque_falsificacion_hecho_firmado_sin_firma_verificada() {
    // Escenario: el atacante quiere que la norma "prod-victim tiene token-secreto"
    // se cumpla en una petición cuyo hash público es known_hash.
    //
    // El atacante NO tiene las claves del productor legítimo "prod-victim".
    // Simplemente construye un HechoFirmado con:
    // - productor: "prod-victim" (identidad falsificada)
    // - valor: "token-secreto" (token deseado)
    // - id_peticion: known_hash (hash de la petición objetivo, público)
    // - firma: bytes aleatorios (no verificada)
    //
    // El motor NO verifica que la firma corresponda al productor declarado.
    // Por tanto, el HechoFirmado falsificado será aceptado.

    let known_hash = [0xDEu8; LONGITUD_HASH_PAQUETE];
    let prod_falsificado = IdProductor::nuevo("prod-victim").expect("productor");
    let valor_falsificado = ValorHecho::token("token-secreto").expect("token");

    // Hecho falsificado SIN claves del productor legítimo
    let hecho_falsificado = HechoFirmado::nuevo(
        prod_falsificado.clone(),
        valor_falsificado.clone(),
        [0u8; LONGITUD_HASH_PAQUETE], // digest arbitrario
        FirmaProductor::nueva(vec![0xFF, 0xFE, 0xFD]).unwrap(), // firma aleatoria
        10,
        100,
        known_hash, // id_peticion copiado del hash público de la petición
    );

    // Contexto de la petición objetivo
    let ctx = Contexto::nuevo(
        EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        vec![hecho_falsificado],
        known_hash,
    );

    // Evaluar el predicado: el HechoFirmado falsificado ACEPTA
    let pred = Predicado::HechoConValor(HechoConValor::nuevo(prod_falsificado, valor_falsificado));
    let mut p = Presupuesto::nuevo();
    let resultado = evaluar(&pred, &ctx, &mut p);

    // El ataque tiene éxito: el motor acepta el hecho falsificado
    assert_eq!(resultado, Ok(Veredicto::Allow), "ataque de falsificación debe tener éxito: falta verificación de firma");

    // Este test demuestra que el mecanismo estructural (id_peticion) es
    // insuficiente sin verificación criptográfica. La deuda conocida
    // queda registrada como evidencia ejecutable.
}

