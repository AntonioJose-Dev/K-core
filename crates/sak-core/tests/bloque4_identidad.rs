//! Harnesses Bloque 4: INV-04, INV-05, H.2 / H.3.

use sak_core::contexto::{ClaseEfecto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::identidad::{
    resolver_puerta_h2_h3, ArtefactoCliente, AutoridadCertificacion, CodigoPuerta, IdSistema,
    Pasaporte, PeticionIdentidad, PruebaPosesion, RegistroSoberano, ResultadoPuerta,
};

struct Mundo {
    ca: AutoridadCertificacion,
    registro: RegistroSoberano,
    sk_cliente: ParMlDsa87,
    pasaporte: Pasaporte,
    artefacto: ArtefactoCliente,
    instante: u32,
}

fn mundo() -> Mundo {
    let mut registro = RegistroSoberano::nuevo().unwrap();
    let sistema = IdSistema::nuevo("sys-alpha").unwrap();
    let pasaporte = registro
        .registrar(
            "pass-alpha",
            1,
            sistema.clone(),
            "responsable@org",
            "asistencia-documental",
            10_000,
            50_000,
        )
        .unwrap();
    let mut ca = AutoridadCertificacion::generar().unwrap();
    let sk_cliente = ParMlDsa87::generar().unwrap();
    let artefacto = ca
        .emitir_artefacto(
            &pasaporte,
            sistema,
            sk_cliente.public.clone(),
            10_000,
            50_000,
        )
        .unwrap();
    Mundo {
        ca,
        registro,
        sk_cliente,
        pasaporte,
        artefacto,
        instante: 20_000,
    }
}

fn peticion(
    m: &Mundo,
    identidad_autodeclarada: Option<&str>,
    artefacto: ArtefactoCliente,
) -> PeticionIdentidad {
    let digest = [42u8; LONGITUD_HASH_PAQUETE];
    let prueba_cliente = PruebaPosesion::firmar(&m.sk_cliente, digest).unwrap();
    let prueba_servidor = m.ca.firmar_como_servidor(digest).unwrap();
    PeticionIdentidad {
        artefacto,
        prueba_cliente,
        prueba_servidor,
        identidad_autodeclarada: identidad_autodeclarada.map(|s| s.to_string()),
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: m.instante,
    }
}

#[test]
fn sin_pasaporte_vigente_deny_sin_registro() {
    let m = mundo();
    // CA y cliente válidos, pero registro vacío distinto.
    let registro_vacio = RegistroSoberano::nuevo().unwrap();
    let pet = peticion(&m, None, m.artefacto.clone());
    let r = resolver_puerta_h2_h3(&m.ca, &registro_vacio, &pet);
    assert_eq!(r.codigo(), Some(CodigoPuerta::SinRegistro));
    match r {
        ResultadoPuerta::Denegado { hallazgo, .. } => {
            let h = hallazgo.expect("hallazgo de sistema no registrado");
            assert!(h.identidad_resuelta.is_some());
            assert!(!h.motivo.is_empty());
        }
        _ => panic!("se esperaba denegacion"),
    }
}

#[test]
fn identidad_desde_artefacto_ignora_autodeclaracion_mentirosa() {
    let m = mundo();
    let pet = peticion(&m, Some("soy-otro-sistema-falso"), m.artefacto.clone());
    let r = resolver_puerta_h2_h3(&m.ca, &m.registro, &pet);
    let ctx = r.permitido().expect("debe autorizar puerta");
    assert_eq!(ctx.identidad.sistema_id(), "sys-alpha");
    assert_ne!(ctx.identidad.sistema_id(), "soy-otro-sistema-falso");
    assert_eq!(ctx.pasaporte.id(), "pass-alpha");
    assert_eq!(ctx.pasaporte.version(), 1);
}

#[test]
fn pasaporte_vencido_deny_sin_registro() {
    let mut registro = RegistroSoberano::nuevo().unwrap();
    let sistema = IdSistema::nuevo("sys-old").unwrap();
    let pasaporte = registro
        .registrar(
            "pass-old",
            1,
            sistema.clone(),
            "r@org",
            "fin",
            1_000,
            2_000, // vencido respecto a instante 20_000
        )
        .unwrap();
    let mut ca = AutoridadCertificacion::generar().unwrap();
    let sk = ParMlDsa87::generar().unwrap();
    let art = ca
        .emitir_artefacto(&pasaporte, sistema, sk.public.clone(), 1_000, 50_000)
        .unwrap();
    let digest = [7u8; LONGITUD_HASH_PAQUETE];
    let pet = PeticionIdentidad {
        artefacto: art,
        prueba_cliente: PruebaPosesion::firmar(&sk, digest).unwrap(),
        prueba_servidor: ca.firmar_como_servidor(digest).unwrap(),
        identidad_autodeclarada: None,
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef2, [2u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: 20_000,
    };
    let r = resolver_puerta_h2_h3(&ca, &registro, &pet);
    assert_eq!(r.codigo(), Some(CodigoPuerta::SinRegistro));
}

#[test]
fn artefacto_firma_invalida_deny_identidad() {
    let mut m = mundo();
    m.artefacto.firma_ca[0] ^= 0xff;
    let pet = peticion(&m, None, m.artefacto.clone());
    let r = resolver_puerta_h2_h3(&m.ca, &m.registro, &pet);
    assert_eq!(r.codigo(), Some(CodigoPuerta::Identidad));
}

#[test]
fn prueba_cliente_invalida_deny_identidad() {
    let m = mundo();
    let digest = [42u8; LONGITUD_HASH_PAQUETE];
    let mut prueba_cliente = PruebaPosesion::firmar(&m.sk_cliente, digest).unwrap();
    prueba_cliente.firma_workload[0] ^= 0xff;
    let pet = PeticionIdentidad {
        artefacto: m.artefacto.clone(),
        prueba_cliente,
        prueba_servidor: m.ca.firmar_como_servidor(digest).unwrap(),
        identidad_autodeclarada: None,
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: m.instante,
    };
    let r = resolver_puerta_h2_h3(&m.ca, &m.registro, &pet);
    assert_eq!(r.codigo(), Some(CodigoPuerta::Identidad));
}

#[test]
fn sin_prueba_servidor_mutua_deny_identidad() {
    let m = mundo();
    let digest = [42u8; LONGITUD_HASH_PAQUETE];
    let otro = ParMlDsa87::generar().unwrap();
    let pet = PeticionIdentidad {
        artefacto: m.artefacto.clone(),
        prueba_cliente: PruebaPosesion::firmar(&m.sk_cliente, digest).unwrap(),
        // Firma con clave ajena: falla autenticación mutua.
        prueba_servidor: PruebaPosesion::firmar(&otro, digest).unwrap(),
        identidad_autodeclarada: None,
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: m.instante,
    };
    let r = resolver_puerta_h2_h3(&m.ca, &m.registro, &pet);
    assert_eq!(r.codigo(), Some(CodigoPuerta::Identidad));
}

#[test]
fn firma_version_y_ligadura_pasaporte_artefacto() {
    let m = mundo();
    assert!(m.pasaporte.firma_valida());
    assert_eq!(m.pasaporte.version(), 1);
    assert_eq!(m.artefacto.pasaporte_id, m.pasaporte.id());
    assert_eq!(m.artefacto.pasaporte_version, m.pasaporte.version());
    assert!(m.ca.verificar_firma_artefacto(&m.artefacto));
    let pet = peticion(&m, Some("mentira"), m.artefacto.clone());
    let ctx = resolver_puerta_h2_h3(&m.ca, &m.registro, &pet)
        .permitido()
        .unwrap()
        .clone();
    assert_eq!(ctx.pasaporte.sistema_id(), ctx.identidad.sistema_id());
    assert_eq!(ctx.pasaporte.version(), ctx.identidad.pasaporte_version());
}

#[test]
fn emitir_artefacto_exige_pasaporte_versionado() {
    let ca = AutoridadCertificacion::generar().unwrap();
    let sk = ParMlDsa87::generar().unwrap();
    let mut registro = RegistroSoberano::nuevo().unwrap();
    let err = registro.registrar(
        "p0",
        0,
        IdSistema::nuevo("s").unwrap(),
        "r",
        "f",
        1,
        2,
    );
    assert!(err.is_err());
    let _ = (ca, sk);
}
