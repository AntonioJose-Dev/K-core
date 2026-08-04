//! INV-05 / H.2 D4: certificado de cliente local (perfil escritorio VAL-EXT).

use sak_core::contexto::{ClaseEfecto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::evidencia::AlmacenDiscoLocal;
use sak_core::identidad::{
    autenticar_mutua, cargar_ca_desde_almacen, conservar_ca, resolver_puerta_h2_h3,
    AutoridadCertificacion, CodigoPuerta, ErrorVerificacionCert, IdSistema, PeticionIdentidad,
    PruebaPosesion, RegistroSoberano, PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir_tmp(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sak-d4-{tag}-{n}"))
}

struct Mundo {
    ca: AutoridadCertificacion,
    registro: RegistroSoberano,
    sk: ParMlDsa87,
    pasaporte: sak_core::identidad::Pasaporte,
    artefacto: sak_core::identidad::ArtefactoCliente,
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
            "asistencia",
            10_000,
            50_000,
        )
        .unwrap();
    let mut ca = AutoridadCertificacion::generar().unwrap();
    assert!(ca.perfil().contains("VAL-EXT"));
    assert_eq!(ca.perfil(), PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT);
    assert!(!ca.perfil().to_lowercase().contains("mtls") || ca.perfil().contains("sin mTLS"));
    let sk = ParMlDsa87::generar().unwrap();
    let artefacto = ca
        .emitir_artefacto(
            &pasaporte,
            sistema,
            sk.public.clone(),
            10_000,
            50_000,
            20_000,
        )
        .unwrap();
    Mundo {
        ca,
        registro,
        sk,
        pasaporte,
        artefacto,
        instante: 20_000,
    }
}

fn peticion(
    m: &Mundo,
    nombre_falso: Option<&str>,
    art: sak_core::identidad::ArtefactoCliente,
) -> PeticionIdentidad {
    let digest = [9u8; LONGITUD_HASH_PAQUETE];
    PeticionIdentidad {
        artefacto: art,
        prueba_cliente: PruebaPosesion::firmar(&m.sk, digest).unwrap(),
        prueba_servidor: m.ca.firmar_como_servidor(digest).unwrap(),
        identidad_autodeclarada: nombre_falso.map(|s| s.to_string()),
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: m.instante,
    }
}

#[test]
fn certificado_valido_identifica_sistema_correcto() {
    let m = mundo();
    let r = resolver_puerta_h2_h3(&m.ca, &m.registro, &peticion(&m, None, m.artefacto.clone()));
    let ctx = r.permitido().expect("permitido");
    assert_eq!(ctx.identidad.sistema_id(), "sys-alpha");
    assert_eq!(ctx.pasaporte.id(), "pass-alpha");
    m.ca
        .verificar_certificado(&m.artefacto, &m.pasaporte, m.instante)
        .unwrap();
}

#[test]
fn nombre_falso_no_cambia_identidad() {
    let m = mundo();
    let r = resolver_puerta_h2_h3(
        &m.ca,
        &m.registro,
        &peticion(&m, Some("soy-otro-sistema-falso"), m.artefacto.clone()),
    );
    let ctx = r.permitido().unwrap();
    assert_eq!(ctx.identidad.sistema_id(), "sys-alpha");
    assert_ne!(ctx.identidad.sistema_id(), "soy-otro-sistema-falso");
}

#[test]
fn certificado_otra_ia_alterado_caducado_revocado_desconocido_deny_identidad() {
    let mut m = mundo();

    // Otra IA: certificado de B frente a pasaporte de A.
    let sys_b = IdSistema::nuevo("sys-beta").unwrap();
    let pass_b = m
        .registro
        .registrar("pass-beta", 1, sys_b.clone(), "rb", "fb", 10_000, 50_000)
        .unwrap();
    let sk_b = ParMlDsa87::generar().unwrap();
    let art_b = m
        .ca
        .emitir_artefacto(&pass_b, sys_b, sk_b.public.clone(), 10_000, 50_000, 20_000)
        .unwrap();
    assert_eq!(
        m.ca.verificar_certificado(&art_b, &m.pasaporte, 20_000),
        Err(ErrorVerificacionCert::PasaporteAjeno)
    );

    // Alterado.
    let mut alt = m.artefacto.clone();
    alt.firma_ca[0] ^= 0xff;
    assert_eq!(
        resolver_puerta_h2_h3(&m.ca, &m.registro, &peticion(&m, None, alt)).codigo(),
        Some(CodigoPuerta::Identidad)
    );

    // Caducado.
    let mut ca2 = AutoridadCertificacion::generar().unwrap();
    let mut reg2 = RegistroSoberano::nuevo().unwrap();
    let p2 = reg2
        .registrar(
            "pass-old",
            1,
            IdSistema::nuevo("sys-old").unwrap(),
            "r",
            "f",
            1_000,
            50_000,
        )
        .unwrap();
    let sk2 = ParMlDsa87::generar().unwrap();
    let art_cad = ca2
        .emitir_artefacto(
            &p2,
            IdSistema::nuevo("sys-old").unwrap(),
            sk2.public.clone(),
            1_000,
            2_000,
            1_500,
        )
        .unwrap();
    assert_eq!(
        ca2.verificar_certificado(&art_cad, &p2, 20_000),
        Err(ErrorVerificacionCert::Caducado)
    );
    let digest = [1u8; LONGITUD_HASH_PAQUETE];
    let pet_cad = PeticionIdentidad {
        artefacto: art_cad,
        prueba_cliente: PruebaPosesion::firmar(&sk2, digest).unwrap(),
        prueba_servidor: ca2.firmar_como_servidor(digest).unwrap(),
        identidad_autodeclarada: None,
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: 20_000,
    };
    assert_eq!(
        resolver_puerta_h2_h3(&ca2, &reg2, &pet_cad).codigo(),
        Some(CodigoPuerta::Identidad)
    );

    // Revocado.
    m.ca.revocar(m.artefacto.serial).unwrap();
    assert_eq!(
        resolver_puerta_h2_h3(
            &m.ca,
            &m.registro,
            &peticion(&m, None, m.artefacto.clone())
        )
        .codigo(),
        Some(CodigoPuerta::Identidad)
    );
    assert_eq!(
        m.ca.verificar_certificado(&m.artefacto, &m.pasaporte, m.instante),
        Err(ErrorVerificacionCert::Revocado)
    );

    // Desconocido: CA distinta no conoce el certificado de B.
    let ca_otra = AutoridadCertificacion::generar().unwrap();
    assert!(autenticar_mutua(
        &ca_otra,
        &art_b,
        &PruebaPosesion::firmar(&sk_b, digest).unwrap(),
        &ca_otra.firmar_como_servidor(digest).unwrap(),
        20_000,
    )
    .is_err());
}

#[test]
fn tras_reiniciar_certificado_y_vinculo_siguen_verificandose() {
    let dir = dir_tmp("persist");
    let (serial, art, pass, pk_ca) = {
        let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
        let mut registro = RegistroSoberano::nuevo().unwrap();
        let sistema = IdSistema::nuevo("sys-alpha").unwrap();
        let pasaporte = registro
            .registrar(
                "pass-alpha",
                1,
                sistema.clone(),
                "r",
                "f",
                10_000,
                50_000,
            )
            .unwrap();
        let mut ca = AutoridadCertificacion::generar().unwrap();
        let sk = ParMlDsa87::generar().unwrap();
        let art = ca
            .emitir_artefacto(
                &pasaporte,
                sistema,
                sk.public.clone(),
                10_000,
                50_000,
                20_000,
            )
            .unwrap();
        conservar_ca(&mut a, &ca).unwrap();
        sak_core::identidad::conservar_pasaporte(&mut a, &pasaporte).unwrap();
        (
            art.serial,
            art,
            pasaporte,
            ca.pk_bytes().to_vec(),
        )
    };
    let a2 = AlmacenDiscoLocal::abrir(&dir).unwrap();
    let ca2 = cargar_ca_desde_almacen(&a2).unwrap().expect("CA durable");
    assert_eq!(ca2.perfil(), PERFIL_IDENTIDAD_ESCRITORIO_VAL_EXT);
    assert_eq!(ca2.pk_bytes(), pk_ca.as_slice());
    let art2 = ca2.emitidos().get(&serial).expect("cert emitido");
    assert_eq!(art2, &art);
    ca2.verificar_certificado(art2, &pass, 20_000).unwrap();
    let _ = fs::remove_dir_all(&dir);
}
