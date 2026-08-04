//! INV-04 / §E D3: pasaporte firmado y versionado durable.

use sak_core::contexto::{ClaseEfecto, EfectoTipado};
use sak_core::crypto::ParMlDsa87;
use sak_core::decision::LONGITUD_HASH_PAQUETE;
use sak_core::evidencia::{AlmacenDiscoLocal, MemoriaDurable};
use sak_core::identidad::{
    cargar_registro_desde_almacen, conservar_pasaporte, registrar_desde_declaracion_y_conservar,
    resolver_pasaporte, resolver_puerta_h2_h3, AutoridadCertificacion, CodigoPuerta,
    DeclaracionResponsable, ErrorRegistro, ErrorRegistroDurable, IdSistema, PeticionIdentidad,
    PruebaPosesion, RegistroSoberano, ResultadoPuerta,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn dir_tmp(tag: &str) -> PathBuf {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sak-d3-{tag}-{n}"))
}

fn decl_para(sistema: &IdSistema, desde: u32, hasta: u32) -> (ParMlDsa87, DeclaracionResponsable) {
    let par = ParMlDsa87::generar().unwrap();
    let d = DeclaracionResponsable::firmar(
        &par,
        sistema.clone(),
        "responsable@org",
        "asistencia-documental",
        "modelo-x",
        "EU",
        "datos-ops",
        "ef1:asistido",
        "herramienta-a",
        "efector-a",
        "limitado",
        desde,
        hasta,
    )
    .unwrap();
    (par, d)
}

fn peticion(
    ca: &AutoridadCertificacion,
    sk: &ParMlDsa87,
    artefacto: sak_core::identidad::ArtefactoCliente,
    instante: u32,
) -> PeticionIdentidad {
    let digest = [42u8; LONGITUD_HASH_PAQUETE];
    PeticionIdentidad {
        artefacto,
        prueba_cliente: PruebaPosesion::firmar(sk, digest).unwrap(),
        prueba_servidor: ca.firmar_como_servidor(digest).unwrap(),
        identidad_autodeclarada: None,
        efecto: EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
        instante_epoch_dias: instante,
    }
}

#[test]
fn crear_apagar_reabrir_misma_version_y_firma() {
    let dir = dir_tmp("persist");
    let sistema = IdSistema::nuevo("sys-alpha").unwrap();
    let (_par, decl) = decl_para(&sistema, 10_000, 50_000);
    let (id, version, firma, pk) = {
        let mut a = AlmacenDiscoLocal::abrir(&dir).unwrap();
        let mut reg = RegistroSoberano::nuevo().unwrap();
        let p = registrar_desde_declaracion_y_conservar(
            &mut reg, &mut a, "pass-alpha", 1, &decl,
        )
        .unwrap();
        assert!(p.firma_valida());
        (
            p.id().to_string(),
            p.version(),
            p.firma().to_vec(),
            p.pk_registro().to_vec(),
        )
    };
    let a2 = AlmacenDiscoLocal::abrir(&dir).unwrap();
    let reg2 = cargar_registro_desde_almacen(&a2).unwrap();
    let p2 = reg2.obtener(&id, version).expect("sigue registrado");
    assert_eq!(p2.version(), version);
    assert_eq!(p2.firma(), firma.as_slice());
    assert_eq!(p2.pk_registro(), pk.as_slice());
    assert!(p2.firma_valida());
    let p3 = resolver_pasaporte(&a2, &id, version).unwrap();
    assert_eq!(p3.firma(), firma.as_slice());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sin_pasaporte_deny_sin_registro() {
    let mut ca = AutoridadCertificacion::generar().unwrap();
    let mut reg_emisor = RegistroSoberano::nuevo().unwrap();
    let sistema = IdSistema::nuevo("sys-x").unwrap();
    let p = reg_emisor
        .registrar("pass-x", 1, sistema.clone(), "r", "f", 1, 99_000)
        .unwrap();
    let sk = ParMlDsa87::generar().unwrap();
    let art = ca
        .emitir_artefacto(&p, sistema, sk.public.clone(), 1, 99_000, 20_000)
        .unwrap();
    let vacio = RegistroSoberano::nuevo().unwrap();
    let r = resolver_puerta_h2_h3(&ca, &vacio, &peticion(&ca, &sk, art, 20_000));
    assert_eq!(r.codigo(), Some(CodigoPuerta::SinRegistro));
}

#[test]
fn caducado_o_sustituido_no_vigente() {
    let mut registro = RegistroSoberano::nuevo().unwrap();
    let sistema = IdSistema::nuevo("sys-old").unwrap();
    let p1 = registro
        .registrar("pass-old", 1, sistema.clone(), "r", "f", 1_000, 2_000)
        .unwrap();
    let mut ca = AutoridadCertificacion::generar().unwrap();
    let sk = ParMlDsa87::generar().unwrap();
    let art = ca
        .emitir_artefacto(&p1, sistema.clone(), sk.public.clone(), 1_000, 50_000, 1_500)
        .unwrap();
    // Caducado.
    let r = resolver_puerta_h2_h3(&ca, &registro, &peticion(&ca, &sk, art.clone(), 20_000));
    assert_eq!(r.codigo(), Some(CodigoPuerta::SinRegistro));

    // Vigente en ventana, luego sustituido por v2.
    let mut reg2 = RegistroSoberano::nuevo().unwrap();
    let p_v1 = reg2
        .registrar("pass-s", 1, sistema.clone(), "r", "f", 10_000, 50_000)
        .unwrap();
    let art_v1 = ca
        .emitir_artefacto(&p_v1, sistema.clone(), sk.public.clone(), 10_000, 50_000, 20_000)
        .unwrap();
    assert!(matches!(
        resolver_puerta_h2_h3(&ca, &reg2, &peticion(&ca, &sk, art_v1.clone(), 20_000)),
        ResultadoPuerta::Permitido(_)
    ));
    let _p_v2 = reg2
        .registrar("pass-s", 2, sistema.clone(), "r", "f-nueva", 10_000, 50_000)
        .unwrap();
    // v1 sustituida: DENY aunque la ventana de fechas siga abierta.
    assert_eq!(
        resolver_puerta_h2_h3(&ca, &reg2, &peticion(&ca, &sk, art_v1, 20_000)).codigo(),
        Some(CodigoPuerta::SinRegistro)
    );
    assert_eq!(
        reg2.exigir_pasaporte_vigente(sistema.como_str(), "pass-s", 1, 20_000)
            .unwrap_err()
            .as_str(),
        "pasaporte sustituido por version posterior"
    );
    // La versión anterior no se reescribe.
    assert!(reg2.obtener("pass-s", 1).is_some());
    assert_eq!(
        reg2.registrar("pass-s", 1, sistema, "r", "f", 10_000, 50_000),
        Err(ErrorRegistro::VersionYaExiste)
    );
}

#[test]
fn pasaporte_de_otra_ia_deny() {
    let mut registro = RegistroSoberano::nuevo().unwrap();
    let sys_a = IdSistema::nuevo("sys-a").unwrap();
    let sys_b = IdSistema::nuevo("sys-b").unwrap();
    let _pa = registro
        .registrar("pass-a", 1, sys_a.clone(), "ra", "fa", 10_000, 50_000)
        .unwrap();
    let pb = registro
        .registrar("pass-b", 1, sys_b.clone(), "rb", "fb", 10_000, 50_000)
        .unwrap();
    let mut ca = AutoridadCertificacion::generar().unwrap();
    let sk = ParMlDsa87::generar().unwrap();
    // Artefacto de B (pasaporte de otra IA respecto de A).
    let art_b = ca
        .emitir_artefacto(&pb, sys_b, sk.public.clone(), 10_000, 50_000, 20_000)
        .unwrap();
    // A no puede usar el pasaporte de B: ligadura sistema≠pasaporte.
    assert!(registro
        .exigir_pasaporte_vigente(sys_a.como_str(), "pass-b", 1, 20_000)
        .is_err());
    // Presentar artefacto de B cuando se espera A: la puerta acepta B como B;
    // si el registro no tiene B, DENY.
    let solo_a = {
        let mut r = RegistroSoberano::nuevo().unwrap();
        r.registrar("pass-a", 1, sys_a, "ra", "fa", 10_000, 50_000)
            .unwrap();
        r
    };
    assert_eq!(
        resolver_puerta_h2_h3(&ca, &solo_a, &peticion(&ca, &sk, art_b, 20_000)).codigo(),
        Some(CodigoPuerta::SinRegistro)
    );
}

#[test]
fn no_reescribe_version_en_disco() {
    let mut almacen = MemoriaDurable::default();
    let mut reg = RegistroSoberano::nuevo().unwrap();
    let sistema = IdSistema::nuevo("sys-w").unwrap();
    let (_par, decl) = decl_para(&sistema, 1, 99_000);
    let p = registrar_desde_declaracion_y_conservar(&mut reg, &mut almacen, "pass-w", 1, &decl)
        .unwrap();
    assert_eq!(
        conservar_pasaporte(&mut almacen, &p),
        Err(ErrorRegistroDurable::YaExiste)
    );
    assert!(resolver_pasaporte(&almacen, "pass-w", 1).is_ok());
}
