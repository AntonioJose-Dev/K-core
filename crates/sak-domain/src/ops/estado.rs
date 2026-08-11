//! Estado durable Conectar + Custodiar (refs/handles sin material).

use std::collections::BTreeMap;

use sak_core::custodia::{BrokerCredenciales, SecretoRaiz};
use sak_core::evidencia::{AlmacenDiscoLocal, AlmacenEvidencia, MemoriaDurable};
use sak_core::gobernanza::{
    CasoConformidad, DiffDecisiones, GobernanzaCorpus, RegistroAprobacionesInterp, RegistroCitas,
    RegistroFirmantesGob,
};
use sak_core::identidad::{
    cargar_registro_desde_almacen, registrar_desde_declaracion_y_conservar, DeclaracionResponsable,
    IdSistema, Pasaporte, RegistroSoberano,
};
use sak_core::libro::{cargar_libro_desde_almacen, conservar_libro, LibroControl};
use sak_core::monitor::EpocaMonotonica;
use sak_core::norma::PaqueteNormativo;
use sak_core::decision::HashPaqueteNormativo;

const CLAVE_ALTAS: &[u8] = b"conectar/v1/altas_index";
const CLAVE_PEP: &[u8] = b"conectar/v1/pep_mapa";
const PREF_ALTA: &[u8] = b"conectar/v1/alta/";
const CLAVE_REFS: &[u8] = b"custodiar/v1/refs_index";
const PREF_REF: &[u8] = b"custodiar/v1/ref/";

/// Mapa clase EF → nombre PEP + destinos egreso (declarativo; sin secretos).
#[derive(Debug, Clone)]
pub struct PepMapa {
    /// clase -> (pep_id, egreso_destinos)
    pub entradas: BTreeMap<String, (String, Vec<String>)>,
}

impl PepMapa {
    pub fn seed() -> Self {
        let mut entradas = BTreeMap::new();
        let seed = [
            ("EF-1", "GatewayModelos"),
            ("EF-2", "GatewayDatos"),
            ("EF-3", "GatewayEscritura"),
            ("EF-4", "BrokerHerramientas"),
            ("EF-5", "EjecutorNegocio"),
            ("EF-6", "GatewayComunicaciones"),
            ("EF-7", "GatewayPublicacion"),
            ("EF-8", "GatewayConsumoDecisionPersona"),
            ("EF-10", "GatewayEgresoDatos"),
            ("EF-11", "GatewayEfectoFisico"),
        ];
        for (c, p) in seed {
            entradas.insert(c.into(), (p.into(), Vec::new()));
        }
        PepMapa { entradas }
    }

    pub fn a_json(&self) -> String {
        let mut parts = Vec::new();
        for (k, (pep, egreso)) in &self.entradas {
            let eg: Vec<String> = egreso.iter().map(|e| format!("\"{}\"", esc_json(e))).collect();
            parts.push(format!(
                "\"{}\":{{\"pep\":\"{}\",\"egreso\":[{}]}}",
                esc_json(k),
                esc_json(pep),
                eg.join(",")
            ));
        }
        format!("{{{}}}", parts.join(","))
    }

    pub fn desde_json_lineas(raw: &str) -> Result<Self, String> {
        // Formato mínimo: {"EF-1":{"pep":"GatewayModelos","egreso":["a"]}}
        let mut mapa = PepMapa::seed();
        if raw.trim().is_empty() {
            return Ok(mapa);
        }
        // Actualizaciones por claves conocidas EF-*
        for clase in [
            "EF-1", "EF-2", "EF-3", "EF-4", "EF-5", "EF-6", "EF-7", "EF-8", "EF-10", "EF-11",
        ] {
            if let Some(bloque) = extraer_objeto(raw, clase) {
                let pep = campo_str_obj(&bloque, "pep").unwrap_or_else(|| {
                    mapa.entradas
                        .get(clase)
                        .map(|(p, _)| p.clone())
                        .unwrap_or_default()
                });
                let egreso = campo_array_str(&bloque, "egreso").unwrap_or_default();
                mapa.entradas.insert(clase.into(), (pep, egreso));
            }
        }
        Ok(mapa)
    }
}

fn esc_json(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn extraer_objeto(raw: &str, clave: &str) -> Option<String> {
    let pat = format!("\"{clave}\"");
    let i = raw.find(&pat)?;
    let rest = &raw[i + pat.len()..];
    let start = rest.find('{')?;
    let mut depth = 0i32;
    for (j, c) in rest[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[start..=start + j].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn campo_str_obj(obj: &str, clave: &str) -> Option<String> {
    let pat = format!("\"{clave}\"");
    let i = obj.find(&pat)?;
    let rest = &obj[i + pat.len()..];
    let colon = rest.find(':')?;
    let mut s = rest[colon + 1..].trim_start();
    if !s.starts_with('"') {
        return None;
    }
    s = &s[1..];
    let end = s.find('"')?;
    Some(s[..end].to_string())
}

fn campo_array_str(obj: &str, clave: &str) -> Option<Vec<String>> {
    let pat = format!("\"{clave}\"");
    let i = obj.find(&pat)?;
    let rest = &obj[i + pat.len()..];
    let lb = rest.find('[')?;
    let rb = rest[lb..].find(']')?;
    let inner = &rest[lb + 1..lb + rb];
    let mut out = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.starts_with('"') && p.ends_with('"') && p.len() >= 2 {
            out.push(p[1..p.len() - 1].to_string());
        }
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct AltaSistema {
    pub sistema_id: String,
    pub pasaporte_id: String,
    pub responsable: String,
    pub finalidad: String,
    pub clasificacion_riesgo: String,
    pub digest_decl: String,
    pub nota: &'static str,
}

/// Referencia de custodia: solo handle + metadatos (INV: sin material).
#[derive(Debug, Clone)]
pub struct RefCustodia {
    pub secreto_id: String,
    pub alias: String,
    pub clase_ef: String,
    pub handle: String,
    pub huella: String,
    pub estado: String,
    pub ttl_derivadas_secs: u32,
    pub operador_id: String,
    /// Historial de rotaciones: huella+handle anteriores (nunca material).
    pub historial: Vec<HistRotacion>,
    pub n_rotaciones: u32,
}

/// Entrada de historial tras rotación (metadatos públicos).
#[derive(Debug, Clone)]
pub struct HistRotacion {
    pub huella: String,
    pub handle: String,
    pub epoca: u64,
}

/// Estado operador: Conectar + Custodiar + Gobernar; almacén en memoria o disco.
pub struct EstadoOps {
    pub registro: RegistroSoberano,
    pub altas: BTreeMap<String, AltaSistema>,
    pub pep: PepMapa,
    pub refs: BTreeMap<String, RefCustodia>,
    pub alias_a_id: BTreeMap<String, String>,
    /// Raíz encapsulada del dominio (sin API de export).
    pub broker: BrokerCredenciales,
    pub gob: GobernanzaCorpus,
    pub citas: RegistroCitas,
    pub aprobaciones: RegistroAprobacionesInterp,
    pub firmantes: RegistroFirmantesGob,
    /// Casos demo para diff (no certifican conformidad).
    pub casos_conformidad: Vec<CasoConformidad>,
    /// Baseline «activo de demo» (paquete vacío) para diff sin activar época.
    pub baseline: PaqueteNormativo,
    /// Diffs calculados pendientes de reconocimiento humano.
    pub diffs_pendientes: BTreeMap<[u8; 48], DiffDecisiones>,
    /// PKs de reconocedores (id → pk).
    pub pks_reconocedores: BTreeMap<String, Vec<u8>>,
    /// Libro de control (ALCANZABLES / hechos); sin secretos.
    pub libro: LibroControl,
    /// Época monótona del dominio (activación G.5).
    pub epoca: EpocaMonotonica,
    /// Frontera sujeto Bloque B (decidir/emitir/ejercer); no es UI.
    pub frontera: crate::sujeto::FronteraSujeto,
    almacen: AlmacenKind,
}

enum AlmacenKind {
    Mem(MemoriaDurable),
    Disco(AlmacenDiscoLocal),
}

impl AlmacenKind {
    fn as_mut(&mut self) -> &mut dyn AlmacenEvidencia {
        match self {
            AlmacenKind::Mem(m) => m,
            AlmacenKind::Disco(d) => d,
        }
    }
    fn as_ref(&self) -> &dyn AlmacenEvidencia {
        match self {
            AlmacenKind::Mem(m) => m,
            AlmacenKind::Disco(d) => d,
        }
    }
}

fn broker_dominio() -> BrokerCredenciales {
    // Semilla de arranque de dominio: material no exportable por ninguna API pública.
    BrokerCredenciales::nuevo(SecretoRaiz::desde_semilla([0x53; 32]))
}

fn seed_gobernanza() -> (
    GobernanzaCorpus,
    RegistroCitas,
    RegistroAprobacionesInterp,
    RegistroFirmantesGob,
    Vec<CasoConformidad>,
    PaqueteNormativo,
    BTreeMap<[u8; 48], DiffDecisiones>,
    BTreeMap<String, Vec<u8>>,
) {
    use sak_core::contexto::{ClaseEfecto, Contexto, EfectoTipado};
    use sak_core::decision::LONGITUD_HASH_PAQUETE;
    let hash_peticion = [1u8; LONGITUD_HASH_PAQUETE];
    let casos = vec![CasoConformidad {
        id: "caso-demo-1".into(),
        contexto: Contexto::con_instante(
            EfectoTipado::nuevo(ClaseEfecto::Ef1, [1u8; LONGITUD_HASH_PAQUETE]),
            vec![],
            20_000,
            hash_peticion,
        ),
    }];
    let baseline = PaqueteNormativo::cargar(vec![]).expect("paquete vacio cargable");
    (
        GobernanzaCorpus::nuevo(),
        RegistroCitas::nuevo(),
        RegistroAprobacionesInterp::nuevo(),
        RegistroFirmantesGob::nuevo(),
        casos,
        baseline,
        BTreeMap::new(),
        BTreeMap::new(),
    )
}

impl EstadoOps {
    pub fn en_memoria() -> Result<Self, String> {
        let mut almacen = MemoriaDurable::default();
        let epoca = EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1)
            .map_err(|e| format!("epoca: {e}"))?;
        let registro = RegistroSoberano::nuevo().map_err(|e| format!("registro: {e}"))?;
        let (gob, citas, aprobaciones, firmantes, casos, baseline, diffs, pks) = seed_gobernanza();
        Ok(EstadoOps {
            registro,
            altas: BTreeMap::new(),
            pep: PepMapa::seed(),
            refs: BTreeMap::new(),
            alias_a_id: BTreeMap::new(),
            broker: broker_dominio(),
            gob,
            citas,
            aprobaciones,
            firmantes,
            casos_conformidad: casos,
            baseline,
            diffs_pendientes: diffs,
            pks_reconocedores: pks,
            libro: LibroControl::nuevo(),
            epoca,
            frontera: crate::sujeto::FronteraSujeto::nueva()?,
            almacen: AlmacenKind::Mem(almacen),
        })
    }

    pub fn abrir_disco(
        root: impl AsRef<std::path::Path>,
        dominio_id: &str,
    ) -> Result<Self, String> {
        let mut almacen =
            AlmacenDiscoLocal::abrir(root).map_err(|e| format!("almacen disco: {e}"))?;
        let epoca = EpocaMonotonica::cargar_o_iniciar(&mut almacen, 1)
            .map_err(|e| format!("epoca: {e}"))?;
        let registro = cargar_registro_desde_almacen(&almacen)
            .map_err(|e| format!("cargar registro: {e}"))?;
        let libro = cargar_libro_desde_almacen(&almacen)
            .map_err(|e| format!("cargar libro: {e}"))?;
        let (gob, citas, aprobaciones, firmantes, casos, baseline, diffs, pks) = seed_gobernanza();
        let mut st = EstadoOps {
            registro,
            altas: BTreeMap::new(),
            pep: PepMapa::seed(),
            refs: BTreeMap::new(),
            alias_a_id: BTreeMap::new(),
            broker: broker_dominio(),
            gob,
            citas,
            aprobaciones,
            firmantes,
            casos_conformidad: casos,
            baseline,
            diffs_pendientes: diffs,
            pks_reconocedores: pks,
            libro,
            epoca,
            frontera: crate::sujeto::FronteraSujeto::nueva_para_dominio(dominio_id)?,
            almacen: AlmacenKind::Disco(almacen),
        };
        st.cargar_pep_y_altas()?;
        st.cargar_refs()?;
        Ok(st)
    }

    /// Activación G.5 en límite de época (conserva historial; write-once corpus).
    pub fn activar_paquete_en_limite(
        &mut self,
        hash: &HashPaqueteNormativo,
        ahora: u64,
        en_limite_epoca: bool,
    ) -> Result<u64, String> {
        sak_core::gobernanza::activar_en_limite_epoca(
            &mut self.gob,
            hash,
            &mut self.epoca,
            self.almacen.as_mut(),
            ahora,
            en_limite_epoca,
        )
        .map_err(|e| e.to_string())
    }

    /// Revoca paquete activo: no borra historial ni decisiones pasadas.
    pub fn revocar_paquete_activo(
        &mut self,
        hash: &HashPaqueteNormativo,
        ahora: u64,
    ) -> Result<usize, String> {
        let mut ver = sak_core::capacidad::VerificadorCapacidades::nuevo(self.epoca.actual());
        sak_core::gobernanza::revocar_paquete(&mut self.gob, hash, &mut ver, ahora)
            .map_err(|e| e.to_string())
    }

    /// Prepara reversión gobernada (→ FIRMADA) conservando firmas/diff/historial.
    pub fn preparar_reversion(
        &mut self,
        hash: &HashPaqueteNormativo,
    ) -> Result<(), String> {
        self.gob
            .preparar_reversion_gobernada(hash)
            .map_err(|e| e.to_string())
    }

    fn cargar_pep_y_altas(&mut self) -> Result<(), String> {
        if let Some(bytes) = self.almacen.as_ref().leer(CLAVE_PEP) {
            let s = String::from_utf8_lossy(&bytes);
            self.pep = PepMapa::desde_json_lineas(&s)?;
        }
        if let Some(idx) = self.almacen.as_ref().leer(CLAVE_ALTAS) {
            let s = String::from_utf8_lossy(&idx);
            for id in s.split('\n').filter(|x| !x.is_empty()) {
                let mut clave = PREF_ALTA.to_vec();
                clave.extend_from_slice(id.as_bytes());
                if let Some(blob) = self.almacen.as_ref().leer(&clave) {
                    if let Ok(alta) = decode_alta(&blob) {
                        self.altas.insert(alta.sistema_id.clone(), alta);
                    }
                }
            }
        }
        Ok(())
    }

    fn cargar_refs(&mut self) -> Result<(), String> {
        if let Some(idx) = self.almacen.as_ref().leer(CLAVE_REFS) {
            let s = String::from_utf8_lossy(&idx);
            for id in s.split('\n').filter(|x| !x.is_empty()) {
                let mut clave = PREF_REF.to_vec();
                clave.extend_from_slice(id.as_bytes());
                if let Some(blob) = self.almacen.as_ref().leer(&clave) {
                    if let Ok(r) = decode_ref(&blob) {
                        self.alias_a_id
                            .insert(r.alias.clone(), r.secreto_id.clone());
                        self.refs.insert(r.secreto_id.clone(), r);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn ref_por_alias(&self, alias: &str) -> Option<&RefCustodia> {
        self.alias_a_id
            .get(alias)
            .and_then(|id| self.refs.get(id))
    }

    pub fn guardar_ref(&mut self, r: &RefCustodia) -> Result<(), String> {
        self.alias_a_id
            .insert(r.alias.clone(), r.secreto_id.clone());
        self.refs.insert(r.secreto_id.clone(), r.clone());
        let mut clave = PREF_REF.to_vec();
        clave.extend_from_slice(r.secreto_id.as_bytes());
        let blob = encode_ref(r);
        self.almacen
            .as_mut()
            .escribir_durable(&clave, &blob)
            .map_err(|_| "fallo escritura ref custodia".to_string())?;
        let mut idx = String::new();
        for id in self.refs.keys() {
            idx.push_str(id);
            idx.push('\n');
        }
        self.almacen
            .as_mut()
            .escribir_durable(CLAVE_REFS, idx.as_bytes())
            .map_err(|_| "fallo index refs".to_string())
    }

    pub fn guardar_pep(&mut self) -> Result<(), String> {
        let json = self.pep.a_json();
        self.almacen
            .as_mut()
            .escribir_durable(CLAVE_PEP, json.as_bytes())
            .map_err(|_| "fallo escritura pep".to_string())
    }

    pub fn guardar_alta(&mut self, alta: &AltaSistema) -> Result<(), String> {
        self.altas.insert(alta.sistema_id.clone(), alta.clone());
        let mut clave = PREF_ALTA.to_vec();
        clave.extend_from_slice(alta.sistema_id.as_bytes());
        let blob = encode_alta(alta);
        self.almacen
            .as_mut()
            .escribir_durable(&clave, &blob)
            .map_err(|_| "fallo escritura alta".to_string())?;
        let mut idx = String::new();
        for id in self.altas.keys() {
            idx.push_str(id);
            idx.push('\n');
        }
        self.almacen
            .as_mut()
            .escribir_durable(CLAVE_ALTAS, idx.as_bytes())
            .map_err(|_| "fallo index altas".to_string())
    }

    pub fn emitir_pasaporte(
        &mut self,
        pasaporte_id: &str,
        version: u32,
        decl: &DeclaracionResponsable,
    ) -> Result<Pasaporte, String> {
        registrar_desde_declaracion_y_conservar(
            &mut self.registro,
            self.almacen.as_mut(),
            pasaporte_id,
            version,
            decl,
        )
        .map_err(|e| format!("{e}"))
    }

    pub fn guardar_libro(&mut self) -> Result<(), String> {
        conservar_libro(self.almacen.as_mut(), &self.libro)
            .map_err(|e| format!("conservar libro: {e}"))
    }

    /// Seed local de demostración: inventario firmado con clave efímera (se descarta).
    /// Sin PEM/raw/seed exportable en respuesta ni almacén de claves.
    pub fn aplicar_seed_demo_alcanzables(&mut self) -> Result<(), String> {
        use sak_core::contexto::ClaseEfecto;
        use sak_core::crypto::ParMlDsa87;
        use sak_core::libro::InventarioAlcanzables;
        use std::collections::BTreeSet;

        if self.libro.alcanzables_map().values().next().is_some() {
            return Ok(());
        }
        let par = ParMlDsa87::generar().map_err(|e| format!("seed demo: {e}"))?;
        let sid = IdSistema::nuevo("sys-demo-alcanzables").map_err(|e| e.to_string())?;
        let mut efectores = BTreeSet::new();
        efectores.insert(ClaseEfecto::Ef1);
        efectores.insert(ClaseEfecto::Ef4);
        let mut rutas = BTreeSet::new();
        rutas.insert("127.0.0.1:8443".into());
        let mut creds = BTreeSet::new();
        creds.insert("cred:digest:demo00aa".into());
        let inv = InventarioAlcanzables::firmar_completo(
            sid,
            "inst-demo",
            efectores,
            rutas,
            creds,
            BTreeSet::from(["store-demo".into()]),
            BTreeSet::from(["svc-demo".into()]),
            BTreeSet::from(["canal-demo".into()]),
            true, // incompleto_declarado: no afirma completitud
            1,
            1,
            0,
            "detector-demo-local",
            &par,
        )
        .map_err(|e| format!("seed inv: {e}"))?;
        // `par` (secreto) cae fuera de alcance aquí.
        self.libro.registrar_alcanzables(inv);
        let _ = self.guardar_libro();
        Ok(())
    }
}

fn encode_alta(a: &AltaSistema) -> Vec<u8> {
    format!(
        "v1|{sid}|{pid}|{resp}|{fin}|{riesgo}|{dig}|{nota}",
        sid = a.sistema_id,
        pid = a.pasaporte_id,
        resp = a.responsable.replace('|', "/"),
        fin = a.finalidad.replace('|', "/"),
        riesgo = a.clasificacion_riesgo.replace('|', "/"),
        dig = a.digest_decl,
        nota = a.nota,
    )
    .into_bytes()
}

fn decode_alta(b: &[u8]) -> Result<AltaSistema, ()> {
    let s = std::str::from_utf8(b).map_err(|_| ())?;
    let parts: Vec<&str> = s.splitn(8, '|').collect();
    if parts.len() < 8 || parts[0] != "v1" {
        return Err(());
    }
    Ok(AltaSistema {
        sistema_id: parts[1].into(),
        pasaporte_id: parts[2].into(),
        responsable: parts[3].into(),
        finalidad: parts[4].into(),
        clasificacion_riesgo: parts[5].into(),
        digest_decl: parts[6].into(),
        nota: "registra; no autoriza efectos",
    })
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex longitud impar".into());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err("hex invalido".to_string()),
        };
        out.push((h(bytes[i])? << 4) | h(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

pub fn id_sistema_ok(id: &str) -> bool {
    IdSistema::nuevo(id).is_ok()
}

fn encode_ref(r: &RefCustodia) -> Vec<u8> {
    let hist: String = r
        .historial
        .iter()
        .map(|h| {
            format!(
                "{}~{}~{}",
                h.huella.replace('~', "/").replace(';', "/"),
                h.handle.replace('~', "/").replace(';', "/"),
                h.epoca
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    format!(
        "v2|{sid}|{alias}|{clase}|{handle}|{huella}|{est}|{ttl}|{op}|{nrot}|{hist}",
        sid = r.secreto_id.replace('|', "/"),
        alias = r.alias.replace('|', "/"),
        clase = r.clase_ef.replace('|', "/"),
        handle = r.handle.replace('|', "/"),
        huella = r.huella.replace('|', "/"),
        est = r.estado.replace('|', "/"),
        ttl = r.ttl_derivadas_secs,
        op = r.operador_id.replace('|', "/"),
        nrot = r.n_rotaciones,
        hist = hist.replace('|', "/"),
    )
    .into_bytes()
}

fn decode_ref(b: &[u8]) -> Result<RefCustodia, ()> {
    let s = std::str::from_utf8(b).map_err(|_| ())?;
    let parts: Vec<&str> = s.splitn(11, '|').collect();
    if parts.len() >= 9 && parts[0] == "v1" {
        return Ok(RefCustodia {
            secreto_id: parts[1].into(),
            alias: parts[2].into(),
            clase_ef: parts[3].into(),
            handle: parts[4].into(),
            huella: parts[5].into(),
            estado: parts[6].into(),
            ttl_derivadas_secs: parts[7].parse().unwrap_or(0),
            operador_id: parts[8].into(),
            historial: Vec::new(),
            n_rotaciones: 0,
        });
    }
    if parts.len() < 11 || parts[0] != "v2" {
        return Err(());
    }
    let mut historial = Vec::new();
    if !parts[10].is_empty() {
        for chunk in parts[10].split(';') {
            let p: Vec<&str> = chunk.splitn(3, '~').collect();
            if p.len() == 3 {
                historial.push(HistRotacion {
                    huella: p[0].into(),
                    handle: p[1].into(),
                    epoca: p[2].parse().unwrap_or(0),
                });
            }
        }
    }
    Ok(RefCustodia {
        secreto_id: parts[1].into(),
        alias: parts[2].into(),
        clase_ef: parts[3].into(),
        handle: parts[4].into(),
        huella: parts[5].into(),
        estado: parts[6].into(),
        ttl_derivadas_secs: parts[7].parse().unwrap_or(0),
        operador_id: parts[8].into(),
        n_rotaciones: parts[9].parse().unwrap_or(0),
        historial,
    })
}
