//! Umbrales fijos del monitor (I.1 / PERFECTO §6.3). No configurables.

use crate::reloj::Ticks;

/// Silencio de PEP ⇒ suspensión de clase (30 s).
pub const UMBRAL_PEP_SILENCIO_MS: Ticks = 30_000;
/// Cofirma/atestación obsoleta ⇒ DEGRADED (900 s).
pub const UMBRAL_COFIRMA_DEGRADED_MS: Ticks = 900_000;
/// Cofirma/atestación obsoleta ⇒ SUSPENDED (3600 s).
pub const UMBRAL_COFIRMA_SUSPEND_MS: Ticks = 3_600_000;
/// Alias atestación plataforma (misma política; VAL-EXT).
pub const UMBRAL_ATESTACION_SUSPEND_MS: Ticks = UMBRAL_COFIRMA_SUSPEND_MS;
/// Divergencia reconciliación ⇒ SUSPENDED del dominio.
pub const UMBRAL_RECONCILIACION_SUSPEND_PCT: u32 = 5;
