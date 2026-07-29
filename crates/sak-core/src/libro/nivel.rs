//! Niveles C0–C5 del Libro de Control.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum NivelControl {
    C0 = 0,
    C1 = 1,
    C2 = 2,
    C3 = 3,
    C4 = 4,
    C5 = 5,
}

impl NivelControl {
    pub fn token(self) -> &'static str {
        match self {
            NivelControl::C0 => "C0",
            NivelControl::C1 => "C1",
            NivelControl::C2 => "C2",
            NivelControl::C3 => "C3",
            NivelControl::C4 => "C4",
            NivelControl::C5 => "C5",
        }
    }

    pub fn min(self, other: Self) -> Self {
        if self <= other {
            self
        } else {
            other
        }
    }
}

impl fmt::Display for NivelControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}
