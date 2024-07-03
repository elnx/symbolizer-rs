// Axel '0vercl0k' Souchet - February 20 2024
//! This module contains the implementation of the [`Guid`] type.
use std::fmt::Display;

/// A GUID.
#[derive(Default, Debug)]
pub struct Guid {
    d0: u32,
    d1: u16,
    d2: u16,
    d3: [u8; 8],
}

impl From<[u8; 16]> for Guid {
    fn from(value: [u8; 16]) -> Self {
        let d0 = u32::from_le_bytes(value[0..4].try_into().unwrap());
        let d1 = u16::from_le_bytes(value[4..6].try_into().unwrap());
        let d2 = u16::from_le_bytes(value[6..8].try_into().unwrap());
        let d3 = value[8..].try_into().unwrap();

        Self { d0, d1, d2, d3 }
    }
}

use std::str::FromStr;

impl FromStr for Guid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return Err("Invalid GUID format".to_string());
        }

        let d0 = u32::from_str_radix(parts[0], 16).map_err(|e| format!("Invalid parse: {}", e))?;
        let d1 = u16::from_str_radix(parts[1], 16).map_err(|e| format!("Invalid parse: {}", e))?;
        let d2 = u16::from_str_radix(parts[2], 16).map_err(|e| format!("Invalid parse: {}", e))?;

        let d3_part = parts[3].to_owned() + parts[4]; // 使用 to_owned() 转换 &str 为 String

        let d3 = hex::decode(d3_part).unwrap().try_into().unwrap();

        Ok(Guid { d0, d1, d2, d3 })
    }
}

impl Display for Guid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:08X}{:04X}{:04X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.d0,
            self.d1,
            self.d2,
            self.d3[0],
            self.d3[1],
            self.d3[2],
            self.d3[3],
            self.d3[4],
            self.d3[5],
            self.d3[6],
            self.d3[7]
        ))
    }
}
