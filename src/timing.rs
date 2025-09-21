//! Timing templates and scan speed control
//!
//! Implements timing control for scans

use std::time::Duration;

pub struct TimingTemplate {
    level: u8,
}

impl TimingTemplate {
    pub fn from_level(level: u8) -> Self {
        Self { level: level.min(5) }
    }
    
    pub fn scan_delay(&self) -> Option<Duration> {
        match self.level {
            0 => Some(Duration::from_millis(5000)), // Paranoid
            1 => Some(Duration::from_millis(1000)), // Sneaky
            2 => Some(Duration::from_millis(400)),  // Polite
            _ => None, // Normal, aggressive, insane - no delay
        }
    }
}
