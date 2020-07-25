// Copyright Claudio Mattera 2020.
// Distributed under the MIT License.
// See accompanying file License.txt, or online at
// https://opensource.org/licenses/MIT

use std::fmt;

pub struct Bytes(i64);

impl Bytes {
    pub fn new(n: i64) -> Self {
        Self(n)
    }
}

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0 < 1024 {
            write!(f, "{} B", self.0)
        } else if self.0 < 1024 * 1024 {
            write!(f, "{:.2} kB", self.0 as f64 / 1024.0)
        } else if self.0 < 1024 * 1024 * 1024 {
            write!(f, "{:.2} MB", self.0 as f64 / 1024.0 / 1024.0)
        } else {
            write!(f, "{:.2} GB", self.0 as f64 / 1024.0 / 1024.0 / 1024.0)
        }
    }
}

pub struct Duration(u64);

impl Duration {
    pub fn from_secs(n: u64) -> Self {
        Self(n)
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "P")?;

        let mut n: u64 = self.0;

        if n == 0 {
            write!(f, "T0S")?;
            return Ok(());
        }

        if n >= 3600 * 24 {
            write!(f, "{}D", n / (3600 * 24))?;
            n %= 3600 * 24;
        }

        if n > 0 {
            write!(f, "T")?;
        }

        if n >= 3600 {
            write!(f, "{}H", n / 3600)?;
        }
        n %= 3600;
        if n >= 60 {
            write!(f, "{}M", n / 60)?;
        }
        n %= 60;
        if n > 0 {
            write!(f, "{}S", n)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_bytes() {
        let bytes = Bytes::new(342);
        assert_eq!(format!("{}", bytes), "342 B");
    }

    #[test]
    fn display_kilobytes() {
        let bytes = Bytes::new(2342);
        assert_eq!(format!("{}", bytes), "2.29 kB");
    }

    #[test]
    fn display_megabytes() {
        let bytes = Bytes::new(45_326_252);
        assert_eq!(format!("{}", bytes), "43.23 MB");
    }

    #[test]
    fn display_gigabytes() {
        let bytes = Bytes::new(987_345_983_759);
        assert_eq!(format!("{}", bytes), "919.54 GB");
    }

    #[test]
    fn display_seconds() {
        let duration = Duration::from_secs(45);
        assert_eq!(format!("{}", duration), "PT45S");
    }

    #[test]
    fn display_minutes() {
        let duration = Duration::from_secs(240);
        assert_eq!(format!("{}", duration), "PT4M");
    }

    #[test]
    fn display_minutes_and_seconds() {
        let duration = Duration::from_secs(138);
        assert_eq!(format!("{}", duration), "PT2M18S");
    }

    #[test]
    fn display_hours_and_minutes_and_seconds() {
        let duration = Duration::from_secs(24543);
        assert_eq!(format!("{}", duration), "PT6H49M3S");
    }

    #[test]
    fn display_days_hours_and_minutes_and_seconds() {
        let duration = Duration::from_secs(2_584_783);
        assert_eq!(format!("{}", duration), "P29DT21H59M43S");
    }

    #[test]
    fn display_zero_duration() {
        let duration = Duration::from_secs(0);
        assert_eq!(format!("{}", duration), "PT0S");
    }
}
