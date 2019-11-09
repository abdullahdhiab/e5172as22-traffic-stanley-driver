// Copyright Claudio Mattera 2019.
// Distributed under the MIT License.
// See accompanying file License.txt, or online at
// https://opensource.org/licenses/MIT

use std::fmt;

#[derive(Debug)]
pub struct TrafficError(String);

impl TrafficError {
    pub fn new(message: String) -> Self {
        Self(message)
    }
}

impl std::error::Error for TrafficError {
    fn description(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrafficError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<std::io::Error> for TrafficError {
    fn from(error: std::io::Error) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<std::num::ParseIntError> for TrafficError {
    fn from(error: std::num::ParseIntError) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<reqwest::Error> for TrafficError {
    fn from(error: reqwest::Error) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<reqwest::UrlError> for TrafficError {
    fn from(error: reqwest::UrlError) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<reqwest::header::ToStrError> for TrafficError {
    fn from(error: reqwest::header::ToStrError) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<toml::de::Error> for TrafficError {
    fn from(error: toml::de::Error) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<serde_json::error::Error> for TrafficError {
    fn from(error: serde_json::error::Error) -> Self {
        TrafficError(error.to_string())
    }
}

impl From<rusqlite::Error> for TrafficError {
    fn from(error: rusqlite::Error) -> Self {
        TrafficError(error.to_string())
    }
}
