// Copyright Claudio Mattera 2020.
// Distributed under the MIT License.
// See accompanying file License.txt, or online at
// https://opensource.org/licenses/MIT

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrafficError {

    #[error("Did not receive a session id")]
    NoSessionId,

    #[error("Did not receive a new cookie")]
    NoCookie,

    #[error("No closing brace found")]
    NoClosingBrace,

    #[error("No WanStatistics structure found")]
    NoWanStatistics,

    #[error("{0}")]
    Custom(String),

    #[error("IO error")]
    IoError(#[from] std::io::Error),

    #[error("Parse error")]
    ParseError(#[from] std::num::ParseIntError),

    #[error("Reqwest error")]
    ReqwestError(#[from] reqwest::Error),

    #[error("Url error")]
    UrlError(#[from] url::ParseError),

    #[error("Header error")]
    HeaderError(#[from] reqwest::header::ToStrError),

    #[error("Serialization error")]
    SerializationError(#[from] serde_json::error::Error),
}
