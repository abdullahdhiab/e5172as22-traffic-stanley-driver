use std::fs::File;
use std::io::prelude::*;

use serde::Deserialize;


use super::TrafficError;

#[derive(Debug, Deserialize)]
pub struct Configuration {
    pub base_url: String,
    pub username: String,
    pub password: String,
    pub database: String,
}

pub fn load_configuration(configuration_path: &str) -> Result<Configuration, TrafficError> {
    let mut file = File::open(configuration_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let configuration: Configuration = toml::from_str(&contents)?;
    Ok(configuration)
}
