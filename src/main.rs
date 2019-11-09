
use std::env;
use std::fs::File;
use std::io::Read;

use log::*;

use env_logger;

use chrono::prelude::*;

use serde::Serialize;

use clap::{app_from_crate, crate_authors, crate_description, crate_name, crate_version,
    Arg, ArgMatches, SubCommand
};

use base64::encode as b64encode;

extern crate traffic_tracker;

use traffic_tracker::error::TrafficError;
use traffic_tracker::types::Bytes;
use traffic_tracker::{clear_statistics, get_overview, login, logout};

fn main() {
    match inner() {
        Ok(_) => {}
        Err(error) => error!("Error: {}", error),
    }
}

fn inner() -> Result<(), Box<dyn std::error::Error>> {
    let matches = parse_command_line();

    setup_logging(matches.occurrences_of("v"));

    let router_base_url = reqwest::Url::parse(&matches.value_of("router-url").unwrap())?;
    let router_username = matches.value_of("router-username").unwrap();
    let router_password = matches.value_of("router-password").unwrap();

    let mut client_builder = reqwest::ClientBuilder::new();
    if matches.is_present("ignore-certificates") {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    if let Some(ca_cert_path) = matches.value_of("ca-cert") {
        let mut buffer = Vec::new();
        File::open(ca_cert_path)?.read_to_end(&mut buffer)?;
        let ca_certificate = reqwest::Certificate::from_pem(&buffer)?;
        client_builder = client_builder.add_root_certificate(ca_certificate)
    }

    let client = client_builder.build()?;

    match matches.subcommand() {
        ("read", Some(_)) => {
            read_traffic(&router_base_url, &client, router_username, router_password)?;
        }
        ("clear", Some(_)) => clear_traffic(&router_base_url, &client, router_username, router_password)?,
        ("read-and-store", Some(subcommand)) => {
            let stanley_base_url = reqwest::Url::parse(&subcommand.value_of("stanley-url").unwrap())?;
            let stanley_username = subcommand.value_of("stanley-username").unwrap();
            let stanley_password = get_password_from_environment_variable()?;
            let time_series_path = subcommand.value_of("stanley-path").unwrap();

            let total_traffic = read_traffic(&router_base_url, &client, router_username, router_password)?;
            post_reading_to_stanley(
                total_traffic,
                &stanley_base_url,
                stanley_username,
                &stanley_password,
                time_series_path,
                &client,
            )?;
        }
        _ => println!("{}", matches.usage()),
    }

    Ok(())
}

fn parse_command_line() -> ArgMatches<'static> {
    app_from_crate!()
        .after_help("Stanley password is read from environment variable STANLEY_PASSWORD")
        .arg(
            Arg::with_name("v")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Verbosity level"),
        )
        .arg(
            Arg::with_name("ca-cert")
                .long("ca-cert")
                .help("Additional CA certificate for HTTPS connections")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ignore-certificates")
                .long("ignore-certificates")
                .help("Ignore certificate validation for HTTPS"),
        )
        .arg(
            Arg::with_name("router-url")
                .long("router-url")
                .required(true)
                .help("URL of the router")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("router-username")
                .long("router-username")
                .required(true)
                .help("Username of the router")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("router-password")
                .long("router-password")
                .required(true)
                .help("Password of the router")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("read")
                .about("Reads traffic data from the router")
        )
        .subcommand(
            SubCommand::with_name("clear")
                .about("Clears traffic data in the router")
        )
        .subcommand(
            SubCommand::with_name("read-and-store")
                .about("Reads traffic data from the router and stores it to a Stanley server")
                .arg(
                    Arg::with_name("stanley-url")
                        .long("stanley-url")
                        .required(true)
                        .help("URL of Stanley server")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("stanley-path")
                        .long("stanley-path")
                        .required(true)
                        .help("Path of time-series")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("stanley-username")
                        .long("stanley-username")
                        .required(true)
                        .help("Username of for Stanley server")
                        .takes_value(true),
                )
        )
        .get_matches()
}

fn setup_logging(verbosity: u64) {
    let default_log_filter = match verbosity {
        0 => "traffic_tracker=warn",
        1 => "traffic_tracker=info",
        2 | _ => "traffic_tracker=debug",
    };
    let filter = env_logger::Env::default().default_filter_or(default_log_filter);
    env_logger::Builder::from_env(filter).init();
}

fn get_password_from_environment_variable() -> Result<String, Box<dyn std::error::Error>> {
    let password = env::var_os("STANLEY_PASSWORD")
        .ok_or_else(|| TrafficError::new("Missing environment variable STANLEY_PASSWORD".to_string()))?
        .into_string()
        .map_err(|_| {
            TrafficError::new("Invalid STANLEY_PASSWORD environment variable content".to_string())
        })?;

    debug!("Removing STANLEY_PASSWORD from environment");
    env::remove_var("STANLEY_PASSWORD");

    Ok(password)
}

fn read_traffic(
        router_base_url: &reqwest::Url,
        client: &reqwest::Client,
        router_username: &str,
        router_password: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
    info!("Retrieving current traffic statistics");
    let session_id = login(&router_base_url, client, router_username, router_password)?;
    debug!("Session ID: {}", session_id);
    let total_traffic = get_overview(router_base_url, client, session_id)?;
    info!("Total traffic: {}", Bytes::new(total_traffic));
    logout(router_base_url, client, session_id)?;
    Ok(total_traffic)
}

fn clear_traffic(
        router_base_url: &reqwest::Url,
        client: &reqwest::Client,
        router_username: &str,
        router_password: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
    info!("Clearing traffic statistics");
    let session_id = login(router_base_url, client, router_username, router_password)?;
    debug!("Session ID: {}", session_id);
    info!("Clearing traffic statistics");
    clear_statistics(router_base_url, client, session_id)?;
    logout(router_base_url, client, session_id)?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct PayloadChunk<'a> {
    readings: Vec<(i64, f64)>,
    path: &'a str,
}

type Payload<'a> = Vec<PayloadChunk<'a>>;

fn post_reading_to_stanley(
        traffic: i64,
        base_url: &reqwest::Url,
        username: &str,
        password: &str,
        path: &str,
        client: &reqwest::Client
    ) -> Result<(), Box<dyn std::error::Error>> {
    let url = base_url.join("/api/v1/post")?;
    let now: i64 = Utc::now().timestamp_nanos();
    let payload_chunk = PayloadChunk {
        readings: vec![(now, traffic as f64)],
        path,
    };
    let payload: Payload = vec![payload_chunk];
    let encoded = b64encode(format!("{}:{}", username, password).as_bytes());
    let authorization = format!("Basic {}", encoded);
    let request = client.post(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .json(&payload)
        .build()?;
    debug!("Sending request: {:?}", request);
    debug!("Payload: {:?}", serde_json::to_string(&payload));
    client.execute(request)?
        .error_for_status()?;

    Ok(())
}
