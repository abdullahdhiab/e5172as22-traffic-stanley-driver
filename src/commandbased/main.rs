
use std::fs::File;
use std::io::Read;

use log::*;
use env_logger;

use chrono::prelude::*;

use serde::Serialize;

use clap::{Arg, ArgMatches, SubCommand, app_from_crate, crate_name, crate_version, crate_authors, crate_description};

use base64::encode as b64encode;

extern crate traffic_tracker;

use traffic_tracker::*;
use traffic_tracker::error::TrafficError;
use traffic_tracker::types::Bytes;

fn main() -> Result<(), TrafficError> {
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
        ("read",  Some(subcommand)) => {
            let database_base_url = reqwest::Url::parse(&subcommand.value_of("database-url").unwrap())?;
            let database_username = subcommand.value_of("database-username").unwrap();
            let database_password = subcommand.value_of("database-password").unwrap();
            let database_path = subcommand.value_of("database-path").unwrap();

            info!("Retrieving current traffic statistics");
            let session_id = login(&router_base_url, &client, &router_username, &router_password)?;
            debug!("Session ID: {}", session_id);
            let total_traffic = get_overview(&router_base_url, &client, session_id)?;
            info!("Total traffic: {}", Bytes::new(total_traffic));
            logout(&router_base_url, &client, session_id)?;
            send_to_database(
                total_traffic,
                &database_base_url,
                database_username,
                database_password,
                database_path,
                &client,
            )?;
        },
        ("clear",   Some(_)) => {
            info!("Clearing traffic statistics");
            let session_id = login(&router_base_url, &client, &router_username, &router_password)?;
            debug!("Session ID: {}", session_id);
            info!("Clearing traffic statistics");
            clear_statistics(&router_base_url, &client, session_id)?;
            logout(&router_base_url, &client, session_id)?;
        },
        _ => {},
    }

    Ok(())
}

fn parse_command_line() -> ArgMatches<'static> {
    app_from_crate!()
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
                .arg(
                    Arg::with_name("database-url")
                        .long("database-url")
                        .required(true)
                        .help("URL of the database")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("database-path")
                        .long("database-path")
                        .required(true)
                        .help("Path of time-series in the database")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("database-username")
                        .long("database-username")
                        .required(true)
                        .help("Username of the database")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("database-password")
                        .long("database-password")
                        .required(true)
                        .help("Password of the database")
                        .takes_value(true),
                )
        )
        .subcommand(
            SubCommand::with_name("clear")
                .about("Clears traffic data in the router")
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

#[derive(Debug, Serialize)]
struct Payload<'a> {
    data: Vec<(i64, f64)>,
    path: &'a str,
}

fn send_to_database(
        traffic: i64,
        base_url: &reqwest::Url,
        username: &str,
        password: &str,
        path: &str,
        client: &reqwest::Client
    ) -> Result<(), TrafficError> {
    let url = base_url.join("/post")?;
    let now: i64 = Utc::now().timestamp_nanos();
    let payload = Payload {
        data: vec![(now, traffic as f64)],
        path: path,
    };
    let encoded = b64encode(format!("{}:{}", username, password).as_bytes());
    let authorization = format!("Basic {}", encoded);
    let request = client.post(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .json(&payload)
        .build()?;
    debug!("Sending request: {:?}", request);
    debug!("Payload: {:?}", serde_json::to_string(&payload));
    let response_maybe = client.execute(request);
    info!("{:?}", response_maybe);
    Ok(())
}
