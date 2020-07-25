// Copyright Claudio Mattera 2019.
// Distributed under the MIT License.
// See accompanying file License.txt, or online at
// https://opensource.org/licenses/MIT

use std::env;
use std::fs::File;
use std::io::Read;

use log::*;

use env_logger;

use chrono::prelude::*;

use clap::{app_from_crate, crate_authors, crate_description, crate_name, crate_version,
    Arg, ArgMatches, SubCommand
};

use base64::encode as b64encode;

extern crate traffic;

use traffic::error::TrafficError;
use traffic::types::Bytes;
use traffic::{clear_statistics, get_overview, login, logout};

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
            let total_traffic = read_traffic(&router_base_url, &client, router_username, router_password)?;
            println!("{}", total_traffic);
        }
        ("clear", Some(_)) => clear_traffic(&router_base_url, &client, router_username, router_password)?,
        ("read-and-store", Some(subcommand)) => {
            let influxdb_base_url = reqwest::Url::parse(&subcommand.value_of("influxdb-url").unwrap())?;
            let influxdb_username = subcommand.value_of("influxdb-username").unwrap();
            let influxdb_password = get_password_from_environment_variable()?;
            let influxdb_database = subcommand.value_of("influxdb-database").unwrap();
            let influxdb_tags = subcommand.values_of("influxdb-tag").unwrap().collect();

            let total_traffic = read_traffic(&router_base_url, &client, router_username, router_password)?;
            post_reading_to_influxdb(
                total_traffic,
                &influxdb_base_url,
                influxdb_username,
                &influxdb_password,
                influxdb_database,
                influxdb_tags,
                &client,
            )?;
        }
        _ => println!("{}", matches.usage()),
    }

    Ok(())
}

fn parse_command_line() -> ArgMatches<'static> {
    app_from_crate!()
        .after_help("Influxdb password is read from environment variable INFLUXDB_PASSWORD")
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
                .about("Reads traffic data from the router and stores it to an Influxdb server")
                .arg(
                    Arg::with_name("influxdb-url")
                        .long("influxdb-url")
                        .required(true)
                        .help("URL of Influxdb server")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("influxdb-tag")
                        .long("influxdb-tag")
                        .required(true)
                        .help("Tags for Influxdb measurement")
                        .takes_value(true)
                        .multiple(true),
                )
                .arg(
                    Arg::with_name("influxdb-username")
                        .long("influxdb-username")
                        .required(true)
                        .help("Username for the Influxdb server")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("influxdb-database")
                        .long("influxdb-database")
                        .required(true)
                        .help("Database name for the Influxdb server")
                        .takes_value(true),
                )
        )
        .get_matches()
}

fn setup_logging(verbosity: u64) {
    let default_log_filter = match verbosity {
        0 => "traffic=warn,e5172as22_traffic_influxdb_driver=warn",
        1 => "traffic=info,e5172as22_traffic_influxdb_driver=info",
        2 | _ => "traffic=debug,e5172as22_traffic_influxdb_driver=debug",
    };
    let filter = env_logger::Env::default().default_filter_or(default_log_filter);
    env_logger::Builder::from_env(filter).init();
}

fn get_password_from_environment_variable() -> Result<String, Box<dyn std::error::Error>> {
    let password = env::var_os("INFLUXDB_PASSWORD")
        .ok_or_else(|| TrafficError::new("Missing environment variable INFLUXDB_PASSWORD".to_string()))?
        .into_string()
        .map_err(|_| {
            TrafficError::new("Invalid INFLUXDB_PASSWORD environment variable content".to_string())
        })?;

    debug!("Removing INFLUXDB_PASSWORD from environment");
    env::remove_var("INFLUXDB_PASSWORD");

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

fn post_reading_to_influxdb(
        traffic: i64,
        base_url: &reqwest::Url,
        username: &str,
        password: &str,
        database: &str,
        tags: Vec<&str>,
        client: &reqwest::Client
    ) -> Result<(), Box<dyn std::error::Error>> {
    info!("Posting traffic to Influxdb");
    let url = base_url.join(&format!("/write?db={}", database))?;
    let now: i64 = Utc::now().timestamp_nanos();
    let tags = if tags.len() > 0 {
            format!(",{}", tags.join(","))
        } else {
            "".to_string()
        };
    let body = format!(
        "traffic{tags} month_cumulative={traffic} {timestamp}",
        tags=tags,
        traffic=traffic,
        timestamp=now,
    );
    let encoded = b64encode(format!("{}:{}", username, password).as_bytes());
    let authorization = format!("Basic {}", encoded);
    debug!("Body: {:?}", &body);
    let request = client.post(url)
        .header(reqwest::header::AUTHORIZATION, authorization)
        .body(body)
        .build()?;
    debug!("Sending request: {:?}", request);
    client.execute(request)?
        .error_for_status()?;

    Ok(())
}
