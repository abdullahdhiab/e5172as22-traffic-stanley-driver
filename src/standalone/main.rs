
use log::*;
use env_logger;

use chrono::prelude::*;

use clap::{Arg, ArgMatches, app_from_crate, crate_name, crate_version, crate_authors, crate_description};

extern crate traffic_tracker;

use traffic_tracker::*;
use traffic_tracker::error::TrafficError;
use traffic_tracker::types::Bytes;
use traffic_tracker::configuration::*;
use traffic_tracker::storage::*;

fn main() -> Result<(), TrafficError> {
    let matches = parse_command_line();

    setup_logging(matches.occurrences_of("v"));

    let configuration = load_configuration(matches.value_of("config").unwrap())?;

    let base_url = reqwest::Url::parse(&configuration.base_url)?;
    let username = configuration.username;
    let password = configuration.password;
    let database = configuration.database;

    let now: Date<Utc> = Utc::now().date();
    let today: NaiveDate = now.naive_utc();

    let client = reqwest::Client::new();

    info!("Retrieving current traffic statistics");
    let session_id = login(&base_url, &client, &username, &password)?;
    debug!("Session ID: {}", session_id);
    let total_traffic = get_overview(&base_url, &client, session_id)?;
    info!("Total traffic: {}", Bytes::new(total_traffic));

    if today.succ().day() == 1 {
        info!("Today it is the last day of the month, clearing statistics");
        clear_statistics(&base_url, &client, session_id)?;
    }

    logout(&base_url, &client, session_id)?;

    info!("Recording traffic statistics in database \"{}\"", database);
    store_traffic(total_traffic, &database)?;

    Ok(())
}

fn parse_command_line() -> ArgMatches<'static> {
    app_from_crate!()
        .arg(
            Arg::with_name("config")
                .short("c")
                .long("config")
                .value_name("FILE")
                .required(true)
                .help("Sets a custom config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("v")
                .short("v")
                .multiple(true)
                .help("Verbosity level"),
        )
        .get_matches()
}

pub fn setup_logging(verbosity: u64) {
    let default_log_filter = match verbosity {
        0 => "traffic_tracker=warn",
        1 => "traffic_tracker=info",
        2 | _ => "traffic_tracker=debug",
    };
    let filter = env_logger::Env::default().default_filter_or(default_log_filter);
    env_logger::Builder::from_env(filter).init();
}
