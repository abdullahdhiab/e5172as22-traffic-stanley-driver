use log::*;

pub mod error;
pub mod types;
pub mod configuration;
pub mod storage;

use crate::error::*;
use crate::types::Duration;

pub fn login(
    base_url: &reqwest::Url,
    client: &reqwest::Client,
    username: &str,
    password: &str,
) -> Result<u64, TrafficError> {
    debug!("Logging in");
    let params = [("Username", username), ("Password", password)];
    let url = base_url.join("/index/login.cgi")?;

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::COOKIE, "Language=en_us.".parse().unwrap());

    let request = client.post(url)
        .form(&params)
        .headers(headers)
        .build()?;

    let response = process_request(&client, request)?;

    if let Some(cookie) = response.headers().get(reqwest::header::SET_COOKIE) {
        let mut cookie = cookie.to_str()?.to_string();
        let index = cookie.find(';').unwrap();
        cookie.truncate(index);
        if cookie.find("SessionID_R3=").is_some() {
            let session_id = cookie.split_off("SessionID_R3=".len());
            let session_id: u64 = session_id.parse()?;
            return Ok(session_id);
        }
        return Err(TrafficError::new(
            "Did not receive a new session id".to_string(),
        ));
    }

    Err(TrafficError::new(
        "Did not receive a new cookie".to_string(),
    ))
}

pub fn logout(
    base_url: &reqwest::Url,
    client: &reqwest::Client,
    session_id: u64,
) -> Result<(), TrafficError> {

    debug!("Logging out");

    let cookie = format!("Language=en_us; SessionID_R3={}", session_id);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::COOKIE, cookie.parse().unwrap());

    let url = base_url.join("/index/logout.cgi")?;
    let request = client.post(url)
        .headers(headers)
        .build()?;
    let _response = process_request(&client, request)?;

    Ok(())
}

pub fn clear_statistics(
    base_url: &reqwest::Url,
    client: &reqwest::Client,
    session_id: u64,
) -> Result<(), TrafficError> {

    debug!("Logging out");

    let cookie = format!("Language=en_us; SessionID_R3={}", session_id);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::COOKIE, cookie.parse().unwrap());

    let url = base_url.join("/html/status/cleanWanStatisticsData.cgi")?;
    let params = [("RequestFile", "/html/status/overview.asp")];
    let request = client.post(url)
        .form(&params)
        .headers(headers)
        .build()?;
    let _response = process_request(&client, request)?;

    Ok(())
}

pub fn get_overview(
    base_url: &reqwest::Url,
    client: &reqwest::Client,
    session_id: u64,
) -> Result<i64, TrafficError> {

    debug!("Getting overview");

    let cookie = format!("Language=en_us; SessionID_R3={}", session_id);
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::COOKIE, cookie.parse().unwrap());
    headers.insert(
        reqwest::header::REFERER,
        "http://192.168.1.1/index/login.cgi".parse().unwrap(),
    );

    let url = base_url.join("/html/status/overview.asp")?;
    let request = client.get(url)
        .headers(headers)
        .build()?;

    let mut response = process_request(&client, request)?;

    let mut text = response.text()?;

    if let Some(index) = text.find("WanStatistics = {") {
        let mut text = text.split_off(index + "WanStatistics = ".len());
        if let Some(index) = text.find('}') {
            text.truncate(index + 1);
            // { uprate' : '0' , 'downrate' : '0' , 'upvolume' : '0' , 'downvolume' : '0' , 'liveTime' : '0' }
            let text = text.replace("'", "\"");
            let dict: serde_json::Value = serde_json::from_str(&text)?;
            let upvolume: i64 = dict.get("upvolume").unwrap()
                .as_str().unwrap()
                .parse().unwrap();
            let downvolume: i64 = dict.get("downvolume").unwrap()
                .as_str().unwrap()
                .parse().unwrap();
            let livetime: u64 = dict.get("liveTime").unwrap()
                .as_str().unwrap()
                .parse().unwrap();
            let livetime = Duration::from_secs(livetime);
            let total_traffic = upvolume + downvolume;
            debug!("Total traffic: {}", total_traffic);
            debug!("Livetime: {}", livetime);
            return Ok(total_traffic);
        } else {
            Err(TrafficError::new("No closing brace".to_string()))
        }
    } else {
        Err(TrafficError::new("No WanStatistics structure".to_string()))
    }
}

fn process_request(
    client: &reqwest::Client,
    request: reqwest::Request,
) -> Result<reqwest::Response, TrafficError> {

    let url = request.url().clone();
    debug!("T {} -> {}", "this", url);
    debug!("{} {} HTTP/1.1.", request.method(), url);
    for (key, value) in request.headers().iter() {
        debug!("{:?}: {:?}.", key, value);
    }
    if let Some(body) = request.body() {
        debug!("");
        debug!("");
        debug!("{:#?}", body);
    }
    debug!("");
    debug!("");

    let response = client.execute(request)?;
    debug!("T {} -> {}", url, "this");
    debug!(
        "HTTP/1.1 {} {}.",
        response.status().as_u16(),
        response.status().as_str(),
    );
    for (key, value) in response.headers().iter() {
        debug!("{:?}: {:?}.", key, value);
    }

    Ok(response)
}
