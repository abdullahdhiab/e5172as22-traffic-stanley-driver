E5172As-22 Traffic Reader
====

An application to fetch traffic statistics from GSM router Huawei E5172As-22.

https://gitlab.com/claudiomattera/e5172as22-traffic-reader/

Copyright Claudio Mattera 2020

When using a GSM router, often the connection is capped to a monthly total traffic, depending on the specific plan available on the SIM card.
This application logs in to the router's web interface, retrieves the current total traffic and prints it to the console, or optionally stores it in a [InfluxDB] database.
It also clears the total traffic on the router.

You are free to copy, modify, and distribute Stanley with attribution under the terms of the MIT license. See the `License.txt` file for details.


Technology
----

This application is written in [Rust], a type-safe system language, and uses [Stanley] database to store data.

[InfluxDB]: https://www.influxdata.com/products/influxdb-overview/


Installation
----

This application can be installed from source, provided the Rust toolchain is installed, by running the command:

~~~~bash
cargo install --path .
~~~~

Otherwise, precompiled binaries could be available in the repository (check the *tags* section).


Usage
----

This application is made of a single command-line executable `e5172as22-traffic-reader` which can be run as follows.

The router password must be encoded according to the router configuration.
I have not been able to figure out what hashing and encoding algorithm is was used, but the encoded password can be obtained using a network analyser and manually log on to the router.


~~~~text
> e5172as22-traffic-reader --help
e5172as22-traffic-reader 4.0.0
Claudio Mattera <claudio@mattera.it>
Track traffic in router Huawei E5172As-22

USAGE:
    e5172as22-traffic-reader [FLAGS] [OPTIONS] --router-password <router-password> --router-url <router-url> --router-username <router-username> [SUBCOMMAND]

FLAGS:
    -h, --help                   Prints help information
        --ignore-certificates    Ignore certificate validation for HTTPS
    -v, --verbose                Verbosity level
    -V, --version                Prints version information

OPTIONS:
        --ca-cert <ca-cert>                    Additional CA certificate for HTTPS connections
        --router-password <router-password>    Password of the router
        --router-url <router-url>              URL of the router
        --router-username <router-username>    Username of the router

SUBCOMMANDS:
    clear             Clears traffic data in the router
    help              Prints this message or the help of the given subcommand(s)
    read              Reads traffic data from the router
    read-and-store    Reads traffic data from the router and stores it to an Influxdb server

Influxdb password is read from environment variable INFLUXDB_PASSWORD
~~~~
