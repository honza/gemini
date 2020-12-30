//  gemini client in rust
//  Copyright (C) 2020 Honza Pokorny <me@honza.ca>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
use openssl::hash::MessageDigest;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use structopt::StructOpt;
use url::Url;

#[derive(Debug, StructOpt)]
#[structopt(name = "gemini", about = "A simple gemini client")]
struct Cli {
    url: String,
}

fn write_cert_to_file(path: &Path, cert: X509) -> io::Result<()> {
    let mut file = File::create(path).unwrap();
    file.write_all(&cert.to_pem()?)?;
    Ok(())
}

fn read_cert_from_file(path: &Path) -> io::Result<X509> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(X509::from_pem(&contents.into_bytes())?)
}

fn hex_fingerprint(cert: X509) -> String {
    let fingerprint = cert.digest(MessageDigest::md5()).unwrap();
    let mut hex = String::new();

    for (pos, a) in fingerprint.iter().enumerate() {
        if pos > 0 {
            hex += ":";
        }
        hex = hex + &format!("{:02X?}", a);
    }

    return hex;
}

// TODO: make this configurable via envvar and cli flag
fn get_cert_dir_path() -> String {
    String::from("certs")
}

fn verify_cert(hostname: String, cert: X509) -> io::Result<bool> {
    let certs_path = get_cert_dir_path();
    let cert_path = Path::new(&certs_path).join(&hostname);

    if !cert_path.exists() {
        // save and exit
        write_cert_to_file(&cert_path, cert)?;
        return Ok(true);
    }

    let existing_cert = read_cert_from_file(&cert_path)?;
    let existing_cert_fingerprint = hex_fingerprint(existing_cert);
    let current_cert_fingerprint = hex_fingerprint(cert);

    Ok(existing_cert_fingerprint == current_cert_fingerprint)
}

fn gemini_request(url: Url) {
    let host = url.host_str().unwrap();
    let connect_str = host.to_owned() + ":1965";

    let connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    let mut ssl_conf = connector.configure().unwrap();
    ssl_conf.set_verify(SslVerifyMode::NONE);
    let stream = TcpStream::connect(connect_str).unwrap();
    let mut stream = ssl_conf.connect(host, stream).unwrap();
    let cert = stream.ssl().peer_certificate().unwrap();
    let verified = verify_cert(host.to_owned(), cert).unwrap();

    if !verified {
        println!("WARNING: certificate not verified");
    }

    let request = url.into_string() + "\r\n";
    stream.write_all(&request.into_bytes()[..]).unwrap();
    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("{}", String::from_utf8_lossy(&res));
}

fn main() {
    let args = Cli::from_args();
    let url = Url::parse(&args.url).unwrap();
    gemini_request(url);
}
