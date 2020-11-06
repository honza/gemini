use std::io::{Read, Write};
use std::net::TcpStream;
use url::Url;

use native_tls::TlsConnector;

// gemini://drewdevault.com/2020/09/27/Gemini-and-Hugo.gmi
// gemini://gemini.circumlunar.space/software/

fn gemini_request(url: Url) {
    let host = url.host_str().unwrap();
    let mut builder = TlsConnector::builder();

    // Self-signed certificates are considered invalid, but they are quite
    // common for gemini servers. Therefore, we accept invalid certs,
    // but check for expiration later
    builder.danger_accept_invalid_certs(true);

    // let connector = TlsConnector::new().unwrap();
    let connector = builder.build().unwrap();

    let connect_str = host.to_owned() + ":1965";
    let stream = TcpStream::connect(connect_str).unwrap();
    let mut stream = connector.connect(host, stream).unwrap();

    // let certificate = stream.peer_certificate().unwrap().unwrap();
    // let sig = certificate.to_der().unwrap();
    // println!("{:?}", sig);

    let request = url.into_string() + "\r\n";
    stream.write_all(request.as_bytes()).unwrap();

    let mut res = vec![];
    stream.read_to_end(&mut res).unwrap();
    println!("-> {}", String::from_utf8_lossy(&res));
}

fn main() {
    // let url = Url::parse("gemini://drewdevault.com/2020/09/27/Gemini-and-Hugo.gmi").unwrap();
    let url = Url::parse("gemini://drewdevault.com").unwrap();
    // let url = Url::parse("gemini://tanelorn.city/").unwrap();
    gemini_request(url);
}
