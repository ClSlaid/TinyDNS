use std::net::UdpSocket;

use tiny_dns::resolve::query_handler;

use anyhow::Result;

fn main() -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", 2053))?;

    loop {
        match query_handler(&socket) {
            Ok(_) => println!("== Handle successful! ==\n\n"),
            Err(e) => eprintln!("== An error occured: {} ==\n\n", e),
        }
    }
}
