use dns_client::dns_client_lib::*;
use std::net::UdpSocket;

fn main() {
    let h = DnsHeader::new(0xABCDu16, false, DnsOpcode::QUERY, false, false,
                           true, false, DnsRcode::NOERROR);
    let qrv : Vec<DnsQuestionRecord> =
        vec![DnsQuestionRecord::new(String::from("google.com."), DnsQType::A, DnsQClass::IN)];
    let q = DnsQuery::new(h, qrv);
    let qbytes = match q.to_bytes() {
        Ok(b) => b,
        Err(e) => { println!("Got an error creating query bytes: {e}"); return }
    };

    let socket = UdpSocket::bind("192.168.1.16:43254").expect("couldn't bind to address");
    socket.connect("8.8.8.8:53").expect("couldn't connect to server");
    match socket.send(qbytes.as_slice()) {
        Ok(bytes_sent) => {
            println!("successfully sent {bytes_sent} bytes");
            let mut rbuf = [0; 65535];
            match socket.recv(&mut rbuf) {
                Ok(response_length) => {
                    println!("got {response_length} bytes back from server.");
                    // TODO handle response.
                    match DnsHeader::from_bytes(rbuf.to_vec(), 0) {
                        Ok(h) => println!("got a header: {h}"),
                        Err(s) => println!("error parsing response: {s}")
                    }
                },
                Err(e) => println!("Error reading response from server: {e}")
            }
        },
        Err(e) => println!("Error sending to socket: {e}")
    }
}
