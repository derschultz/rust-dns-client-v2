use dns_client::dns_client_lib::*;
use std::net::UdpSocket;

fn main() {
    let h = DnsHeader::new(0xABCDu16, false, DnsOpcode::QUERY, false, false,
                           true, false, DnsRcode::NOERROR);
    let qrv : Vec<DnsQuestionRecord> =
        vec![DnsQuestionRecord::new(String::from("akasecure.net."), DnsQType::ANY, DnsQClass::IN)];
    let q = DnsQuery::new(h, qrv);
    println!("{q}");
    let qbytes = match q.to_bytes() {
        Ok(b) => b,
        Err(e) => { println!("Got an error creating query bytes: {e}"); return }
    };

    let socket = UdpSocket::bind("192.168.1.16:43254").expect("couldn't bind to address");
    socket.connect("8.8.8.8:53").expect("couldn't connect to server");
    match socket.send(qbytes.as_slice()) {
        Ok(bytes_sent) => {
            //println!("successfully sent {bytes_sent} bytes");
            let mut rbuf = [0; 65535];
            match socket.recv(&mut rbuf) {
                Ok(response_length) => {
                    let buf = rbuf[0 .. response_length].to_vec();
                    println!("got {response_length} bytes back from server: {buf:x?}");
                    let response = match DnsResponse::from_bytes(&buf, 0) {
                        Ok(r) => r,
                        Err(e) => {
                            println!("Error parsing response: {e}");
                            return;
                        }
                    };
                    println!("{response}");
                },
                Err(e) => println!("Error reading response from server: {e}")
            }
        },
        Err(e) => println!("Error sending to socket: {e}")
    }
}
