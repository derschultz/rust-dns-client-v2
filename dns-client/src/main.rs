use dns_client::dns_client_lib::*;
use std::net::{UdpSocket,TcpStream};
use std::io::{Read,Write};

fn main() {
    // response for google.com/TXT/IN
    /*
    match DnsResponse::from_bytes(&buf, 0) {
        Ok(response) => { println!("{response}") },
        Err(e) => { println!("{e}") }
    }
    */

    let h = DnsHeader::new(0xABCDu16, false, DnsOpcode::QUERY, false, false,
                           true, false, DnsRcode::NOERROR);
    let qrv : Vec<DnsQuestionRecord> =
        //vec![DnsQuestionRecord::new(String::from("google.com."), DnsQType::TXT, DnsQClass::IN)];
        vec![DnsQuestionRecord::new(String::from("google.com."), DnsQType::ANY, DnsQClass::IN)];
    let optr = DnsOPTRecord::new(vec![]);
    let addv : Vec<DnsResourceRecord> =
        vec![DnsResourceRecord::new(String::from("."), DnsQType::OPT,
             DnsQClass::RESERVED(4096u16), 0, DnsResourceRecordEnum::OPT(optr))];
    let q = DnsQuery::new(h, qrv, Some(addv));
    println!("{q}");
    let qbytes = match q.to_bytes() {
        Ok(b) => b,
        Err(e) => { println!("Got an error creating query bytes: {e}"); return }
    };
    /* tcp
    let mut stream = TcpStream::connect("8.8.8.8:53").expect("couldn't connect to server over tcp");
    match stream.write(qbytes.as_slice()) {
    */

    /* udp */
    let socket = UdpSocket::bind("192.168.1.16:43254").expect("couldn't bind to address");
    socket.connect("8.8.8.8:53").expect("couldn't connect to server");
    match socket.send(qbytes.as_slice()) {
        //Ok(bytes_sent) => {
        Ok(_) => {
            //println!("successfully sent {bytes_sent} bytes");
            let mut rbuf = [0 as u8; 65535];
            match socket.recv(&mut rbuf) {
            //let mut rbuf: Vec<u8> = Vec::new();
            //match stream.read_to_end(&mut rbuf) {
                Ok(response_length) => {
                    let buf = rbuf[0 .. response_length].to_vec();
                    //println!("got {response_length} bytes back from server: {buf:x?}");
                    //println!("got {response_length} bytes back from server: {rbuf:x?}");
                    let response = match DnsResponse::from_bytes(&buf, 0) {
                    //let response = match DnsResponse::from_bytes(&rbuf, 0) {
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
