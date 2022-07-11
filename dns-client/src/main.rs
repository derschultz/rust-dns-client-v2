use dns_client::dns_client_lib::*;
use std::net::UdpSocket;
use clap::Parser;
use rand::Rng;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about=None)]
struct Arguments {
    #[clap(short='s', long, value_parser, default_value_t = String::from("8.8.8.8:53"))]
    server: String,
    #[clap(short='n', long, value_parser, default_value_t = String::from("google.com"))]
    qname: String,
    #[clap(short='t', long, value_parser, default_value_t = String::from("A"))]
    qtype: String,
    #[clap(short='c', long, value_parser, default_value_t = String::from("IN"))]
    qclass: String
}

fn make_query(args: &Arguments) -> Result<DnsQuery, String> {
    // header
    let mut rng = rand::thread_rng();
    let qid: u16 = rng.gen();
    let h = DnsHeader::new(qid, false, DnsOpcode::QUERY, false, false,
                           true, false, DnsRcode::NOERROR);

    // question
    let qtype = DnsQType::from_string(&args.qtype)?;
    let qclass = DnsQClass::from_string(&args.qclass)?;
    let qrv : Vec<DnsQuestionRecord> =
        vec![DnsQuestionRecord::new(args.qname.clone(), qtype, qclass)];

    // add on the opt RR to let them know we can handle big packets
    let optr = DnsOPTRecord::new(vec![]);
    let addv : Vec<DnsResourceRecord> =
        vec![DnsResourceRecord::new(String::from("."), DnsQType::OPT,
             DnsQClass::RESERVED(4096u16), 0, DnsResourceRecordEnum::OPT(optr))];

    Ok(DnsQuery::new(h, qrv, Some(addv)))
}

fn main() {
    let args = Arguments::parse();

    let q = match make_query(&args) {
        Ok(q) => q,
        Err(e) => { println!("{e}"); return; }
    };
    println!("{q}");

    let qbytes = match q.to_bytes() {
        Ok(b) => b,
        Err(e) => { println!("Got an error creating query: {e}"); return }
    };

    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    socket.connect(&args.server.as_str()).expect("couldn't connect to server");

    match socket.send(qbytes.as_slice()) {
        Ok(_) => {
            // TODO what if bytes sent != qbytes.len() ?
            let mut rbuf = [0 as u8; 65535];

            match socket.recv(&mut rbuf) {
                Ok(response_length) => {
                    let buf = rbuf[0 .. response_length].to_vec();

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
