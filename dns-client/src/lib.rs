pub mod dns_client_lib {
    use std::net::{Ipv4Addr,Ipv6Addr};
    use std::fmt;
    use regex::Regex;
    use rand::Rng;

    const HEADER_SIZE: usize = 12; 

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsOpcode {
        QUERY = 0,
        IQUERY = 1,
        STATUS = 2,
        RESERVED // 3-15
    }

    impl DnsOpcode {
        pub fn from_u8(value: u8) -> DnsOpcode {
            match value {
                0 => DnsOpcode::QUERY,
                1 => DnsOpcode::IQUERY,
                2 => DnsOpcode::STATUS,
                _ => DnsOpcode::RESERVED
            }
        }
    }

    impl fmt::Display for DnsOpcode {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsOpcode::QUERY => write!(f, "QUERY"),
                DnsOpcode::IQUERY => write!(f, "IQUERY"),
                DnsOpcode::STATUS => write!(f, "STATUS"),
                DnsOpcode::RESERVED => write!(f, "RESERVED")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsRcode {
        NOERROR = 0,
        FORMERR = 1,
        SERVFAIL = 2,
        NAMERR = 3,
        NOTIMP = 4,
        REFUSED = 5,
        RESERVED // 6-15
    }

    impl DnsRcode {
        pub fn from_u8(value: u8) -> DnsRcode {
            match value {
                0 => DnsRcode::NOERROR,
                1 => DnsRcode::FORMERR,
                2 => DnsRcode::SERVFAIL,
                3 => DnsRcode::NAMERR,
                4 => DnsRcode::NOTIMP,
                5 => DnsRcode::REFUSED,
                _ => DnsRcode::RESERVED
            }
        }
    }

    impl fmt::Display for DnsRcode {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsRcode::NOERROR => write!(f, "NOERROR"),
                DnsRcode::FORMERR => write!(f, "FORMERR"),
                DnsRcode::SERVFAIL => write!(f, "SERVFAIL"),
                DnsRcode::NAMERR => write!(f, "NAMERR"),
                DnsRcode::NOTIMP => write!(f, "NOTIMP"),
                DnsRcode::REFUSED => write!(f, "REFUSED"),
                DnsRcode::RESERVED => write!(f, "RESERVED")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsQType {
        A = 1,
        CNAME = 5,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        RESERVED // catch-all
    }

    impl DnsQType {
        pub fn from_u16(value: u16) -> DnsQType {
            match value {
                1 => DnsQType::A,
                5 => DnsQType::CNAME,
                15 => DnsQType::MX,
                16 => DnsQType::TXT,
                28 => DnsQType::AAAA,
                _ => DnsQType::RESERVED
            }
        }
    }

    impl fmt::Display for DnsQType {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsQType::A => write!(f, "A"),
                DnsQType::CNAME => write!(f, "CNAME"),
                DnsQType::MX => write!(f, "MX"),
                DnsQType::TXT => write!(f, "TXT"),
                DnsQType::AAAA => write!(f, "AAAA"),
                DnsQType::RESERVED => write!(f, "RESERVED")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsQClass {
        IN = 1,
        CH = 3,
        HS = 4,
        NONE = 254,
        ANY = 255,
        RESERVED // any values not mentioned above.
    }

    pub struct DnsQuestionRecord {
        name: String,
        qtype: DnsQType,
        qclass: DnsQClass
    }

    impl DnsQuestionRecord {
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            /*
            let mut name_bytes = match string_to_dns_name(&self.name) {
                Ok(bytes) => bytes,
                Err(e) => return Err(e)
            };
            */
            let mut name_bytes = string_to_dns_name(&self.name)?;
            ret.append(&mut name_bytes);
            let qtype = self.qtype as u16;
            ret.extend_from_slice(&qtype.to_be_bytes());
            let qclass = self.qclass as u16;
            ret.extend_from_slice(&qclass.to_be_bytes());
            Ok(ret)
        }

        pub fn new(n: String, t: DnsQType, c: DnsQClass) -> DnsQuestionRecord {
            DnsQuestionRecord { name: n, qtype: t, qclass: c }
        }
    }

    pub struct DnsARecord {
        addr: Ipv4Addr
    }

    pub struct DnsAAAARecord {
        addr: Ipv6Addr
    }

    pub struct DnsTXTRecord {
        text: String
    }

    pub struct DnsCNAMERecord {
        name: String
    }

    pub struct DnsMXRecord {
        preference: u16,
        exchange: String
    }

    pub enum DnsResourceRecordEnum {
        // keep this in sync with the DnsQType enum and type-specific structs above.
        A(DnsARecord),
        AAAA(DnsAAAARecord),
        TXT(DnsTXTRecord),
        CNAME(DnsCNAMERecord),
        MX(DnsMXRecord),
        Generic(Vec<u8>) 
        /* Generic is a string of bytes from the wire (network order), and it's meant to 
           handle records for which the struct associated with the type
           has yet to be implemented in this code */
    }

    pub struct DnsResourceRecord {
        name: String,
        // qtype implied from record field
        class: DnsQClass,
        ttl: u32,
        record: DnsResourceRecordEnum
    }

    // note that this only contains the qid/options fields - RR counts aren't included,
    // b/c they're implied from the Vecs used to hold the RRs of a query/response.
    pub struct DnsHeader {
        id: u16,
        response: bool,
        opcode: DnsOpcode,
        aa: bool,
        tc: bool,
        rd: bool,
        ra: bool,
        rcode: DnsRcode
    }

    impl DnsHeader {
        pub fn make_options(&self) -> u16 {
            // these are all masks to be OR'd together.
            let response: u16 = if self.response { 0x8000 } else { 0 } ;
            let opcode: u16 = ((self.opcode as u16) & 0xf) << 11;
            let aa: u16 = if self.aa { 0x400 } else { 0 };
            let tc: u16 = if self.tc { 0x200 } else { 0 };
            let rd: u16 = if self.rd { 0x100 } else { 0 };
            let ra: u16 = if self.ra { 0x80 } else { 0 };
            let rcode: u16 = (self.rcode as u16) & 0xf;

            response | opcode | aa | tc | rd | ra | rcode 
        }

        pub fn new(id: u16, response: bool, opcode: DnsOpcode, aa: bool, 
                   tc: bool, rd: bool, ra: bool, rcode: DnsRcode) -> DnsHeader {
            DnsHeader { id: id, response: response, opcode: opcode, aa: aa, 
                        tc: tc, rd: rd, ra: ra, rcode: rcode }
        }
    }

    pub struct DnsQuery {
        header: DnsHeader,
        questions: Vec<DnsQuestionRecord>
    }

    impl DnsQuery {

        pub fn new(h: DnsHeader, q: Vec<DnsQuestionRecord>) -> DnsQuery {
            DnsQuery { header: h, questions: q }
        }
        
        // output bytes are network-order, ready to be written to wire.
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();

            // header
            let qid: u16 = self.header.id;
            ret.extend_from_slice(&qid.to_be_bytes());
            let options = self.header.make_options();
            ret.extend_from_slice(&options.to_be_bytes());

            // qcount/ancount/nscount/arcount
            let qcount = self.questions.len() as u16;
            ret.extend_from_slice(&qcount.to_be_bytes());
            let other_count = 0u16;
            ret.extend_from_slice(&other_count.to_be_bytes());
            ret.extend_from_slice(&other_count.to_be_bytes());
            ret.extend_from_slice(&other_count.to_be_bytes());

            for question in &self.questions {
                match question.to_bytes() {
                    Ok(mut bytes) => ret.append(&mut bytes),
                    Err(e) => return Err(e)
                }
            }
            
            Ok(ret)
        }

        // expects network-order input bytes, as if just read from wire.
        /* TODO implement
        pub fn from_bytes(bytes: Vec<u8>) -> Result(DnsHeader, String) {

        }
        */
    }

    pub struct DnsResponse {
        header: DnsHeader,
        questions: Vec<DnsQuestionRecord>,
        answers: Vec<DnsResourceRecord>,
        authorities: Vec<DnsResourceRecord>,
        additionals: Vec<DnsResourceRecord>
    }

    impl DnsResponse {
        pub fn new(h: DnsHeader, q: Vec<DnsQuestionRecord>, an: Vec<DnsResourceRecord>,
                   auth: Vec<DnsResourceRecord>, add: Vec<DnsResourceRecord>) -> DnsResponse {
            DnsResponse { header: h, questions: q, answers: an, authorities: auth, additionals: add }
        }
    }

    /* given a hostname, validate it as a dns name, per the rules in
       https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1 */
    pub fn is_valid_dns_name(name: &String) -> Result<(), String> {
        // use a regex for all this? stack overflow suggests a few:
        // https://stackoverflow.com/questions/10306690

        let stripped = String::from(name.trim());

        // base cases
        if stripped.len() == 0 || stripped == "." { 
            return Ok(()); 
        }

        let parts: Vec<&str> = stripped.split('.').collect();

        // labels contain only hyphens and alphanumeric characters
        let re = Regex::new(r"^[a-zA-Z0-9-]*$").unwrap();

        for (idx, label) in parts.iter().enumerate() {

            let len = label.len();

            // empty labels are not allowed, except at end, for trailing '.'
            if len == 0 && (idx != (parts.len() - 1)) {
                return Err(String::from("Got an empty label."));
            }

            if len >= 64 {
                return Err(format!("Got a label ({}) that is more than 63 characters.", label));
            }

            if !re.is_match(label) {
                return Err(format!("Got a label ({}) that contains invalid characters.", label));
            }

            if label.starts_with("-") {
                return Err(format!("Got a label ({}) that starts with a hyphen.", label));
            }

            if label.ends_with("-") {
                return Err(format!("Got a label ({}) that ends with a hyphen.", label));
            }
        }
        Ok(())
    }

    // given a hostname s, return the equivalent domain name in raw bytes
    pub fn string_to_dns_name(name: &String) -> Result<Vec<u8>, String> {
        // this does all the validation of the name for us, which simplifies this fn.
        match is_valid_dns_name(&name) {
            Ok(_) => {},
            Err(e) => return Err(format!("'{}' doesn't appear to be a valid DNS name: {}", name, e))
        }

        let stripped = String::from(name.trim());

        let mut ret : Vec<u8> = Vec::new();

        if stripped.len() == 0 || stripped == "." { // handle both root cases
            ret.push(0u8);
            return Ok(ret);
        }
        
        let split : Vec<&str> = stripped.split('.').collect();

        for s in split {
            // first, push the label length
            ret.push(s.len() as u8);
            // then, push the label itself
            ret.extend_from_slice(s.as_bytes());
        }

        if !stripped.ends_with('.') {
            ret.push(0u8);
        }

        Ok(ret)
    }
}
