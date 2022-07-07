pub mod dns_client_lib {
    use std::net::{Ipv4Addr,Ipv6Addr};
    use std::fmt;

    /* pages used to construct this library:
       https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
       https://datatracker.ietf.org/doc/html/rfc1035
       https://www.rfc-editor.org/rfc/rfc6895.html
       */

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsOpcode {
        QUERY = 0,
        IQUERY = 1,
        STATUS = 2,
        NOTIFY = 4,
        UPDATE = 5,
        DSO = 6,
        RESERVED // 3, 7-15
    }

    impl DnsOpcode {
        pub fn from_u8(value: u8) -> DnsOpcode {
            match value {
                0 => DnsOpcode::QUERY,
                1 => DnsOpcode::IQUERY,
                2 => DnsOpcode::STATUS,
                4 => DnsOpcode::NOTIFY,
                5 => DnsOpcode::UPDATE,
                6 => DnsOpcode::DSO,
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
                DnsOpcode::NOTIFY => write!(f, "NOTIFY"),
                DnsOpcode::UPDATE => write!(f, "UPDATE"),
                DnsOpcode::DSO => write!(f, "DSO"),
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
        YXDOMAIN = 6,
        YXRRSET = 7,
        NXRRSET = 8,
        NOTAUTH = 9,
        NOTZONE = 10,
        RESERVED // 11-15
        /*
          there's lots of other rcodes. see rfc6895, section 2.3.
          basically, there are RRs for which these rcodes also have meaning,
          but they have more than 4 bits to store an rcode, so those other
          bits are used with type-specific meaning
         */

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
                6 => DnsRcode::YXDOMAIN,
                7 => DnsRcode::YXRRSET,
                8 => DnsRcode::NXRRSET,
                9 => DnsRcode::NOTAUTH,
                10 => DnsRcode::NOTZONE,
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
                DnsRcode::YXDOMAIN => write!(f, "YXDOMAIN"),
                DnsRcode::YXRRSET => write!(f, "YXRRSET"),
                DnsRcode::NXRRSET => write!(f, "NXRRSET"),
                DnsRcode::NOTAUTH => write!(f, "NOTAUTH"),
                DnsRcode::NOTZONE => write!(f, "NOTZONE"),
                DnsRcode::RESERVED => write!(f, "RESERVED")
            }
        }
    }

    /* to add support for a new qtype, a few things must be done:
       1) add the new qtype to the DnsQType struct and its functions (from_u16, fmt)
       2) create the new struct associated with the new qtype, and its functions:
          to/from_bytes, new, fmt
          see any of the Dns*Record structs for an example of this.
       3) add an entry to the DnsResourceRecordEnum enum and its fmt function, using the struct from (2)
       4) add a match arm to DnsResourceRecord::to/from_bytes for the struct from (2)
     */
    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsQType {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        MX = 15,
        TXT = 16,
        AAAA = 28,
        OPT = 41,
        ANY = 255, // no associated RR struct. what would a DnsANYRecord hold?
        CAA = 257,
        RESERVED // catch-all
    }

    impl DnsQType {
        pub fn from_u16(value: u16) -> DnsQType {
            match value {
                1 => DnsQType::A,
                2 => DnsQType::NS,
                5 => DnsQType::CNAME,
                6 => DnsQType::SOA,
                15 => DnsQType::MX,
                16 => DnsQType::TXT,
                28 => DnsQType::AAAA,
                41 => DnsQType::OPT,
                255 => DnsQType::ANY,
                257 => DnsQType::CAA,
                _ => DnsQType::RESERVED
            }
        }
    }

    impl fmt::Display for DnsQType {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsQType::A => write!(f, "A"),
                DnsQType::NS => write!(f, "NS"),
                DnsQType::CNAME => write!(f, "CNAME"),
                DnsQType::SOA => write!(f, "SOA"),
                DnsQType::MX => write!(f, "MX"),
                DnsQType::TXT => write!(f, "TXT"),
                DnsQType::AAAA => write!(f, "AAAA"),
                DnsQType::OPT => write!(f, "OPT"),
                DnsQType::ANY => write!(f, "ANY"),
                DnsQType::CAA => write!(f, "CAA"),
                DnsQType::RESERVED => write!(f, "RESERVED")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
    pub enum DnsQClass {
        IN,
        CH,
        HS,
        NONE,
        ANY,
        RESERVED(u16) // any values not mentioned above.
    }

    impl DnsQClass {
        pub fn from_u16(value: u16) -> DnsQClass {
            match value {
                1 => DnsQClass::IN,
                3 => DnsQClass::CH,
                4 => DnsQClass::HS,
                254 => DnsQClass::NONE,
                255 => DnsQClass::ANY,
                other => DnsQClass::RESERVED(other)
            }
        }

        // XXX is there a more idiomatic way to do this? so that one can do "foo as u16"?
        pub fn to_u16(&self) -> u16 {
            match &self {
                DnsQClass::IN => 1,
                DnsQClass::CH => 3,
                DnsQClass::HS => 4,
                DnsQClass::NONE => 254,
                DnsQClass::ANY => 255,
                DnsQClass::RESERVED(o) => *o
            }
        }
    }

    impl fmt::Display for DnsQClass {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsQClass::IN => write!(f, "IN"),
                DnsQClass::CH => write!(f, "CH"),
                DnsQClass::HS => write!(f, "HS"),
                DnsQClass::NONE => write!(f, "NONE"),
                DnsQClass::ANY => write!(f, "ANY"),
                DnsQClass::RESERVED(o) => write!(f, "RESERVED({o})")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsQuestionRecord {
        name: String,
        qtype: DnsQType,
        qclass: DnsQClass
    }

    impl DnsQuestionRecord {
        pub fn new(n: String, t: DnsQType, c: DnsQClass) -> DnsQuestionRecord {
            DnsQuestionRecord { name: n, qtype: t, qclass: c }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            let mut name_bytes = string_to_dns_name(&self.name)?;
            ret.append(&mut name_bytes); // append consumes the target
            let qtype = self.qtype as u16;
            ret.extend_from_slice(&qtype.to_be_bytes());
            let qclass = self.qclass.to_u16();
            ret.extend_from_slice(&qclass.to_be_bytes());
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsQuestionRecord, usize), String> {
            let mut o = offset;

            let name = match dns_name_to_string(buf, offset) {
                Ok((s, bytes_read)) => {
                    o += bytes_read;
                    s
                },
                Err(e) => return Err(e)
            };
            let buflen = buf.len();
            if o >= buflen || o+4 > buflen {
                return Err(String::from("Hit buffer bounds reading qtype/class in QuestionRecord."));
            }
            let mut twobytes = [0u8, 0u8];
            twobytes.clone_from_slice(&buf[o .. o+2]);
            let qtype = DnsQType::from_u16(u16::from_be_bytes(twobytes));
            twobytes.clone_from_slice(&buf[o+2 .. o+4]);
            let qclass = DnsQClass::from_u16(u16::from_be_bytes(twobytes));
            o += 4;

            Ok((DnsQuestionRecord::new(name, qtype, qclass), o - offset))
        }

    }

    impl fmt::Display for DnsQuestionRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{} {} {}", self.name, self.qtype, self.qclass)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsARecord {
        addr: Ipv4Addr
    }

    impl DnsARecord {
        pub fn new(a: Ipv4Addr) -> DnsARecord {
            DnsARecord { addr: a }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            Ok(self.addr.octets().to_vec())
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsARecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing A record."));
            }
            if (offset + 4) > buflen {
                return Err(String::from("Got a buffer with too few bytes to read."));
            }
            Ok(DnsARecord::new(Ipv4Addr::new(buf[offset], buf[offset+1], buf[offset+2], buf[offset+3])))
        }
    }

    impl fmt::Display for DnsARecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "A: {}", self.addr)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsAAAARecord {
        addr: Ipv6Addr
    }

    impl DnsAAAARecord {
        pub fn new(a: Ipv6Addr) -> DnsAAAARecord {
            DnsAAAARecord { addr: a }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            Ok(self.addr.octets().to_vec())
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsAAAARecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing AAAA record."));
            }
            if (offset + 16) > buflen {
                return Err(String::from("Got a buffer with too few bytes to read."));
            }
            // TODO this is ugly.
            let bytes = [buf[offset],    buf[offset+1],  buf[offset+2],  buf[offset+3],
                         buf[offset+4],  buf[offset+5],  buf[offset+6],  buf[offset+7],
                         buf[offset+8],  buf[offset+9],  buf[offset+10], buf[offset+11],
                         buf[offset+12], buf[offset+13], buf[offset+14], buf[offset+15]];
            let hbo128: u128 = u128::from_be_bytes(bytes);
            let v6addr = Ipv6Addr::from(hbo128);
            Ok(DnsAAAARecord::new(v6addr))
        }
    }

    impl fmt::Display for DnsAAAARecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "AAAA: {}", self.addr)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsTXTRecord {
        text: String
    }

    impl DnsTXTRecord {
        pub fn new(t: String) -> DnsTXTRecord {
            DnsTXTRecord { text: t }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            /* len byte, then string. string can be up to 255 chars as a character-string.
               see rfc1035, 3.3.14 (TXT RDATA format) and 3.3 (re: character-string)
             */
            if self.text.len() > 255 {
                return Err(String::from("Got a TXT record with too much data!"));
            }
            let lenbyte = self.text.len() as u8;
            let mut ret: Vec<u8> = Vec::new();
            ret.push(lenbyte);
            ret.extend_from_slice(self.text.as_bytes());
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsTXTRecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing TXT record."));
            }
            let lenbyte = buf[offset]; // first byte is len, followed by that many characters.
            let txtstart = offset + 1;
            if txtstart + (lenbyte as usize) > buflen {
                return Err(String::from("Got a TXT record with a len byte pointing outside buffer."))
            }

            let txt = match String::from_utf8(buf[txtstart .. txtstart + (lenbyte as usize)].to_vec()) {
                Ok(s) => s,
                Err(e) => return Err(e.to_string())
            };
            Ok((DnsTXTRecord::new(txt), (1 + lenbyte) as usize))
        }
    }

    impl fmt::Display for DnsTXTRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "TXT: {}", self.text)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsCNAMERecord {
        name: String
    }

    impl DnsCNAMERecord {
        pub fn new(n: String) -> DnsCNAMERecord {
            DnsCNAMERecord { name: n }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            string_to_dns_name(&self.name)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsCNAMERecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing CNAME record."));
            }

            let (cname, count) = dns_name_to_string(buf, offset)?;
            Ok((DnsCNAMERecord::new(cname), count))
        }
    }

    impl fmt::Display for DnsCNAMERecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "CNAME: {}", self.name)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsMXRecord {
        preference: u16,
        exchange: String
    }

    impl DnsMXRecord {
        pub fn new(p: u16, e: String) -> DnsMXRecord {
            DnsMXRecord { preference: p, exchange: e }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            ret.extend_from_slice(&self.preference.to_be_bytes());
            match string_to_dns_name(&self.exchange) {
                Ok(mut namebytes) => {
                    ret.append(&mut namebytes)
                },
                Err(e) => return Err(e)
            }
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsMXRecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing MX record."));
            }
            if offset + 3 > buflen { // two bytes for prefs, and at least 1 byte for exchange.
                return Err(String::from("Got an offset with not enough buf for prefs/exchange."));
            }

            let prefbytes = [buf[offset], buf[offset+1]];
            let prefs = u16::from_be_bytes(prefbytes);
            let (exchange, count) = dns_name_to_string(buf, offset+2)?;
            Ok((DnsMXRecord::new(prefs, exchange), count + 2))
        }
    }

    impl fmt::Display for DnsMXRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "MX: Preference {}; Exchange {}", self.preference, self.exchange)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsNSRecord {
        name: String
    }

    impl DnsNSRecord {
        pub fn new(n: String) -> DnsNSRecord {
            DnsNSRecord { name: n }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            string_to_dns_name(&self.name)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsNSRecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing NS record."));
            }

            let (name, count) = dns_name_to_string(buf, offset)?;
            Ok((DnsNSRecord::new(name), count))
        }
    }

    impl fmt::Display for DnsNSRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "NS: name: {}", self.name)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsSOARecord {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32
    }

    impl DnsSOARecord {
        pub fn new(mname: String, rname: String, serial: u32, refresh: u32, retry: u32, 
                   expire: u32, minimum: u32) -> DnsSOARecord {
            DnsSOARecord { mname: mname, rname: rname, serial: serial, refresh: refresh,
                           retry: retry, expire: expire, minimum: minimum }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            match string_to_dns_name(&self.mname) {
                Ok(mut mnamebytes) => { ret.append(&mut mnamebytes) },
                Err(e) => return Err(e)
            }
            match string_to_dns_name(&self.rname) {
                Ok(mut rnamebytes) => { ret.append(&mut rnamebytes) },
                Err(e) => return Err(e)
            }
            ret.extend_from_slice(&self.serial.to_be_bytes());
            ret.extend_from_slice(&self.refresh.to_be_bytes());
            ret.extend_from_slice(&self.retry.to_be_bytes());
            ret.extend_from_slice(&self.expire.to_be_bytes());
            ret.extend_from_slice(&self.minimum.to_be_bytes());

            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsSOARecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing SOA record."));
            }

            // we need at least 22 bytes - 1+ for each name, then 4 for each of the 5 u32s.
            if offset + 22 > buflen {
                return Err(String::from("Hit buffer bounds reading SOA RR."));
            }

            let mut o = offset;

            let (mname, count) = dns_name_to_string(buf, o)?;
            o += count;
            let (rname, count) = dns_name_to_string(buf, o)?;
            o += count;

            let serial = u32::from_be_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
            o += 4;
            let refresh = u32::from_be_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
            o += 4;
            let retry = u32::from_be_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
            o += 4;
            let expire = u32::from_be_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
            o += 4;
            let minimum = u32::from_be_bytes([buf[o], buf[o+1], buf[o+2], buf[o+3]]);
            o += 4;

            Ok((DnsSOARecord::new(mname, rname, serial, refresh, retry, expire, minimum), o - offset))
        }
    }

    impl fmt::Display for DnsSOARecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f,
            "SOA: mname: {}, rname: {}, serial: {}, refresh: {}, retry: {}, expire: {}, minimum: {}", 
            self.mname, self.rname, self.serial, self.refresh, self.retry, self.expire, self.minimum)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsOPTRecordOption {
        code: u16,
        // length u16 implied by data field
        data: Vec<u8>
    }

    impl DnsOPTRecordOption {
        pub fn new(code: u16, data: Vec<u8>) -> DnsOPTRecordOption {
            DnsOPTRecordOption { code: code, data: data }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            if self.data.len() > u16::MAX as usize {
                return Err(String::from("Got an OPT record option with too many bytes."));
            }
            let datalen = self.data.len() as u16;
            ret.extend_from_slice(&self.code.to_be_bytes());
            ret.extend_from_slice(&datalen.to_be_bytes());
            ret.extend(self.data.iter());
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsOPTRecordOption, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing OPT record option."));
            }
            if offset + 4 > buflen {
                return Err(String::from("hit buffer bounds reading an OPT record option."));
            }

            let mut o = offset;
            let mut twobytes = [0u8, 0u8];

            twobytes.clone_from_slice(&buf[o .. o+2]);
            let code = u16::from_be_bytes(twobytes);
            o += 2;

            twobytes.clone_from_slice(&buf[o .. o+2]);
            let optlen = u16::from_be_bytes(twobytes);
            o += 2;

            if o + (optlen as usize) > buflen {
                return Err(String::from("hit buffer bounds reading an OPT record option data."));
            }

            let data: Vec<u8> = buf[o .. o+(optlen as usize)].to_vec();
            Ok((DnsOPTRecordOption::new(code, data), o - offset))
        }
    }

    impl fmt::Display for DnsOPTRecordOption {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{} {:x?}", self.code, self.data)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsOPTRecord {
        options: Vec<DnsOPTRecordOption>
    }

    impl DnsOPTRecord {
        pub fn new(options: Vec<DnsOPTRecordOption>) -> DnsOPTRecord {
            DnsOPTRecord { options: options }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            for o in &self.options {
                ret.append(&mut o.to_bytes()?);
            }
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize, rdlen: usize) ->
            Result<(DnsOPTRecord, usize), String> {
            let mut options: Vec<DnsOPTRecordOption> = Vec::new();
            if rdlen == 0 {
                return Ok((DnsOPTRecord::new(options), 0));
            }

            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(format!("Got an offset {offset} outside of the buffer (len: {}) parsing OPT record.", buflen));
            }
            let end = offset + rdlen;
            if end > buflen {
                return Err(String::from("Got an offset+rdlen pointing outside a buffer."));
            }

            let mut o = offset;

            loop {
                if o == end { break; }
                if o > end { // this should never happen - it means we read past what rdlen told us to.
                    return Err(String::from("went past rdlen in buf when parsing OPT record option."));
                }
                let (option, bytes_read) = DnsOPTRecordOption::from_bytes(buf, o)?;
                options.push(option);
                o += bytes_read;
            }

            Ok((DnsOPTRecord::new(options), o - offset))
        }
    }

    impl fmt::Display for DnsOPTRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "OPT: ")?;
            for o in &self.options {
                write!(f, "{o} ")?;
            }
            Ok(())
        }
    }

    /* this is the struct to hold dns records for which we don't yet have an associated struct. */
    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsGenericRecord {
        qtype: u16,
        v: Vec<u8>
    }

    impl DnsGenericRecord {
        pub fn new(q: u16, v: Vec<u8>) -> DnsGenericRecord {
            DnsGenericRecord { qtype: q, v: v }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            Ok(self.v.clone())
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize, len: usize, qtype: u16) ->
                          Result<DnsGenericRecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer parsing generic record."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside the buffer parsing generic record."));
            }
            if offset + len > buflen {
                return Err(String::from("ran out of bytes parsing generic record."));
            }

            Ok(DnsGenericRecord::new(qtype, buf[offset .. offset+len].to_vec()))
        }
    }

    impl fmt::Display for DnsGenericRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Generic (qtype={}): {:x?}", self.qtype, self.v)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsCAARecord {
        critical: bool,
        tag: String,
        value: String,
    }

    impl DnsCAARecord {
        pub fn new(critical: bool, tag: String, value: String) -> DnsCAARecord {
            // TODO validate that tag contains only A-Za-z0-9
            // TODO validate value characters - see rfc8659.
            DnsCAARecord { critical: critical, tag: tag, value: value }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            let flagbyte: u8 = if self.critical { 0x80 } else { 0 };
            ret.push(flagbyte);
            // TODO validate tag/value characters? see above
            ret.extend_from_slice(self.tag.as_bytes());
            ret.extend_from_slice(self.value.as_bytes());
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize, rdlen: usize) ->
                          Result<(DnsCAARecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer parsing CAA record."));
            }
            if offset + 3 > buflen { // flag, tag len, and at least 1 tag char
                return Err(String::from("Got too few bytes to read a CAA record."));
            }
            let mut o = offset;
            let flags = buf[o];
            o += 1;
            let taglen = buf[o];
            o += 1;
            if o + taglen as usize > buflen {
                return Err(String::from("Got too few bytes to read a CAA record tag."));
            }
            let mut tagvec: Vec<u8> = Vec::new();
            tagvec.extend_from_slice(&buf[o .. o + taglen as usize]);
            let tag = match String::from_utf8(tagvec) {
                Ok(t) => t,
                Err(e) => return Err(e.to_string())
            };
            o += taglen as usize;
            let mut valuevec: Vec<u8> = Vec::new();
            valuevec.extend_from_slice(&buf[o .. o + (rdlen - taglen as usize - 2)]);
            let value = match String::from_utf8(valuevec) {
                Ok(v) => v,
                Err(e) => return Err(e.to_string())
            };
            Ok((DnsCAARecord::new(flags == 0x80u8, tag, value), o - offset))
        }
    }

    impl fmt::Display for DnsCAARecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "CAA: ")?;
            if self.critical {
                write!(f, "Critical ")?;
            } else {
                write!(f, "Non-critical ")?;
            }
            write!(f, "{}: {:x?}", self.tag, self.value);
            Ok(())
        }
    }

    /* skeleton functions for new Dns*Record
    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsFOORecord {
        // TODO
    }

    impl DnsFOORecord {
        pub fn new() -> DnsFOORecord {
            DnsFOORecord { }
        }
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }
        */

        // choose signature based on length (variable or static) of record
        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsFOORecord, String> {
        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsFOORecord, usize), String> {
            let count = 0;
            Ok(DnsFOORecord::new()) // or
            Ok((DnsFOORecord::new(), count))
        }
    }

    impl fmt::Display for DnsFOORecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "FOO: ")
        }
    }
    */

    #[derive(Debug, Eq, PartialEq)]
    pub enum DnsResourceRecordEnum {
        A(DnsARecord),
        NS(DnsNSRecord),
        CNAME(DnsCNAMERecord),
        SOA(DnsSOARecord),
        MX(DnsMXRecord),
        TXT(DnsTXTRecord),
        AAAA(DnsAAAARecord),
        OPT(DnsOPTRecord),
        CAA(DnsCAARecord),
        Generic(DnsGenericRecord)
        /* Generic is a string of bytes from the wire (network order), and it's meant to 
           handle records for which the struct associated with the type
           has yet to be implemented in this code */
    }

    impl fmt::Display for DnsResourceRecordEnum {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                DnsResourceRecordEnum::A(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::NS(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::CNAME(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::SOA(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::MX(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::TXT(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::AAAA(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::OPT(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::CAA(rr) => write!(f, "{rr}"),
                DnsResourceRecordEnum::Generic(rr) => write!(f, "{rr}")
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsResourceRecord {
        name: String,
        qtype: DnsQType,
        class: DnsQClass,
        ttl: u32,
        record: DnsResourceRecordEnum
    }

    impl DnsResourceRecord {
        pub fn new(n: String, t: DnsQType, c: DnsQClass, ttl: u32, r: DnsResourceRecordEnum)
            -> DnsResourceRecord {
            DnsResourceRecord { name: n, qtype: t, class: c, ttl: ttl, record: r }
        }

        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();
            ret.append(&mut string_to_dns_name(&self.name)?);
            let qtype = self.qtype as u16;
            ret.extend_from_slice(&qtype.to_be_bytes());
            let qclass = self.class.to_u16();
            ret.extend_from_slice(&qclass.to_be_bytes());
            ret.extend_from_slice(&self.ttl.to_be_bytes());

            let mut rdata: Vec<u8> = match &self.record {
                DnsResourceRecordEnum::A(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::NS(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::CNAME(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::SOA(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::MX(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::TXT(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::AAAA(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::OPT(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::CAA(rr) => { rr.to_bytes()? },
                DnsResourceRecordEnum::Generic(rr) => { rr.to_bytes()? },
            };
            if rdata.len() > u16::MAX as usize {
                return Err(String::from("Got an rdlen that doesn't fit in a u16!"));
            }

            let rdlen = rdata.len() as u16;
            ret.extend_from_slice(&rdlen.to_be_bytes());
            ret.append(&mut rdata);

            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<(DnsResourceRecord, usize), String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a buffer with length of 0."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside the buffer parsing an RR."));
            }

            let mut o = offset;

            let (name, count) = dns_name_to_string(buf, offset)?;
            o += count;

            if o + 10 > buflen { // qtype, qclass, ttl, rdlen
                return Err(String::from("Hit buffer end when parsing resource record."));
            }

            let typebytes = [buf[o], buf[o+1]];
            let typeu16 = u16::from_be_bytes(typebytes);
            let qtype = DnsQType::from_u16(typeu16);
            o += 2;

            let classbytes = [buf[o], buf[o+1]];
            let qclass = DnsQClass::from_u16(u16::from_be_bytes(classbytes));
            o += 2;

            let ttlbytes = [buf[o], buf[o+1], buf[o+2], buf[o+3]];
            let ttl = u32::from_be_bytes(ttlbytes);
            o += 4;

            let rdlenbytes = [buf[o], buf[o+1]];
            let rdlen = u16::from_be_bytes(rdlenbytes);
            o += 2;

            let record: DnsResourceRecordEnum = match qtype {
                /* what if the count of bytes returned by some of the various from_bytes functions
                   does not equal the rdlen read above?
                   it might be worth being pedantic about this - if count != rdlen (or rdlen !=
                   the static lengths used, like 4 bytes for A records), then we should
                   return an error.
                 */
                DnsQType::A => {
                    let record = DnsARecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::A(record)
                },
                DnsQType::NS => {
                    let (record, _) = DnsNSRecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::NS(record)
                },
                DnsQType::CNAME => {
                    let (record, _) = DnsCNAMERecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::CNAME(record)
                },
                DnsQType::SOA => {
                    let (record, _) = DnsSOARecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::SOA(record)
                },
                DnsQType::MX => {
                    let (record, _) = DnsMXRecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::MX(record)
                },
                DnsQType::TXT => {
                    let (record, _) = DnsTXTRecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::TXT(record)
                },
                DnsQType::AAAA => {
                    let record = DnsAAAARecord::from_bytes(buf, o)?;
                    DnsResourceRecordEnum::AAAA(record)
                },
                DnsQType::OPT => {
                    let (record, _) = DnsOPTRecord::from_bytes(buf, o, rdlen as usize)?;
                    DnsResourceRecordEnum::OPT(record)
                },
                DnsQType::CAA => {
                    let (record, _) = DnsCAARecord::from_bytes(buf, o, rdlen as usize)?;
                    DnsResourceRecordEnum::CAA(record)
                },
                _ => {
                    let record = DnsGenericRecord::from_bytes(buf, o, rdlen as usize, typeu16)?;
                    DnsResourceRecordEnum::Generic(record)
                }
            };
            o += rdlen as usize;

            Ok((DnsResourceRecord::new(name, qtype, qclass, ttl, record), o - offset))
        }
    }

    impl fmt::Display for DnsResourceRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{} {} {} {}", self.name, self.class, self.ttl, self.record)
        }
    }

    // note that this only contains the qid/options fields - RR counts aren't included,
    // b/c they're implied from the Vecs used to hold the RRs of a query/response.
    #[derive(Debug, Eq, PartialEq, Copy, Clone)]
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
        pub fn new(id: u16, response: bool, opcode: DnsOpcode, aa: bool,
                   tc: bool, rd: bool, ra: bool, rcode: DnsRcode) -> DnsHeader {
            DnsHeader { id: id, response: response, opcode: opcode, aa: aa,
                        tc: tc, rd: rd, ra: ra, rcode: rcode }
        }

        pub fn flags_to_u16(&self) -> u16 {
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

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsHeader, String> {
            // check that the fields read here lie inside the buf bounds
            // note that we only read the qid/flags here, so we only need 4 bytes.
            if (offset + 4) > buf.len() {
                return Err(String::from("Buffer does not contain enough bytes to read qid/flags!"));
            }

            let mut twobytes = [0u8, 0u8];
            twobytes.clone_from_slice(&buf[offset .. offset+2]);
            let qid = u16::from_be_bytes(twobytes);
            twobytes.clone_from_slice(&buf[offset+2 .. offset+4]);
            let flags = u16::from_be_bytes(twobytes);

            let response : bool = (flags & 0x8000) != 0;
            let opcode = DnsOpcode::from_u8(((flags & 0x78) >> 11) as u8);
            let aa : bool = (flags & 0x0400) != 0;
            let tc : bool = (flags & 0x0200) != 0;
            let rd : bool = (flags & 0x0100) != 0;
            let ra : bool = (flags & 0x0080) != 0;
            let rcode = DnsRcode::from_u8((flags & 0xF) as u8);

            Ok(DnsHeader::new(qid, response, opcode, aa, tc, rd, ra, rcode))
        }

    }

    impl fmt::Display for DnsHeader {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            let s = format!("QID: {:x}, Opcode: {}, AA: {}, TC: {}, RD: {}, RA: {}, Rcode: {}", 
                            self.id, self.opcode, self.aa, self.tc, self.rd, self.ra, self.rcode);
            write!(f, "{s}")
        }
    }

    pub struct DnsQuery {
        header: DnsHeader,
        questions: Vec<DnsQuestionRecord>,
        additionals: Option<Vec<DnsResourceRecord>>
    }

    impl DnsQuery {

        pub fn new(h: DnsHeader, q: Vec<DnsQuestionRecord>,
                   add: Option<Vec<DnsResourceRecord>>) -> DnsQuery {
            DnsQuery { header: h, questions: q, additionals: add }
        }
        
        // output bytes are network-order, ready to be written to wire.
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
            let mut ret: Vec<u8> = Vec::new();

            // header
            let qid: u16 = self.header.id;
            ret.extend_from_slice(&qid.to_be_bytes());
            let options = self.header.flags_to_u16();
            ret.extend_from_slice(&options.to_be_bytes());

            // qcount/ancount/nscount/arcount
            let qcount = self.questions.len() as u16;
            ret.extend_from_slice(&qcount.to_be_bytes());
            let other_count = 0u16;
            ret.extend_from_slice(&other_count.to_be_bytes());
            ret.extend_from_slice(&other_count.to_be_bytes());
            let addcount = match &self.additionals {
                Some(a) => a.len() as u16,
                None => 0u16
            };
            ret.extend_from_slice(&addcount.to_be_bytes());

            for question in &self.questions {
                let mut bytes = question.to_bytes()?;
                ret.append(&mut bytes);
            }

            if let Some(additionals) = &self.additionals {
                for rr in additionals {
                    let mut bytes = rr.to_bytes()?;
                    ret.append(&mut bytes);
                }
            }
            
            Ok(ret)
        }

        /*
        pub fn from_bytes(bytes: Vec<u8>) -> Result(DnsHeader, String) {

        }
        */
    }

    impl fmt::Display for DnsQuery {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Query:\n  Header: {}\n", self.header)?;
            for qr in &self.questions {
                write!(f, "  Question: {qr}\n")?;
            }
            if let Some(additionals) = &self.additionals {
                for rr in additionals {
                    write!(f, "  Additional: {rr}\n")?;
                }
            }
            Ok(())
        }
    }

    #[derive(Debug, Eq, PartialEq)]
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

        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }
        */

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsResponse, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside the buffer parsing DNS response."));
            }

            let mut o = offset;

            if o + 8 > buflen { // header, qcount, ancount, authcount, addcount
                return Err(String::from("Buf contains too few bytes to read response."));
            }

            let header = DnsHeader::from_bytes(buf, offset)?;
            o += 4; // qid, flags

            let qcountbytes = [buf[o], buf[o+1]];
            let qcount = u16::from_be_bytes(qcountbytes);
            o += 2;
            let ancountbytes = [buf[o], buf[o+1]];
            let ancount = u16::from_be_bytes(ancountbytes);
            o += 2;
            let authcountbytes = [buf[o], buf[o+1]];
            let authcount = u16::from_be_bytes(authcountbytes);
            o += 2;
            let addcountbytes = [buf[o], buf[o+1]];
            let addcount = u16::from_be_bytes(addcountbytes);
            o += 2;

            let mut questions: Vec<DnsQuestionRecord> = Vec::new();
            for _ in 0..qcount {
                let (record, count) = DnsQuestionRecord::from_bytes(buf, o)?;
                o += count;
                questions.push(record);
            }
            let mut answers: Vec<DnsResourceRecord> = Vec::new();
            for _ in 0..ancount {
                let (record, count) = DnsResourceRecord::from_bytes(buf, o)?;
                o += count;
                answers.push(record);
            }
            let mut authorities: Vec<DnsResourceRecord> = Vec::new();
            for _ in 0..authcount {
                let (record, count) = DnsResourceRecord::from_bytes(buf, o)?;
                o += count;
                authorities.push(record);
            }
            let mut additionals: Vec<DnsResourceRecord> = Vec::new();
            for _c in 0..addcount {
                let (record, count) = DnsResourceRecord::from_bytes(buf, o)?;
                o += count;
                additionals.push(record);
            }

            // XXX should we check that o == buf.len() ? if o < buf.len(), we have unused bytes.

            Ok(DnsResponse::new(header, questions, answers, authorities, additionals))
        }
    }

    impl fmt::Display for DnsResponse {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Response:\n  Header: {}\n", self.header)?;
            for qr in &self.questions {
                write!(f, "  Question: {qr}\n")?;
            }
            for rr in &self.answers {
                write!(f, "  Answer: {rr}\n")?;
            }
            for rr in &self.authorities {
                write!(f, "  Authority: {rr}\n")?;
            }
            for rr in &self.additionals {
                write!(f, "  Additional: {rr}\n")?;
            }
            Ok(())
        }
    }

    /* given a hostname, validate it as a dns name, per the rules in
       https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.1 */
    pub fn is_valid_dns_name(name: &String) -> Result<(), String> {

        let stripped = String::from(name.trim());

        // base cases
        if stripped.len() == 0 || stripped == "." { 
            return Ok(()); 
        }

        let parts: Vec<&str> = stripped.split('.').collect();

        for (idx, label) in parts.iter().enumerate() {

            let len = label.len();

            // empty labels are not allowed, except at end, for trailing '.'
            if len == 0 && (idx != (parts.len() - 1)) {
                return Err(String::from("Got an empty label."));
            }

            if len >= 64 {
                return Err(format!("Got a label ({}) that is more than 63 characters.", label));
            }

            // labels are only allowed to contain A-Z, a-z, 0-9, and '-'.
            for c in label.chars() {
                match c {
                    'a'..='z' | 'A'..='Z' | '0'..='9' | '-' => {}, // who needs regexes?
                    _ => return Err(format!("Got a label ({label}) with a bad character ({c})."))
                }
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
        if let Err(e) = is_valid_dns_name(&name) {
            return Err(format!("'{}' doesn't appear to be a valid DNS name: {}", name, e));
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

    /* Result is String containing name parsed and usize containing bytes read *in this label*.
       The distinction is important here - if this function is pointed at a label containing
       a compression pointer, we don't count the bytes of what was read when parsing the area
       of the buf pointed to by the compression pointer - only the bytes in this label, and just
       the two bytes for the compression pointer itself. See dns_name_to_string_test in tests.
    */
    pub fn dns_name_to_string(buf: &Vec<u8>, offset: usize) -> Result<(String, usize), String> {
        let mut labels: Vec<String> = Vec::new();

        /*
           a dns name consists of a series of labels.
           labels consist of a len byte L , followed (optionally) by other bytes.
           L=0 is the null label - either root (if alone) or end of a label (also root)
           0 < L < 64 -> label is L bytes in length, and follows the len byte.
           64 <= L < 192 -> reserved meaning. probably should err out if this is encountered.
              this has meaning... but only in a draft. see local-compression link below.
           192 <= L -> compression ptr. mask off top two bits and consider next byte
              to get an offset into the packet buffer, from where we need to read another label.
           see RFC1035, section 4.1.4 for details.

           https://datatracker.ietf.org/doc/html/draft-ietf-dnsind-local-compression-05
           according to this site, "It is important that these pointers always point backwards."
           can we declare as invalid any pointers that are >= the current offset?
         */

        // result usize is how many bytes were read in this call.
        fn _helper(buf: &Vec<u8>, offset: usize, labels: &mut Vec<String>) -> Result<usize, String> {
            let buflen = buf.len();

            if buflen == 0 {
                return Err(String::from("Can't operate on empty name buffer."));
            }

            if offset >= buflen {
                return Err(String::from("Offset outside of buffer bounds."));
            }

            let mut o = offset; // local mutable copy for work

            loop {
                let lenbyte = &buf[o];
                match lenbyte {
                    0 => { // null byte. done with this name.
                        o += 1;
                        break;
                    },

                    1..=63 => { // label. parse it out.
                        o += 1; // done with len byte, go onto label.
                        let top = o + (*lenbyte as usize);
                        if o > buflen || top > buflen {
                            return Err(String::from("Hit buffer bounds when parsing label."));
                        }
                        let label = &buf[o .. top];
                        match String::from_utf8(label.to_vec()) {
                            Ok(s) => labels.push(s),
                            Err(e) => return Err(e.to_string())
                        }
                        o += *lenbyte as usize;
                    },

                    64..=191 => { // reserved. return err (for now)
                        return Err(String::from("Got 10/01 in top bits of dns name length byte."));
                    },

                    192..=255 => { // compression. recurse!
                        let mut twobytes = [0u8, 0u8];
                        let top = o + 2;
                        if top > buflen {
                            return Err(String::from("Hit buffer bounds when parsing compression ptr."));
                        }
                        twobytes.clone_from_slice(&buf[o .. top]);
                        let new_offset = (u16::from_be_bytes(twobytes) & 0x3FFF) as usize;
                        /* technically it's not codified anywhere that compression pointers HAVE
                           to be prior in the packet to the current one. if we want to support
                           this, use a HashSet<usize> to keep track of visited offsets, so as
                           to avoid loops in compression pointers. */
                        if new_offset > offset {
                            return Err(String::from("Got a forward-pointing compression pointer."));
                        }
                        if new_offset == offset {
                            return Err(String::from("Got a self-referencing compression pointer."));
                        }
                        /* don't care about count of bytes read in this case, b/c it's from
                         elsewhere in the packet. */
                        let _ = _helper(&buf, new_offset, labels)?;
                        o += 2; // compression ptr takes up len byte and next one too.
                        break; // pointers are always at the end of the labels
                    }
                }
            }

            Ok(o - offset)
        }

        match _helper(&buf, offset, &mut labels) {
            Ok(count) => {
                match labels.len() {
                    0 => Ok((String::from("."), 1)),
                    _ => {
                        labels.push(String::from(""));
                        Ok((labels.join("."), count))
                    }
                }
            },
            Err(e) => Err(e)
        }
    }
}
