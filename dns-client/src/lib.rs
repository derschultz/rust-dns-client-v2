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
        /*TODO there's lots of other rcodes. see rfc6895, section 2.3.
          basically, there are RRs for which these rcodes also have meaning,
          but they have more than 4 bits to store an rcode, so those other
          bits are used with type-specific meaning */

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

    impl DnsQClass {
        pub fn from_u16(value: u16) -> DnsQClass {
            match value {
                1 => DnsQClass::IN,
                3 => DnsQClass::CH,
                4 => DnsQClass::HS,
                254 => DnsQClass::NONE,
                255 => DnsQClass::ANY,
                _ => DnsQClass::RESERVED
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
                DnsQClass::RESERVED => write!(f, "RESERVED")
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
            let qclass = self.qclass as u16;
            ret.extend_from_slice(&qclass.to_be_bytes());
            Ok(ret)
        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsQuestionRecord, String> {
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

            Ok(DnsQuestionRecord::new(name, qtype, qclass))
        }

    }

    impl fmt::Display for DnsQuestionRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "Question: {} {} {}", self.name, self.qtype, self.qclass)
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

        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }
        */

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsARecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer."));
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
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }
        */

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsAAAARecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer."));
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
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }

        */
        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsTXTRecord, String> {
            let buflen = buf.len();
            if buflen == 0 {
                return Err(String::from("Got a zero-length buffer."));
            }
            if offset >= buflen {
                return Err(String::from("Got an offset outside of the buffer."));
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
            Ok(DnsTXTRecord::new(txt))
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
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsCNAMERecord, String> {

        }
        */
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
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsMXRecord, String> {

        }
        */
    }

    impl fmt::Display for DnsMXRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "MX: Preference {}; Exchange {}", self.preference, self.exchange)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub enum DnsResourceRecordEnum {
        // keep this in sync with the DnsQType enum and type-specific structs/impls above.
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

    impl fmt::Display for DnsResourceRecordEnum {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    pub struct DnsResourceRecord {
        name: String,
        // qtype implied from record field
        class: DnsQClass,
        ttl: u32,
        record: DnsResourceRecordEnum
    }

    impl DnsResourceRecord {
        pub fn new(n: String, c: DnsQClass, t: u32, r: DnsResourceRecordEnum) -> DnsResourceRecord {
            DnsResourceRecord { name: n, class: c, ttl: t, record: r }
        }
        /*
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> DnsResourceRecord {

        }
        */
    }

    impl fmt::Display for DnsResourceRecord {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "RR: name {}; class {}, ttl {}, record {}",
                   self.name, self.class, self.ttl, self.record)
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

        pub fn to_u16(&self) -> u16 {
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
            write!(f, "{}", s)
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
            let options = self.header.to_u16();
            ret.extend_from_slice(&options.to_be_bytes());

            // qcount/ancount/nscount/arcount
            let qcount = self.questions.len() as u16;
            ret.extend_from_slice(&qcount.to_be_bytes());
            let other_count = 0u16;
            ret.extend_from_slice(&other_count.to_be_bytes());
            ret.extend_from_slice(&other_count.to_be_bytes());
            ret.extend_from_slice(&other_count.to_be_bytes());

            for question in &self.questions {
                let mut bytes = question.to_bytes()?;
                ret.append(&mut bytes);
            }
            
            Ok(ret)
        }

        // expects network-order input bytes, as if just read from wire.
        /* TODO implement
        pub fn from_bytes(bytes: Vec<u8>) -> Result(DnsHeader, String) {

        }
        */
    }

    impl fmt::Display for DnsQuery {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // TODO fix the :? in the next line - have an actual formatter for questions
            write!(f, "Query:\n Header: {}\nQuestions: {:?}", self.header, self.questions)
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

        /* TODO implement!
        pub fn to_bytes(&self) -> Result<Vec<u8>, String> {

        }

        pub fn from_bytes(buf: &Vec<u8>, offset: usize) -> Result<DnsResponse, String> {
            Err(String::from("placeholder!"))
        }
        */
    }

    impl fmt::Display for DnsResponse {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // TODO fix the :? in the next line - have an actual formatter for vecs of records
            let s = format!(
                "Response:\n Header: {}\nQuestions: {:?}\nAnswers: {:?}\nAuths: {:?}\nAdditional: {:?}",
                self.header, self.questions, self.answers, self.authorities, self.additionals);
            write!(f, "{}", s)
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
