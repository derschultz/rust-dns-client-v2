#[cfg(test)]
mod tests {

    /* https://routley.io/posts/hand-writing-dns-messages/ was very useful
       when writing tests using raw bytes. */

    use dns_client::dns_client_lib::*;
    use std::net::{Ipv4Addr,Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn dnsopcode_from_u8_test() {
        assert_eq!(DnsOpcode::from_u8(0), DnsOpcode::QUERY);
        assert_eq!(DnsOpcode::from_u8(1), DnsOpcode::IQUERY);
        assert_eq!(DnsOpcode::from_u8(42), DnsOpcode::RESERVED);
    }

    #[test]
    fn dnsopcode_fmt_test() {
        assert_eq!(format!("{}", DnsOpcode::QUERY), String::from("QUERY"));
        assert_eq!(format!("{}", DnsOpcode::RESERVED), String::from("RESERVED"));
    }

    #[test]
    fn dnsrcode_from_u8_test() {
        assert_eq!(DnsRcode::from_u8(0), DnsRcode::NOERROR);
        assert_eq!(DnsRcode::from_u8(1), DnsRcode::FORMERR);
        assert_eq!(DnsRcode::from_u8(42), DnsRcode::RESERVED);
    }

    #[test]
    fn dnsrcode_fmt_test() {
        assert_eq!(format!("{}", DnsRcode::NOERROR), String::from("NOERROR"));
        assert_eq!(format!("{}", DnsRcode::RESERVED), String::from("RESERVED"));
    }

    #[test]
    fn dnsqtype_from_u16_test() {
        assert_eq!(DnsQType::from_u16(1), DnsQType::A);
        assert_eq!(DnsQType::from_u16(28), DnsQType::AAAA);
        assert_eq!(DnsQType::from_u16(253), DnsQType::RESERVED);
    }

    #[test]
    fn dnsqtype_fmt_test() {
        assert_eq!(format!("{}", DnsQType::A), String::from("A"));
        assert_eq!(format!("{}", DnsQType::RESERVED), String::from("RESERVED"));
    }

    #[test]
    fn dnsheader_flags_to_u16_test() {
        // flags.
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x0u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, true, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x80u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, true, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x0100u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, true, false, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x200u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, true, false, false, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x400u16);

        // opcodes
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::IQUERY, false, false, false, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x0800u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::STATUS, false, false, false, false, DnsRcode::NOERROR);
        assert_eq!(header.flags_to_u16(), 0x1000u16);

        // rcodes
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::FORMERR);
        assert_eq!(header.flags_to_u16(), 0x1u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::SERVFAIL);
        assert_eq!(header.flags_to_u16(), 0x2u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::NAMERR);
        assert_eq!(header.flags_to_u16(), 0x3u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::NOTIMP);
        assert_eq!(header.flags_to_u16(), 0x4u16);
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::QUERY, false, false, false, false, DnsRcode::REFUSED);
        assert_eq!(header.flags_to_u16(), 0x5u16);

        // and in combination, or with response bit set
        let header = DnsHeader::new(
            0xFF, false, DnsOpcode::IQUERY, true, false, true, false, DnsRcode::FORMERR);
        assert_eq!(header.flags_to_u16(), 0x0D01u16);
        let header = DnsHeader::new(
            0xFF, true, DnsOpcode::IQUERY, true, false, true, false, DnsRcode::FORMERR);
        assert_eq!(header.flags_to_u16(), 0x8D01u16);
    }

    #[test]
    fn string_to_dns_name_test() {
        // www.google.com
        let buf: Vec<u8> = vec![0x03, 0x77, 0x77, 0x77, // length 3, w, w, w
                                0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                                0x67, 0x6c, 0x65,       // g, l, e
                                0x03, 0x63, 0x6f, 0x6d, // length 3, c, o, m
                                0x00]; // ending null byte

        assert_eq!(string_to_dns_name(&String::from("www.google.com.")), Ok(buf.clone()));

        // example.com
        let buf: Vec<u8> = vec![0x07, 0x65, 0x78, 0x61, // length 7, e, x, a
                                0x6d, 0x70, 0x6c, 0x65, // m, p, l, e
                                0x03, 0x63, 0x6f, 0x6d, // length 3, c, o, m
                                0x00]; // ending null byte

        // including a trailing . or not
        assert_eq!(string_to_dns_name(&String::from("example.com.")), Ok(buf.clone()));
        assert_eq!(string_to_dns_name(&String::from("example.com")), Ok(buf.clone()));
        // whitespace gets trimmed
        assert_eq!(string_to_dns_name(&String::from(" example.com\n")), Ok(buf.clone()));

        // root (".")
        let buf: Vec<u8> = vec![0x00];
        assert_eq!(string_to_dns_name(&String::from("")), Ok(buf.clone()));
        assert_eq!(string_to_dns_name(&String::from(".")), Ok(buf.clone()));
        assert_eq!(string_to_dns_name(&String::from(" ")), Ok(buf.clone()));
        
        /* negative results are in is_valid_dns_name_test below, as that is the only way
           (currently) for the string_to_dns_name fn to fail */
    }

    #[test]
    fn is_valid_dns_name_test() {

        assert_eq!(is_valid_dns_name(&String::from("www.google.com.")), Ok(()));
        assert_eq!(is_valid_dns_name(&String::from("www.goo-gle.com.")), Ok(()));

        // empty label 
        assert_eq!(is_valid_dns_name(&String::from("foo..bar")),
                   Err(String::from("Got an empty label.")));
        assert_eq!(is_valid_dns_name(&String::from("..")),
                   Err(String::from("Got an empty label.")));

        // label too long
        let name = String::from(
            "a1234567890123456789012345678901234567890123456789012345678901234567890");
        assert_eq!(is_valid_dns_name(&name), 
                   Err(format!("Got a label ({}) that is more than 63 characters.", name)));

        // label starts/ends with a hyphen
        assert_eq!(is_valid_dns_name(&String::from("-foo.com")), 
                   Err(String::from("Got a label (-foo) that starts with a hyphen.")));
        assert_eq!(is_valid_dns_name(&String::from("foo-.com")), 
                   Err(String::from("Got a label (foo-) that ends with a hyphen.")));

        // label contains non-alphanumeric/hyphen characters
        assert_eq!(is_valid_dns_name(&String::from("a@b.com.")),
                   Err(String::from("Got a label (a@b) with a bad character (@).")));

        // TODO more tests! lots of corner/error cases for this one.
    }

    #[test]
    fn dnsquestionrecord_to_bytes_test() {
        let qr = DnsQuestionRecord::new(String::from("google.com."), DnsQType::A, DnsQClass::IN);
        assert_eq!(qr.to_bytes(), 
                   Ok(vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                           0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                           0x63, 0x6f, 0x6d, 0x00, // c, o, m, null
                           0x00, 0x01, 0x00, 0x01])); // qtype=A, qclass=IN

        let qr = DnsQuestionRecord::new(String::from("google.com."), DnsQType::AAAA, DnsQClass::IN);
        assert_eq!(qr.to_bytes(), 
                   Ok(vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                           0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                           0x63, 0x6f, 0x6d, 0x00, // c, o, m, null
                           0x00, 0x1c, 0x00, 0x01])); // qtype=AAAA, qclass=IN
        
        let qr = DnsQuestionRecord::new(String::from("google.com."), DnsQType::A, DnsQClass::CH);
        assert_eq!(qr.to_bytes(), 
                   Ok(vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                           0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                           0x63, 0x6f, 0x6d, 0x00, // c, o, m, null
                           0x00, 0x01, 0x00, 0x03])); // qtype=A, qclass=CH

        let qr = DnsQuestionRecord::new(String::from("goo@gle.com."), DnsQType::A, DnsQClass::IN);
        assert_eq!(qr.to_bytes(), 
                   Err(String::from("'goo@gle.com.' doesn't appear to be a valid DNS name: Got a label (goo@gle) with a bad character (@).")));
    }

    #[test]
    fn dnsquestionrecord_from_bytes_test() {
        let qr = DnsQuestionRecord::new(String::from("google.com."), DnsQType::A, DnsQClass::IN);
        let buf: Vec<u8> = vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                                0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                                0x63, 0x6f, 0x6d, 0x00, // c, o, m, null
                                0x00, 0x01, 0x00, 0x01];// qtype=A, qclass=IN
        assert_eq!(DnsQuestionRecord::from_bytes(&buf, 0), Ok((qr, 16)));

        let buf: Vec<u8> = vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                                0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                                0x63, 0x6f, 0x6d, 0x00];// c, o, m, null - but no qtype/qclass!
        assert_eq!(DnsQuestionRecord::from_bytes(&buf, 0),
                   Err(String::from("Hit buffer bounds reading qtype/class in QuestionRecord.")));

        let buf: Vec<u8> = vec![0x06, 0x67, 0x6f, 0x6f, // length 6, g, o, o
                                0x67, 0x6c, 0x65, 0x03, // g, l, e, length 3
                                0x63, 0x6f, 0x6d, 0x00, // c, o, m, null
                                0x00, 0x01];            // qtype=A, but no qclass!
        assert_eq!(DnsQuestionRecord::from_bytes(&buf, 0),
                   Err(String::from("Hit buffer bounds reading qtype/class in QuestionRecord.")));

        // TODO more tests!
    }

    #[test]
    fn dnsquery_to_bytes_test() {
        let h = DnsHeader::new(0xABCDu16, false, DnsOpcode::QUERY, false, false,
                               true, false, DnsRcode::NOERROR);
        let qrv : Vec<DnsQuestionRecord> =
            vec![DnsQuestionRecord::new(String::from("google.com."), DnsQType::A, DnsQClass::IN)];
        let q = DnsQuery::new(h, qrv, None);
        assert_eq!(q.to_bytes(),
                   Ok(vec![0xAB, 0xCD, 0x01, 0x00,      // qid, options
                           0x00, 0x01, 0x00, 0x00,      // qcount, ancount
                           0x00, 0x00, 0x00, 0x00,      // authcount, addcount
                           0x06, 0x67, 0x6f, 0x6f,      // len 6, g, o, o
                           0x67, 0x6c, 0x65, 0x03,      // g, l, e, len 3
                           0x63, 0x6f, 0x6d, 0x00,      // c, o, m, null
                           0x00, 0x01, 0x00, 0x01]));   // qtype=A, qclass=IN

        // TODO more tests! diff qtypes/qclasses, header flags/codes
    }

    #[test]
    fn dnsheader_from_bytes_test() {
        let h = DnsHeader::new(0xABCDu16, true, DnsOpcode::QUERY, false,
                               false, true, true, DnsRcode::NOERROR);
        let v : Vec<u8> = vec![0xAB, 0xCD, 0x81, 0x80]; // qid, flags
        assert_eq!(Ok(h), DnsHeader::from_bytes(&v, 0));
        // TODO more tests! diff header options, etc.
    }

    #[test]
    fn dns_name_to_string_test() {
        // normal
        let buf: Vec<u8> = vec![0x06, 0x67, 0x6f, 0x6f,      // len 6, g, o, o
                                0x67, 0x6c, 0x65, 0x03,      // g, l, e, len 3
                                0x63, 0x6f, 0x6d, 0x00];     // c, o, m, null
        assert_eq!(Ok((String::from("google.com."), 12)), dns_name_to_string(&buf, 0));

        // root
        let buf: Vec<u8> = vec![0x00]; // null
        assert_eq!(Ok((String::from("."), 1)), dns_name_to_string(&buf, 0));

        /* with compression. start at offset 12
         note that it's 6 bytes read here - 1 len byte, 3 label bytes, and 2 compression bytes.
         the bytes parsed when following the compression pointer don't count as bytes read!
         */
        let buf: Vec<u8> = vec![0x06, 0x67, 0x6f, 0x6f,     // len 6, g, o, o
                                0x67, 0x6c, 0x65, 0x03,     // g, l, e, len 3
                                0x63, 0x6f, 0x6d, 0x00,     // c, o, m, null
                                0x03, 0x77, 0x77, 0x77,     // len 3, w, w, w
                                0xc0, 0x00];                // ptr to 0
        assert_eq!(Ok((String::from("www.google.com."), 6)), dns_name_to_string(&buf, 12));

        let buf: Vec<u8> = vec![0xC0, 0x00]; // ptr to 0 at 0
        assert_eq!(Err(String::from("Got a self-referencing compression pointer.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0xC0, 0x02]; // ptr to 2 at 0
        assert_eq!(Err(String::from("Got a forward-pointing compression pointer.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0x80, 0x02]; // 10 in top bits of len byte
        assert_eq!(Err(String::from("Got 10/01 in top bits of dns name length byte.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0x40, 0x02]; // 10 in top bits of len byte
        assert_eq!(Err(String::from("Got 10/01 in top bits of dns name length byte.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0xC0]; // ptr, but without followup byte in buf
        assert_eq!(Err(String::from("Hit buffer bounds when parsing compression ptr.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0x02, 0x67]; // len 2, g, then nothing - not enough for label!
        assert_eq!(Err(String::from("Hit buffer bounds when parsing label.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0x01]; // len 1 then nothing - not enough for label!
        assert_eq!(Err(String::from("Hit buffer bounds when parsing label.")),
                   dns_name_to_string(&buf, 0));

        let buf: Vec<u8> = vec![0x00]; // root, but starting at offset outside buffer
        assert_eq!(Err(String::from("Offset outside of buffer bounds.")),
                   dns_name_to_string(&buf, 1));

        let buf: Vec<u8> = vec![]; // nothing - obvious error
        assert_eq!(Err(String::from("Can't operate on empty name buffer.")),
                   dns_name_to_string(&buf, 0));

        // TODO more tests!
    }

    #[test]
    fn dnsarecord_from_bytes_test() {
        let buf: Vec<u8> = vec![];
        assert_eq!(DnsARecord::from_bytes(&buf, 0),
                   Err(String::from("Got a zero-length buffer.")));
        let buf: Vec<u8> = vec![0x00];
        assert_eq!(DnsARecord::from_bytes(&buf, 1),
                   Err(String::from("Got an offset outside of the buffer parsing A record.")));
        let buf: Vec<u8> = vec![0xAB, 0xCD, 0xEF];
        assert_eq!(DnsARecord::from_bytes(&buf, 0),
                   Err(String::from("Got a buffer with too few bytes to read.")));

        let arecord = DnsARecord::new(Ipv4Addr::new(0xAB, 0xCD, 0xEF, 0x01));
        let buf: Vec<u8> = vec![0xAB, 0xCD, 0xEF, 0x01];
        assert_eq!(DnsARecord::from_bytes(&buf, 0), Ok(arecord));
    }

    #[test]
    fn dnsaaaarecord_from_bytes_test() {
        let buf: Vec<u8> = vec![];
        assert_eq!(DnsAAAARecord::from_bytes(&buf, 0),
                   Err(String::from("Got a zero-length buffer.")));
        let buf: Vec<u8> = vec![0x00];
        assert_eq!(DnsAAAARecord::from_bytes(&buf, 1),
                   Err(String::from("Got an offset outside of the buffer.")));
        let buf: Vec<u8> = vec![0xAB, 0xCD, 0xEF];
        assert_eq!(DnsAAAARecord::from_bytes(&buf, 0),
                   Err(String::from("Got a buffer with too few bytes to read.")));

        let aaaarecord = DnsAAAARecord::new(Ipv6Addr::from_str("CAFE::F00D").unwrap());
        let buf: Vec<u8> = vec![0xCA, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x0D];
        assert_eq!(DnsAAAARecord::from_bytes(&buf, 0), Ok(aaaarecord));
    }

    #[test]
    fn dnstxtrecord_from_bytes_test() {
        let buf: Vec<u8> = vec![];
        assert_eq!(DnsTXTRecord::from_bytes(&buf, 0),
                   Err(String::from("Got a zero-length buffer.")));
        let buf: Vec<u8> = vec![0x00];
        assert_eq!(DnsTXTRecord::from_bytes(&buf, 1),
                   Err(String::from("Got an offset outside of the buffer parsing TXT record.")));
        let buf: Vec<u8> = vec![0x02, 0x74]; // len 2, t, then nothing!
        assert_eq!(DnsTXTRecord::from_bytes(&buf, 0),
                   Err(String::from("Got a TXT record with a len byte pointing outside buffer.")));

        let txtrecord = DnsTXTRecord::new(String::from("test"));
        let buf: Vec<u8> = vec![0x04, 0x74, 0x65, 0x73, 0x74];
        let (parsed_record, count) = DnsTXTRecord::from_bytes(&buf, 0).unwrap();
        assert_eq!(parsed_record, txtrecord);
    }

    #[test]
    fn dnscnamerecord_from_bytes_test() {
        // TODO add tests for this. I didn't do it initially b/c the function is trivial.
    }

    #[test]
    fn dnsmxrecord_from_bytes_test() {
        let buf: Vec<u8> = vec![];
        assert_eq!(DnsMXRecord::from_bytes(&buf, 0),
                   Err(String::from("Got a zero-length buffer.")));
        let buf: Vec<u8> = vec![0x00];
        assert_eq!(DnsMXRecord::from_bytes(&buf, 1),
                   Err(String::from("Got an offset outside of the buffer parsing MX record.")));
        let buf: Vec<u8> = vec![0x02, 0x74]; // prefs, but no exchange!
        assert_eq!(DnsMXRecord::from_bytes(&buf, 0),
                   Err(String::from("Got an offset with not enough buf for prefs/exchange.")));

        let mxrecord = DnsMXRecord::new(0xabcd, String::from("exchange."));
        let buf: Vec<u8> = vec![0xab, 0xcd, 0x08, 0x65, 0x78, 0x63,     // prefs, len 8, e, x, c
                                0x68, 0x61, 0x6e, 0x67, 0x65, 0x00];    // h, a, n, g, e, null
        assert_eq!(DnsMXRecord::from_bytes(&buf, 0), Ok((mxrecord, 12)));
    }

    #[test]
    fn dnsnsrecord_from_bytes_test() {
        // TODO add tests for this. like DnsCNAMERecord::from_bytes, this function is trivial.
    }

    #[test]
    fn dnsresourcerecord_from_bytes_test() {
        // TODO
    }

    #[test]
    fn dnsresponse_from_bytes_test() {
        // TODO
        let buf: Vec<u8> = vec![
            // header + counts - 0-11
            0xab, 0xcd, 0x81, 0x80, 0x0, 0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0,
            // question (akasecure.net) - 12-30
            0x9, 0x61, 0x6b, 0x61, 0x73, 0x65, 0x63, 0x75, 0x72, 0x65,  // akasecure
            0x3, 0x6e, 0x65, 0x74, 0x0, // net, root
            0x0, 0x1, 0x0, 0x1, // A IN
            // answer 1 - 31-47
            0xc0, 0xc,  // ptr to name in question
            0x0, 0x1, 0x0, 0x1, // A IN
            0x0, 0x0, 0x1, 0x2c,  // ttl
            0x0, 0x4,  // rdlen
            0x48, 0xf6, 0x2, 0x4c, // rdata (A record -> ipv4 addr)
            // answer 2 - 47-62
            0xc0, 0xc,  // ptr to name in question
            0x0, 0x1, 0x0, 0x1,  // A IN
            0x0, 0x0, 0x1, 0x2c,  // ttl
            0x0, 0x4, // rdlen
            0x60, 0x6, 0x72, 0x53]; // rdata (A record -> ipv4 addr)
        let header = DnsHeader::new(0xabcd, true, DnsOpcode::QUERY, false, false, true,
                                    true, DnsRcode::NOERROR);
        let qvec = vec![DnsQuestionRecord::new(String::from("akasecure.net."),
                                               DnsQType::A, DnsQClass::IN)];
        let anvec = vec![DnsResourceRecord::new(
            String::from("akasecure.net."), DnsQType::A, DnsQClass::IN, 300, DnsResourceRecordEnum::A(
                DnsARecord::new(Ipv4Addr::new(72,246,2,76))
            )),
                         DnsResourceRecord::new(
            String::from("akasecure.net."), DnsQType::A, DnsQClass::IN, 300, DnsResourceRecordEnum::A(
                DnsARecord::new(Ipv4Addr::new(96,6,114,83))
            ))];
        let auvec = vec![];
        let addvec = vec![];
        let response = DnsResponse::new(header, qvec, anvec, auvec, addvec);
        assert_eq!(DnsResponse::from_bytes(&buf, 0), Ok(response));
    }

}
