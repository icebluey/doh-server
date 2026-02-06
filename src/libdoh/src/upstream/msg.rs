#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};

use super::rr_types::RrType;

const DNS_HEADER_SIZE: usize = 12;
const DNS_CLASS_IN: u16 = 1;
const MAX_DOMAIN_NAME_WIRE_OCTETS: usize = 255;
const MAX_COMPRESSION_POINTERS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MsgError {
    ShortPacket,
    InvalidName,
    CompressionLoop,
    InvalidLabelLength,
    InvalidRecord,
    TrailingBytes,
    RdataTooLong,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MsgHeader {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub zero: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub rcode: u8,
}

impl MsgHeader {
    fn from_wire(id: u16, bits: u16) -> Self {
        Self {
            id,
            response: bits & (1 << 15) != 0,
            opcode: ((bits >> 11) & 0x0f) as u8,
            authoritative: bits & (1 << 10) != 0,
            truncated: bits & (1 << 9) != 0,
            recursion_desired: bits & (1 << 8) != 0,
            recursion_available: bits & (1 << 7) != 0,
            zero: bits & (1 << 6) != 0,
            authenticated_data: bits & (1 << 5) != 0,
            checking_disabled: bits & (1 << 4) != 0,
            rcode: (bits & 0x0f) as u8,
        }
    }

    fn to_wire_bits(self) -> u16 {
        let mut bits = ((self.opcode as u16) & 0x0f) << 11;
        if self.response {
            bits |= 1 << 15;
        }
        if self.authoritative {
            bits |= 1 << 10;
        }
        if self.truncated {
            bits |= 1 << 9;
        }
        if self.recursion_desired {
            bits |= 1 << 8;
        }
        if self.recursion_available {
            bits |= 1 << 7;
        }
        if self.zero {
            bits |= 1 << 6;
        }
        if self.authenticated_data {
            bits |= 1 << 5;
        }
        if self.checking_disabled {
            bits |= 1 << 4;
        }
        bits | (u16::from(self.rcode) & 0x0f)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Name {
    labels: Vec<Vec<u8>>,
}

impl Name {
    fn from_wire(packet: &[u8], offset: usize) -> Result<(Self, usize), MsgError> {
        let mut labels = Vec::new();
        let mut current = offset;
        let mut consumed: Option<usize> = None;
        let mut pointers_followed = 0usize;
        let mut wire_len = 1usize;

        loop {
            let len = *packet.get(current).ok_or(MsgError::ShortPacket)?;

            match len & 0xC0 {
                0xC0 => {
                    let b2 = *packet.get(current + 1).ok_or(MsgError::ShortPacket)?;
                    let ptr = (((len & 0x3f) as usize) << 8) | b2 as usize;
                    if ptr >= packet.len() {
                        return Err(MsgError::InvalidName);
                    }
                    if consumed.is_none() {
                        consumed = Some(current + 2);
                    }
                    pointers_followed += 1;
                    if pointers_followed > MAX_COMPRESSION_POINTERS {
                        return Err(MsgError::CompressionLoop);
                    }
                    current = ptr;
                }
                0x00 => {
                    let label_len = len as usize;
                    current += 1;
                    if label_len == 0 {
                        let next = consumed.unwrap_or(current);
                        return Ok((Self { labels }, next));
                    }
                    let end = current + label_len;
                    if end > packet.len() {
                        return Err(MsgError::ShortPacket);
                    }
                    wire_len += 1 + label_len;
                    if wire_len > MAX_DOMAIN_NAME_WIRE_OCTETS {
                        return Err(MsgError::InvalidName);
                    }
                    labels.push(packet[current..end].to_vec());
                    current = end;
                }
                _ => return Err(MsgError::InvalidLabelLength),
            }
        }
    }

    fn skip_wire(packet: &[u8], offset: usize) -> Result<usize, MsgError> {
        let mut current = offset;
        loop {
            let len = *packet.get(current).ok_or(MsgError::ShortPacket)?;
            match len & 0xC0 {
                0xC0 => {
                    let _ = packet.get(current + 1).ok_or(MsgError::ShortPacket)?;
                    return Ok(current + 2);
                }
                0x00 => {
                    let label_len = len as usize;
                    if label_len >= 0x40 {
                        return Err(MsgError::InvalidLabelLength);
                    }
                    current += 1 + label_len;
                    if label_len == 0 {
                        return Ok(current);
                    }
                    if current > packet.len() {
                        return Err(MsgError::ShortPacket);
                    }
                }
                _ => return Err(MsgError::InvalidLabelLength),
            }
        }
    }

    fn wire_len(&self) -> usize {
        1 + self.labels.iter().map(|label| 1 + label.len()).sum::<usize>()
    }

    fn pack_into(&self, out: &mut Vec<u8>) -> Result<(), MsgError> {
        for label in &self.labels {
            if label.len() >= 0x40 {
                return Err(MsgError::InvalidLabelLength);
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Question {
    pub name: Name,
    pub qtype: RrType,
    pub qclass: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResourceRecord {
    pub name: Name,
    pub rr_type: RrType,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Msg {
    pub header: MsgHeader,
    pub compress: bool,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    pub authorities: Vec<ResourceRecord>,
    pub additionals: Vec<ResourceRecord>,
}

impl Msg {
    pub(crate) fn unpack(packet: &[u8]) -> Result<Self, MsgError> {
        if packet.len() < DNS_HEADER_SIZE {
            return Err(MsgError::ShortPacket);
        }

        let id = BigEndian::read_u16(&packet[0..2]);
        let bits = BigEndian::read_u16(&packet[2..4]);
        let qdcount = BigEndian::read_u16(&packet[4..6]) as usize;
        let ancount = BigEndian::read_u16(&packet[6..8]) as usize;
        let nscount = BigEndian::read_u16(&packet[8..10]) as usize;
        let arcount = BigEndian::read_u16(&packet[10..12]) as usize;

        let mut offset = DNS_HEADER_SIZE;
        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (name, next) = Name::from_wire(packet, offset)?;
            if packet.len().saturating_sub(next) < 4 {
                return Err(MsgError::ShortPacket);
            }
            let qtype = RrType::from_u16(BigEndian::read_u16(&packet[next..next + 2]));
            let qclass = BigEndian::read_u16(&packet[next + 2..next + 4]);
            questions.push(Question {
                name,
                qtype,
                qclass,
            });
            offset = next + 4;
        }

        let (answers, next) = unpack_rr_section(packet, offset, ancount)?;
        let (authorities, next) = unpack_rr_section(packet, next, nscount)?;
        let (additionals, next) = unpack_rr_section(packet, next, arcount)?;
        if next != packet.len() {
            return Err(MsgError::TrailingBytes);
        }

        Ok(Self {
            header: MsgHeader::from_wire(id, bits),
            compress: false,
            questions,
            answers,
            authorities,
            additionals,
        })
    }

    pub(crate) fn pack(&self) -> Result<Vec<u8>, MsgError> {
        let qdcount = u16::try_from(self.questions.len()).map_err(|_| MsgError::InvalidRecord)?;
        let ancount = u16::try_from(self.answers.len()).map_err(|_| MsgError::InvalidRecord)?;
        let nscount = u16::try_from(self.authorities.len()).map_err(|_| MsgError::InvalidRecord)?;
        let arcount = u16::try_from(self.additionals.len()).map_err(|_| MsgError::InvalidRecord)?;

        let mut estimated = DNS_HEADER_SIZE;
        for q in &self.questions {
            estimated += q.name.wire_len() + 4;
        }
        for rr in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .chain(self.additionals.iter())
        {
            estimated += rr.name.wire_len() + 10 + rr.rdata.len();
        }

        let mut out = Vec::with_capacity(estimated);
        out.resize(DNS_HEADER_SIZE, 0);
        BigEndian::write_u16(&mut out[0..2], self.header.id);
        BigEndian::write_u16(&mut out[2..4], self.header.to_wire_bits());
        BigEndian::write_u16(&mut out[4..6], qdcount);
        BigEndian::write_u16(&mut out[6..8], ancount);
        BigEndian::write_u16(&mut out[8..10], nscount);
        BigEndian::write_u16(&mut out[10..12], arcount);

        for q in &self.questions {
            q.name.pack_into(&mut out)?;
            out.extend_from_slice(&q.qtype.to_u16().to_be_bytes());
            out.extend_from_slice(&q.qclass.to_be_bytes());
        }

        for rr in &self.answers {
            pack_rr(rr, &mut out)?;
        }
        for rr in &self.authorities {
            pack_rr(rr, &mut out)?;
        }
        for rr in &self.additionals {
            pack_rr(rr, &mut out)?;
        }

        Ok(out)
    }

    pub(crate) fn qtype(&self) -> Option<RrType> {
        self.questions.first().map(|q| q.qtype)
    }

    pub(crate) fn answer_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for rr in &self.answers {
            if rr.rr_class != DNS_CLASS_IN {
                continue;
            }
            match rr.rr_type {
                RrType::A if rr.rdata.len() == 4 => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        rr.rdata[0],
                        rr.rdata[1],
                        rr.rdata[2],
                        rr.rdata[3],
                    )));
                }
                RrType::AAAA if rr.rdata.len() == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&rr.rdata);
                    ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        ips
    }

    pub(crate) fn contains_answer_ip(&self, target_ip: IpAddr) -> bool {
        self.answers.iter().any(|rr| {
            if rr.rr_class != DNS_CLASS_IN {
                return false;
            }
            match (rr.rr_type, target_ip) {
                (RrType::A, IpAddr::V4(ip)) if rr.rdata.len() == 4 => rr.rdata == ip.octets(),
                (RrType::AAAA, IpAddr::V6(ip)) if rr.rdata.len() == 16 => rr.rdata == ip.octets(),
                _ => false,
            }
        })
    }

    pub(crate) fn rewrite_answer_ips(&mut self, selected_ip: IpAddr) {
        for rr in &mut self.answers {
            if rr.rr_class != DNS_CLASS_IN {
                continue;
            }
            match (rr.rr_type, selected_ip) {
                (RrType::A, IpAddr::V4(ip)) if rr.rdata.len() == 4 => {
                    rr.rdata.copy_from_slice(&ip.octets());
                }
                (RrType::AAAA, IpAddr::V6(ip)) if rr.rdata.len() == 16 => {
                    rr.rdata.copy_from_slice(&ip.octets());
                }
                _ => {}
            }
        }
    }

    pub(crate) fn validate_packet(packet: &[u8]) -> bool {
        Self::unpack(packet).is_ok()
    }

    pub(crate) fn qtype_from_packet(packet: &[u8]) -> Option<RrType> {
        let qdcount = packet
            .get(4..6)
            .map(BigEndian::read_u16)
            .unwrap_or_default() as usize;
        if qdcount == 0 {
            return None;
        }
        let mut offset = DNS_HEADER_SIZE;
        offset = Name::skip_wire(packet, offset).ok()?;
        if packet.len().saturating_sub(offset) < 4 {
            return None;
        }
        Some(RrType::from_u16(BigEndian::read_u16(
            &packet[offset..offset + 2],
        )))
    }

    pub(crate) fn extract_answer_ips_from_packet(packet: &[u8]) -> Vec<IpAddr> {
        match Self::unpack(packet) {
            Ok(msg) => msg.answer_ips(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) fn contains_answer_ip_in_packet(packet: &[u8], target_ip: IpAddr) -> bool {
        match Self::unpack(packet) {
            Ok(msg) => msg.contains_answer_ip(target_ip),
            Err(_) => false,
        }
    }

    pub(crate) fn rewrite_answer_ips_in_packet(
        packet: &mut [u8],
        selected_ip: IpAddr,
    ) -> Result<(), MsgError> {
        if packet.len() < DNS_HEADER_SIZE {
            return Err(MsgError::ShortPacket);
        }

        let qdcount = BigEndian::read_u16(&packet[4..6]) as usize;
        let ancount = BigEndian::read_u16(&packet[6..8]) as usize;
        let nscount = BigEndian::read_u16(&packet[8..10]) as usize;
        let arcount = BigEndian::read_u16(&packet[10..12]) as usize;

        let mut offset = DNS_HEADER_SIZE;
        for _ in 0..qdcount {
            offset = Name::skip_wire(packet, offset)?;
            if packet.len().saturating_sub(offset) < 4 {
                return Err(MsgError::ShortPacket);
            }
            offset += 4;
        }

        for _ in 0..ancount {
            offset = Name::skip_wire(packet, offset)?;
            if packet.len().saturating_sub(offset) < 10 {
                return Err(MsgError::ShortPacket);
            }
            let rr_type = RrType::from_u16(BigEndian::read_u16(&packet[offset..offset + 2]));
            let rr_class = BigEndian::read_u16(&packet[offset + 2..offset + 4]);
            let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
            let rdata_offset = offset + 10;
            if packet.len().saturating_sub(rdata_offset) < rdlen {
                return Err(MsgError::InvalidRecord);
            }

            if rr_class == DNS_CLASS_IN {
                match (rr_type, selected_ip) {
                    (RrType::A, IpAddr::V4(ip)) if rdlen == 4 => {
                        packet[rdata_offset..rdata_offset + 4].copy_from_slice(&ip.octets());
                    }
                    (RrType::AAAA, IpAddr::V6(ip)) if rdlen == 16 => {
                        packet[rdata_offset..rdata_offset + 16].copy_from_slice(&ip.octets());
                    }
                    _ => {}
                }
            }
            offset = rdata_offset + rdlen;
        }

        for _ in 0..(nscount + arcount) {
            offset = Name::skip_wire(packet, offset)?;
            if packet.len().saturating_sub(offset) < 10 {
                return Err(MsgError::ShortPacket);
            }
            let rdlen = BigEndian::read_u16(&packet[offset + 8..offset + 10]) as usize;
            let rdata_offset = offset + 10;
            if packet.len().saturating_sub(rdata_offset) < rdlen {
                return Err(MsgError::InvalidRecord);
            }
            offset = rdata_offset + rdlen;
        }

        if offset != packet.len() {
            return Err(MsgError::TrailingBytes);
        }
        Ok(())
    }
}

fn unpack_rr_section(
    packet: &[u8],
    mut offset: usize,
    count: usize,
) -> Result<(Vec<ResourceRecord>, usize), MsgError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (name, next) = Name::from_wire(packet, offset)?;
        if packet.len().saturating_sub(next) < 10 {
            return Err(MsgError::ShortPacket);
        }
        let rr_type = RrType::from_u16(BigEndian::read_u16(&packet[next..next + 2]));
        let rr_class = BigEndian::read_u16(&packet[next + 2..next + 4]);
        let ttl = BigEndian::read_u32(&packet[next + 4..next + 8]);
        let rdlen = BigEndian::read_u16(&packet[next + 8..next + 10]) as usize;
        let rdata_offset = next + 10;
        if packet.len().saturating_sub(rdata_offset) < rdlen {
            return Err(MsgError::InvalidRecord);
        }
        let rdata = packet[rdata_offset..rdata_offset + rdlen].to_vec();
        records.push(ResourceRecord {
            name,
            rr_type,
            rr_class,
            ttl,
            rdata,
        });
        offset = rdata_offset + rdlen;
    }
    Ok((records, offset))
}

fn pack_rr(rr: &ResourceRecord, out: &mut Vec<u8>) -> Result<(), MsgError> {
    if rr.rdata.len() > u16::MAX as usize {
        return Err(MsgError::RdataTooLong);
    }
    rr.name.pack_into(out)?;
    out.extend_from_slice(&rr.rr_type.to_u16().to_be_bytes());
    out.extend_from_slice(&rr.rr_class.to_be_bytes());
    out.extend_from_slice(&rr.ttl.to_be_bytes());
    out.extend_from_slice(&(rr.rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rr.rdata);
    Ok(())
}
