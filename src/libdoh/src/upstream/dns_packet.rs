use std::net::IpAddr;

use super::msg::{Msg, MsgError};
use super::rr_types::RrType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PacketError {
    InvalidPacket,
}

impl From<MsgError> for PacketError {
    fn from(_: MsgError) -> Self {
        Self::InvalidPacket
    }
}

pub(crate) fn query_qtype(packet: &[u8]) -> Option<RrType> {
    Msg::qtype_from_packet(packet)
}

pub(crate) fn validate_response_packet(packet: &[u8]) -> bool {
    Msg::validate_packet(packet)
}

pub(crate) fn extract_answer_ips(packet: &[u8]) -> Vec<IpAddr> {
    Msg::extract_answer_ips_from_packet(packet)
}

pub(crate) fn contains_answer_ip(packet: &[u8], target_ip: IpAddr) -> bool {
    Msg::contains_answer_ip_in_packet(packet, target_ip)
}

pub(crate) fn rewrite_answer_ips_in_place(
    packet: &mut [u8],
    selected_ip: IpAddr,
) -> Result<(), PacketError> {
    Msg::rewrite_answer_ips_in_packet(packet, selected_ip).map_err(PacketError::from)
}
