mod base_converter;
mod core_protocol_functionalities;
mod encode_decode;
mod frodo_variant_wrapper;
mod mlkem_variant_wrapper;
mod overall_common_functionalities;
mod protocol_variants;

use std::str::from_utf8;

pub use crate::{
    core_protocol_functionalities::b_pake_protocols::{
        kem_ae_pake::{client::KemAeClient, server::KemAeServer},
        ocake_pake::{client::OcakeClient, server::OcakeServer},
        tk_pake::{client::TkClient, server::TkServer},
    },
    protocol_variants::{AvailableVariants, KemChoice},
};

pub fn to_human_readable(bytes: &[u8]) -> &str {
    let s = from_utf8(bytes).expect("Bytes not in valid UTF‑8 format");
    s
}
