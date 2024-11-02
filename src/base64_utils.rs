use base64::{
    alphabet::{STANDARD, URL_SAFE},
    engine::{GeneralPurpose, GeneralPurposeConfig},
    Engine,
};

/// Helper to encode given bytes as base64.
pub(crate) fn bytes_to_base64(bytes: &[u8], url_safe: bool) -> String {
    let abc = if url_safe { URL_SAFE } else { STANDARD };
    let engine = GeneralPurpose::new(&abc, GeneralPurposeConfig::new());
    engine.encode(bytes)
}
/// Helper to decode given base64 into bytes.
pub(crate) fn base64_to_bytes(
    base64: &str,
    url_safe: bool,
) -> Result<Vec<u8>, base64::DecodeError> {
    let abc = if url_safe { URL_SAFE } else { STANDARD };
    let engine = GeneralPurpose::new(&abc, GeneralPurposeConfig::new());
    engine.decode(base64.as_bytes())
}
