use crate::token_raw;

#[derive(Debug)]
pub(crate) enum TokenError
{
    InitError,
    MissingMandatoryClaim,
    InvalidCoseTag,
    InvalidClaimLen,
    InternalError,
}

impl std::fmt::Display for TokenError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TokenError {}

impl From<i32> for TokenError
{
    fn from(value: i32) -> Self
    {
        match value {
            1 => TokenError::InitError,
            2 => TokenError::MissingMandatoryClaim,
            3 => TokenError::InvalidCoseTag,
            4 => TokenError::InvalidClaimLen,
            _ => TokenError::InternalError,
        }
    }
}

#[allow(dead_code)]
fn new_claims() -> token_raw::attestation_claims
{
    let claim_union = token_raw::claim_t__bindgen_ty_1 {
        bool_data: false,
    };
    let claim = token_raw::claim_t {
        mandatory: false,
        type_: 0,
        key: 0,
        title: std::ptr::null() as *const std::os::raw::c_char,
        present: false,
        __bindgen_anon_1: claim_union,
    };
    let component = token_raw::sw_component_t {
        present: false,
        claims: [claim; token_raw::CLAIM_COUNT_SW_COMPONENT as usize],
    };
    token_raw::attestation_claims {
        realm_cose_sign1_wrapper: [claim; token_raw::CLAIM_COUNT_COSE_SIGN1_WRAPPER as usize],
        realm_token_claims: [claim; token_raw::CLAIM_COUNT_REALM_TOKEN as usize],
        realm_measurement_claims: [claim; token_raw::CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS as usize],
        plat_cose_sign1_wrapper: [claim; token_raw::CLAIM_COUNT_COSE_SIGN1_WRAPPER as usize],
        plat_token_claims: [claim; token_raw::CLAIM_COUNT_PLATFORM_TOKEN as usize],
        sw_component_claims: [component; token_raw::MAX_SW_COMPONENT_COUNT as usize]
    }
}

#[allow(dead_code)]
pub(crate) fn verify_token(token: &[u8])
                           -> Result<token_raw::attestation_claims, TokenError>
{
    let mut claims = new_claims();
    let ret = unsafe {
        token_raw::verify_token(token.as_ptr() as *const std::os::raw::c_char,
                                token.len(), &mut claims)
    };
    match ret {
        0 => Ok(claims),
        _ => Err(ret.into()),
    }
}

#[allow(dead_code)]
pub(crate) fn print_raw_token(token: &[u8])
{
    unsafe {
        token_raw::print_raw_token(token.as_ptr() as *const std::os::raw::c_char,
                                   token.len());
    }
}

#[allow(dead_code)]
pub(crate) fn print_token(claims: &token_raw::attestation_claims)
{
    unsafe {
        token_raw::print_token(claims as *const token_raw::attestation_claims);
    }
}
