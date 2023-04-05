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

pub(crate) fn print_token(claims: &token_raw::attestation_claims)
{
    unsafe {
        token_raw::print_token(claims as *const token_raw::attestation_claims);
    }
}

// Rust code that prints c struct

use std::ffi::{CStr, c_char};
use core::slice;

const COLUMN: usize = 30;

fn cstr_to_str<'a>(s: *const c_char) -> &'a str
{
    unsafe {
        CStr::from_ptr(s)
    }.to_str().unwrap()
}

fn print_indent(indent: i32)
{
    for _i in 0..indent {
        print!("  ");
    }
}

fn print_byte_string(name: *const c_char, index: i64,
                     buf: token_raw::q_useful_buf_c)
{
    let v = unsafe {
        slice::from_raw_parts(buf.ptr as *const u8, buf.len)
    }.to_vec();
    println!("{:COLUMN$} (#{}) = [{}]", cstr_to_str(name), index, hex::encode(v));
}

fn print_text(name: *const c_char, index: i64,
              buf: token_raw::q_useful_buf_c)
{
    let v = unsafe {
        slice::from_raw_parts(buf.ptr as *const u8, buf.len)
    }.to_vec();
    println!("{:COLUMN$} (#{}) = \"{}\"", cstr_to_str(name), index, String::from_utf8_lossy(&v));
}

fn print_claim(claim: &token_raw::claim_t, indent: i32)
{
    print_indent(indent);

    if claim.present {
        match claim.type_ {
            token_raw::claim_data_type_CLAIM_INT64 =>
                println!("{:COLUMN$} (#{}) = {}",
                         cstr_to_str(claim.title), claim.key,
                         unsafe { claim.__bindgen_anon_1.int_data }),
            token_raw::claim_data_type_CLAIM_BOOL =>
                println!("{:COLUMN$} (#{}) = {}",
                         cstr_to_str(claim.title), claim.key,
                         unsafe { claim.__bindgen_anon_1.bool_data }),
            token_raw::claim_data_type_CLAIM_BSTR =>
                print_byte_string(claim.title, claim.key,
                                  unsafe { claim.__bindgen_anon_1.buffer_data }),
            token_raw::claim_data_type_CLAIM_TEXT =>
                print_text(claim.title, claim.key,
                           unsafe { claim.__bindgen_anon_1.buffer_data }),
            _ => println!("* Internal error, print_claim, Key: {}, Title: {}",
                          claim.key, cstr_to_str(claim.title)),
        }
    } else {
        let mandatory = if claim.mandatory { "mandatory " } else { "" };
        println!("* Missing {}claim with key: {} ({})",
                 mandatory, claim.key, cstr_to_str(claim.title));
    }
}

fn print_cose_sign1_wrapper(token_type: &str,
                            cose_sign1_wrapper: &[token_raw::claim_t])
{
    println!("== {} Token cose header:", token_type);
    print_claim(&cose_sign1_wrapper[0], 0);
	/* Don't print wrapped token bytestring */
    print_claim(&cose_sign1_wrapper[2], 0);
    println!("== End of {} Token cose header\n", token_type);
}

pub(crate) fn print_token_rust(claims: &token_raw::attestation_claims)
{
    print_cose_sign1_wrapper("Realm", &claims.realm_cose_sign1_wrapper);

    println!("== Realm Token:");
    for token in &claims.realm_token_claims {
        print_claim(token, 0);
    }
    println!("{:COLUMN$} (#{})", "Realm measurements", token_raw::CCA_REALM_EXTENSIBLE_MEASUREMENTS);
    for claim in &claims.realm_measurement_claims {
        print_claim(claim, 1);
    }
    println!("== End of Realm Token.\n\n");

    print_cose_sign1_wrapper("Platform", &claims.plat_cose_sign1_wrapper);

    println!("== Platform Token:");
    for claim in &claims.plat_token_claims {
        print_claim(claim, 0);
    }
    println!("== End of Platform Token\n");

    let mut count = 0;
    println!("== Platform Token SW components:");
    for component in &claims.sw_component_claims {
        if component.present {
            println!("  SW component #{}:", count);
            for claim in &component.claims {
                print_claim(&claim, 2)
            }
            count += 1;
        }
    }
	println!("== End of Platform Token SW components\n\n");
}
