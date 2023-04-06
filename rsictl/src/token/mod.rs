pub(crate) mod dumper;
pub(crate) mod verifier;


use ciborium::de;
use coset::CoseSign1;
use std::fmt::Debug;
use std::default::Default;


const TAG_COSE_SIGN1: u64 =                             18;
const TAG_CCA_TOKEN: u64 =                             399;

const CCA_PLAT_TOKEN: u32 =                          44234;
const CCA_REALM_DELEGATED_TOKEN: u32 =               44241;

/* CCA Platform Attestation Token */
const CCA_PLAT_CHALLENGE: u32 =                         10;
const CCA_PLAT_INSTANCE_ID: u32 =                      256;
const CCA_PLAT_PROFILE: u32 =                          265;
const CCA_PLAT_SECURITY_LIFECYCLE: u32 =              2395;
const CCA_PLAT_IMPLEMENTATION_ID: u32 =               2396;
const CCA_PLAT_SW_COMPONENTS: u32 =                   2399;
const CCA_PLAT_VERIFICATION_SERVICE: u32 =            2400;
const CCA_PLAT_CONFIGURATION: u32 =                   2401;
const CCA_PLAT_HASH_ALGO_ID: u32 =                    2402;

/* CCA Realm Delegated Attestation Token */
const CCA_REALM_CHALLENGE: u32 =                        10;
const CCA_REALM_PERSONALIZATION_VALUE: u32 =         44235;
const CCA_REALM_HASH_ALGO_ID: u32 =                  44236;
const CCA_REALM_PUB_KEY: u32 =                       44237;
const CCA_REALM_INITIAL_MEASUREMENT: u32 =           44238;
const CCA_REALM_EXTENSIBLE_MEASUREMENTS: u32 =       44239;
const CCA_REALM_PUB_KEY_HASH_ALGO_ID: u32 =          44240;

/* Software components */
const CCA_SW_COMP_TITLE: u32 =                           1;
const CCA_SW_COMP_MEASUREMENT_VALUE: u32 =               2;
const CCA_SW_COMP_VERSION: u32 =                         4;
const CCA_SW_COMP_SIGNER_ID: u32 =                       5;
const CCA_SW_COMP_HASH_ALGORITHM: u32 =                  6;

/* Counts */
const CLAIM_COUNT_REALM_TOKEN: usize =                   6;
const CLAIM_COUNT_COSE_SIGN1_WRAPPER: usize =            3;
const CLAIM_COUNT_PLATFORM_TOKEN: usize =                8;
const CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS: usize = 4;
const CLAIM_COUNT_SW_COMPONENT: usize =                  5;
const MAX_SW_COMPONENT_COUNT: usize =                   32;


#[derive(Debug)]
pub(crate) enum ClaimData
{
    Bool(bool),
    Int64(i64),
    Bstr(Vec<u8>),
    Text(String),
}

#[allow(dead_code)]
impl ClaimData
{
    fn get_bool(&self) -> bool
    {
        if let ClaimData::Bool(b) = self {
            return *b;
        } else {
            panic!("ClaimData is not Bool");
        }
    }
    fn get_int64(&self) -> i64
    {
        if let ClaimData::Int64(i) = self {
            return *i;
        } else {
            panic!("ClaimData is not Int64");
        }
    }
    fn get_bstr(&self) -> &[u8]
    {
        if let ClaimData::Bstr(d) = self {
            return d;
        } else {
            panic!("ClaimData is not Bstr");
        }
    }
    fn get_text(&self) -> &str
    {
        if let ClaimData::Text(s) = self {
            return s;
        } else {
            panic!("ClaimData is not Text");
        }
    }
}

impl Default for ClaimData
{
    fn default() -> Self
    {
        Self::Bool(false)
    }
}

#[derive(Debug, Default)]
pub(crate) struct Claim
{
    pub mandatory: bool,
    pub key: i64,
    pub title: String,
    pub present: bool,
    pub data: ClaimData,
}

#[derive(Debug, Default)]
pub(crate) struct SwComponent
{
    pub present: bool,
    pub claims: [Claim; CLAIM_COUNT_SW_COMPONENT],
}

#[derive(Debug, Default)]
pub(crate) struct AttestationClaims
{
    pub realm_cose_sign1_wrapper: [Claim; CLAIM_COUNT_COSE_SIGN1_WRAPPER],
    pub realm_cose_sign1: CoseSign1,
    pub realm_token_claims: [Claim; CLAIM_COUNT_REALM_TOKEN],
    pub realm_measurement_claims: [Claim; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS],
    pub plat_cose_sign1_wrapper: [Claim; CLAIM_COUNT_COSE_SIGN1_WRAPPER],
    pub plat_cose_sign1: CoseSign1,
    pub plat_token_claims: [Claim; CLAIM_COUNT_PLATFORM_TOKEN],
    pub sw_component_claims: [SwComponent; MAX_SW_COMPONENT_COUNT],
}

#[derive(Debug)]
pub(crate) enum TokenError
{
    InitError,
    MissingMandatoryClaim,
    InvalidTag,
    InvalidClaimLen,
    InvalidTokenFormat(&'static str),
    InternalError,
    Ciborium(de::Error<std::io::Error>),
    Coset(coset::CoseError),
    Ecdsa(ecdsa::Error),
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
            3 => TokenError::InvalidTag,
            4 => TokenError::InvalidClaimLen,
            _ => TokenError::InternalError,
        }
    }
}

impl From<de::Error<std::io::Error>> for TokenError
{
    fn from(value: de::Error<std::io::Error>) -> Self {
        Self::Ciborium(value)
    }
}

impl From<coset::CoseError> for TokenError
{
    fn from(value: coset::CoseError) -> Self {
        Self::Coset(value)
    }
}

impl From<ecdsa::Error> for TokenError
{
    fn from(value: ecdsa::Error) -> Self {
        Self::Ecdsa(value)
    }
}
