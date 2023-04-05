use ciborium::{de, value::Value};
use super::*;


fn init_claim(claim: &mut Claim, mandatory: bool, data: ClaimData,
              key: i64, title: &str, present: bool)
{
    claim.mandatory = mandatory;
    claim.data = data;
    claim.key = key;
    claim.title = title.to_string();
    claim.present = present;
}

fn init_cose_wrapper_claim(wrapper: &mut [Claim; CLAIM_COUNT_COSE_SIGN1_WRAPPER])
{
    init_claim(&mut wrapper[0], true, ClaimData::Bstr(Vec::new()), 0, "Protected header",       false);
    init_claim(&mut wrapper[1], true, ClaimData::Bstr(Vec::new()), 0, "Platform token payload", false);
    init_claim(&mut wrapper[2], true, ClaimData::Bstr(Vec::new()), 0, "Signature",              false);
}

fn init_claims(claims: &mut AttestationClaims)
{
    init_cose_wrapper_claim(&mut claims.realm_cose_sign1_wrapper);

    init_claim(&mut claims.realm_token_claims[0], true, ClaimData::Bstr(Vec::new()),    CCA_REALM_CHALLENGE.into(),             "Realm challenge",               false);
    init_claim(&mut claims.realm_token_claims[1], true, ClaimData::Bstr(Vec::new()),    CCA_REALM_PERSONALIZATION_VALUE.into(), "Realm personalization value",   false);
    init_claim(&mut claims.realm_token_claims[2], true, ClaimData::Text(String::new()), CCA_REALM_HASH_ALGO_ID.into(),          "Realm hash algo id",            false);
    init_claim(&mut claims.realm_token_claims[3], true, ClaimData::Text(String::new()), CCA_REALM_PUB_KEY_HASH_ALGO_ID.into(),  "Realm public key hash algo id", false);
    init_claim(&mut claims.realm_token_claims[4], true, ClaimData::Bstr(Vec::new()),    CCA_REALM_PUB_KEY.into(),               "Realm signing public key",      false);
    init_claim(&mut claims.realm_token_claims[5], true, ClaimData::Bstr(Vec::new()),    CCA_REALM_INITIAL_MEASUREMENT.into(),   "Realm initial measurement",     false);

    init_cose_wrapper_claim(&mut claims.plat_cose_sign1_wrapper);

    init_claim(&mut claims.plat_token_claims[0], true,  ClaimData::Bstr(Vec::new()),    CCA_PLAT_CHALLENGE.into(),            "Challange",            false);
    init_claim(&mut claims.plat_token_claims[1], false, ClaimData::Text(String::new()), CCA_PLAT_VERIFICATION_SERVICE.into(), "Verification service", false);
    init_claim(&mut claims.plat_token_claims[2], true,  ClaimData::Text(String::new()), CCA_PLAT_PROFILE.into(),              "Profile",              false);
    init_claim(&mut claims.plat_token_claims[3], true,  ClaimData::Bstr(Vec::new()),    CCA_PLAT_INSTANCE_ID.into(),          "Instance ID",          false);
    init_claim(&mut claims.plat_token_claims[4], true,  ClaimData::Bstr(Vec::new()),    CCA_PLAT_IMPLEMENTATION_ID.into(),    "Implementation ID",    false);
    init_claim(&mut claims.plat_token_claims[5], true,  ClaimData::Int64(0),            CCA_PLAT_SECURITY_LIFECYCLE.into(),   "Lifecycle",            false);
    init_claim(&mut claims.plat_token_claims[6], true,  ClaimData::Bstr(Vec::new()),    CCA_PLAT_CONFIGURATION.into(),        "Configuration",        false);
    init_claim(&mut claims.plat_token_claims[7], true,  ClaimData::Text(String::new()), CCA_PLAT_HASH_ALGO_ID.into(),         "Platform hash algo",   false);

    let mut count = 0;
    for claim in &mut claims.realm_measurement_claims {
        init_claim(claim, true, ClaimData::Bstr(Vec::new()), count, "Realm extensible measurement", false);
        count += 1;
    }

    for component in &mut claims.sw_component_claims {
        component.present = false;
        init_claim(&mut component.claims[0], true,  ClaimData::Text(String::new()), CCA_SW_COMP_TITLE.into(),             "SW Type",           false);
        init_claim(&mut component.claims[1], false, ClaimData::Text(String::new()), CCA_SW_COMP_HASH_ALGORITHM.into(),    "Hash algorithm",    false);
        init_claim(&mut component.claims[2], true,  ClaimData::Bstr(Vec::new()),    CCA_SW_COMP_MEASUREMENT_VALUE.into(), "Measurement value", false);
        init_claim(&mut component.claims[3], false, ClaimData::Text(String::new()), CCA_SW_COMP_VERSION.into(),           "Version",           false);
        init_claim(&mut component.claims[4], true,  ClaimData::Bstr(Vec::new()),    CCA_SW_COMP_SIGNER_ID.into(),         "Signer ID",         false);
    }
}

fn get_claim(val: Value, claim: &mut Claim) -> Result<(), TokenError>
{
    match (val, &claim.data) {
        (Value::Bool(b),    ClaimData::Bool(_))  => claim.data = ClaimData::Bool(b),
        (Value::Integer(i), ClaimData::Int64(_))
            => claim.data = ClaimData::Int64(
                if let Ok(i) = i.try_into() {
                    i
                } else {
                    return Err(TokenError::InvalidTokenFormat("too big int"));
                }),
        (Value::Bytes(v),   ClaimData::Bstr(_))  => claim.data = ClaimData::Bstr(v),
        (Value::Text(s),    ClaimData::Text(_))  => claim.data = ClaimData::Text(s),
         _ => return Err(TokenError::InvalidTokenFormat("wrong claim data")),
    }

    claim.present = true;

    Ok(())
}

fn unwrap_i64(val: &Value) -> Result<i64, TokenError>
{
    if let Value::Integer(i) = val {
        if let Ok(i) = (*i).try_into() {
            return Ok(i);
        }
    }

    Err(TokenError::InvalidTokenFormat("unwrap i64 failed"))
}

fn find_claim(claims: &mut [Claim], key: i64) -> Option<&mut Claim>
{
    for elem in claims {
        if elem.key == key {
            return Some(elem);
        }
    }

    None
}

fn get_claims_from_map(map: Vec<(Value, Value)>, claims: &mut [Claim])
                       -> Result<Vec<(Value, Value)>, TokenError>
{
    let mut rest = Vec::<(Value, Value)>::new();

    for (k, v) in map {
        let i = unwrap_i64(&k)?;
        let claim = find_claim(claims, i);
        if let Some(c) = claim {
            c.key = i;
            get_claim(v, c)?;
        } else {
            rest.push((k, v));
        }
    }

    // return the rest if any
    Ok(rest)
}

fn verify_realm_token(attest_claims: &mut AttestationClaims) -> Result<(), TokenError>
{
    if let ClaimData::Bstr(realm_payload) = &attest_claims.realm_cose_sign1_wrapper[1].data {
        if let Value::Map(v) = de::from_reader(&realm_payload[..])? {
            let rest = get_claims_from_map(v, &mut attest_claims.realm_token_claims)?;

            if rest.len() != 1 {
                return Err(TokenError::InvalidTokenFormat("no rems"));
            }

            let rems = rest.into_iter().next().unwrap();

            if let (Value::Integer(i), Value::Array(rems)) = rems {
                if i != CCA_REALM_EXTENSIBLE_MEASUREMENTS.into() {
                    return Err(TokenError::InvalidTokenFormat("wrong rems key"));
                }

                if rems.len() != CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
                    println!("wrong rems count");
                    return Err(TokenError::InvalidTokenFormat("wrong rems count"));
                }

                let rem_map = rems
                    .into_iter()
                    .zip(&mut attest_claims.realm_measurement_claims);

                for (rem, claim) in rem_map {
                    get_claim(rem, claim)?;
                }
            }

            return Ok(());
        }
    }

    Err(TokenError::InvalidTokenFormat("verify realm token failed"))
}

fn verify_platform_token(attest_claims: &mut AttestationClaims) -> Result<(), TokenError>
{
    if let ClaimData::Bstr(platform_payload) = &attest_claims.plat_cose_sign1_wrapper[1].data {
        if let Value::Map(v) = de::from_reader(&platform_payload[..])? {
            let rest = get_claims_from_map(v, &mut attest_claims.plat_token_claims)?;

            if rest.len() != 1 {
                return Err(TokenError::InvalidTokenFormat("no sw components"));
            }

            let sw_components = rest.into_iter().next().unwrap();

            if let (Value::Integer(i), Value::Array(sw_components)) = sw_components {
                if i != CCA_PLAT_SW_COMPONENTS.into() {
                    return Err(TokenError::InvalidTokenFormat("wrong sw components key"));
                }

                if sw_components.len() > attest_claims.sw_component_claims.len() {
                    return Err(TokenError::InvalidTokenFormat("too much sw components"));
                }

                let sw_components_map = sw_components
                    .into_iter()
                    .zip(&mut attest_claims.sw_component_claims);

                for (sw_comp, sw_comp_claim) in sw_components_map {
                    if let Value::Map(v) = sw_comp {
                        get_claims_from_map(v, &mut sw_comp_claim.claims)?;
                        sw_comp_claim.present = true;
                    } else {
                        return Err(TokenError::InvalidTokenFormat("wrong sw component format"));
                    }
                }

            }

            return Ok(());
        }
    }

    Err(TokenError::InvalidTokenFormat("verify platform token failed"))
}

fn verify_token_sign1_wrapping(buf: &[u8],
                               cose_sign1_wrapper: &mut [Claim; CLAIM_COUNT_COSE_SIGN1_WRAPPER])
                               -> Result<(), TokenError>
{
    if let Value::Tag(tag, data) = de::from_reader(buf)? {
        if let Value::Array(v) = *data {
            if tag != TAG_COSE_SIGN1 {
                return Err(TokenError::InvalidTag);
            }

            if v.len() != CLAIM_COUNT_COSE_SIGN1_WRAPPER + 1 {
                return Err(TokenError::InvalidTokenFormat("wrong cose sign1 claim count"));
            }

            let mut iter = v.into_iter();

            // Protected header
            get_claim(iter.next().unwrap(), &mut cose_sign1_wrapper[0])?;
            // Unprotected header, map, may me empty (ignored)
            iter.next().unwrap();
            // Payload
            get_claim(iter.next().unwrap(), &mut cose_sign1_wrapper[1])?;
            // Signature
            get_claim(iter.next().unwrap(), &mut cose_sign1_wrapper[2])?;

            return Ok(());
        }
    }

    Err(TokenError::InvalidTokenFormat("verify token sign1 wrapping failed"))
}

fn unpack_tuple_bytes(elem: (Value, Value), id: u32) -> Result<Vec<u8>, TokenError>
{
    if let (Value::Integer(i), Value::Bytes(v)) = elem {
        if i == id.into() {
            return Ok(v);
        }
    }

    Err(TokenError::InvalidTokenFormat("unpack vec elem failed"))
}

fn verify_cca_token(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TokenError>
{
    if let Value::Tag(tag, data) = de::from_reader(buf)? {
        if let Value::Map(v) = *data {
            if tag != TAG_CCA_TOKEN {
                return Err(TokenError::InvalidTag);
            }

            if v.len() != 2 {
                return Err(TokenError::InvalidTokenFormat("wrong realm/plat token count"));
            }

            let mut iter = v.into_iter();
            let plat = unpack_tuple_bytes(iter.next().unwrap(), CCA_PLAT_TOKEN)?;
            let realm = unpack_tuple_bytes(iter.next().unwrap(), CCA_REALM_DELEGATED_TOKEN)?;

            return Ok((plat, realm));
        }
    }

    Err(TokenError::InvalidTokenFormat("verify cca token failed"))
}

pub(crate) fn verify_token(buf: &[u8]) -> Result<AttestationClaims, TokenError>
{
    let mut attest_claims = AttestationClaims::default();
    init_claims(&mut attest_claims);

    let (platform_token, realm_token) = verify_cca_token(&buf)?;

    verify_token_sign1_wrapping(&realm_token, &mut attest_claims.realm_cose_sign1_wrapper)?;
    verify_token_sign1_wrapping(&platform_token, &mut attest_claims.plat_cose_sign1_wrapper)?;

    verify_realm_token(&mut attest_claims)?;
    verify_platform_token(&mut attest_claims)?;

    Ok(attest_claims)
}
