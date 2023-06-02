use ciborium::{de, value::Value};
use coset::{AsCborValue, CoseSign1};
use p384::ecdsa::signature::Verifier;
use sha2::{Sha256, Digest, Sha384, Sha512};
use super::*;


fn unpack_i64(val: &Value) -> Result<i64, TokenError>
{
    if let Value::Integer(i) = val {
        if let Ok(i) = (*i).try_into() {
            return Ok(i);
        }
    }

    Err(TokenError::InvalidTokenFormat("unpack i64 failed"))
}

fn unpack_map(val: Value, err: &'static str) -> Result<Vec<(Value, Value)>, TokenError>
{
    if let Value::Map(v) = val {
        Ok(v)
    } else {
        Err(TokenError::InvalidTokenFormat(err))
    }
}

fn unpack_tag(val: Value, id: u64, err: &'static str) -> Result<Value, TokenError>
{
    if let Value::Tag(tag, data) = val {
        if tag != id {
            return Err(TokenError::InvalidTag(err));
        }
        let unboxed = *data;
        Ok(unboxed)
    } else {
        Err(TokenError::InvalidTokenFormat(err))
    }
}

fn unpack_keyed_array(tupple: (Value, Value), id: u32, err: &'static str) -> Result<Vec<Value>, TokenError>
{
    if let (Value::Integer(key), Value::Array(vec)) = tupple {
        if key != id.into() {
            return Err(TokenError::InvalidKey(err));
        }
        Ok(vec)
    } else {
        Err(TokenError::InvalidTokenFormat("unpack vec elem failed"))
    }
}

fn unpack_keyed_bytes(tupple: (Value, Value), id: u32, err: &'static str) -> Result<Vec<u8>, TokenError>
{
    if let (Value::Integer(key), Value::Bytes(vec)) = tupple {
        if key != id.into() {
            return Err(TokenError::InvalidKey(err));
        }
        Ok(vec)
    } else {
        Err(TokenError::InvalidTokenFormat(err))
    }
}

fn get_claim(val: Value, claim: &mut Claim) -> Result<(), TokenError>
{
    match (val, &claim.data) {
        (Value::Bool(b),        ClaimData::Bool(_))  => claim.data = ClaimData::Bool(b),
        (i @ Value::Integer(_), ClaimData::Int64(_)) => claim.data = ClaimData::Int64(unpack_i64(&i)?),
        (Value::Bytes(v),       ClaimData::Bstr(_))  => claim.data = ClaimData::Bstr(v),
        (Value::Text(s),        ClaimData::Text(_))  => claim.data = ClaimData::Text(s),
         _ => return Err(TokenError::InvalidTokenFormat("incompatible claim data type")),
    }

    claim.present = true;

    Ok(())
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
    let mut unknown = Vec::<(Value, Value)>::new();

    for (orig_key, val) in map {
        let key = unpack_i64(&orig_key)?;
        let claim = find_claim(claims, key);
        if let Some(claim) = claim {
            claim.key = key;
            get_claim(val, claim)?;
        } else {
            unknown.push((orig_key, val));
        }
    }

    // return the rest if any
    Ok(unknown)
}

fn unpack_token_realm(token: &mut RealmToken) -> Result<(), TokenError>
{
    let realm_payload = token.cose_sign1.payload.as_ref()
        .ok_or(TokenError::InvalidTokenFormat("payload empty"))?;
    let val = de::from_reader(&realm_payload[..])?;
    let map = unpack_map(val, "realm token not a map")?;

    // main parsing
    let rest = get_claims_from_map(map, &mut token.token_claims)?;

    // there should be one element left, rems array
    if rest.len() != 1 {
        return Err(TokenError::InvalidTokenFormat("no rems"));
    }

    let rems = rest.into_iter().next().unwrap();
    let rems = unpack_keyed_array(rems, CCA_REALM_EXTENSIBLE_MEASUREMENTS, "rems array")?;

    if rems.len() != CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
        return Err(TokenError::InvalidTokenFormat("wrong rems count"));
    }

    // zip rems (Value) and claims (Claim) to easily iterate together
    let rem_map = rems
        .into_iter()
        .zip(&mut token.measurement_claims);

    for (rem, claim) in rem_map {
        get_claim(rem, claim)?;
    }

    Ok(())
}

fn unpack_token_platform(token: &mut PlatformToken) -> Result<(), TokenError>
{
    let platform_payload = token.cose_sign1.payload.as_ref()
        .ok_or(TokenError::InvalidTokenFormat("payload empty"))?;
    let val = de::from_reader(&platform_payload[..])?;
    let map = unpack_map(val, "platform token not a map")?;

    // main parsing
    let rest = get_claims_from_map(map, &mut token.token_claims)?;

    // there should be one element left, sw components array
    if rest.len() != 1 {
        return Err(TokenError::InvalidTokenFormat("no sw components"));
    }

    let sw_components = rest.into_iter().next().unwrap();
    let sw_components = unpack_keyed_array(sw_components, CCA_PLAT_SW_COMPONENTS, "sw components array")?;

    if sw_components.len() > token.sw_component_claims.len() {
        return Err(TokenError::InvalidTokenFormat("too much sw components"));
    }

    // zip components (Value) and claims (SwComponent) to easily iterate together
    let sw_components_zipped = sw_components
        .into_iter()
        .zip(&mut token.sw_component_claims);

    for (sw_comp, sw_comp_claim) in sw_components_zipped {
        let map = unpack_map(sw_comp, "sw component not a map")?;
        let rest = get_claims_from_map(map, &mut sw_comp_claim.claims)?;
        if rest.len() != 0 {
            return Err(TokenError::InvalidTokenFormat("sw component contains unrecognized claims"));
        }
        sw_comp_claim.present = true;
    }

    Ok(())
}

fn verify_token_sign1(buf: &[u8], cose_sign1: &mut CoseSign1) -> Result<(), TokenError>
{
    let val = de::from_reader(buf)?;
    let data = unpack_tag(val, TAG_COSE_SIGN1, "cose sign1 tag")?;

    // unpack with CoseSign1 for the purpose of coset verification
    *cose_sign1 = CoseSign1::from_cbor_value(data.clone())?;

    Ok(())
}

fn unpack_cca_token(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TokenError>
{
    let val = de::from_reader(buf)?;
    let data = unpack_tag(val, TAG_CCA_TOKEN, "cca token tag")?;
    let map = unpack_map(data, "cca token not a map")?;

    if map.len() != 2 {
        return Err(TokenError::InvalidTokenFormat("wrong realm/plat token count"));
    }

    let mut iter = map.into_iter();
    let platform = unpack_keyed_bytes(iter.next().unwrap(), CCA_PLAT_TOKEN, "platform token bytes")?;
    let realm = unpack_keyed_bytes(iter.next().unwrap(), CCA_REALM_DELEGATED_TOKEN, "realm token bytes")?;

    Ok((platform, realm))
}

pub fn verify_token_realm(buf: &[u8]) -> Result<RealmToken, TokenError>
{
    let mut token = RealmToken::new();

    verify_token_sign1(buf, &mut token.cose_sign1)?;

    unpack_token_realm(&mut token)?;

    let realm_key = token.token_claims[4].data.get_bstr();
    verify_coset_signature(&token.cose_sign1, realm_key, b"")?;

    Ok(token)
}

pub fn verify_token_platform(buf: &[u8], key: Option<&[u8]>) -> Result<PlatformToken, TokenError>
{
    let mut token = PlatformToken::new();

    verify_token_sign1(buf, &mut token.cose_sign1)?;

    unpack_token_platform(&mut token)?;

    if let Some(platform_key) = key {
        verify_coset_signature(&token.cose_sign1, platform_key, b"")?;
    }

    Ok(token)
}

pub fn verify_token(buf: &[u8]) -> Result<AttestationClaims, TokenError>
{
    let (platform_token, realm_token) = unpack_cca_token(buf)?;

    let realm_token = verify_token_realm(&realm_token)?;
    let platform_token = verify_token_platform(&platform_token, None)?;

    let dak_pub = realm_token.token_claims[4].data.get_bstr();
    let challenge = platform_token.token_claims[0].data.get_bstr();
    let alg = realm_token.token_claims[3].data.get_text();
    verify_platform_challenge(dak_pub, challenge, alg)?;

    let attest_claims = AttestationClaims::new(realm_token, platform_token);

    Ok(attest_claims)
}

// RustCrypto verifier

fn verify_platform_challenge(dak_pub: &[u8], dak_pub_hash: &[u8], alg: &str) -> Result<(), TokenError>
{
    let digest = match alg {
        "sha-256" => {
            let mut hasher = Sha256::new();
            hasher.update(dak_pub);
            hasher.finalize().to_vec()
        },
        "sha-384" => {
            let mut hasher = Sha384::new();
            hasher.update(dak_pub);
            hasher.finalize().to_vec()
        },
        "sha-512" => {
            let mut hasher = Sha512::new();
            hasher.update(dak_pub);
            hasher.finalize().to_vec()
        },
        _ => {
            return Err(TokenError::InvalidTokenFormat("invalid hash algorithm"));
        }
    };

    if digest != dak_pub_hash {
        return Err(TokenError::InvalidTokenFormat("challenge verification failed"));
    }

    Ok(())
}

fn verify_coset_signature(cose: &CoseSign1, key: &[u8], aad: &[u8]) -> Result<(), TokenError>
{
    if cose.protected.header.alg.is_none() {
        return Err(TokenError::InvalidAlgorithm(None));
    }
    let alg = cose.protected.header.alg.as_ref().unwrap().clone().try_into()?;
    let verifier = RustCryptoVerifier::new(alg, &key);
    cose.verify_signature(aad, |sig, data| verifier.verify(sig, data))
}

enum SigningAlgorithm
{
    // sha256 + secp256r1/prime256v1/P-256
    ES256,
    // sha384 + secp384r1/P-384
    ES384,
    // sha512 + secp521r1/P-521
    ES512,
}

impl TryFrom<coset::Algorithm> for SigningAlgorithm
{
    type Error = TokenError;

    fn try_from(alg: coset::Algorithm) -> Result<Self, Self::Error>
    {
        match alg {
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => Ok(SigningAlgorithm::ES256),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES384) => Ok(SigningAlgorithm::ES384),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES512) => Ok(SigningAlgorithm::ES512),
            unknown => Err(TokenError::InvalidAlgorithm(Some(unknown))),
        }
    }
}

struct RustCryptoVerifier
{
    algorithm: SigningAlgorithm,
    key_public_raw: Vec<u8>,
}

impl RustCryptoVerifier
{
    fn new(algorithm: SigningAlgorithm, key_public: &[u8]) -> Self
    {
        Self {
            algorithm,
            key_public_raw: key_public.to_vec(),
        }
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), TokenError>
    {
        match self.algorithm {
            SigningAlgorithm::ES256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_public_raw)?;
                let sig = p256::ecdsa::Signature::from_slice(sig)?;
                key.verify(data, &sig)?;
            },
            SigningAlgorithm::ES384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&self.key_public_raw)?;
                let sig = p384::ecdsa::Signature::from_slice(sig)?;
                key.verify(data, &sig)?;
            },
            SigningAlgorithm::ES512 => {
                // p521 from RustCrypto cannot do ecdsa
                return Err(TokenError::NotImplemented("p521 ecdsa"));
            },
        }
        Ok(())
    }
}
