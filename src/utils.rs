use std::fs;
use std::str::FromStr;

use tss_esapi::constants::algorithm::HashingAlgorithm;
use tss_esapi::constants::tss as tss_constants;
use tss_esapi::tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER};
use tss_esapi::Context;
use tss_esapi::Tcti;

use serde::Deserialize;

use super::PinError;

use tpm2_policy::{PublicKey, SignedPolicyList, TPMPolicyStep};

pub(crate) fn get_authorized_policy_step(
    policy_pubkey_path: &str,
    policy_path: &Option<String>,
    policy_ref: &Option<String>,
) -> Result<TPMPolicyStep, PinError> {
    let policy_ref = match policy_ref {
        Some(policy_ref) => policy_ref.as_bytes().to_vec(),
        None => vec![],
    };

    let signkey = {
        let contents = fs::read_to_string(policy_pubkey_path)?;
        serde_json::from_str::<PublicKey>(&contents)?
    };

    let policies = match policy_path {
        None => None,
        Some(policy_path) => {
            let contents = fs::read_to_string(policy_path)?;
            Some(serde_json::from_str::<SignedPolicyList>(&contents)?)
        }
    };

    Ok(TPMPolicyStep::Authorized {
        signkey,
        policy_ref,
        policies,
        next: Box::new(TPMPolicyStep::NoStep),
    })
}

pub(crate) fn get_pcr_hash_alg_from_name(name: Option<&String>) -> HashingAlgorithm {
    match name {
        None => HashingAlgorithm::Sha256,
        Some(val) => match val.to_lowercase().as_str() {
            "sha1" => HashingAlgorithm::Sha1,
            "sha256" => HashingAlgorithm::Sha256,
            "sha384" => HashingAlgorithm::Sha384,
            "sha512" => HashingAlgorithm::Sha512,
            _ => panic!(format!("Unsupported hash algo: {:?}", name)),
        },
    }
}

pub(crate) fn serialize_as_base64_url_no_pad<S>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
}

pub(crate) fn deserialize_as_base64_url_no_pad<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        base64::decode_config(&string, base64::URL_SAFE_NO_PAD).map_err(serde::de::Error::custom)
    })
}

pub(crate) fn get_tpm2_ctx() -> Result<tss_esapi::Context, tss_esapi::Error> {
    let tcti_path = if std::path::Path::new("/dev/tpmrm0").exists() {
        "device:/dev/tpmrm0"
    } else {
        "device:/dev/tpm0"
    };

    let tcti = Tcti::from_str(tcti_path)?;
    unsafe { Context::new(tcti) }
}

pub(crate) fn perform_with_other_sessions<T, E, F>(
    ctx: &mut Context,
    sestype: tss_esapi::tss2_esys::TPM2_SE,
    f: F,
) -> Result<T, E>
where
    F: Fn(&mut Context) -> Result<T, E>,
    E: From<tss_esapi::Error> + From<PinError>,
{
    let oldses = ctx.sessions();

    let res = create_and_set_tpm2_session(ctx, sestype);
    if res.is_err() {
        ctx.set_sessions(oldses);
        ctx.flush_context(ctx.sessions().0)?;
        res?;
    }

    let res = f(ctx);

    ctx.flush_context(ctx.sessions().0)?;

    ctx.set_sessions(oldses);

    res
}

pub(crate) fn get_tpm2_primary_key(
    ctx: &mut Context,
    pub_template: &tss_esapi::tss2_esys::TPM2B_PUBLIC,
) -> Result<ESYS_TR, PinError> {
    perform_with_other_sessions(ctx, tss_constants::TPM2_SE_HMAC, |ctx| {
        ctx.create_primary_key(ESYS_TR_RH_OWNER, pub_template, None, None, None, &[])
            .map_err(|e| e.into())
    })
}

pub(crate) fn create_and_set_tpm2_session(
    ctx: &mut tss_esapi::Context,
    session_type: tss_esapi::tss2_esys::TPM2_SE,
) -> Result<ESYS_TR, PinError> {
    let symdef = tpm_sym_def(ctx)?;

    let session = ctx.start_auth_session(
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        None,
        session_type,
        symdef,
        tss_constants::TPM2_ALG_SHA256,
    )?;
    let session_attr = tss_esapi::utils::TpmaSessionBuilder::new()
        .with_flag(tss_constants::TPMA_SESSION_DECRYPT)
        .with_flag(tss_constants::TPMA_SESSION_ENCRYPT)
        .build();

    ctx.tr_sess_set_attributes(session, session_attr)?;

    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));

    Ok(session)
}

fn tpm_sym_def(
    _ctx: &mut tss_esapi::Context,
) -> Result<tss_esapi::tss2_esys::TPMT_SYM_DEF, PinError> {
    Ok(tss_esapi::tss2_esys::TPMT_SYM_DEF {
        algorithm: tss_constants::TPM2_ALG_AES,
        keyBits: tss_esapi::tss2_esys::TPMU_SYM_KEY_BITS { aes: 128 },
        mode: tss_esapi::tss2_esys::TPMU_SYM_MODE {
            aes: tss_constants::TPM2_ALG_CFB,
        },
    })
}
