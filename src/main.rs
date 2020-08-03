// Copyright 2020 Patrick Uiterwijk
//
// Licensed under the EUPL-1.2-or-later
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::convert::{TryFrom, TryInto};
use std::error::Error;
use std::fmt;
use std::fs;

extern crate atty;
extern crate base64;
extern crate biscuit;
extern crate serde;
extern crate serde_json;
extern crate tss_esapi;

use std::env;
use std::io::{self, Read, Write};

use biscuit::jwe;
use biscuit::CompactJson;

use tss_esapi::constants;
use tss_esapi::tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_OWNER};
use tss_esapi::utils;
use tss_esapi::utils::tcti;
use tss_esapi::Context;

use serde::{Deserialize, Serialize};

pub fn serialize_as_base64_url_no_pad<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
}

pub fn deserialize_as_base64_url_no_pad<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        base64::decode_config(&string, base64::URL_SAFE_NO_PAD).map_err(serde::de::Error::custom)
    })
}

pub fn serialize_as_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

pub fn deserialize_as_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|string| base64::decode(&string).map_err(serde::de::Error::custom))
}

fn tpm_sym_def(_ctx: &mut tss_esapi::Context) -> Result<tss_esapi::tss2_esys::TPMT_SYM_DEF, PinError> {
    Ok(tss_esapi::tss2_esys::TPMT_SYM_DEF {
        algorithm: tss_esapi::constants::TPM2_ALG_AES,
        keyBits: tss_esapi::tss2_esys::TPMU_SYM_KEY_BITS { aes: 128 },
        mode: tss_esapi::tss2_esys::TPMU_SYM_MODE { aes: tss_esapi::constants::TPM2_ALG_CFB },
    })
}

#[derive(Debug)]
enum PinError {
    Text(&'static str),
    NoCommand,
    Serde(serde_json::Error),
    IO(std::io::Error),
    TPM(tss_esapi::response_code::Error),
    JWE(biscuit::errors::Error),
    Base64Decoding(base64::DecodeError),
    Utf8(std::str::Utf8Error),
}

impl PinError {}

impl fmt::Display for PinError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PinError::Text(e) => write!(f, "Error: {}", e),
            PinError::Serde(err) => {
                write!(f, "Serde error: ")?;
                err.fmt(f)
            }
            PinError::IO(err) => {
                write!(f, "IO error: ")?;
                err.fmt(f)
            }
            PinError::TPM(err) => {
                write!(f, "TPM error: ")?;
                err.fmt(f)
            }
            PinError::JWE(err) => {
                write!(f, "JWE error: ")?;
                err.fmt(f)
            }
            PinError::Base64Decoding(err) => {
                write!(f, "Base64 Decoding error: ")?;
                err.fmt(f)
            }
            PinError::Utf8(err) => {
                write!(f, "UTF8 error: ")?;
                err.fmt(f)
            }
            PinError::NoCommand => write!(f, "No command provided"),
        }
    }
}

impl Error for PinError {}

impl From<&'static str> for PinError {
    fn from(err: &'static str) -> Self {
        PinError::Text(err)
    }
}

impl From<serde_json::Error> for PinError {
    fn from(err: serde_json::Error) -> Self {
        PinError::Serde(err)
    }
}

impl From<std::io::Error> for PinError {
    fn from(err: std::io::Error) -> Self {
        PinError::IO(err)
    }
}

impl From<tss_esapi::response_code::Error> for PinError {
    fn from(err: tss_esapi::response_code::Error) -> Self {
        PinError::TPM(err)
    }
}

impl From<biscuit::errors::Error> for PinError {
    fn from(err: biscuit::errors::Error) -> Self {
        PinError::JWE(err)
    }
}

impl From<base64::DecodeError> for PinError {
    fn from(err: base64::DecodeError) -> Self {
        PinError::Base64Decoding(err)
    }
}

impl From<std::str::Utf8Error> for PinError {
    fn from(err: std::str::Utf8Error) -> Self {
        PinError::Utf8(err)
    }
}

#[derive(Debug)]
enum TPMPolicyStep {
    NoStep,
    PCRs(
        tss_esapi::utils::algorithm_specifiers::HashingAlgorithm,
        Vec<u64>,
        Box<TPMPolicyStep>,
    ),
    Authorized {
        signkey: PublicKey,
        policy_ref: Vec<u8>,
        policies: Option<SignedPolicyList>,
        next: Box<TPMPolicyStep>,
    },
    Or([Box<TPMPolicyStep>; 8]),
}

fn create_and_set_tpm2_session(
    ctx: &mut tss_esapi::Context,
    session_type: tss_esapi::tss2_esys::TPM2_SE,
) -> Result<ESYS_TR, PinError> {
    let symdef = tpm_sym_def(ctx)?;

    let session = ctx.start_auth_session(
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &[],
        session_type,
        symdef,
        tss_esapi::constants::TPM2_ALG_SHA256,
    )?;
    let session_attr = utils::TpmaSessionBuilder::new()
        .with_flag(tss_esapi::constants::TPMA_SESSION_DECRYPT)
        .with_flag(tss_esapi::constants::TPMA_SESSION_ENCRYPT)
        .build();

    ctx.tr_sess_set_attributes(session, session_attr)?;

    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));

    Ok(session)
}

impl TPMPolicyStep {
    /// Sends the generate policy to the TPM2, and sets the authorized policy as active
    /// Returns the policy_digest for authInfo
    fn send_policy(
        self,
        ctx: &mut tss_esapi::Context,
        trial_policy: bool,
    ) -> Result<Option<tss_esapi::utils::Digest>, PinError> {
        let pol_type = if trial_policy {
            tss_esapi::constants::TPM2_SE_TRIAL
        } else {
            tss_esapi::constants::TPM2_SE_POLICY
        };

        let symdef = tpm_sym_def(ctx)?;

        let session = ctx.start_auth_session(
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &[],
            pol_type,
            symdef,
            tss_esapi::constants::TPM2_ALG_SHA256,
        )?;
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(tss_esapi::constants::TPMA_SESSION_DECRYPT)
            .with_flag(tss_esapi::constants::TPMA_SESSION_ENCRYPT)
            .build();
        ctx.tr_sess_set_attributes(session, session_attr)?;

        match self {
            TPMPolicyStep::NoStep => {
                create_and_set_tpm2_session(ctx, tss_esapi::constants::TPM2_SE_HMAC)?;
                Ok(None)
            }
            _ => {
                self._send_policy(ctx, session)?;

                let pol_digest = ctx.policy_get_digest(session)?;

                if trial_policy {
                    create_and_set_tpm2_session(ctx, tss_esapi::constants::TPM2_SE_HMAC)?;
                } else {
                    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));
                }
                Ok(Some(pol_digest))
            }
        }
    }

    fn _send_policy(
        self,
        ctx: &mut tss_esapi::Context,
        policy_session: tss_esapi::tss2_esys::ESYS_TR,
    ) -> Result<(), PinError> {
        match self {
            TPMPolicyStep::NoStep => Ok(()),

            TPMPolicyStep::PCRs(pcr_hash_alg, pcr_ids, next) => {
                let pcr_ids: Result<Vec<tss_esapi::utils::PcrSlot>, PinError> =
                    pcr_ids.iter().map(|x| pcr_id_to_slot(x)).collect();
                let pcr_ids: Vec<tss_esapi::utils::PcrSlot> = pcr_ids?;

                let pcr_sel = tss_esapi::utils::PcrSelectionsBuilder::new()
                    .with_selection(pcr_hash_alg, &pcr_ids)
                    .build();

                // Ensure PCR reading occurs with no sessions (we don't use audit sessions)
                let old_ses = ctx.sessions();
                ctx.set_sessions((ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE));
                let (_update_counter, pcr_sel, pcr_data) = ctx.pcr_read(pcr_sel)?;
                ctx.set_sessions(old_ses);

                let concatenated_pcr_values: Vec<&[u8]> = pcr_ids
                    .iter()
                    .map(|x| {
                        pcr_data
                            .pcr_bank(pcr_hash_alg)
                            .unwrap()
                            .pcr_value(*x)
                            .unwrap()
                            .value()
                    })
                    .collect();
                let concatenated_pcr_values = concatenated_pcr_values.as_slice().concat();

                let (hashed_data, _ticket) = ctx.hash(
                    &concatenated_pcr_values,
                    tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
                    tss_esapi::utils::Hierarchy::Owner,
                )?;

                ctx.policy_pcr(policy_session, &hashed_data, pcr_sel)?;
                next._send_policy(ctx, policy_session)
            }

            TPMPolicyStep::Authorized {
                signkey,
                policy_ref,
                policies,
                next,
            } => {
                let policy_ref = tss_esapi::utils::Digest::try_from(policy_ref)?;

                let tpm_signkey = tss_esapi::tss2_esys::TPM2B_PUBLIC::try_from(&signkey)?;
                let loaded_key =
                    ctx.load_external_public(&tpm_signkey, tss_esapi::utils::Hierarchy::Owner)?;
                let loaded_key_name = ctx.tr_get_name(loaded_key)?;

                let (approved_policy, check_ticket) = match policies {
                    None => {
                        /* Some TPMs don't seem to like the Null ticket.. Let's just use a dummy
                        let null_ticket = tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
                            tag: tss_esapi::constants::TPM2_ST_VERIFIED,
                            hierarchy: tss_esapi::tss2_esys::ESYS_TR_RH_NULL,
                            digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
                                size: 32,
                                buffer: [0; 64],
                            },
                        };
                        */
                        let dummy_ticket = get_dummy_ticket(ctx);
                        (tss_esapi::utils::Digest::try_from(vec![])?, dummy_ticket)
                    }
                    Some(policies) => find_and_play_applicable_policy(
                        ctx,
                        &policies,
                        policy_session,
                        policy_ref.value(),
                        signkey.get_signing_scheme(),
                        loaded_key,
                    )?,
                };

                ctx.policy_authorize(
                    policy_session,
                    approved_policy,
                    tss_esapi::tss2_esys::TPM2B_DIGEST::try_from(policy_ref)?,
                    loaded_key_name,
                    check_ticket,
                )?;

                next._send_policy(ctx, policy_session)
            }

            _ => Err(PinError::Text("Policy not implemented")),
        }
    }
}

fn find_and_play_applicable_policy(
    ctx: &mut tss_esapi::Context,
    policies: &[SignedPolicy],
    policy_session: ESYS_TR,
    policy_ref: &[u8],
    scheme: utils::AsymSchemeUnion,
    loaded_key: ESYS_TR,
) -> Result<
    (
        tss_esapi::utils::Digest,
        tss_esapi::tss2_esys::TPMT_TK_VERIFIED,
    ),
    PinError,
> {
    for policy in policies {
        if policy.policy_ref != policy_ref {
            continue;
        }

        if let Some(policy_digest) = play_policy(ctx, &policy, policy_session)? {
            // aHash ≔ H_{aHashAlg}(approvedPolicy || policyRef)
            let mut ahash = Vec::new();
            ahash.write_all(&policy_digest)?;
            ahash.write_all(&policy_ref)?;

            let ahash = ctx
                .hash(
                    &ahash,
                    tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
                    tss_esapi::utils::Hierarchy::Null,
                )?
                .0;
            let signature = tss_esapi::utils::Signature {
                scheme,
                signature: tss_esapi::utils::SignatureData::RsaSignature(policy.signature.clone()),
            };
            let tkt = ctx.verify_signature(loaded_key, &ahash, &signature.try_into()?)?;

            return Ok((policy_digest, tkt));
        }
    }

    Err(PinError::Text("No matching authorized policy found"))
}

// This function would do a simple check whether the policy has a chance for success.
// It does explicitly not change policy_session
fn check_policy_feasibility(_ctx: &mut tss_esapi::Context, _policy: &SignedPolicy) -> Result<bool,PinError> {
    Ok(true)
    // TODO: Implement this, to check whether the PCRs in this branch would match
}

fn play_policy(
    ctx: &mut tss_esapi::Context,
    policy: &SignedPolicy,
    policy_session: ESYS_TR,
) -> Result<Option<tss_esapi::utils::Digest>, PinError> {
    if !check_policy_feasibility(ctx, policy)? {
        return Ok(None)
    }

    for step in &policy.steps {
        let tpmstep = TPMPolicyStep::try_from(step)?;
        tpmstep._send_policy(ctx, policy_session)?;
    }

    Ok(Some(ctx.policy_get_digest(policy_session)?))
}

// It turns out that a Null ticket does not work for some TPMs, so let's just generate
// a dummy ticket. This is a valid ticket, but over a totally useless piece of data.
fn get_dummy_ticket(context: &mut tss_esapi::Context) -> tss_esapi::tss2_esys::TPMT_TK_VERIFIED {
    let old_ses = context.sessions();
    context.set_sessions((ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE));
    create_and_set_tpm2_session(context, tss_esapi::constants::TPM2_SE_HMAC).unwrap();

    let signing_key_pub = utils::create_unrestricted_signing_rsa_public(
        tss_esapi::utils::AsymSchemeUnion::RSASSA(
            tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
        ),
        2048,
        0,
    )
    .unwrap();

    let key_handle = context
        .create_primary_key(ESYS_TR_RH_OWNER, &signing_key_pub, &[], &[], &[], &[])
        .unwrap();
    let ahash = context
        .hash(
            &[0x1, 0x2],
            tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
            tss_esapi::utils::Hierarchy::Null,
        )
        .unwrap()
        .0;

    let scheme = tss_esapi::tss2_esys::TPMT_SIG_SCHEME {
        scheme: tss_esapi::constants::TPM2_ALG_NULL,
        details: Default::default(),
    };
    let validation = tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
        tag: tss_esapi::constants::TPM2_ST_HASHCHECK,
        hierarchy: tss_esapi::constants::TPM2_RH_NULL,
        digest: Default::default(),
    };
    // A signature over just the policy_digest, since the policy_ref is empty
    let signature = context
        .sign(key_handle, &ahash, scheme, &validation)
        .unwrap();
    let tkt = context
        .verify_signature(key_handle, &ahash, &signature.try_into().unwrap())
        .unwrap();

    context.set_sessions(old_ses);

    tkt
}

#[derive(Serialize, Deserialize, std::fmt::Debug)]
struct TPM2Config {
    hash: Option<String>,
    key: Option<String>,
    pcr_bank: Option<String>,
    // PCR IDs can be passed in as comma-separated string or json array
    pcr_ids: Option<serde_json::Value>,
    pcr_digest: Option<String>,
    // Public key (in JSON format) for a wildcard policy that's possibly OR'd with the PCR one
    policy_pubkey_path: Option<String>,
    policy_ref: Option<String>,
    policy_path: Option<String>,
}

fn get_authorized_policy_step(
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

impl TryFrom<&SignedPolicyStep> for TPMPolicyStep {
    type Error = PinError;

    fn try_from(spolicy: &SignedPolicyStep) -> Result<Self, PinError> {
        match spolicy {
            SignedPolicyStep::PCRs{pcr_ids, hash_algorithm, value: _} => {
                Ok(TPMPolicyStep::PCRs(
                    get_pcr_hash_alg_from_name(Some(&hash_algorithm)),
                    pcr_ids.iter().map(|x| *x as u64).collect(),
                    Box::new(TPMPolicyStep::NoStep),
                ))
            },
        }
    }
}

impl TryFrom<&TPM2Config> for TPMPolicyStep {
    type Error = PinError;

    fn try_from(cfg: &TPM2Config) -> Result<Self, PinError> {
        if cfg.pcr_ids.is_some() && cfg.policy_pubkey_path.is_some() {
            Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    cfg.get_pcr_hash_alg(),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(get_authorized_policy_step(
                    cfg.policy_pubkey_path.as_ref().unwrap(),
                    &None,
                    &cfg.policy_ref,
                )?),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
            ]))
        } else if cfg.pcr_ids.is_some() {
            Ok(TPMPolicyStep::PCRs(
                cfg.get_pcr_hash_alg(),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            get_authorized_policy_step(
                cfg.policy_pubkey_path.as_ref().unwrap(),
                &None,
                &cfg.policy_ref,
            )
        } else {
            Ok(TPMPolicyStep::NoStep)
        }
    }
}

fn pcr_id_to_slot(pcr: &u64) -> Result<tss_esapi::utils::PcrSlot, PinError> {
    match pcr {
        0 => Ok(tss_esapi::utils::PcrSlot::Slot0),
        1 => Ok(tss_esapi::utils::PcrSlot::Slot1),
        2 => Ok(tss_esapi::utils::PcrSlot::Slot2),
        3 => Ok(tss_esapi::utils::PcrSlot::Slot3),
        4 => Ok(tss_esapi::utils::PcrSlot::Slot4),
        5 => Ok(tss_esapi::utils::PcrSlot::Slot5),
        6 => Ok(tss_esapi::utils::PcrSlot::Slot6),
        7 => Ok(tss_esapi::utils::PcrSlot::Slot7),
        8 => Ok(tss_esapi::utils::PcrSlot::Slot8),
        9 => Ok(tss_esapi::utils::PcrSlot::Slot9),
        10 => Ok(tss_esapi::utils::PcrSlot::Slot10),
        11 => Ok(tss_esapi::utils::PcrSlot::Slot11),
        12 => Ok(tss_esapi::utils::PcrSlot::Slot12),
        13 => Ok(tss_esapi::utils::PcrSlot::Slot13),
        14 => Ok(tss_esapi::utils::PcrSlot::Slot14),
        15 => Ok(tss_esapi::utils::PcrSlot::Slot15),
        16 => Ok(tss_esapi::utils::PcrSlot::Slot16),
        17 => Ok(tss_esapi::utils::PcrSlot::Slot17),
        18 => Ok(tss_esapi::utils::PcrSlot::Slot18),
        19 => Ok(tss_esapi::utils::PcrSlot::Slot19),
        20 => Ok(tss_esapi::utils::PcrSlot::Slot20),
        21 => Ok(tss_esapi::utils::PcrSlot::Slot21),
        22 => Ok(tss_esapi::utils::PcrSlot::Slot22),
        23 => Ok(tss_esapi::utils::PcrSlot::Slot23),
        _ => Err(PinError::Text("Invalid PCR slot requested")),
    }
}

fn get_pcr_hash_alg_from_name(
    name: Option<&String>,
) -> tss_esapi::utils::algorithm_specifiers::HashingAlgorithm {
    match name {
        None => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
        Some(val) => match val.to_lowercase().as_str() {
            "sha1" => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha1,
            "sha256" => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
            "sha384" => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha384,
            "sha512" => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha512,
            _ => panic!(format!("Unsupported hash algo: {:?}", name)),
        },
    }
}

impl TPM2Config {
    fn get_pcr_hash_alg(&self) -> tss_esapi::utils::algorithm_specifiers::HashingAlgorithm {
        get_pcr_hash_alg_from_name(self.pcr_bank.as_ref())
    }

    fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => {
                Some(vals.iter().map(|x| x.as_u64().unwrap()).collect())
            }
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    fn get_pcr_ids_str(&self) -> Option<String> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => Some(
                vals.iter()
                    .map(|x| x.as_u64().unwrap().to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            ),
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    fn normalize(mut self) -> Result<TPM2Config, PinError> {
        self.normalize_pcr_ids()?;
        if self.pcr_ids.is_some() && self.pcr_bank.is_none() {
            self.pcr_bank = Some("sha256".to_string());
        }
        if (self.policy_pubkey_path.is_some()
            || self.policy_path.is_some()
            || self.policy_ref.is_some())
            && (self.policy_pubkey_path.is_none()
                || self.policy_path.is_none()
                || self.policy_ref.is_none())
        {
            return Err(PinError::Text(
                "Not all of policy pubkey, path and ref are specified",
            ));
        }
        Ok(self)
    }

    fn normalize_pcr_ids(&mut self) -> Result<(), PinError> {
        // Normalize pcr_ids from comma-separated string to array
        if let Some(serde_json::Value::String(val)) = &self.pcr_ids {
            // Was a string, do a split
            let newval: Vec<serde_json::Value> = val
                .split(',')
                .map(|x| serde_json::Value::String(x.to_string()))
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newval));
        }
        // Normalize pcr_ids from array of Strings to array of Numbers
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            let newvals: Result<Vec<serde_json::Value>, _> = vals
                .iter()
                .map(|x| match x {
                    serde_json::Value::String(val) => match val.parse::<serde_json::Number>() {
                        Ok(res) => {
                            let new = serde_json::Value::Number(res);
                            if !new.is_u64() {
                                return Err("Non-positive string int");
                            }
                            Ok(new)
                        }
                        Err(_) => Err("Unparseable string int"),
                    },
                    serde_json::Value::Number(n) => {
                        let new = serde_json::Value::Number(n.clone());
                        if !new.is_u64() {
                            return Err("Non-positive int");
                        }
                        Ok(new)
                    }
                    _ => Err("Invalid value in pcr_ids"),
                })
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newvals?));
        }

        match &self.pcr_ids {
            None => Ok(()),
            // The normalization above would've caught any non-ints
            Some(serde_json::Value::Array(_)) => Ok(()),
            _ => Err(PinError::Text("Invalid type")),
        }
    }
}

#[derive(Debug)]
enum ActionMode {
    Encrypt,
    Decrypt,
    Summary,
    Help,
}

fn get_mode_and_cfg(args: &[String]) -> Result<(ActionMode, Option<TPM2Config>), PinError> {
    if args.len() > 1 && args[1] == "--summary" {
        return Ok((ActionMode::Summary, None))
    }
    if atty::is(atty::Stream::Stdin) {
        return Ok((ActionMode::Help, None))
    }
    let (mode, cfgstr) = if args[0].contains("encrypt") && args.len() == 2 {
        (ActionMode::Encrypt, Some(&args[1]))
    } else if args[0].contains("decrypt") {
        (ActionMode::Decrypt, None)
    } else if args.len() > 1 {
        if args[1] == "encrypt" && args.len() == 3 {
            (ActionMode::Encrypt, Some(&args[2]))
        } else if args[1] == "decrypt" {
            (ActionMode::Decrypt, None)
        } else {
            return Err(PinError::NoCommand);
        }
    } else {
        return Err(PinError::NoCommand);
    };

    let cfg: Option<TPM2Config> = match cfgstr {
        None => None,
        Some(cfgstr) => Some(serde_json::from_str::<TPM2Config>(cfgstr)?.normalize()?),
    };

    Ok((mode, cfg))
}

fn create_tpm2b_public_sealed_object(
    policy: Option<tss_esapi::utils::Digest>,
) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC, PinError> {
    let mut object_attributes = utils::ObjectAttributes(0);
    object_attributes.set_fixed_tpm(true);
    object_attributes.set_fixed_parent(true);
    object_attributes.set_no_da(true);
    object_attributes.set_admin_with_policy(true);

    if policy.is_none() {
        object_attributes.set_user_with_auth(true);
    }
    let policy = match policy {
        Some(p) => p,
        None => tss_esapi::utils::Digest::try_from(vec![])?,
    };

    let mut params: tss_esapi::tss2_esys::TPMU_PUBLIC_PARMS = Default::default();
    params.keyedHashDetail.scheme.scheme = tss_esapi::constants::TPM2_ALG_NULL;

    Ok(tss_esapi::tss2_esys::TPM2B_PUBLIC {
        size: std::mem::size_of::<tss_esapi::tss2_esys::TPMT_PUBLIC>() as u16,
        publicArea: tss_esapi::tss2_esys::TPMT_PUBLIC {
            type_: tss_esapi::constants::TPM2_ALG_KEYEDHASH,
            nameAlg: tss_esapi::constants::TPM2_ALG_SHA256,
            objectAttributes: object_attributes.0,
            authPolicy: tss_esapi::tss2_esys::TPM2B_DIGEST::try_from(policy)?,
            parameters: params,
            unique: Default::default(),
        },
    })
}

fn perform_encrypt(cfg: TPM2Config, input: &str) -> Result<(), PinError> {
    let key_type = match &cfg.key {
        None => "ecc",
        Some(key_type) => key_type,
    };
    let key_public = get_key_public(&key_type)?;

    let mut ctx = get_tpm2_ctx()?;
    let key_handle = get_tpm2_primary_key(&mut ctx, &key_public)?;

    let policy_runner: TPMPolicyStep = TPMPolicyStep::try_from(&cfg)?;

    let pin_type = match policy_runner {
        TPMPolicyStep::NoStep => "tpm2",
        TPMPolicyStep::PCRs(_, _, _) => "tpm2",
        _ => "tpm2plus",
    };

    let policy_digest = policy_runner.send_policy(&mut ctx, true)?;

    let key_bytes: Vec<u8> = ctx.get_random(32)?;
    let mut jwk = biscuit::jwk::JWK::new_octet_key(&key_bytes, biscuit::Empty {});
    jwk.common.algorithm = Some(biscuit::jwa::Algorithm::ContentEncryption(
        biscuit::jwa::ContentEncryptionAlgorithm::A256GCM,
    ));
    jwk.common.key_operations = Some(vec![
        biscuit::jwk::KeyOperations::Encrypt,
        biscuit::jwk::KeyOperations::Decrypt,
    ]);
    let jwk_str = serde_json::to_string(&jwk)?;

    let public = create_tpm2b_public_sealed_object(policy_digest)?;
    let (jwk_priv, jwk_pub) =
        ctx.create_key(key_handle, &public, &[], jwk_str.as_bytes(), &[], &[])?;

    let jwk_priv = get_tpm2b_private(jwk_priv)?;

    let jwk_pub = get_tpm2b_public(jwk_pub)?;

    let hdr: biscuit::jwe::Header<ClevisHeader> = biscuit::jwe::Header {
        registered: biscuit::jwe::RegisteredHeader {
            cek_algorithm: biscuit::jwa::KeyManagementAlgorithm::DirectSymmetricKey,
            enc_algorithm: biscuit::jwa::ContentEncryptionAlgorithm::A256GCM,
            compression_algorithm: None,
            media_type: None,
            content_type: None,
            web_key_url: None,
            web_key: None,
            key_id: None,
            x509_url: None,
            x509_chain: None,
            x509_fingerprint: None,
            critical: None,
        },
        cek_algorithm: biscuit::jwe::CekAlgorithmHeader {
            nonce: None,
            tag: None,
        },
        private: ClevisHeader {
            clevis: ClevisInner {
                pin: pin_type.to_string(),
                tpm2: Tpm2Inner {
                    hash: "sha256".to_string(),
                    key: key_type.to_string(),
                    jwk_pub,
                    jwk_priv,
                    pcr_bank: cfg.pcr_bank.clone(),
                    pcr_ids: cfg.get_pcr_ids_str(),
                    policy_pubkey_path: cfg.policy_pubkey_path,
                    policy_ref: cfg.policy_ref,
                    policy_path: cfg.policy_path,
                },
            },
        },
    };

    let rand_nonce = ctx.get_random(12)?;
    let jwe_enc_options = biscuit::jwa::EncryptionOptions::AES_GCM { nonce: rand_nonce };

    let jwe_token = biscuit::jwe::Compact::new_decrypted(hdr, input.as_bytes().to_vec());
    let jwe_token_compact = jwe_token.encrypt(&jwk, &jwe_enc_options)?;
    let encoded_token = jwe_token_compact.encrypted()?.encode();
    io::stdout().write_all(encoded_token.as_bytes())?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Tpm2Inner {
    hash: String,
    #[serde(
        deserialize_with = "deserialize_as_base64_url_no_pad",
        serialize_with = "serialize_as_base64_url_no_pad"
    )]
    jwk_priv: Vec<u8>,
    #[serde(
        deserialize_with = "deserialize_as_base64_url_no_pad",
        serialize_with = "serialize_as_base64_url_no_pad"
    )]
    jwk_pub: Vec<u8>,
    key: String,

    // PCR Binding may be specified, may not
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_bank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcr_ids: Option<String>,

    // Public key (in PEM format) for a wildcard policy that's OR'd with the PCR one
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_pubkey_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<String>,
}

impl Tpm2Inner {
    fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        Some(
            self.pcr_ids
                .as_ref()?
                .split(',')
                .map(|x| x.parse::<u64>().unwrap())
                .collect(),
        )
    }
}

impl TryFrom<&Tpm2Inner> for TPMPolicyStep {
    type Error = PinError;

    fn try_from(cfg: &Tpm2Inner) -> Result<Self, PinError> {
        if cfg.pcr_ids.is_some() && cfg.policy_pubkey_path.is_some() {
            Ok(TPMPolicyStep::Or([
                Box::new(TPMPolicyStep::PCRs(
                    get_pcr_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(get_authorized_policy_step(
                    cfg.policy_pubkey_path.as_ref().unwrap(),
                    &cfg.policy_path,
                    &cfg.policy_ref,
                )?),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
                Box::new(TPMPolicyStep::NoStep),
            ]))
        } else if cfg.pcr_ids.is_some() {
            Ok(TPMPolicyStep::PCRs(
                get_pcr_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            get_authorized_policy_step(
                cfg.policy_pubkey_path.as_ref().unwrap(),
                &cfg.policy_path,
                &cfg.policy_ref,
            )
        } else {
            Ok(TPMPolicyStep::NoStep)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ClevisInner {
    pin: String,
    tpm2: Tpm2Inner,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ClevisHeader {
    clevis: ClevisInner,
}

impl CompactJson for Tpm2Inner {}
impl CompactJson for ClevisHeader {}
impl CompactJson for ClevisInner {}

fn get_tpm2b_public(val: tss_esapi::tss2_esys::TPM2B_PUBLIC) -> Result<Vec<u8>, PinError> {
    let mut offset = 0 as u64;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as u64,
            &mut offset,
        );
        if res != 0 {
            return Err(PinError::Text("Marshalling tpm2b_public failed"));
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

fn get_tpm2b_private(val: tss_esapi::tss2_esys::TPM2B_PRIVATE) -> Result<Vec<u8>, PinError> {
    let mut offset = 0 as u64;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as u64,
            &mut offset,
        );
        if res != 0 {
            return Err(PinError::Text("Marshalling tpm2b_private failed"));
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

fn build_tpm2b_private(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PRIVATE, PinError> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PRIVATE::default();
    let mut offset = 0 as u64;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            val[..].as_ptr(),
            val.len() as u64,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            return Err(PinError::Text("Unmarshalling tpm2b_private failed"));
        }
    }

    Ok(resp)
}

fn build_tpm2b_public(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC, PinError> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PUBLIC::default();
    let mut offset = 0 as u64;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            val[..].as_ptr(),
            val.len() as u64,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            return Err(PinError::Text("Unmarshalling tpm2b_public failed"));
        }
    }

    Ok(resp)
}

fn create_restricted_ecc_public() -> tss_esapi::tss2_esys::TPM2B_PUBLIC {
    let ecc_params = utils::TpmsEccParmsBuilder::new_restricted_decryption_key(
        utils::algorithm_specifiers::Cipher::aes_128_cfb(),
        utils::algorithm_specifiers::EllipticCurve::NistP256,
    )
    .build()
    .unwrap();
    let mut object_attributes = utils::ObjectAttributes(0);
    object_attributes.set_fixed_tpm(true);
    object_attributes.set_fixed_parent(true);
    object_attributes.set_sensitive_data_origin(true);
    object_attributes.set_user_with_auth(true);
    object_attributes.set_decrypt(true);
    object_attributes.set_sign_encrypt(false);
    object_attributes.set_restricted(true);

    utils::Tpm2BPublicBuilder::new()
        .with_type(constants::TPM2_ALG_ECC)
        .with_name_alg(constants::TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(utils::PublicParmsUnion::EccDetail(ecc_params))
        .build()
        .unwrap()
}

fn get_key_public(key_type: &str) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC, PinError> {
    match key_type {
        "ecc" => Ok(create_restricted_ecc_public()),
        "rsa" => Ok(tss_esapi::utils::create_restricted_decryption_rsa_public(
            utils::algorithm_specifiers::Cipher::aes_128_cfb(),
            2048,
            0,
        )?),
        _ => Err(PinError::Text("Unsupported key type used")),
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum SignedPolicyStep {
    PCRs {
        pcr_ids: Vec<u16>,
        hash_algorithm: String,
        #[serde(
            deserialize_with = "deserialize_as_base64",
            serialize_with = "serialize_as_base64"
        )]
        value: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct SignedPolicy {
    // policy_ref contains the policy_ref used in the aHash, used to determine the policy to use from a list
    #[serde(
        deserialize_with = "deserialize_as_base64",
        serialize_with = "serialize_as_base64"
    )]
    policy_ref: Vec<u8>,
    // steps contains the policy steps that are signed
    steps: Vec<SignedPolicyStep>,
    // signature contains the signature over aHash
    #[serde(
        deserialize_with = "deserialize_as_base64",
        serialize_with = "serialize_as_base64"
    )]
    signature: Vec<u8>,
}

type SignedPolicyList = Vec<SignedPolicy>;

#[derive(Debug, Serialize, Deserialize)]
enum RSAPublicKeyScheme {
    RSAPSS,
    RSASSA,
}

impl RSAPublicKeyScheme {
    fn to_scheme(&self, hash_algo: &HashAlgo) -> tss_esapi::utils::AsymSchemeUnion {
        match self {
            RSAPublicKeyScheme::RSAPSS => {
                tss_esapi::utils::AsymSchemeUnion::RSAPSS(hash_algo.into())
            }
            RSAPublicKeyScheme::RSASSA => {
                tss_esapi::utils::AsymSchemeUnion::RSASSA(hash_algo.into())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HashAlgo {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SM3_256,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl HashAlgo {
    fn to_tpmi_alg_hash(&self) -> tss_esapi::tss2_esys::TPMI_ALG_HASH {
        let alg: tss_esapi::utils::algorithm_specifiers::HashingAlgorithm = self.into();
        alg.into()
    }
}

impl From<&HashAlgo> for tss_esapi::utils::algorithm_specifiers::HashingAlgorithm {
    fn from(halg: &HashAlgo) -> Self {
        match halg {
            HashAlgo::SHA1 => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha1,
            HashAlgo::SHA256 => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha256,
            HashAlgo::SHA384 => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha384,
            HashAlgo::SHA512 => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha512,
            HashAlgo::SM3_256 => tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sm3_256,
            HashAlgo::SHA3_256 => {
                tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha3_256
            }
            HashAlgo::SHA3_384 => {
                tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha3_384
            }
            HashAlgo::SHA3_512 => {
                tss_esapi::utils::algorithm_specifiers::HashingAlgorithm::Sha3_512
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
enum PublicKey {
    RSA {
        scheme: RSAPublicKeyScheme,
        hashing_algo: HashAlgo,
        exponent: u32,
        #[serde(
            deserialize_with = "deserialize_as_base64",
            serialize_with = "serialize_as_base64"
        )]
        modulus: Vec<u8>,
    },
}

impl PublicKey {
    fn get_signing_scheme(&self) -> tss_esapi::utils::AsymSchemeUnion {
        match self {
            PublicKey::RSA {
                scheme,
                hashing_algo,
                exponent: _,
                modulus: _,
            } => scheme.to_scheme(hashing_algo),
        }
    }
}

impl TryFrom<&PublicKey> for tss_esapi::tss2_esys::TPM2B_PUBLIC {
    type Error = PinError;

    fn try_from(publickey: &PublicKey) -> Result<Self, Self::Error> {
        match publickey {
            PublicKey::RSA {
                scheme,
                hashing_algo,
                modulus,
                exponent,
            } => {
                let mut object_attributes = tss_esapi::utils::ObjectAttributes(0);
                object_attributes.set_fixed_tpm(false);
                object_attributes.set_fixed_parent(false);
                object_attributes.set_sensitive_data_origin(false);
                object_attributes.set_user_with_auth(true);
                object_attributes.set_decrypt(false);
                object_attributes.set_sign_encrypt(true);
                object_attributes.set_restricted(false);

                let len = modulus.len();
                let mut buffer = [0_u8; 512];
                buffer[..len].clone_from_slice(&modulus[..len]);
                let rsa_uniq = Box::new(tss_esapi::tss2_esys::TPM2B_PUBLIC_KEY_RSA {
                    size: len as u16,
                    buffer,
                });

                Ok(tss_esapi::utils::Tpm2BPublicBuilder::new()
                    .with_type(tss_esapi::constants::TPM2_ALG_RSA)
                    .with_name_alg(hashing_algo.to_tpmi_alg_hash())
                    .with_parms(tss_esapi::utils::PublicParmsUnion::RsaDetail(
                        tss_esapi::utils::TpmsRsaParmsBuilder::new_unrestricted_signing_key(
                            scheme.to_scheme(&hashing_algo),
                            (modulus.len() * 8) as u16,
                            *exponent,
                        )
                        .build()?,
                    ))
                    .with_object_attributes(object_attributes)
                    .with_unique(tss_esapi::utils::PublicIdUnion::Rsa(rsa_uniq))
                    .build()?)
            }
        }
    }
}

fn perform_decrypt(input: &str) -> Result<(), PinError> {
    let token = biscuit::Compact::decode(input.trim());
    let hdr: biscuit::jwe::Header<ClevisHeader> = token.part(0)?;

    if hdr.private.clevis.pin != "tpm2" && hdr.private.clevis.pin != "tpm2plus" {
        return Err(PinError::Text("JWE pin mismatch"));
    }

    let jwkpub = build_tpm2b_public(&hdr.private.clevis.tpm2.jwk_pub)?;
    let jwkpriv = build_tpm2b_private(&hdr.private.clevis.tpm2.jwk_priv)?;

    let policy = TPMPolicyStep::try_from(&hdr.private.clevis.tpm2)?;

    let key_public = get_key_public(hdr.private.clevis.tpm2.key.as_str())?;

    let mut ctx = get_tpm2_ctx()?;
    let key_handle = get_tpm2_primary_key(&mut ctx, &key_public)?;

    create_and_set_tpm2_session(&mut ctx, tss_esapi::constants::TPM2_SE_HMAC)?;
    let key = ctx.load(key_handle, jwkpriv, jwkpub)?;

    policy.send_policy(&mut ctx, false)?;

    let unsealed = ctx.unseal(key)?;
    let unsealed = &unsealed.value();
    let unsealed = std::str::from_utf8(unsealed)?;
    let jwk: biscuit::jwk::JWK<biscuit::Empty> = serde_json::from_str(unsealed)?;

    let token: biscuit::jwe::Compact<Vec<u8>, biscuit::Empty> = jwe::Compact::Encrypted(token);

    let token = token.decrypt(
        &jwk,
        biscuit::jwa::KeyManagementAlgorithm::DirectSymmetricKey,
        biscuit::jwa::ContentEncryptionAlgorithm::A256GCM,
    )?;
    // We just decrypted the token, there should be a payload
    let payload = token.payload()?;

    io::stdout().write_all(payload)?;

    Ok(())
}

fn read_input_token() -> Result<String, PinError> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    if buffer.is_empty() {
        return Err(PinError::Text("No data provided"));
    }
    Ok(buffer)
}

fn print_summary() {
    println!("Encrypts using a TPM2.0 chip binding policy");
}

fn print_help() {
    eprintln!("
Usage: clevis encrypt tpm2 CONFIG < PLAINTEXT > JWE

Encrypts using a TPM2.0 chip binding policy

This command uses the following configuration properties:

  hash: <string>  Hash algorithm used in the computation of the object name (default: sha256)

  key: <string>  Algorithm type for the generated key (options: eecc, rsa; default: ecc)

  pcr_bank: <string>  PCR algorithm bank to use for policy (default: sha256)

  pcr_ids: <string>  PCR list used for policy. If not present, no PCR policy is used

  policy_pubkey_path: <string>  Path to the policy public key for authorized policy decryption

  policy_ref: <string>  Reference to search for in signed policy file

  policy_path: <string>  Path to the policy path to search for decryption policy
");

    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (mode, cfg) = match get_mode_and_cfg(&args) {
        Err(e) => {
            eprintln!("Error during parsing operation: {}", e);
            std::process::exit(1);
        }
        Ok((mode, cfg)) => (mode, cfg),
    };

    match mode {
        ActionMode::Summary => return print_summary(),
        ActionMode::Help => return print_help(),
        _ => {},
    };

    let input = match read_input_token() {
        Err(e) => {
            eprintln!("Error getting input token: {}", e);
            std::process::exit(1);
        }
        Ok(input) => input,
    };

    if let Err(e) = match mode {
        ActionMode::Encrypt => perform_encrypt(cfg.unwrap(), &input),
        ActionMode::Decrypt => perform_decrypt(&input),
        ActionMode::Summary => panic!("Summary was already handled supposedly"),
        ActionMode::Help => panic!("Help was already handled supposedly"),
    } {
        eprintln!("Error executing command: {}", e);
        std::process::exit(2);
    }
}

fn get_tpm2_ctx() -> Result<Context, tss_esapi::response_code::Error> {
    if std::path::Path::new("/dev/tpmrm0").exists() {
        unsafe { Context::new(tcti::Tcti::Tabrmd(Default::default())) }
    } else {
        unsafe { Context::new(tcti::Tcti::Device(Default::default())) }
    }
}

fn get_tpm2_primary_key(
    ctx: &mut Context,
    pub_template: &tss_esapi::tss2_esys::TPM2B_PUBLIC,
) -> Result<ESYS_TR, PinError> {
    let cur_sessions = ctx.sessions();

    create_and_set_tpm2_session(ctx, tss_esapi::constants::TPM2_SE_HMAC)?;
    let key_handle = ctx.create_primary_key(ESYS_TR_RH_OWNER, pub_template, &[], &[], &[], &[])?;

    ctx.set_sessions(cur_sessions);
    Ok(key_handle)
}
