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

use std::env;
use std::io::{self, Read, Write};

use biscuit::jwe;
use biscuit::CompactJson;

use serde::{Deserialize, Serialize};

use tpm2_policy::TPMPolicyStep;

mod cli;
mod tpm_objects;
mod utils;

use cli::TPM2Config;

use tss_esapi::structures::SensitiveData;

#[derive(Debug)]
enum PinError {
    Text(&'static str),
    NoCommand,
    Serde(serde_json::Error),
    IO(std::io::Error),
    TPM(tss_esapi::Error),
    JWE(biscuit::errors::Error),
    Base64Decoding(base64::DecodeError),
    Utf8(std::str::Utf8Error),
    FromUtf8(std::string::FromUtf8Error),
    PolicyError(tpm2_policy::Error),
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
            PinError::FromUtf8(err) => {
                write!(f, "UTF8 error: ")?;
                err.fmt(f)
            }
            PinError::NoCommand => write!(f, "No command provided"),
            PinError::PolicyError(err) => {
                write!(f, "Policy Error: ")?;
                err.fmt(f)
            }
        }
    }
}

impl Error for PinError {}

impl From<std::io::Error> for PinError {
    fn from(err: std::io::Error) -> Self {
        PinError::IO(err)
    }
}

impl From<tpm2_policy::Error> for PinError {
    fn from(err: tpm2_policy::Error) -> Self {
        PinError::PolicyError(err)
    }
}

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

impl From<tss_esapi::Error> for PinError {
    fn from(err: tss_esapi::Error) -> Self {
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

fn perform_encrypt(cfg: TPM2Config, input: Vec<u8>) -> Result<(), PinError> {
    let key_type = match &cfg.key {
        None => "ecc",
        Some(key_type) => key_type,
    };
    let key_public = tpm_objects::get_key_public(&key_type, cfg.get_name_hash_alg())?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, &key_public)?;

    let policy_runner: TPMPolicyStep = TPMPolicyStep::try_from(&cfg)?;

    let pin_type = match policy_runner {
        TPMPolicyStep::NoStep => "tpm2",
        TPMPolicyStep::PCRs(_, _, _) => "tpm2",
        _ => "tpm2plus",
    };

    let (_, policy_digest) = policy_runner.send_policy(&mut ctx, true)?;

    let key_bytes = ctx.get_random(32)?;
    let key_bytes: &[u8] = key_bytes.value();
    let mut jwk = biscuit::jwk::JWK::new_octet_key(&key_bytes, biscuit::Empty {});
    jwk.common.algorithm = Some(biscuit::jwa::Algorithm::ContentEncryption(
        biscuit::jwa::ContentEncryptionAlgorithm::A256GCM,
    ));
    jwk.common.key_operations = Some(vec![
        biscuit::jwk::KeyOperations::Encrypt,
        biscuit::jwk::KeyOperations::Decrypt,
    ]);
    let jwk_str = serde_json::to_string(&jwk)?;

    let public = tpm_objects::create_tpm2b_public_sealed_object(policy_digest)?;
    let jwk_str = SensitiveData::try_from(jwk_str.as_bytes().to_vec())?;
    let jwk_result = ctx.execute_with_nullauth_session(|ctx| {
        ctx.create(key_handle, &public, None, Some(&jwk_str), None, None)
    })?;

    let jwk_priv = tpm_objects::get_tpm2b_private(jwk_result.out_private.into())?;

    let jwk_pub = tpm_objects::get_tpm2b_public(jwk_result.out_public)?;

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
                    hash: cfg.hash.as_ref().unwrap_or(&"sha256".to_string()).clone(),
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
    let jwe_enc_options = biscuit::jwa::EncryptionOptions::AES_GCM {
        nonce: rand_nonce.value().to_vec(),
    };

    let jwe_token = biscuit::jwe::Compact::new_decrypted(hdr, input);
    let jwe_token_compact = jwe_token.encrypt(&jwk, &jwe_enc_options)?;
    let encoded_token = jwe_token_compact.encrypted()?.encode();
    io::stdout().write_all(encoded_token.as_bytes())?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Tpm2Inner {
    hash: String,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
    )]
    jwk_priv: Vec<u8>,
    #[serde(
        deserialize_with = "utils::deserialize_as_base64_url_no_pad",
        serialize_with = "utils::serialize_as_base64_url_no_pad"
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
                    utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                    cfg.get_pcr_ids().unwrap(),
                    Box::new(TPMPolicyStep::NoStep),
                )),
                Box::new(utils::get_authorized_policy_step(
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
                utils::get_hash_alg_from_name(cfg.pcr_bank.as_ref()),
                cfg.get_pcr_ids().unwrap(),
                Box::new(TPMPolicyStep::NoStep),
            ))
        } else if cfg.policy_pubkey_path.is_some() {
            utils::get_authorized_policy_step(
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

fn perform_decrypt(input: Vec<u8>) -> Result<(), PinError> {
    let input = String::from_utf8(input).map_err(PinError::FromUtf8)?;
    let token = biscuit::Compact::decode(input.trim());
    let hdr: biscuit::jwe::Header<ClevisHeader> = token.part(0)?;

    if hdr.private.clevis.pin != "tpm2" && hdr.private.clevis.pin != "tpm2plus" {
        return Err(PinError::Text("JWE pin mismatch"));
    }

    let jwkpub = tpm_objects::build_tpm2b_public(&hdr.private.clevis.tpm2.jwk_pub)?;
    let jwkpriv = tpm_objects::build_tpm2b_private(&hdr.private.clevis.tpm2.jwk_priv)?;

    let policy = TPMPolicyStep::try_from(&hdr.private.clevis.tpm2)?;

    let name_alg = crate::utils::get_hash_alg_from_name(Some(&hdr.private.clevis.tpm2.hash));
    let key_public = tpm_objects::get_key_public(hdr.private.clevis.tpm2.key.as_str(), name_alg)?;

    let mut ctx = utils::get_tpm2_ctx()?;
    let key_handle = utils::get_tpm2_primary_key(&mut ctx, &key_public)?;

    let key =
        ctx.execute_with_nullauth_session(|ctx| ctx.load(key_handle, jwkpriv.try_into()?, jwkpub))?;

    let (policy_session, _) = policy.send_policy(&mut ctx, false)?;

    let unsealed = ctx.execute_with_session(policy_session, |ctx| ctx.unseal(key.into()))?;
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

fn print_summary() {
    println!("Encrypts using a TPM2.0 chip binding policy");
}

fn print_help() {
    eprintln!(
        "
Usage: clevis encrypt tpm2 CONFIG < PLAINTEXT > JWE

Encrypts using a TPM2.0 chip binding policy

This command uses the following configuration properties:

  hash: <string>  Hash algorithm used in the computation of the object name (default: sha256)

  key: <string>  Algorithm type for the generated key (options: eecc, rsa; default: ecc)

  pcr_bank: <string>  PCR algorithm bank to use for policy (default: sha256)

  pcr_ids: <string>  PCR list used for policy. If not present, no PCR policy is used

  use_policy: <bool>  Whether to use a policy

  policy_ref: <string>  Reference to search for in signed policy file (default: {})

  > For policies, the path is {}, and the public key is at {}
",
        cli::DEFAULT_POLICY_REF,
        cli::DEFAULT_POLICY_PATH,
        cli::DEFAULT_PUBKEY_PATH,
    );

    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (mode, cfg) = match cli::get_mode_and_cfg(&args) {
        Err(e) => {
            eprintln!("Error during parsing operation: {}", e);
            std::process::exit(1);
        }
        Ok((mode, cfg)) => (mode, cfg),
    };

    match mode {
        cli::ActionMode::Summary => return print_summary(),
        cli::ActionMode::Help => return print_help(),
        _ => {}
    };

    let mut input = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut input) {
        eprintln!("Error getting input token: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = match mode {
        cli::ActionMode::Encrypt => perform_encrypt(cfg.unwrap(), input),
        cli::ActionMode::Decrypt => perform_decrypt(input),
        cli::ActionMode::Summary => panic!("Summary was already handled supposedly"),
        cli::ActionMode::Help => panic!("Help was already handled supposedly"),
    } {
        eprintln!("Error executing command: {}", e);
        std::process::exit(2);
    }
}
