use std::convert::TryFrom;

use super::PinError;
use crate::utils::get_authorized_policy_step;

use serde::{Deserialize, Serialize};

use tpm2_policy::TPMPolicyStep;

#[derive(Serialize, Deserialize, std::fmt::Debug)]
pub(super) struct TPM2Config {
    pub hash: Option<String>,
    pub key: Option<String>,
    pub pcr_bank: Option<String>,
    // PCR IDs can be passed in as comma-separated string or json array
    pub pcr_ids: Option<serde_json::Value>,
    pub pcr_digest: Option<String>,
    // Public key (in JSON format) for a wildcard policy that's possibly OR'd with the PCR one
    pub policy_pubkey_path: Option<String>,
    pub policy_ref: Option<String>,
    pub policy_path: Option<String>,
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

impl TPM2Config {
    pub(super) fn get_pcr_hash_alg(&self) -> tss_esapi::constants::algorithm::HashingAlgorithm {
        crate::utils::get_pcr_hash_alg_from_name(self.pcr_bank.as_ref())
    }

    pub(super) fn get_pcr_ids(&self) -> Option<Vec<u64>> {
        match &self.pcr_ids {
            None => None,
            Some(serde_json::Value::Array(vals)) => {
                Some(vals.iter().map(|x| x.as_u64().unwrap()).collect())
            }
            _ => panic!("Unexpected type found for pcr_ids"),
        }
    }

    pub(super) fn get_pcr_ids_str(&self) -> Option<String> {
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
        // Normalize from array with one string to just string
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            if vals.len() == 1 {
                if let serde_json::Value::String(val) = &vals[0] {
                    self.pcr_ids = Some(serde_json::Value::String(val.to_string()));
                }
            }
        }
        // Normalize pcr_ids from comma-separated string to array
        if let Some(serde_json::Value::String(val)) = &self.pcr_ids {
            // Was a string, do a split
            let newval: Vec<serde_json::Value> = val
                .split(',')
                .map(|x| serde_json::Value::String(x.trim().to_string()))
                .collect();
            self.pcr_ids = Some(serde_json::Value::Array(newval));
        }
        // Normalize pcr_ids from array of Strings to array of Numbers
        if let Some(serde_json::Value::Array(vals)) = &self.pcr_ids {
            let newvals: Result<Vec<serde_json::Value>, _> = vals
                .iter()
                .map(|x| match x {
                    serde_json::Value::String(val) => match val.trim().parse::<serde_json::Number>() {
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
pub(super) enum ActionMode {
    Encrypt,
    Decrypt,
    Summary,
    Help,
}

pub(super) fn get_mode_and_cfg(
    args: &[String],
) -> Result<(ActionMode, Option<TPM2Config>), PinError> {
    if args.len() > 1 && args[1] == "--summary" {
        return Ok((ActionMode::Summary, None));
    }
    if args.len() > 1 && args[1] == "--help" {
        return Ok((ActionMode::Help, None));
    }
    if atty::is(atty::Stream::Stdin) {
        return Ok((ActionMode::Help, None));
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
