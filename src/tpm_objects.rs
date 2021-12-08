use std::convert::TryFrom;

use anyhow::{anyhow, bail, Result};
use tss_esapi::attributes::object::ObjectAttributesBuilder;
use tss_esapi::constants::tss as tss_constants;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::Digest;
use tss_esapi::utils::{PublicParmsUnion, Tpm2BPublicBuilder, TpmsEccParmsBuilder};
use tss_esapi::{abstraction::cipher::Cipher, interface_types::algorithm::HashingAlgorithm};

#[cfg(target_pointer_width = "64")]
type Sizedu = u64;
#[cfg(target_pointer_width = "32")]
type Sizedu = u32;

pub(super) fn get_key_public(
    key_type: &str,
    name_alg: HashingAlgorithm,
) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    match key_type {
        "ecc" => Ok(create_restricted_ecc_public()),
        "rsa" => Ok(tss_esapi::utils::create_restricted_decryption_rsa_public(
            Cipher::aes_128_cfb(),
            2048,
            0,
        )?),
        _ => Err(anyhow!("Unsupported key type used")),
    }
    .map(|mut public| {
        public.publicArea.nameAlg = name_alg.into();
        public
    })
}

pub(super) fn create_tpm2b_public_sealed_object(
    policy: Option<Digest>,
) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(true);

    if policy.is_none() {
        object_attributes = object_attributes.with_user_with_auth(true);
    }
    let policy = match policy {
        Some(p) => p,
        None => Digest::try_from(vec![])?,
    };

    let mut params: tss_esapi::tss2_esys::TPMU_PUBLIC_PARMS = Default::default();
    params.keyedHashDetail.scheme.scheme = tss_constants::TPM2_ALG_NULL;

    Ok(tss_esapi::tss2_esys::TPM2B_PUBLIC {
        size: std::mem::size_of::<tss_esapi::tss2_esys::TPMT_PUBLIC>() as u16,
        publicArea: tss_esapi::tss2_esys::TPMT_PUBLIC {
            type_: tss_constants::TPM2_ALG_KEYEDHASH,
            nameAlg: tss_constants::TPM2_ALG_SHA256,
            objectAttributes: object_attributes.build()?.0,
            authPolicy: tss_esapi::tss2_esys::TPM2B_DIGEST::from(policy),
            parameters: params,
            unique: Default::default(),
        },
    })
}

pub(super) fn get_tpm2b_public(val: tss_esapi::tss2_esys::TPM2B_PUBLIC) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_public failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn get_tpm2b_private(val: tss_esapi::tss2_esys::TPM2B_PRIVATE) -> Result<Vec<u8>> {
    let mut offset = 0 as Sizedu;
    let mut resp = Vec::with_capacity((val.size + 4) as usize);

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
            &val,
            resp.as_mut_ptr(),
            resp.capacity() as Sizedu,
            &mut offset,
        );
        if res != 0 {
            bail!("Marshalling tpm2b_private failed");
        }
        resp.set_len(offset as usize);
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_private(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PRIVATE> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PRIVATE::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_private failed");
        }
    }

    Ok(resp)
}

pub(super) fn build_tpm2b_public(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC> {
    let mut resp = tss_esapi::tss2_esys::TPM2B_PUBLIC::default();
    let mut offset = 0 as Sizedu;

    unsafe {
        let res = tss_esapi::tss2_esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(
            val[..].as_ptr(),
            val.len() as Sizedu,
            &mut offset,
            &mut resp,
        );
        if res != 0 {
            bail!("Unmarshalling tpm2b_public failed");
        }
    }

    Ok(resp)
}

pub(super) fn create_restricted_ecc_public() -> tss_esapi::tss2_esys::TPM2B_PUBLIC {
    let ecc_params = TpmsEccParmsBuilder::new_restricted_decryption_key(
        Cipher::aes_128_cfb(),
        EccCurve::NistP256,
    )
    .build()
    .unwrap();
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true);

    Tpm2BPublicBuilder::new()
        .with_type(tss_constants::TPM2_ALG_ECC)
        .with_name_alg(tss_constants::TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes.build().unwrap())
        .with_parms(PublicParmsUnion::EccDetail(ecc_params))
        .build()
        .unwrap()
}
