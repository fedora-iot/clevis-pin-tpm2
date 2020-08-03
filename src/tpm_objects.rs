use std::convert::TryFrom;

use tss_esapi::constants;
use tss_esapi::utils;

use crate::PinError;

pub(super) fn create_tpm2b_public_sealed_object(
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

pub(super) fn get_tpm2b_public(val: tss_esapi::tss2_esys::TPM2B_PUBLIC) -> Result<Vec<u8>, PinError> {
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

pub(super) fn get_tpm2b_private(val: tss_esapi::tss2_esys::TPM2B_PRIVATE) -> Result<Vec<u8>, PinError> {
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

pub(super) fn build_tpm2b_private(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PRIVATE, PinError> {
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

pub(super) fn build_tpm2b_public(val: &[u8]) -> Result<tss_esapi::tss2_esys::TPM2B_PUBLIC, PinError> {
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

pub(super) fn create_restricted_ecc_public() -> tss_esapi::tss2_esys::TPM2B_PUBLIC {
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
