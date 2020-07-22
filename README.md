# clevis-pin-tpm2
Rewritten Clevis TPM2 PIN

This rewrite supports all previously encrypted values of the PCR-only clevis TPM2 PIN.
Additionally, it supports Authorized Policies to delegate authorization of PCR values to an external party.


## Creating policies

A [reference implementation](https://github.com/puiterwijk/clevis-pin-tpm2-signtool) has been made available for creating policies as parsed by this pin.
To use this, first create a policy (see instructions in the repository) and take the output signed policy and the public key JSON.
These files need to be available when the PIN runs, so if the pin is used to encrypt the filesystem root, it will probably need to be in /boot.
Then run: `$binary encrypt '{"policy_pubkey_path": "/boot/policy_pubkey.json", "policy_ref": "", "policy_path": "/boot/policy.json"}' <somefile`.
This results in an encrypted blob.
During the encryption, the policy pubkey needs to exist, the policy does not.

To decrypt this blob, the file specified in the policy_path during encrypt needs to contain a policy that matches the policy_ref with any steps that would match the current PCRs of the system.
If that's the case, `$binary decrypt <blob` will return the contents of the original file back.
