## Download P12 keyfile for service account

Go to the target service account in the Console and generate a new P12 key.

Extract the public and private keys from the key file
```
# Private key
openssl pkcs12 -in example_sa_keyfile.p12  \
  -nocerts -nodes -passin pass:notasecret \
  | openssl rsa -out private.pem

# Public key
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

Create a primary object under the `TPM_RH_ENDORSEMENT` hierarchy
and save it to `primary.ctx`
```
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
```

Import the private key into the TPM as a TPM managed key object
```
tpm2_import -C primary.ctx -G rsa -i private.pem -u key.pub -r key.prv
```

Load the private and public keys into the TPM and save the resulting context
object to `key.ctx`
```
tpm2_load -C primary.ctx -u key.pub -r key.prv -c key.ctx
```

Make the key persistent in the TPM at the handle `0x81010002`. This handle
value is arbitrary... I took it from the `tpm2_evictcontrol` man page.
You can leave it blank and the key will be persisted at the first available
handle.
```
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```