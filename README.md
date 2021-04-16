# TPM Bound GCP Service Account Credentials

> Credit to ![salrashid123](https://github.com/salrashid123/tpm2_evp_sign_decrypt)!

This repo demonstrates how you can embed a service account's
private key into a Shielded VMs vTPM then use it to sign JWTs that can
be used to authenticate to Google Cloud APIs. Assuming that the key pair
only exists within the TPM (barring exfiltration), valid JWTs can only
be signed while on the Compute VM effectively "binding" the credentials.

> **NOTE:** The content in this repo is very experimental and for demonstration
> purposes only. You should take proper precautions before using this method in
> an active environment.

## Create Compute Shielded VM

Create a VM with a Shielded vTPM
```
gcloud compute instances create example-vtpm-compute-vm \
  --zone=us-central1-a --machine-type=n1-standard-1 \
  --subnet=default --network-tier=PREMIUM --no-service-account \
  --no-scopes --image=ubuntu-2010-groovy-v20210130 \
  --image-project=ubuntu-os-cloud --no-shielded-secure-boot \
  --shielded-vtpm --shielded-integrity-monitoring
```

Remote into the instance
```
gcloud compute ssh example-vtpm-compute-vm --zone=us-central1-a
```

## Install Dependencies

> *NOTE:* The following commands assume you are running as root `sudo su -`

Verify that the TPM is correctly recognized
```
dmesg | grep tpm
```

Install `tpm2-tss` dependencies
```
apt update && apt -y install \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  procps \
  iproute2 \
  build-essential \
  git \
  pkg-config \
  gcc \
  libtool \
  automake \
  libssl-dev \
  uthash-dev \
  autoconf \
  doxygen \
  libjson-c-dev \
  libcjson1 \
  libcjson-dev \
  libini-config-dev \
  libcurl4-openssl-dev
```

Install [tpm2-tss](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md)
```
git clone --depth=1 https://github.com/tpm2-software/tpm2-tss.git
cd tmp2-tss
./bootstrap
./configure
make -j$(nproc)
make install
udevadm control --reload-rules && udevadm trigger
ldconfig
```

Install [tpm2-tss-engine](https://github.com/tpm2-software/tpm2-tss-engine/blob/master/INSTALL.md)
```
git clone --depth=1 https://github.com/tpm2-software/tpm2-tss-engine.git
cd tpm2-tss-engine
./bootstrap
./configure
make -j$(nproc)
make install
ldconfig
```

Install [tpm2-tools](https://github.com/tpm2-software/tpm2-tools)
```
apt install tpm2-tools
```

## Generate the key in the TPM

> This method generates the primary key in the TPM; however, you could
> also [download a P12 key file for a service account](embed_sa_p12_keys.md).
> The method shown below is recommended to reduce exposure of the private key.

Create a primary object under the `TPM_RH_ENDORSEMENT` hierarchy
and save it to `primary.ctx`
```
tpm2_createprimary -C e -g sha256 -G rsa -c primary.ctx
```

Generate the private key as a child object of the primary context that was
just created
```
tpm2_create -G rsa -u key.pub -r key.priv -C primary.ctx
```

Load the private and public keys into the TPM and save the resulting context
object to `key.ctx`
```
tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx
```

Make the key persistent in the TPM at the handle `0x81010002`. This handle
value is arbitrary. If leave it blank and the key will be persisted at the
first available handle.
```
tpm2_evictcontrol -C o -c key.ctx 0x81010002
```

### Generate the x509 cert and upload it to the service account

Generate the cert and write it to `public.crt`
```
openssl req -new -x509 -engine tpm2tss \
  -key 0x81010002 -keyform engine -out public.crt \
  -subj "/CN=example.com"
```

Upload the certificate to the service account
```
gcloud iam service-accounts keys upload public.crt \
  --iam-account=example-sa@project_id.iam.gserviceaccount.com
```

Confirm the key was successfully uploaded
```
gcloud iam service-accounts keys list \
  --iam-account=example-sa@project_id.iam.gserviceaccount.com
```

## Create and Sign a JWT to Authenticate to Google APIs

[Service account JWT format](https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests)

You can use [sign_sa_jwt](./sign_sa_jwt) included in this repo to accomplish this.

> **NOTE:** You will probably want to update the claim values to for your use case

```
cd sign_sa_jwt
GOOS=linux GOARCH=amd64 go build -v main.go

# Move the binary to the VM
gcloud compute scp ./main example-vtpm-compute-vm:~ --zone=us-central1-a
```

On the VM, run the `main` binary and a JWT will be printed
```
# ./main
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiAiamVzc2UtdHBtLX...
```

Confirm everything is working by requesting an access token
```
curl https://oauth2.googleapis.com/token \
  -d "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=$SA_JWT"
```