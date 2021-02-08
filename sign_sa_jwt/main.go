package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	jwtHeader = `{"alg":"RS256","typ":"JWT"}`
	jwtIss    = "REPLACE_ME@PROJECT_ID.iam.gserviceaccount.com"
	jwtScope  = "https://www.googleapis.com/auth/compute.readonly"
	jwtAud    = "https://oauth2.googleapis.com/token"
	jwtSub    = "REPLACE_ME@PROJECT_ID.iam.gserviceaccount.com"

	keyHandle = 0x81010002
)

func main() {

	jwtString := buildJWT()
	signedJWT, err := signJWT(jwtString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println(signedJWT)
}

func buildJWT() string {
	now := time.Now().Unix()
	expires := now + 3600

	jwtClaims := fmt.Sprintf(`{"iss": "%s","scope": "%s","aud": "%s","sub": "%s","iat": %d,"exp": %d}`, jwtIss, jwtScope, jwtAud, jwtSub, now, expires)

	b64JWTHeader := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))
	b64JWTClaims := base64.RawURLEncoding.EncodeToString([]byte(jwtClaims))

	jwtString := fmt.Sprintf("%s.%s", b64JWTHeader, b64JWTClaims)

	return jwtString
}

func signJWT(jwt string) (signed string, retErr error) {
	// https://github.com/google/go-tpm/blob/master/examples/tpm2-seal-unseal
	rwc, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return "", fmt.Errorf("Unable to open TPM /dev/tpm0: %v", err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			retErr = fmt.Errorf("%v\nCan't close TPM /dev/tpm0: %v", retErr, err)
		}
	}()

	handle := tpmutil.Handle(keyHandle)

	digest, validationTicket, err := tpm2.Hash(rwc, tpm2.AlgSHA256, []byte(jwt), tpm2.HandleOwner)
	if err != nil {
		return "", fmt.Errorf("Error while generating hash: %v", err)
	}

	sig, err := tpm2.Sign(rwc, handle, "", digest[:], validationTicket, &tpm2.SigScheme{
		Alg:  tpm2.AlgRSASSA,
		Hash: tpm2.AlgSHA256,
	})
	if err != nil {
		return "", fmt.Errorf("Error while signing JWT: %v", err)
	}

	b64JWTSignature := base64.RawURLEncoding.EncodeToString([]byte(sig.RSA.Signature))

	return fmt.Sprintf("%s.%s", jwt, b64JWTSignature), nil
}
