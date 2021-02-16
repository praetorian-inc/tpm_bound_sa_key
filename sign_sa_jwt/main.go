package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	jwtHeader = `{"alg":"RS256","typ":"JWT"}`
	jwtAud    = "https://oauth2.googleapis.com/token"

	jwtScope       string
	serviceAccount string

	keyHandle = 0x81010002
)

type claims struct {
	Issuer   string `json:"iss"`
	Scope    string `json:"scope"`
	Audience string `json:"aud"`
	Subject  string `json:"sub"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

func main() {
	flag.StringVar(&jwtScope, "scope", "https://www.googleapis.com/auth/compute.readonly", "API scope of the JWT")
	flag.StringVar(&serviceAccount, "sa-email", "REPLACE_ME@PROJECT_ID.iam.gserviceaccount.com", "Email of the service account")
	flag.Parse()

	jwtString, err := buildJWT(jwtScope, serviceAccount)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	signedJWT, err := signJWT(jwtString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println(signedJWT)
}

func buildJWT(jwtScope, serviceAccount string) (string, error) {
	now := time.Now().Unix()
	expires := now + 3600

	claimsStruct := &claims{
		Issuer:   serviceAccount,
		Scope:    jwtScope,
		Audience: jwtAud,
		Subject:  serviceAccount,
		IssuedAt: now,
		Expires:  expires,
	}

	jwtClaims, err := json.Marshal(claimsStruct)
	if err != nil {
		return "", fmt.Errorf("Failed to construct JWT claims: %v", err)
	}

	b64JWTHeader := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))
	b64JWTClaims := base64.RawURLEncoding.EncodeToString([]byte(jwtClaims))

	jwtString := fmt.Sprintf("%s.%s", b64JWTHeader, b64JWTClaims)

	return jwtString, nil
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
