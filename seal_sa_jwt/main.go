package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm-tools/server"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
)

func main() {

	instanceName := flag.String("instanceName", "", "Instance for which to generate key")
	projectID := flag.String("projectID", "", "Instance Project")
	instanceZone := flag.String("zone", "", "Zone where instance resides")
	serviceAccount := flag.String("serviceAccount", "", "Service Account to Impersonate")
	// pcrValues := flag.String("PCR", "", "PCR Values for Instance")
	flag.Parse()

	if *instanceName == "" {
		fmt.Printf("Please enter an instance name.")
		os.Exit(1)
	}

	if *projectID== "" {
		fmt.Printf("Please enter a project ID.")
		os.Exit(1)
	}

	if *instanceZone == "" {
		fmt.Printf("Please enter a project ID.")
		os.Exit(1)
	}

	if *serviceAccount == "" {
		fmt.Printf("Please enter a Service Account to impersonate.")
		os.Exit(1)
	}

	/* if *pcrValues == "" {
		fmt.Printf("Please enter VM PCR Values.")
		os.Exit(1)
	} */

	// Initialize Gcloud
	ctx := context.Background()
	computeService, err := compute.NewService(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	iamService, err := iam.NewService(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Create keypair in memory and generate x509
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	publickey := &privatekey.PublicKey

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Taken from: https://golang.org/src/crypto/tls/generate_cert.go
	var notBefore time.Time
	notAfter := notBefore.Add(time.Hour*24)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:							 x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:					 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publickey, privatekey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	certEncoded := &bytes.Buffer{}
	pem.Encode(certEncoded, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// upload key
	keyService := iam.NewProjectsServiceAccountsKeysService(iamService)
	_, keyError := keyService.Upload(*serviceAccount, &iam.UploadServiceAccountKeyRequest{
		PublicKeyData: certEncoded.String(),
	}).Do()
	if keyError != nil {
		fmt.Fprintf(os.Stderr, "%v\n", keyError)
		os.Exit(1)
	}

	response, err := computeService.Instances.GetShieldedInstanceIdentity(*projectID,
	 *instanceZone, *instanceName).Do()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Taken from https://github.com/salrashid123/gcp_tpm_sealed_keys/blob/494c1235f152455ae6bbd8957af7997f6fdecf67/asymmetric/seal/main.go
	block, _ := pem.Decode([]byte(response.EncryptionKey.EkPub))
	parsedPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	// Sign private key and save blob.
	var pcrValues *tpmpb.Pcrs = nil
	blob, err := server.CreateSigningKeyImportBlob(parsedPublicKey, privatekey, pcrValues)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n",blob) // Print with Variable Name
	fmt.Printf("Utilize SCP or your instrumentation of choice to upload the key to the vTPM.")
}
