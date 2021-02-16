package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm-tools/server"
	compute "google.golang.org/api/compute/v1"
	iam "google.golang.org/api/iam/v1"
	"google.golang.org/protobuf/proto"
)

var (
	instanceName   string
	projectID      string
	zone           string
	serviceAccount string
	outputFile     string

	ctx = context.Background()
)

func main() {

	flag.StringVar(&instanceName, "instanceName", "", "Instance for which to generate key")
	flag.StringVar(&projectID, "projectID", "", "Instance Project")
	flag.StringVar(&zone, "zone", "", "Zone where instance resides")
	flag.StringVar(&serviceAccount, "serviceAccount", "", "Service Account to Impersonate")
	flag.StringVar(&outputFile, "outputFile", "", "File to write the sealed blob to")
	flag.Parse()

	var unset []string
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() == "" {
			unset = append(unset, f.Name)
		}
	})

	if len(unset) != 0 {
		fmt.Printf("[!] Missing required flags: %s\n", unset)
		os.Exit(1)
	}

	fmt.Println("[+] Generating keypair....")
	publicKeyData, privateKey, err := generateKeysAndCert()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Println("[+] Uploading Certificate into Service Account....")
	if err := uploadKeyToServiceAccount(publicKeyData); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Signing blob and writing it to %s\n", outputFile)
	if err := signAndSaveBlob(privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	// 	fmt.Println("Utilize SCP or your instrumentation of choice to upload the key to the vTPM.")
}

// Create keypair in memory and generate x509
func generateKeysAndCert() (string, *rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to generate RSA keypair: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to generate x509 serial number: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.AddDate(1, 0, 0)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "unused",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to create x509 cert: %v", err)
	}

	certEncoded := &bytes.Buffer{}
	pem.Encode(certEncoded, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	pubKeyData := base64.StdEncoding.EncodeToString([]byte(certEncoded.String()))
	return pubKeyData, privateKey, nil
}

// Upload key to GCP to associate it with the service account
func uploadKeyToServiceAccount(publicKeyData string) error {
	iamService, err := iam.NewService(ctx)
	if err != nil {
		return fmt.Errorf("Failed to initiate IAM client SDK: %v", err)
	}
	keyService := iam.NewProjectsServiceAccountsKeysService(iamService)

	uploadKeyRequest := &iam.UploadServiceAccountKeyRequest{
		PublicKeyData: publicKeyData,
	}

	if _, err := keyService.Upload(serviceAccount, uploadKeyRequest).Do(); err != nil {
		return fmt.Errorf("Failed to upload key to service account: %v", err)
	}
	return nil
}

// Fetch the VMs EKPub, sign the private key, and write the signed blob to a file
func signAndSaveBlob(privateKey *rsa.PrivateKey) error {
	computeService, err := compute.NewService(ctx)
	if err != nil {
		return fmt.Errorf("Failed to initiate Compute client SDK: %v", err)
	}

	resp, err := computeService.Instances.GetShieldedInstanceIdentity(projectID, zone, instanceName).Do()
	if err != nil {
		return fmt.Errorf("Failed to get Compute instance's shielded instance identity: %v", err)
	}

	// Taken from https://github.com/salrashid123/gcp_tpm_sealed_keys/blob/494c1235f152455ae6bbd8957af7997f6fdecf67/asymmetric/seal/main.go
	fmt.Println("[+] Signing blob with GCP VM key.....")
	block, _ := pem.Decode([]byte(resp.EncryptionKey.EkPub))
	parsedPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse public key from instance EKPub: %v", err)
	}

	// Sign private key and save blob.
	blob, err := server.CreateSigningKeyImportBlob(parsedPublicKey, privateKey, nil)
	if err != nil {
		return fmt.Errorf("Failed to create signing key import blob: %v", err)
	}

	data, err := proto.Marshal(blob)
	if err != nil {
		return fmt.Errorf("Failed to serialize blob to protobuf: %v", err)
	}

	if err := ioutil.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("Failed to write signed blob to file: %v", err)
	}
	return nil
}
