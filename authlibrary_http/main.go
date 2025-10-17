package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"

	"cloud.google.com/go/auth"
	"cloud.google.com/go/auth/oauth2adapt"
	"cloud.google.com/go/storage"
	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	signermtls "github.com/salrashid123/mtls-tokensource/signer"
	"google.golang.org/api/option"

	tpmsigner "github.com/salrashid123/tpmsigner"

	"cloud.google.com/go/auth/httptransport"
)

var (
	pubCert = flag.String("pubCert", "workload1.crt", "Public Cert file")
	//persistentHandle = flag.Uint("persistentHandle", 0x81008001, "Handle value")
	kf            = flag.String("keyfile", "workload1_tpm_key.pem", "Keyfile value")
	tpmPath       = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	projectId     = flag.String("projectId", "core-eso", "ProjectID")
	bucketName    = flag.String("bucketName", "core-eso-bucket", "bucket where the object is")
	objectName    = flag.String("objectName", "foo.txt", "object to recall")
	projectNumber = flag.String("projectNumber", "995081011111", "ProjectNumber")
	poolid        = flag.String("poolid", "cert-pool-1", "Workload PoolID")
	providerid    = flag.String("providerid", "cert-provider-1", "Workload providerid")
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	log.Printf("======= Init  ========")

	os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "true")
	os.Setenv("GOOGLE_API_USE_MTLS_ENDPOINT", "true")
	os.Setenv("GOOGLE_API_USE_MTLS", "true")

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			log.Fatalf("can't close TPM %q: %v", *tpmPath, err)
		}
	}()
	rwr := transport.FromReadWriter(rwc)

	log.Printf("======= reloading key from file ========")

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't create primary TPM %q: %v", *tpmPath, err)
	}

	// load the tpm-tss generated rsa key from disk
	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*kf)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	regenRSAKey, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{
			Handle: primary.ObjectHandle,
			Name:   tpm2.TPM2BName(primary.Name),
			Auth:   tpm2.PasswordAuth([]byte("")),
		},
		InPublic:  key.Pubkey,
		InPrivate: key.Privkey,
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("can't load rsa key: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: regenRSAKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	flush := tpm2.FlushContext{
		FlushHandle: primary.ObjectHandle,
	}
	_, err = flush.Execute(rwr)
	if err != nil {
		log.Fatalf("can't close primary  %v", err)
	}

	pubPEMData, err := os.ReadFile(*pubCert)
	if err != nil {
		log.Fatalf("can't read public cert %v", err)
	}
	block, _ := pem.Decode(pubPEMData)
	if err != nil {
		log.Fatalf("can't decode cert  %v", err)
	}
	filex509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("can't parce cert %v", err)
	}
	// get a signer, this happens to be for a TPM
	tpmsigner, err := tpmsigner.NewTPMCrypto(&tpmsigner.TPM{
		TpmDevice:       rwc,
		Handle:          regenRSAKey.ObjectHandle,
		X509Certificate: filex509,
	})
	if err != nil {
		log.Fatal(err)
	}

	// apply the signer to a tokensource that uses mTLS
	ts, err := signermtls.SignerMTLSTokenSource(&signermtls.SignerMtlsTokenConfig{
		Signer:         tpmsigner,
		PublicCertFile: *pubCert,
		Audience:       fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", *projectNumber, *poolid, *providerid),
	})
	if err != nil {
		log.Fatal(err)
	}

	tcrt, err := tpmsigner.TLSCertificate()
	if err != nil {
		log.Fatal(err)
	}

	// sslKeyLogfile := os.Getenv("SSLKEYLOGFILE")
	// var w *os.File
	// if sslKeyLogfile != "" {
	// 	w, err = os.OpenFile(sslKeyLogfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// } else {
	// 	w = os.Stdout
	// }

	tp := oauth2adapt.TokenProviderFromTokenSource(ts)

	opts := &httptransport.Options{
		Credentials: &auth.Credentials{
			TokenProvider: tp,
		},
		ClientCertProvider: func(c *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &tcrt, nil
		},
		// BaseRoundTripper: &http.Transport{
		// 	TLSClientConfig: &tls.Config{
		// 		//Certificates: []tls.Certificate{tcrt},
		// 		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		// 			return &tcrt, nil
		// 		},
		// 		KeyLogWriter: w,
		// 		MinVersion:   tls.VersionTLS13,
		// 	},
		// },
	}
	client, err := httptransport.NewClient(opts)
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	// Using Client Library

	storageClient, err := storage.NewClient(ctx,
		option.WithEndpoint("storage.mtls.googleapis.com:443"),
		option.WithHTTPClient(client))

	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	defer storageClient.Close()

	bkt := storageClient.Bucket(*bucketName)
	obj := bkt.Object(*objectName)

	rdr, err := obj.NewReader(ctx)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	_, err = io.Copy(os.Stdout, rdr)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	if err = rdr.Close(); err != nil {
		fmt.Println(err)
	}
	fmt.Println()
}
