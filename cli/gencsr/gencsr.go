// Package gencsr implements the gencsr command.
package gencsr

import (
	"encoding/json"
	"errors"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

var gencsrUsageText = `cfssl gencsr -- generate a csr from a private key with existing CSR json specification or certificate

Usage of gencsr:
        cfssl gencsr -key private_key_file [-host hostname_override] CSRJSON
        cfssl gencsr -key private_key_file [-host hostname_override] -cert certificate_file

Arguments:
        CSRJSON:    JSON file containing the request, use '-' for reading JSON from stdin

Flags:
`

var gencsrFlags = []string{"key", "cert"}

func gencsrMain(args []string, c cli.Config) (err error) {
	key, err := sign.SignerFromConfig(c)
	if err != nil {
		return
	}

	// prepare a stub CertificateRequest
	req := &csr.CertificateRequest{
		KeyRequest: csr.NewKeyRequest(),
	}

	privk := key.(*local.Signer)

	if c.CertFile != "" {
		if len(args) > 0 {
			return errors.New("no argument is accepted with '-cert', please check with usage")
		}

		certBytes, err := helpers.ReadBytes(c.CertFile)
		if err != nil {
			return err
		}

		cert, err := helpers.ParseCertificatePEM(certBytes)
		if err != nil {
			return err
		}

		req = csr.ExtractCertificateRequest(cert)
	} else {
		csrFile, args, err := cli.PopFirstArgument(args)
		if err != nil {
			return err
		}

		if len(args) > 0 {
			return errors.New("only one argument is accepted, please check with usage")
		}

		csrFileBytes, err := cli.ReadStdin(csrFile)
		if err != nil {
			return err
		}

		err = json.Unmarshal(csrFileBytes, req)
		if err != nil {
			return err
		}
	}

	if c.Hostname != "" {
		req.Hosts = signer.SplitHosts(c.Hostname)
	}

	csrBytes, err := csr.Generate(privk.GetCryptoSigner(), req)
	if err != nil {
		return err
	}

	cli.PrintCert(nil, csrBytes, nil)
	return nil
}

// Command assembles the definition of Command 'gencsr'
var Command = &cli.Command{UsageText: gencsrUsageText, Flags: gencsrFlags, Main: gencsrMain}
