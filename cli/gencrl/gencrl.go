//Package gencrl implements the gencrl command
package gencrl

import (
	"strings"

	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/cli/sign"
	"github.com/cloudflare/cfssl/crl"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer/local"
)

var gencrlUsageText = `cfssl gencrl -- generate a new Certificate Revocation List

Usage of gencrl:
        cfssl gencrl INPUTFILE TIME

Arguments:
        INPUTFILE:               Text file with one serial number per line, use '-' for reading text from stdin
        TIME (OPTIONAL):         The desired expiration from now, in seconds

Flags:
`
var gencrlFlags = []string{}

func gencrlMain(args []string, c cli.Config) (err error) {
	serialList, args, err := cli.PopFirstArgument(args)
	if err != nil {
		return
	}
	log.Debugf("read seriallist file %s", serialList)

	serialListBytes, err := cli.ReadStdin(serialList)
	if err != nil {
		return
	}

	certFile := c.CertFile
	if certFile == "" {
		certFile = c.CAFile
	}
	log.Debugf("read cert file %s", certFile)
	certFileBytes, err := helpers.ReadBytes(certFile)
	if err != nil {
		return
	}

	log.Debugf("generate signer")

	key, err := sign.SignerFromConfig(c)
	if err != nil {
		return
	}
	privk := key.(*local.Signer)

	// Default value if no expiry time is given
	timeString := string("0")

	if len(args) > 0 {
		timeArg, _, err := cli.PopFirstArgument(args)
		if err != nil {
			return err
		}

		timeString = string(timeArg)

		// This is used to get rid of newlines
		timeString = strings.TrimSpace(timeString)

	}

	req, err := crl.NewCRLFromFile(serialListBytes, certFileBytes, privk.GetCryptoSigner(), timeString)
	if err != nil {
		return
	}

	cli.PrintCRL(req)
	return nil
}

// Command assembles the definition of Command 'gencrl'
var Command = &cli.Command{UsageText: gencrlUsageText, Flags: gencrlFlags, Main: gencrlMain}
