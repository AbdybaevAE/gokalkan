package gokalkan

import (
	"github.com/AbdybaevAE/gokalkan/ckalkan"
)

func (cli *Client) ValidateCert(cert string) (string, error) {
	validateType := ckalkan.ValidateTypeNothing
	validatePath := ""
	return cli.kc.X509ValidateCertificate(cert, validateType, validatePath)
}

func (cli *Client) ValidateCertOCSP(cert string, url ...string) (string, error) {
	validateType := ckalkan.ValidateTypeOCSP
	validatePath := cli.o.OCSP

	if len(url) > 0 {
		validatePath = url[0]
	}

	return cli.kc.X509ValidateCertificate(cert, validateType, validatePath)
}


func (cli *Client) 	X509CertificateGetInfo(inCert string, prop ckalkan.CertProp) (result string, err error)
{
	return cli.kc.X509CertificateGetInfo(inCert, prop)
}