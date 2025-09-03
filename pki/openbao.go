// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package pki wraps OpenBao client for PKI operations
package pki

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/absmach/certs"
	"github.com/absmach/certs/errors"
	"github.com/mitchellh/mapstructure"
	"github.com/openbao/openbao/api/v2"
	"golang.org/x/crypto/ocsp"
)

const (
	issue     = "issue"
	sign      = "sign"
	cert      = "cert"
	revoke    = "revoke"
	ca        = "ca"
	caChain   = "ca_chain"
	crl       = "crl"
	ocspPath  = "ocsp"
	certsList = "certs"
)

var (
	errFailedToLogin = errors.New("failed to login to OpenBao")
	errNoAuthInfo    = errors.New("no auth information from OpenBao")
	errRenewWatcher  = errors.New("unable to initialize new lifetime watcher for renewing auth token")
)

type openbaoPKIAgent struct {
	appRole    string
	appSecret  string
	namespace  string
	path       string
	role       string
	host       string
	issueURL   string
	signURL    string
	readURL    string
	revokeURL  string
	caURL      string
	caChainURL string
	crlURL     string
	ocspURL    string
	certsURL   string
	client     *api.Client
	secret     *api.Secret
	logger     *slog.Logger
}

// NewAgent instantiates an OpenBao PKI client that implements certs.Agent.
func NewAgent(appRole, appSecret, host, namespace, path, role string, logger *slog.Logger) (certs.Agent, error) {
	conf := api.DefaultConfig()
	conf.Address = host

	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	p := openbaoPKIAgent{
		appRole:    appRole,
		appSecret:  appSecret,
		host:       host,
		namespace:  namespace,
		role:       role,
		path:       path,
		client:     client,
		logger:     logger,
		issueURL:   "/" + path + "/" + issue + "/" + role,
		signURL:    "/" + path + "/" + sign + "/" + role,
		readURL:    "/" + path + "/" + cert + "/",
		revokeURL:  "/" + path + "/" + revoke,
		caURL:      "/" + path + "/" + ca,
		caChainURL: "/" + path + "/" + caChain,
		crlURL:     "/" + path + "/" + crl,
		ocspURL:    "/" + path + "/" + ocspPath,
		certsURL:   "/" + path + "/" + certsList,
	}
	return &p, nil
}

func (va *openbaoPKIAgent) Issue(entityId, ttl string, ipAddrs []string, options certs.SubjectOptions) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secretValues := map[string]any{
		"common_name":          options.CommonName,
		"ttl":                  ttl,
		"exclude_cn_from_sans": true,
	}

	if len(options.Organization) > 0 {
		secretValues["organization"] = options.Organization
	}
	if len(options.OrganizationalUnit) > 0 {
		secretValues["ou"] = options.OrganizationalUnit
	}
	if len(options.Country) > 0 {
		secretValues["country"] = options.Country
	}
	if len(options.Province) > 0 {
		secretValues["province"] = options.Province
	}
	if len(options.Locality) > 0 {
		secretValues["locality"] = options.Locality
	}
	if len(options.StreetAddress) > 0 {
		secretValues["street_address"] = options.StreetAddress
	}
	if len(options.PostalCode) > 0 {
		secretValues["postal_code"] = options.PostalCode
	}

	allDNSNames := make([]string, 0)
	allDNSNames = append(allDNSNames, options.DnsNames...)
	if len(allDNSNames) > 0 {
		secretValues["alt_names"] = allDNSNames
	}

	allIPs := make([]string, 0)
	allIPs = append(allIPs, ipAddrs...)
	for _, ip := range options.IpAddresses {
		allIPs = append(allIPs, ip.String())
	}
	if len(allIPs) > 0 {
		secretValues["ip_sans"] = allIPs
	}

	secret, err := va.client.Logical().Write(va.issueURL, secretValues)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("no certificate data returned from OpenBao")
	}

	cert := certs.Certificate{
		EntityID: entityId,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	if keyData, ok := secret.Data["private_key"].(string); ok {
		cert.Key = []byte(keyData)
	}

	if serialNumber, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = serialNumber
	}

	if expirationInterface, ok := secret.Data["expiration"]; ok {
		switch exp := expirationInterface.(type) {
		case int64:
			cert.ExpiryTime = time.Unix(exp, 0)
		case float64:
			cert.ExpiryTime = time.Unix(int64(exp), 0)
		case json.Number:
			if expInt, err := exp.Int64(); err == nil {
				cert.ExpiryTime = time.Unix(expInt, 0)
			}
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) View(serialNumber string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secret, err := va.client.Logical().Read(va.readURL + serialNumber)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("certificate not found")
	}

	cert := certs.Certificate{
		SerialNumber: serialNumber,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	cert.Revoked = false
	if revokedTimeStr, ok := secret.Data["revocation_time_rfc3339"].(string); ok && revokedTimeStr != "" {
		cert.Revoked = true
	}

	if len(cert.Certificate) > 0 {
		if expiry, err := va.parseCertificateExpiry(string(cert.Certificate)); err == nil {
			cert.ExpiryTime = expiry
		}

		if entityID, err := va.parseCertificateEntityID(string(cert.Certificate)); err == nil {
			cert.EntityID = entityID
		}
	}
	return cert, nil
}

func (va *openbaoPKIAgent) parseCertificateExpiry(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert.NotAfter, nil
}

func (va *openbaoPKIAgent) parseCertificateEntityID(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert.Subject.CommonName, nil
}

func (va *openbaoPKIAgent) Renew(existingCert certs.Certificate, increment string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	block, _ := pem.Decode(existingCert.Certificate)
	if block == nil {
		return certs.Certificate{}, fmt.Errorf("failed to decode existing certificate PEM")
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return certs.Certificate{}, fmt.Errorf("failed to parse existing certificate: %w", err)
	}

	options := certs.SubjectOptions{
		DnsNames: x509Cert.DNSNames,
	}

	options.IpAddresses = append(options.IpAddresses, x509Cert.IPAddresses...)

	if len(x509Cert.Subject.Organization) > 0 {
		options.Organization = x509Cert.Subject.Organization
	}
	if len(x509Cert.Subject.OrganizationalUnit) > 0 {
		options.OrganizationalUnit = x509Cert.Subject.OrganizationalUnit
	}
	if len(x509Cert.Subject.Country) > 0 {
		options.Country = x509Cert.Subject.Country
	}
	if len(x509Cert.Subject.Province) > 0 {
		options.Province = x509Cert.Subject.Province
	}
	if len(x509Cert.Subject.Locality) > 0 {
		options.Locality = x509Cert.Subject.Locality
	}
	if len(x509Cert.Subject.StreetAddress) > 0 {
		options.StreetAddress = x509Cert.Subject.StreetAddress
	}
	if len(x509Cert.Subject.PostalCode) > 0 {
		options.PostalCode = x509Cert.Subject.PostalCode
	}

	var ipAddrs []string
	for _, ip := range x509Cert.IPAddresses {
		ipAddrs = append(ipAddrs, ip.String())
	}

	newCert, err := va.Issue(existingCert.EntityID, increment, ipAddrs, options)
	if err != nil {
		return certs.Certificate{}, fmt.Errorf("failed to issue renewed certificate: %w", err)
	}

	return newCert, nil
}

func (va *openbaoPKIAgent) Revoke(serialNumber string) error {
	err := va.LoginAndRenew()
	if err != nil {
		return err
	}

	secretValues := map[string]any{
		"serial_number": serialNumber,
	}

	_, err = va.client.Logical().Write(va.revokeURL, secretValues)
	if err != nil {
		return err
	}
	return nil
}

func (va *openbaoPKIAgent) ListCerts(pm certs.PageMetadata) (certs.CertificatePage, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.CertificatePage{}, err
	}

	secret, err := va.client.Logical().List(va.certsURL)
	if err != nil {
		return certs.CertificatePage{}, err
	}

	certPage := certs.CertificatePage{
		Certificates: []certs.Certificate{},
		PageMetadata: pm,
	}

	if secret == nil || secret.Data == nil {
		return certPage, nil
	}

	keysInterface, ok := secret.Data["keys"]
	if !ok {
		return certPage, nil
	}

	var serialNumbers []string
	if err := mapstructure.Decode(keysInterface, &serialNumbers); err != nil {
		return certPage, fmt.Errorf("failed to decode certificate serial numbers: %w", err)
	}

	var filteredCerts []certs.Certificate
	for _, serialNumber := range serialNumbers {
		cert, err := va.View(serialNumber)
		if err != nil {
			va.logger.Warn("failed to retrieve certificate details", "serial", serialNumber, "error", err)
			continue
		}

		if pm.EntityID != "" {
			if cert.EntityID != pm.EntityID {
				continue
			}
		}

		filteredCerts = append(filteredCerts, cert)
	}

	certPage.Total = uint64(len(filteredCerts))

	start := pm.Offset
	end := pm.Offset + pm.Limit
	if pm.Limit == 0 {
		end = uint64(len(filteredCerts))
	}
	if start >= uint64(len(filteredCerts)) {
		return certPage, nil
	}
	if end > uint64(len(filteredCerts)) {
		end = uint64(len(filteredCerts))
	}

	for i := start; i < end; i++ {
		certPage.Certificates = append(certPage.Certificates, filteredCerts[i])
	}

	return certPage, nil
}

func (va *openbaoPKIAgent) LoginAndRenew() error {
	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		_, err := va.client.Auth().Token().LookupSelf()
		if err == nil {
			return nil
		}
	}

	authData := map[string]any{
		"role_id":   va.appRole,
		"secret_id": va.appSecret,
	}

	authResp, err := va.client.Logical().Write("auth/approle/login", authData)
	if err != nil {
		return fmt.Errorf("%s: %w", errFailedToLogin, err)
	}

	if authResp == nil || authResp.Auth == nil {
		return errNoAuthInfo
	}

	va.secret = authResp
	va.client.SetToken(authResp.Auth.ClientToken)

	if authResp.Auth.Renewable {
		watcher, err := va.client.NewLifetimeWatcher(&api.LifetimeWatcherInput{
			Secret: authResp,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", errRenewWatcher, err)
		}

		go va.renewToken(watcher)
	}

	return nil
}

func (va *openbaoPKIAgent) renewToken(watcher *api.LifetimeWatcher) {
	defer watcher.Stop()

	watcher.Start()
	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				va.logger.Error("token renewal failed", "error", err)
			}
			return
		case renewal := <-watcher.RenewCh():
			va.logger.Info("token renewed successfully", "lease_duration", renewal.Secret.LeaseDuration)
		}
	}
}

func (va *openbaoPKIAgent) GetCA() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	url := va.host + "/v1/" + va.path + "/ca"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		req.Header.Set("X-Vault-Token", va.secret.Auth.ClientToken)
	}

	if va.namespace != "" {
		req.Header.Set("X-Vault-Namespace", va.namespace)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to get CA certificate: HTTP %d - %s", resp.StatusCode, string(body))
	}

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA response: %w", err)
	}

	if len(certData) == 0 {
		return nil, fmt.Errorf("CA certificate response is empty - PKI may not be initialized")
	}

	_, err = x509.ParseCertificate(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER certificate: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certData,
	}

	pemData := pem.EncodeToMemory(pemBlock)
	return pemData, nil
}

func (va *openbaoPKIAgent) GetCAChain() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	url := va.host + "/v1/" + va.path + "/ca_chain"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		req.Header.Set("X-Vault-Token", va.secret.Auth.ClientToken)
	}

	if va.namespace != "" {
		req.Header.Set("X-Vault-Namespace", va.namespace)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CA chain: HTTP %d", resp.StatusCode)
	}

	chainData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA chain response: %w", err)
	}

	return chainData, nil
}

func (va *openbaoPKIAgent) GetCRL() ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	url := va.host + "/v1/" + va.path + "/crl"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		req.Header.Set("X-Vault-Token", va.secret.Auth.ClientToken)
	}

	if va.namespace != "" {
		req.Header.Set("X-Vault-Namespace", va.namespace)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get CRL: HTTP %d", resp.StatusCode)
	}

	crlData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL response: %w", err)
	}

	return crlData, nil
}

func (va *openbaoPKIAgent) SignCSR(csr []byte, entityId, ttl string) (certs.Certificate, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return certs.Certificate{}, err
	}

	secretValues := map[string]any{
		"csr": string(csr),
		"ttl": ttl,
	}

	secret, err := va.client.Logical().Write(va.signURL, secretValues)
	if err != nil {
		return certs.Certificate{}, err
	}

	if secret == nil || secret.Data == nil {
		return certs.Certificate{}, fmt.Errorf("no certificate data returned from OpenBao")
	}

	cert := certs.Certificate{
		EntityID: entityId,
	}

	if certData, ok := secret.Data["certificate"].(string); ok {
		cert.Certificate = []byte(certData)
	}

	if serialNumber, ok := secret.Data["serial_number"].(string); ok {
		cert.SerialNumber = serialNumber
	}

	if expirationInterface, ok := secret.Data["expiration"]; ok {
		switch exp := expirationInterface.(type) {
		case int64:
			cert.ExpiryTime = time.Unix(exp, 0)
		case float64:
			cert.ExpiryTime = time.Unix(int64(exp), 0)
		case json.Number:
			if expInt, err := exp.Int64(); err == nil {
				cert.ExpiryTime = time.Unix(expInt, 0)
			}
		}
	}

	return cert, nil
}

func (va *openbaoPKIAgent) OCSP(serialNumber string) ([]byte, error) {
	err := va.LoginAndRenew()
	if err != nil {
		return nil, err
	}

	issuerCert, err := va.getIssuerCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get issuer certificate for OCSP: %w", err)
	}

	serialBytes, err := parseSerialNumber(serialNumber)
	if err != nil {
		return nil, fmt.Errorf("failed to parse serial number: %w", err)
	}

	issuerNameDER, err := va.encodeRDNSequence(issuerCert.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to encode issuer name: %w", err)
	}

	var issuerKeyHash []byte
	if len(issuerCert.SubjectKeyId) > 0 {
		issuerKeyHash = sha1Hash(issuerCert.SubjectKeyId)
	}

	ocspReq := &ocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: sha1Hash(issuerNameDER),
		IssuerKeyHash:  issuerKeyHash,
		SerialNumber:   new(big.Int).SetBytes(serialBytes),
	}

	ocspRequestDER, err := ocspReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OCSP request: %w", err)
	}

	url := fmt.Sprintf("%s/v1/%s/ocsp", va.host, va.path)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(ocspRequestDER)))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	if va.secret != nil && va.secret.Auth != nil && va.secret.Auth.ClientToken != "" {
		req.Header.Set("X-Vault-Token", va.secret.Auth.ClientToken)
	}
	if va.namespace != "" {
		req.Header.Set("X-Vault-Namespace", va.namespace)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query OpenBao OCSP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("OCSP request failed: HTTP %d - %s", resp.StatusCode, string(body))
	}

	der, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP response: %w", err)
	}

	_, err = ocsp.ParseResponse(der, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid OCSP response from OpenBao: %w", err)
	}

	return der, nil
}

func (va *openbaoPKIAgent) getIssuerCertificate() (*x509.Certificate, error) {
	certData, err := va.GetCA()
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X509 certificate: %w", err)
	}

	return cert, nil
}

func parseSerialNumber(serialStr string) ([]byte, error) {
	cleaned := strings.ReplaceAll(strings.ReplaceAll(serialStr, ":", ""), "-", "")

	serialBytes, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid serial number format: %w", err)
	}

	return serialBytes, nil
}

func sha1Hash(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func (va *openbaoPKIAgent) encodeRDNSequence(name pkix.Name) ([]byte, error) {
	return asn1.Marshal(name.ToRDNSequence())
}
