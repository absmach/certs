// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"golang.org/x/crypto/ocsp"
	"moul.io/http2curl"
)

const (
	certsEndpoint     = "certs"
	csrEndpoint       = "csrs"
	issueCertEndpoint = "certs/issue"
	crlEndpoint       = "crl"
)

const (
	// CTJSON represents JSON content type.
	CTJSON ContentType = "application/json"

	// CTJSONSenML represents JSON SenML content type.
	CTJSONSenML ContentType = "application/senml+json"

	// CTBinary represents binary content type.
	CTBinary ContentType = "application/octet-stream"
)

// ContentType represents all possible content types.
type ContentType string

type CertStatus int

const (
	Valid CertStatus = iota
	Revoked
	Unknown
)

const (
	valid   = "Valid"
	revoked = "Revoked"
	unknown = "Unknown"
)

const BearerPrefix = "Bearer "

func (c CertStatus) String() string {
	switch c {
	case Valid:
		return valid
	case Revoked:
		return revoked
	default:
		return unknown
	}
}

func (c CertStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

type CertType int

const (
	RootCA CertType = iota
	IntermediateCA
)

func (c CertType) String() string {
	switch c {
	case RootCA:
		return "root"
	case IntermediateCA:
		return "intermediate"
	default:
		return "unknown"
	}
}

type PageMetadata struct {
	Total              uint64   `json:"total"`
	Offset             uint64   `json:"offset,omitempty"`
	Limit              uint64   `json:"limit"`
	EntityID           string   `json:"entity_id,omitempty"`
	Token              string   `json:"token,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	Province           []string `json:"province,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	DNSNames           []string `json:"dns_names,omitempty"`
	IPAddresses        []string `json:"ip_addresses,omitempty"`
	EmailAddresses     []string `json:"email_addresses,omitempty"`
	Status             string   `json:"status,omitempty"`
	TTL                string   `json:"ttl,omitempty"`
}

type Options struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	DnsNames           []string `json:"dns_names"`
}

type Token struct {
	Token string `json:"token"`
}

type Certificate struct {
	SerialNumber string    `json:"serial_number,omitempty"`
	Certificate  string    `json:"certificate,omitempty"`
	Key          string    `json:"key,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
	ExpiryTime   time.Time `json:"expiry_time,omitempty"`
	EntityID     string    `json:"entity_id,omitempty"`
	DownloadUrl  string    `json:"-"`
}

type CertificatePage struct {
	Total        uint64        `json:"total"`
	Offset       uint64        `json:"offset"`
	Limit        uint64        `json:"limit"`
	Certificates []Certificate `json:"certificates,omitempty"`
}

type Config struct {
	CertsURL string
	HostURL  string

	MsgContentType  ContentType
	TLSVerification bool
	CurlFlag        bool
}

type mgSDK struct {
	certsURL string
	HostURL  string

	msgContentType ContentType
	client         *http.Client
	curlFlag       bool
}

type CertificateBundle struct {
	CA          []byte `json:"ca"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
}

type OCSPResponse struct {
	Status           CertStatus `json:"status"`
	SerialNumber     string     `json:"serial_number"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	ProducedAt       *time.Time `json:"produced_at,omitempty"`
	ThisUpdate       *time.Time `json:"this_update,omitempty"`
	NextUpdate       *time.Time `json:"next_update,omitempty"`
	Certificate      []byte     `json:"certificate,omitempty"`
	IssuerHash       string     `json:"issuer_hash,omitempty"`
	RevocationReason int        `json:"revocation_reason,omitempty"`
}

type CSRMetadata struct {
	CommonName         string   `json:"common_name"`
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	EmailAddresses     []string `json:"email_addresses"`
}

type CSR struct {
	CSR []byte `json:"csr,omitempty"`
}

type SDK interface {
	// IssueCert issues a certificate for a thing required for mTLS.
	//
	// example:
	// cert , _ := sdk.IssueCert("entityID", "10h", []string{"ipAddr1", "ipAddr2"}, sdk.Options{CommonName: "commonName"}, "domainID", "token")
	//  fmt.Println(cert)
	IssueCert(entityID, ttl string, ipAddrs []string, opts Options, domainID, token string) (Certificate, errors.SDKError)

	// RevokeCert revokes certificate for thing with thingID
	//
	// example:
	//  err := sdk.RevokeCert("serialNumber", "domainID", "token")
	//  fmt.Println(err) // nil if successful
	RevokeCert(serialNumber, domainID, token string) errors.SDKError

	// RenewCert renews certificate for entity with entityID and returns the new certificate
	//
	// example:
	//  newCert, err := sdk.RenewCert("serialNumber", "domainID", "token")
	//  fmt.Println(newCert.SerialNumber)
	RenewCert(serialNumber, domainID, token string) (Certificate, errors.SDKError)

	// ListCerts lists all certificates for a client
	//
	// example:
	//  page, _ := sdk.ListCerts(PageMetadata{Limit: 10, Offset: 0}, "domainID", "token")
	//  fmt.Println(page)
	ListCerts(pm PageMetadata, domainID, token string) (CertificatePage, errors.SDKError)

	// DeleteCert deletes certificates for a given entityID.
	//
	// example:
	//  err := sdk.DeleteCert("entityID", "domainID", "token")
	//  fmt.Println(err)
	DeleteCert(entityID, domainID, token string) errors.SDKError

	// ViewCert retrieves a certificate record from the database.
	//
	// example:
	//  cert, _ := sdk.ViewCert("serialNumber", "domainID", "token")
	//  fmt.Println(cert)
	ViewCert(serialNumber, domainID, token string) (Certificate, errors.SDKError)

	// OCSP checks the revocation status of a certificate using OpenBao's OCSP endpoint.
	// Returns a binary OCSP response (RFC 6960) with detailed status information.
	//
	// example:
	//  response, _ := sdk.OCSP("serialNumber", "")
	//  fmt.Println(response)
	OCSP(serialNumber, cert string) (OCSPResponse, errors.SDKError)

	// ViewCA views the signing certificate
	//
	// example:
	//  response, _ := sdk.ViewCA("domainID", "token")
	//  fmt.Println(response)
	ViewCA(domainID, token string) (Certificate, errors.SDKError)

	// DownloadCA downloads the signing certificate
	//
	// example:
	//  response, _ := sdk.DownloadCA("domainID", "token")
	//  fmt.Println(response)
	DownloadCA(domainID, token string) (CertificateBundle, errors.SDKError)

	// IssueFromCSR issues certificate from provided CSR
	//
	// example:
	//	certs, err := sdk.IssueFromCSR("entityID", "ttl", "csrFile", "domainID", "token")
	//	fmt.Println(err)
	IssueFromCSR(entityID, ttl, csr, domainID, token string) (Certificate, errors.SDKError)

	// IssueFromCSRInternal issues certificate from provided CSR using agent authentication
	//
	// example:
	//	certs, err := sdk.IssueFromCSRInternal("entityID", "ttl", "csrFile", "agentToken")
	//	fmt.Println(err)
	IssueFromCSRInternal(entityID, ttl, csr, token string) (Certificate, errors.SDKError)

	// GenerateCRL generates a Certificate Revocation List
	//
	// example:
	//	crlBytes, err := sdk.GenerateCRL()
	//	fmt.Println(err)
	GenerateCRL() ([]byte, errors.SDKError)

	// RevokeAll revokes all certificates for an entity ID
	//
	// example:
	//	err := sdk.RevokeAll("entityID", "domainID", "token")
	//	fmt.Println(err)
	RevokeAll(entityID, domainID, token string) errors.SDKError

	// GetEntityID gets the entity ID for a certificate by serial number
	//
	// example:
	//	entityID, err := sdk.GetEntityID("serialNumber", "domainID", "token")
	//	fmt.Println(entityID)
	GetEntityID(serialNumber, domainID, token string) (string, errors.SDKError)
}

func (sdk mgSDK) IssueCert(entityID, ttl string, ipAddrs []string, opts Options, domainID, token string) (Certificate, errors.SDKError) {
	r := certReq{
		IpAddrs: ipAddrs,
		TTL:     ttl,
		Options: opts,
	}
	d, err := json.Marshal(r)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	url := fmt.Sprintf("%s/%s/%s/issue/%s", sdk.certsURL, domainID, certsEndpoint, entityID)
	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodPost, url, token, d, nil, http.StatusCreated)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}
	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	return cert, nil
}

func (sdk mgSDK) ViewCert(serialNumber, domainID, token string) (Certificate, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.certsURL, domainID, certsEndpoint, serialNumber)

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	return cert, nil
}

func (sdk mgSDK) RevokeCert(serialNumber, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/revoke", sdk.certsURL, domainID, certsEndpoint, serialNumber)

	_, _, sdkerr := sdk.processRequest(context.Background(), http.MethodPatch, url, token, nil, nil, http.StatusNoContent)
	return sdkerr
}

func (sdk mgSDK) RenewCert(serialNumber, domainID, token string) (Certificate, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/renew", sdk.certsURL, domainID, certsEndpoint, serialNumber)

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodPatch, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var renewRes struct {
		Renewed     bool        `json:"renewed"`
		Certificate Certificate `json:"certificate"`
	}
	if err := json.Unmarshal(body, &renewRes); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	return renewRes.Certificate, nil
}

func (sdk mgSDK) ListCerts(pm PageMetadata, domainID, token string) (CertificatePage, errors.SDKError) {
	url, err := sdk.withQueryParams(fmt.Sprintf("%s/%s/%s", sdk.certsURL, domainID, certsEndpoint), "", pm)
	if err != nil {
		return CertificatePage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return CertificatePage{}, sdkerr
	}
	var cp CertificatePage
	if err := json.Unmarshal(body, &cp); err != nil {
		return CertificatePage{}, errors.NewSDKError(err)
	}
	return cp, nil
}

func (sdk mgSDK) DeleteCert(entityID, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/delete", sdk.certsURL, domainID, certsEndpoint, entityID)

	_, _, sdkerr := sdk.processRequest(context.Background(), http.MethodDelete, url, token, nil, nil, http.StatusNoContent)
	return sdkerr
}

func (sdk mgSDK) OCSP(serialNumber, cert string) (OCSPResponse, errors.SDKError) {
	if serialNumber == "" && cert == "" {
		return OCSPResponse{}, errors.NewSDKError(errors.New("either serial number or certificate must be provided"))
	}

	ocspReq := struct {
		SerialNumber string `json:"serial_number,omitempty"`
		Certificate  string `json:"certificate,omitempty"`
	}{}

	if serialNumber != "" {
		ocspReq.SerialNumber = serialNumber
	}

	if cert != "" {
		ocspReq.Certificate = cert
	}

	requestBody, err := json.Marshal(ocspReq)
	if err != nil {
		return OCSPResponse{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/certs/ocsp", sdk.certsURL)

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodPost, url, "", requestBody, nil, http.StatusOK)
	if sdkerr != nil {
		return OCSPResponse{}, sdkerr
	}

	ocspResp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		return OCSPResponse{}, errors.NewSDKError(fmt.Errorf("failed to parse OCSP response: %w", err))
	}

	var status CertStatus
	switch ocspResp.Status {
	case ocsp.Good:
		status = Valid
	case ocsp.Revoked:
		status = Revoked
	case ocsp.Unknown:
		status = Unknown
	default:
		status = Unknown
	}

	resp := OCSPResponse{
		Status:       status,
		SerialNumber: ocspResp.SerialNumber.String(),
		Certificate:  body,
	}

	if ocspResp.RevokedAt != (time.Time{}) {
		resp.RevokedAt = &ocspResp.RevokedAt
	}

	if ocspResp.ProducedAt != (time.Time{}) {
		resp.ProducedAt = &ocspResp.ProducedAt
	}

	if ocspResp.ThisUpdate != (time.Time{}) {
		resp.ThisUpdate = &ocspResp.ThisUpdate
	}

	if ocspResp.NextUpdate != (time.Time{}) {
		resp.NextUpdate = &ocspResp.NextUpdate
	}

	resp.RevocationReason = int(ocspResp.RevocationReason)

	return resp, nil
}

func (sdk mgSDK) ViewCA(domainID, token string) (Certificate, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/view-ca", sdk.certsURL, domainID, certsEndpoint)

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	return cert, nil
}

func (sdk mgSDK) DownloadCA(domainID, token string) (CertificateBundle, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/download-ca", sdk.certsURL, domainID, certsEndpoint)

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return CertificateBundle{}, sdkerr
	}

	zipReader, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return CertificateBundle{}, errors.NewSDKError(err)
	}

	var bundle CertificateBundle
	for _, file := range zipReader.File {
		fileContent, err := readZipFile(file)
		if err != nil {
			return CertificateBundle{}, errors.NewSDKError(err)
		}
		switch file.Name {
		case "ca.crt":
			bundle.Certificate = fileContent
		}
	}

	return bundle, nil
}

func (sdk mgSDK) IssueFromCSR(entityID, ttl, csr, domainID, token string) (Certificate, errors.SDKError) {
	pm := PageMetadata{
		TTL: ttl,
	}

	r := csrReq{
		CSR: []byte(csr),
	}

	d, err := json.Marshal(r)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	url, err := sdk.withQueryParams(fmt.Sprintf("%s/%s/%s/%s/%s", sdk.certsURL, domainID, certsEndpoint, csrEndpoint, entityID), "", pm)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodPost, url, token, d, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	return cert, nil
}

func (sdk mgSDK) IssueFromCSRInternal(entityID, ttl, csr, token string) (Certificate, errors.SDKError) {
	r := csrReq{
		CSR: []byte(csr),
	}

	d, err := json.Marshal(r)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	pm := PageMetadata{
		TTL: ttl,
	}

	url, err := sdk.withQueryParams(fmt.Sprintf("%s/certs/csrs/%s", sdk.certsURL, entityID), "", pm)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodPost, url, token, d, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	return cert, nil
}

func (sdk mgSDK) GenerateCRL() ([]byte, errors.SDKError) {
	url := fmt.Sprintf("%s/certs/%s", sdk.certsURL, crlEndpoint)
	_, body, sdkerr := sdk.processRequest(context.Background(), http.MethodGet, url, "", nil, nil, http.StatusOK)
	if sdkerr != nil {
		return nil, sdkerr
	}

	var crlRes struct {
		CRL string `json:"crl"`
	}
	if err := json.Unmarshal(body, &crlRes); err != nil {
		return nil, errors.NewSDKError(err)
	}

	// Decode base64 CRL data
	crlData, err := base64.StdEncoding.DecodeString(crlRes.CRL)
	if err != nil {
		return nil, errors.NewSDKError(err)
	}

	return crlData, nil
}

func (sdk mgSDK) RevokeAll(entityID, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/delete", sdk.certsURL, domainID, certsEndpoint, entityID)
	_, _, sdkerr := sdk.processRequest(context.Background(), http.MethodDelete, url, token, nil, nil, http.StatusNoContent)
	return sdkerr
}

func (sdk mgSDK) GetEntityID(serialNumber, domainID, token string) (string, errors.SDKError) {
	cert, err := sdk.ViewCert(serialNumber, domainID, token)
	if err != nil {
		return "", err
	}
	return cert.EntityID, nil
}

func NewSDK(conf Config) SDK {
	return &mgSDK{
		certsURL: conf.CertsURL,
		HostURL:  conf.HostURL,

		msgContentType: conf.MsgContentType,
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: !conf.TLSVerification,
				},
			},
		},
		curlFlag: conf.CurlFlag,
	}
}

// processRequest creates and send a new HTTP request, and checks for errors in the HTTP response.
// It then returns the response headers, the response body, and the associated error(s) (if any).
func (sdk mgSDK) processRequest(ctx context.Context, method, reqUrl, token string, data []byte, headers map[string]string, expectedRespCodes ...int) (http.Header, []byte, errors.SDKError) {
	req, err := http.NewRequestWithContext(ctx, method, reqUrl, bytes.NewReader(data))
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}

	// Sets a default value for the Content-Type.
	// Overridden if Content-Type is passed in the headers arguments.
	req.Header.Add("Content-Type", string(CTJSON))

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	if token != "" {
		token = fmt.Sprintf("%s%s", BearerPrefix, token)
		req.Header.Set("Authorization", token)
	}

	if sdk.curlFlag {
		curlCommand, err := http2curl.GetCurlCommand(req)
		if err != nil {
			return nil, nil, errors.NewSDKError(err)
		}
		log.Println(curlCommand.String())
	}

	resp, err := sdk.client.Do(req)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}
	defer resp.Body.Close()

	sdkErr := errors.CheckError(resp, expectedRespCodes...)
	if sdkErr != nil {
		return make(http.Header), []byte{}, sdkErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}

	return resp.Header, body, nil
}

func (sdk mgSDK) withQueryParams(baseURL, endpoint string, pm PageMetadata) (string, error) {
	q, err := pm.query()
	if err != nil {
		return "", err
	}

	if endpoint == "" {
		return fmt.Sprintf("%s?%s", baseURL, q), nil
	}
	return fmt.Sprintf("%s/%s?%s", baseURL, endpoint, q), nil
}

func (pm PageMetadata) query() (string, error) {
	q := url.Values{}
	if pm.Offset != 0 {
		q.Add("offset", strconv.FormatUint(pm.Offset, 10))
	}
	if pm.Limit != 0 {
		q.Add("limit", strconv.FormatUint(pm.Limit, 10))
	}
	if pm.Total != 0 {
		q.Add("total", strconv.FormatUint(pm.Total, 10))
	}
	if pm.EntityID != "" {
		q.Add("entity_id", pm.EntityID)
	}
	if pm.CommonName != "" {
		q.Add("common_name", pm.CommonName)
	}
	if pm.TTL != "" {
		q.Add("ttl", pm.TTL)
	}

	return q.Encode(), nil
}

func readZipFile(file *zip.File) ([]byte, error) {
	fc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer fc.Close()
	return io.ReadAll(fc)
}

type certReq struct {
	IpAddrs []string `json:"ip_addresses"`
	TTL     string   `json:"ttl"`
	Options Options  `json:"options"`
}

type csrReq struct {
	CSR []byte `json:"csr,omitempty"`
}
