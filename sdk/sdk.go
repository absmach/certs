// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/absmach/certs/errors"
	"golang.org/x/crypto/ocsp"
	"moul.io/http2curl"
)

const (
	certsEndpoint     = "certs"
	issueCertEndpoint = "certs/issue"
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

type PageMetadata struct {
	Total      uint64 `json:"total,omitempty"`
	Offset     uint64 `json:"offset,omitempty"`
	Limit      uint64 `json:"limit,omitempty"`
	EntityID   string `json:"entity_id,omitempty"`
	Token      string `json:"token,omitempty"`
	CommonName string `json:"common_name,omitempty"`
}

type Options struct {
	CommonName         string
	Organization       []string `json:"organization"`
	OrganizationalUnit []string `json:"organizational_unit"`
	Country            []string `json:"country"`
	Province           []string `json:"province"`
	Locality           []string `json:"locality"`
	StreetAddress      []string `json:"street_address"`
	PostalCode         []string `json:"postal_code"`
}

type Token struct {
	Token string `json:"token"`
}

type Certificate struct {
	SerialNumber string    `json:"serial_number"`
	Certificate  string    `json:"certificate,omitempty"`
	Key          string    `json:"key,omitempty"`
	Revoked      bool      `json:"revoked"`
	ExpiryTime   time.Time `json:"expiry_time"`
	EntityID     string    `json:"entity_id"`
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

type SDK interface {
	// IssueCert issues a certificate for a thing required for mTLS.
	//
	// example:
	// serial , _ := sdk.IssueCert("entityID", "10h", []string{"ipAddr1", "ipAddr2"}, sdk.Options{CommonName: "commonName"})
	//  fmt.Println(serial)
	IssueCert(entityID, ttl string, ipAddrs []string, opts Options) (Certificate, errors.SDKError)

	// DownloadCert returns a certificate given certificate ID
	//
	// example:
	//  certBundle, _ := sdk.DownloadCert("serialNumber", "download-token")
	//  fmt.Println(certBundle)
	DownloadCert(token, serialNumber string) (CertificateBundle, errors.SDKError)

	// RevokeCert revokes certificate for thing with thingID
	//
	// example:
	//  err := sdk.RevokeCert("serialNumber")
	//  fmt.Println(err) // nil if successful
	RevokeCert(serialNumber string) errors.SDKError

	// RenewCert renews certificate for thing with thingID
	//
	// example:
	//  err := sdk.RenewCert("serialNumber")
	//  fmt.Println(err) // nil if successful
	RenewCert(serialNumber string) errors.SDKError

	// ListCerts lists all certificates for a client
	//
	// example:
	//  page, _ := sdk.ListCerts(PageMetadata{Limit: 10, Offset: 0})
	//  fmt.Println(page)
	ListCerts(pm PageMetadata) (CertificatePage, errors.SDKError)

	// ViewCert retrieves a certificate record from the database.
	//
	// example:
	//  cert, _ := sdk.ViewCert("serialNumber")
	//  fmt.Println(cert)
	ViewCert(serialNumber string) (Certificate, errors.SDKError)

	// RetrieveCertDownloadToken retrieves a download token for a certificate
	//
	// example:
	//  token, _ := sdk.RetrieveCertDownloadToken("serialNumber")
	//  fmt.Println(token)
	RetrieveCertDownloadToken(serialNumber string) (Token, errors.SDKError)

	// OCSP checks the revocation status of a certificate
	//
	// example:
	//  response, _ := sdk.OCSP("serialNumber")
	//  fmt.Println(response)
	OCSP(serialNumber string) (*ocsp.Response, errors.SDKError)
}

func (sdk mgSDK) IssueCert(entityID, ttl string, ipAddrs []string, opts Options) (Certificate, errors.SDKError) {
	r := certReq{
		IpAddrs: ipAddrs,
		TTL:     ttl,
		Options: opts,
	}
	d, err := json.Marshal(r)
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	url := fmt.Sprintf("%s/%s", issueCertEndpoint, entityID)

	url, err = sdk.withQueryParams(sdk.certsURL, url, PageMetadata{CommonName: opts.CommonName})
	if err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, d, nil, http.StatusCreated)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}
	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}

	return cert, nil
}

func (sdk mgSDK) DownloadCert(token, serialNumber string) (CertificateBundle, errors.SDKError) {
	pm := PageMetadata{
		Token: token,
	}
	url, err := sdk.withQueryParams(sdk.certsURL, fmt.Sprintf("%s/%s/download", certsEndpoint, serialNumber), pm)
	if err != nil {
		return CertificateBundle{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
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
		case "ca.pem":
			bundle.CA = fileContent
		case "cert.pem":
			bundle.Certificate = fileContent
		case "key.pem":
			bundle.PrivateKey = fileContent
		}
	}

	return bundle, nil
}

func (sdk mgSDK) ViewCert(serialNumber string) (Certificate, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s", sdk.certsURL, certsEndpoint, serialNumber)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Certificate{}, sdkerr
	}

	var cert Certificate
	if err := json.Unmarshal(body, &cert); err != nil {
		return Certificate{}, errors.NewSDKError(err)
	}
	return cert, nil
}

func (sdk mgSDK) RevokeCert(serialNumber string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/revoke", sdk.certsURL, certsEndpoint, serialNumber)
	_, _, sdkerr := sdk.processRequest(http.MethodPatch, url, nil, nil, http.StatusOK)
	return sdkerr
}

func (sdk mgSDK) RenewCert(serialNumber string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/renew", sdk.certsURL, certsEndpoint, serialNumber)
	_, _, sdkerr := sdk.processRequest(http.MethodPatch, url, nil, nil, http.StatusOK)
	return sdkerr
}

func (sdk mgSDK) ListCerts(pm PageMetadata) (CertificatePage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.certsURL, certsEndpoint, pm)
	if err != nil {
		return CertificatePage{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return CertificatePage{}, sdkerr
	}
	var cp CertificatePage
	if err := json.Unmarshal(body, &cp); err != nil {
		return CertificatePage{}, errors.NewSDKError(err)
	}
	return cp, nil
}

func (sdk mgSDK) RetrieveCertDownloadToken(serialNumber string) (Token, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/download/token", sdk.certsURL, certsEndpoint, serialNumber)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Token{}, sdkerr
	}

	var tk Token
	if err := json.Unmarshal(body, &tk); err != nil {
		return Token{}, errors.NewSDKError(err)
	}
	return tk, nil
}

func (sdk mgSDK) OCSP(serialNumber string) (*ocsp.Response, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/ocsp", sdk.certsURL, certsEndpoint)
	requestBody := []byte(serialNumber)
	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, requestBody, nil, http.StatusOK)
	if sdkerr != nil {
		return &ocsp.Response{}, sdkerr
	}
	ocspResp, err := ocsp.ParseResponse(body, nil)
	if err != nil {
		return &ocsp.Response{}, errors.NewSDKError(err)
	}
	return ocspResp, nil
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
func (sdk mgSDK) processRequest(method, reqUrl string, data []byte, headers map[string]string, expectedRespCodes ...int) (http.Header, []byte, errors.SDKError) {
	req, err := http.NewRequest(method, reqUrl, bytes.NewReader(data))
	if err != nil {
		return make(http.Header), []byte{}, errors.NewSDKError(err)
	}

	// Sets a default value for the Content-Type.
	// Overridden if Content-Type is passed in the headers arguments.
	req.Header.Add("Content-Type", string(CTJSON))

	for key, value := range headers {
		req.Header.Add(key, value)
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
	sdkerr := errors.CheckError(resp, expectedRespCodes...)
	if sdkerr != nil {
		return make(http.Header), []byte{}, sdkerr
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
	if pm.Token != "" {
		q.Add("token", pm.Token)
	}
	if pm.CommonName != "" {
		q.Add("common_name", pm.CommonName)
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
