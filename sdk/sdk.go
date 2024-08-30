// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
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
	Total    uint64   `json:"total,omitempty"`
	Offset   uint64   `json:"offset,omitempty"`
	Limit    uint64   `json:"limit,omitempty"`
	EntityID string   `json:"entity_id,omitempty"`
	IpAddrs  []string `json:"ip_addresses,omitempty"`
	Token    string   `json:"token,omitempty"`
}

type CertsPage struct {
	PageMetadata
	Certificates []Cert `json:"certificates"`
}

type Cert struct {
	SerialNumber string    `json:"serial_number,omitempty"`
	Certificate  []byte    `json:"certificate,omitempty"`
	Key          []byte    `json:"key,omitempty"`
	Revoked      bool      `json:"revoked,omitempty"`
	ExpiryDate   time.Time `json:"expiry_date,omitempty"`
	EntityID     string    `json:"entity_id,omitempty"`
	DownloadUrl  string    `json:"-,omitempty"`
}

type SDK interface {
	// IssueCert issues a certificate for a thing required for mTLS.
	//
	// example:
	//  cert, _ := sdk.IssueCert("thingID", "24h", "token")
	//  fmt.Println(cert)
	IssueCert(entityID string, ipAddrs []string) (Cert, errors.SDKError)

	// ViewCert returns a certificate given certificate ID
	//
	// example:
	//  cert, _ := sdk.ViewCert("certID", "token")
	//  fmt.Println(cert)
	RetrieveCert(token, serialNumber string) (Cert, errors.SDKError)

	// RevokeCert revokes certificate for thing with thingID
	//
	// example:
	//  tm, _ := sdk.RevokeCert("thingID", "token")
	//  fmt.Println(tm)
	RevokeCert(serialNumber string) errors.SDKError

	// RenewCert renews certificate for thing with thingID
	//
	// example:
	//  tm, _ := sdk.RenewCert("serialNumber")
	//  fmt.Println(tm)
	RenewCert(serialNumber string) errors.SDKError

	// ListCerts lists all certificates for a client
	//
	ListCerts(pm PageMetadata) (CertsPage, errors.SDKError)

	RetrieveCertDownloadToken(serialNumber string) (string, errors.SDKError)

	OCSP(serialNumber string) (Cert, int, errors.SDKError)
}

func (sdk mgSDK) IssueCert(entityID string, ipAddrs []string) (Cert, errors.SDKError) {
	r := PageMetadata{
		IpAddrs: ipAddrs,
	}
	d, err := json.Marshal(r)
	if err != nil {
		return Cert{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.certsURL, issueCertEndpoint, entityID)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, d, nil, http.StatusCreated)
	if sdkerr != nil {
		return Cert{}, sdkerr
	}

	return Cert{
		SerialNumber: string(body),
	}, nil
}

func (sdk mgSDK) RetrieveCert(token, serialNumber string) (Cert, errors.SDKError) {
	pm := PageMetadata{
		Token: token,
	}
	url, err := sdk.withQueryParams(sdk.certsURL, fmt.Sprintf("%s/%s/%s/download", sdk.certsURL, certsEndpoint, serialNumber), pm)
	if err != nil {
		return Cert{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Cert{}, sdkerr
	}
	var c Cert
	if err := json.Unmarshal(body, &c); err != nil {
		return Cert{}, errors.NewSDKError(err)
	}
	return c, nil
}

func (sdk mgSDK) RevokeCert(serialNumber string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/revoke", sdk.certsURL, certsEndpoint, serialNumber)
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, nil, nil, http.StatusOK)
	return sdkerr
}

func (sdk mgSDK) RenewCert(serialNumber string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/renew", sdk.certsURL, certsEndpoint, serialNumber)
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, nil, nil, http.StatusOK)
	return sdkerr
}

func (sdk mgSDK) ListCerts(pm PageMetadata) (CertsPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.certsURL, certsEndpoint, pm)
	if err != nil {
		return CertsPage{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return CertsPage{}, sdkerr
	}
	var cp CertsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return CertsPage{}, errors.NewSDKError(err)
	}
	return cp, nil
}

func (sdk mgSDK) RetrieveCertDownloadToken(serialNumber string) (string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/download/token", sdk.certsURL, certsEndpoint, serialNumber)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return "", sdkerr
	}
	return string(body), nil
}

func (sdk mgSDK) OCSP(serialNumber string) (Cert, int, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/ocsp", sdk.certsURL, certsEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Cert{}, 0, sdkerr
	}
	var c Cert
	if err := json.Unmarshal(body, &c); err != nil {
		return Cert{}, 0, errors.NewSDKError(err)
	}
	return c, 0, nil
}

type mgSDK struct {
	certsURL string
	HostURL  string

	msgContentType ContentType
	client         *http.Client
	curlFlag       bool
}

type Config struct {
	CertsURL string
	HostURL  string

	MsgContentType  ContentType
	TLSVerification bool
	CurlFlag        bool
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
	if pm.Token != "" {
		q.Add("token", pm.Token)
	}

	return q.Encode(), nil
}
