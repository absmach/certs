// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/absmach/certs"
	"github.com/absmach/certs/cli"
	"github.com/absmach/certs/sdk"
	sdkmocks "github.com/absmach/certs/sdk/mocks"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	revokeCmd     = "revoke"
	deleteCmd     = "delete"
	issueCmd      = "issue"
	renewCmd      = "renew"
	listCmd       = "get"
	all           = "all"
	downloadCACmd = "download-ca"
	CATokenCmd    = "token-ca"
	viewCACmd     = "view-ca"
)

var (
	serialNumber = "39054620502613157373429341617471746606"
	id           = "5b4c9ee3-e719-4a0a-9ee5-354932c5e6a4"
	commonName   = "test-name"
	extraArg     = "extra-arg"
	token        = "token"
	domainID     = "domain-id"
)

func TestIssueCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	ipAddrs := "[\"192.168.100.22\"]"

	var cert sdk.Certificate
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		cert          sdk.Certificate
	}{
		{
			desc: "issue cert successfully",
			args: []string{
				id,
				commonName,
				ipAddrs,
				domainID,
				token,
			},
			logType: entityLog,
			cert:    sdk.Certificate{SerialNumber: serialNumber},
		},
		{
			desc: "issue cert with invalid args",
			args: []string{
				id,
				ipAddrs,
			},
			logType: usageLog,
		},
		{
			desc: "issue cert failed",
			args: []string{
				id,
				commonName,
				ipAddrs,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
		{
			desc: "issue cert with 6 args",
			args: []string{
				id,
				commonName,
				ipAddrs,
				domainID,
				token,
				"{\"organization\":[\"organization_name\"]}",
			},
			logType: entityLog,
			cert:    sdk.Certificate{SerialNumber: serialNumber},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("IssueCert", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.cert, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{issueCmd}, tc.args...)...)
			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &cert)
				assert.Nil(t, err)
				assert.Equal(t, tc.cert, cert, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.cert, cert))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestRevokeCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "revoke cert successfully",
			args: []string{
				serialNumber,
				domainID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "revoke cert with invalid args",
			args: []string{
				serialNumber,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "revoke cert failed",
			args: []string{
				serialNumber,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RevokeCert", mock.Anything, mock.Anything, mock.Anything).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{revokeCmd}, tc.args...)...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestDeleteCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "delete certs successfully",
			args: []string{
				id,
				domainID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "delete certs with invalid args",
			args: []string{
				id,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "delete certs failed",
			args: []string{
				id,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("DeleteCert", mock.Anything, mock.Anything, mock.Anything).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{deleteCmd}, tc.args...)...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestRenewCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "renew cert successfully",
			args: []string{
				serialNumber,
				domainID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "renew cert with invalid args",
			args: []string{
				serialNumber,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "renew cert failed",
			args: []string{
				serialNumber,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RenewCert", mock.Anything, mock.Anything, mock.Anything).Return(sdk.Certificate{}, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{renewCmd}, tc.args...)...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestListCertsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	var page sdk.CertificatePage
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		page          sdk.CertificatePage
	}{
		{
			desc: "list certs successfully",
			args: []string{
				all,
				domainID,
				token,
			},
			logType: entityLog,
			page: sdk.CertificatePage{
				Total:  1,
				Offset: 0,
				Limit:  10,
				Certificates: []sdk.Certificate{
					{SerialNumber: serialNumber},
				},
			},
		},
		{
			desc: "list certs successfully with entity ID",
			args: []string{
				id,
				domainID,
				token,
			},
			logType: entityLog,
			page: sdk.CertificatePage{
				Total:  1,
				Offset: 0,
				Limit:  10,
				Certificates: []sdk.Certificate{
					{SerialNumber: serialNumber},
				},
			},
		},
		{
			desc: "list certs with invalid args",
			args: []string{
				all,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "failed list certs with all",
			args: []string{
				all,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
		{
			desc: "failed list certs with entity ID",
			args: []string{
				id,
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("ListCerts", mock.Anything, mock.Anything, mock.Anything).Return(tc.page, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{listCmd}, tc.args...)...)

			switch tc.logType {
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case entityLog:
				err := json.Unmarshal([]byte(out), &page)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}
				assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
			}

			sdkCall.Unset()
		})
	}
}

func TestDownloadCACmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logMessage    string
		logType       outputLog
		certBundle    sdk.CertificateBundle
	}{
		{
			desc: "download CA successfully",
			args: []string{
				"ca_token",
				domainID,
				token,
			},
			logType: entityLog,
			certBundle: sdk.CertificateBundle{
				Certificate: []byte("certificate"),
				PrivateKey:  []byte("privatekey"),
			},
			logMessage: "Saved ca.pem\nSaved cert.pem\nSaved key.pem\n\nAll certificate files have been saved successfully.\n",
		},
		{
			desc: "download CA with invalid args",
			args: []string{
				"ca_token",
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "download cert failed",
			args: []string{
				"ca_token",
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
			certBundle:    sdk.CertificateBundle{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			defer func() {
				cleanupFiles(t, []string{"ca.key", "ca.crt"})
			}()
			sdkCall := sdkMock.On("DownloadCA", mock.Anything, mock.Anything, mock.Anything).Return(tc.certBundle, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{downloadCACmd}, tc.args...)...)
			switch tc.logType {
			case entityLog:
				assert.True(t, strings.Contains(out, "Saved ca.crt"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
				assert.True(t, strings.Contains(out, "Saved ca.key"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestViewCACmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	var cert sdk.Certificate
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		cert          sdk.Certificate
	}{
		{
			desc: "view cert successfully",
			args: []string{
				"ca_token",
				domainID,
				token,
			},
			logType: entityLog,
			cert: sdk.Certificate{
				Certificate: "certificate",
				Key:         "privatekey",
			},
		},
		{
			desc: "view cert with invalid args",
			args: []string{
				"ca_token",
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "view cert failed",
			args: []string{
				"ca_token",
				domainID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
			cert:          sdk.Certificate{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("ViewCA", mock.Anything, mock.Anything, mock.Anything).Return(tc.cert, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{viewCACmd}, tc.args...)...)
			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &cert)
				assert.Nil(t, err)
				assert.Equal(t, tc.cert, cert, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.cert, cert))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestGenerateCRLCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		crlBytes      []byte
	}{
		{
			desc:     "generate CRL successfully for root",
			args:     []string{"root", domainID, token},
			logType:  entityLog,
			crlBytes: []byte("mock-crl-data"),
		},
		{
			desc:     "generate CRL successfully for intermediate",
			args:     []string{"intermediate", domainID, token},
			logType:  entityLog,
			crlBytes: []byte("mock-crl-data"),
		},
		{
			desc:    "generate CRL with invalid args",
			args:    []string{"invalid", domainID},
			logType: usageLog,
		},
		{
			desc:          "generate CRL failed",
			args:          []string{"root", domainID, token},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrFailedCertCreation, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrFailedCertCreation, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			defer func() {
				cleanupFiles(t, []string{"root_ca.crl", "intermediate_ca.crl"})
			}()
			sdkCall := sdkMock.On("GenerateCRL", mock.Anything, mock.Anything, mock.Anything).Return(tc.crlBytes, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{"crl"}, tc.args...)...)

			switch tc.logType {
			case entityLog:
				assert.True(t, strings.Contains(out, "CRL file has been saved successfully"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestGetEntityIDCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	entityID := "test-entity-id"

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		entityID      string
	}{
		{
			desc:     "get entity ID successfully",
			args:     []string{serialNumber, domainID, token},
			logType:  entityLog,
			entityID: entityID,
		},
		{
			desc:    "get entity ID with invalid args",
			args:    []string{serialNumber, extraArg},
			logType: usageLog,
		},
		{
			desc:          "get entity ID failed",
			args:          []string{serialNumber, domainID, token},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("GetEntityID", mock.Anything, mock.Anything, mock.Anything).Return(tc.entityID, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{"entity-id"}, tc.args...)...)

			switch tc.logType {
			case entityLog:
				assert.True(t, strings.Contains(out, tc.entityID), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestGetCACmd(t *testing.T) {
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	var cert sdk.Certificate
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		cert          sdk.Certificate
	}{
		{
			desc:    "get CA successfully",
			args:    []string{domainID, token},
			logType: entityLog,
			cert: sdk.Certificate{
				SerialNumber: serialNumber,
				Certificate:  "ca-cert",
			},
		},
		{
			desc:    "get CA with invalid args",
			args:    []string{extraArg},
			logType: usageLog,
		},
		{
			desc:    "get CA failed",
			args:    []string{domainID, token},
			sdkErr:  errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkMock := new(sdkmocks.SDK)
			cli.SetSDK(sdkMock)
			sdkCall := sdkMock.On("GetCA", mock.Anything, mock.Anything).Return(tc.cert, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{"ca"}, tc.args...)...)

			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &cert)
				assert.Nil(t, err)
				assert.Equal(t, tc.cert, cert, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.cert, cert))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func cleanupFiles(t *testing.T, filenames []string) {
	for _, filename := range filenames {
		err := os.Remove(filename)
		if err != nil && !os.IsNotExist(err) {
			t.Logf("Failed to remove file %s: %v", filename, err)
		}
	}
}
