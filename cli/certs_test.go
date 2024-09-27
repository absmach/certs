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
	"github.com/absmach/certs/errors"
	"github.com/absmach/certs/sdk"
	sdkmocks "github.com/absmach/certs/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	revokeCmd   = "revoke"
	issueCmd    = "issue"
	renewCmd    = "renew"
	listCmd     = "get"
	tokenCmd    = "token"
	downloadCmd = "download"
	all         = "all"
)

var (
	serialNumber = "39054620502613157373429341617471746606"
	id           = "5b4c9ee3-e719-4a0a-9ee5-354932c5e6a4"
	commonName   = "test-name"
	extraArg     = "extra-arg"
)

func TestIssueCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.MockSDK)
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
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
		{
			desc: "issue cert with 4 args",
			args: []string{
				id,
				commonName,
				ipAddrs,
				"{\"organization\":[\"organization_name\"]}",
			},
			logType: entityLog,
			cert:    sdk.Certificate{SerialNumber: serialNumber},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("IssueCert", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.cert, tc.sdkErr)
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
	sdkMock := new(sdkmocks.MockSDK)
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
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RevokeCert", mock.Anything).Return(tc.sdkErr)
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

func TestRenewCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.MockSDK)
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
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RenewCert", mock.Anything).Return(tc.sdkErr)
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
	sdkMock := new(sdkmocks.MockSDK)
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
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
		{
			desc: "failed list certs with entity ID",
			args: []string{
				id,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrViewEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("ListCerts", mock.Anything).Return(tc.page, tc.sdkErr)
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

func TestGetTokenCmd(t *testing.T) {
	sdkMock := new(sdkmocks.MockSDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	tk := "ca1121f5-d66a-44c9-bf3c-d267498a0f3d"

	var token sdk.Token
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		token         sdk.Token
	}{
		{
			desc: "get token successfully",
			args: []string{
				serialNumber,
			},
			logType: entityLog,
			token:   sdk.Token{Token: tk},
		},
		{
			desc: "get token with invalid args",
			args: []string{
				serialNumber,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get token failed",
			args: []string{
				serialNumber,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrGetToken, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrGetToken, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RetrieveCertDownloadToken", mock.Anything).Return(tc.token, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{tokenCmd}, tc.args...)...)

			switch tc.logType {
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case entityLog:
				err := json.Unmarshal([]byte(out), &token)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}
				assert.Equal(t, tc.token, token, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.token, token))
			}
			sdkCall.Unset()
		})
	}
}

func TestDownloadCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.MockSDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	token := "token"
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
			desc: "download cert successfully",
			args: []string{
				serialNumber,
				token,
			},
			logType: entityLog,
			certBundle: sdk.CertificateBundle{
				CA:          []byte("ca"),
				Certificate: []byte("certificate"),
				PrivateKey:  []byte("privatekey"),
			},
			logMessage: "Saved ca.pem\nSaved cert.pem\nSaved key.pem\n\nAll certificate files have been saved successfully.\n",
		},
		{
			desc: "download cert with invalid args",
			args: []string{
				serialNumber,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "download cert failed",
			args: []string{
				serialNumber,
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
				cleanupFiles(t, []string{"ca.pem", "cert.pem", "key.pem"})
			}()
			sdkCall := sdkMock.On("DownloadCert", mock.Anything, mock.Anything).Return(tc.certBundle, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{downloadCmd}, tc.args...)...)
			switch tc.logType {
			case entityLog:
				assert.True(t, strings.Contains(out, "Saved key.pem"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
				assert.True(t, strings.Contains(out, "Saved cert.pem"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
				assert.True(t, strings.Contains(out, "Saved ca.pem"), fmt.Sprintf("%s invalid output: %s", tc.desc, out))
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
