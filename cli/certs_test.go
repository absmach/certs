// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
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
	extraArg     = "extra-arg"
)

func TestIssueCertCmd(t *testing.T) {
	sdkMock := new(sdkmocks.MockSDK)
	cli.SetSDK(sdkMock)
	certCmd := cli.NewCertsCmd()
	rootCmd := setFlags(certCmd)

	ipAddrs := "[\"192.168.100.22\"]"

	var sn sdk.SerialNumber
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		serial        sdk.SerialNumber
	}{
		{
			desc: "issue cert successfully",
			args: []string{
				id,
				ipAddrs,
			},
			logType: entityLog,
			serial:  sdk.SerialNumber{SerialNumber: serialNumber},
		},
		{
			desc: "issue cert with invalid args",
			args: []string{
				id,
				ipAddrs,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "issue cert failed",
			args: []string{
				id,
				ipAddrs,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrCreateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("IssueCert", mock.Anything, mock.Anything, mock.Anything).Return(tc.serial, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{issueCmd}, tc.args...)...)
			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &sn)
				assert.Nil(t, err)
				assert.Equal(t, tc.serial, sn, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.serial, sn))
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

func TestRetrieveCertCmd(t *testing.T) {
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
		logType       outputLog
	}{
		{
			desc: "retrieve cert successfully",
			args: []string{
				serialNumber,
				token,
			},
			logType: entityLog,
		},
		{
			desc: "retrieve cert with invalid args",
			args: []string{
				serialNumber,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "retrieve cert failed",
			args: []string{
				serialNumber,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(certs.ErrUpdateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RetrieveCert", mock.Anything, mock.Anything).Return([]byte{}, tc.sdkErr)
			out := executeCommand(t, rootCmd, append([]string{downloadCmd}, tc.args...)...)
			switch tc.logType {
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}
