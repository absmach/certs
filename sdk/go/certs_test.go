// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk_test

import (
	"net/http/httptest"

	httpapi "github.com/absmach/certs/api/http"
	"github.com/absmach/certs/mocks"
	logger "github.com/absmach/certs/sdk/go/mocks"
)

const instanceID = "5de9b29a-feb9-11ed-be56-0242ac120002"

func setupCerts() (*httptest.Server, *mocks.MockService) {
	svc := new(mocks.MockService)
	logger := logger.NewMock()
	mux := httpapi.MakeHandler(svc, logger, instanceID)

	return httptest.NewServer(mux), svc
}
