// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package apiutil

import "errors"

var (
	// ErrBearerToken indicates missing or invalid bearer user token.
	ErrBearerToken = errors.New("missing or invalid bearer user token")

	// ErrMissingID indicates missing entity ID.
	ErrMissingID = errors.New("missing entity id")

	// ErrNameSize indicates that name size exceeds the max.
	ErrNameSize = errors.New("invalid name size")

	// ErrInvalidOrder indicates an invalid list order.
	ErrInvalidOrder = errors.New("invalid list order provided")

	// ErrEmptyList indicates that entity data is empty.
	ErrEmptyList = errors.New("empty list provided")

	// ErrMalformedPolicy indicates that policies are malformed.
	ErrMalformedPolicy = errors.New("malformed policy")

	// ErrMissingUser indicates that the user is missing.
	ErrMissingUser = errors.New("missing user")

	// ErrMissingComputation indicates that the computation is missing.
	ErrMissingComputation = errors.New("missing computation")

	// ErrInvalidRole indicates missing or invalid role.
	ErrInvalidRole = errors.New("missing or invalid role")

	// ErrUnsupportedContentType indicates unacceptable or lack of Content-Type.
	ErrUnsupportedContentType = errors.New("unsupported content type")

	// ErrValidation indicates that an error was returned by the API.
	ErrValidation = errors.New("something went wrong with the request")

	// ErrInvalidQueryParams indicates invalid query parameters.
	ErrInvalidQueryParams = errors.New("invalid query parameters")

	// ErrInvalidRequest indicates that the request is invalid.
	ErrInvalidRequest = errors.New("invalid request")
)
