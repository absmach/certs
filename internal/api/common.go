// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/absmach/certs/pkg/apiutil"
	"github.com/absmach/certs/pkg/errors"
	svcerr "github.com/absmach/certs/pkg/errors/service"
)

const (
	// ContentType represents JSON content type.
	ContentType = "application/json"
)

// Response contains HTTP response specific methods.
type Response interface {
	// Code returns HTTP response code.
	Code() int

	// Headers returns map of HTTP headers with their values.
	Headers() map[string]string

	// Empty indicates if HTTP response has content.
	Empty() bool
}

// EncodeResponse encodes successful response.
func EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if ar, ok := response.(Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", ContentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

// EncodeError encodes an error response.
func EncodeError(_ context.Context, err error, w http.ResponseWriter) {
	var wrapper error
	if errors.Contains(err, apiutil.ErrValidation) {
		wrapper, err = errors.Unwrap(err)
	}

	w.Header().Set("Content-Type", ContentType)
	switch {
	case errors.Contains(err, svcerr.ErrAuthorization):
		err = unwrap(err)
		w.WriteHeader(http.StatusForbidden)

	case errors.Contains(err, svcerr.ErrAuthentication),
		errors.Contains(err, apiutil.ErrBearerToken):
		err = unwrap(err)
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Contains(err, svcerr.ErrMalformedEntity),
		errors.Contains(err, apiutil.ErrMalformedPolicy),
		errors.Contains(err, apiutil.ErrMissingID),
		errors.Contains(err, apiutil.ErrEmptyList),
		errors.Contains(err, apiutil.ErrNameSize),
		errors.Contains(err, apiutil.ErrInvalidQueryParams),
		errors.Contains(err, apiutil.ErrValidation),
		errors.Contains(err, apiutil.ErrInvalidRequest),
		errors.Contains(err, svcerr.ErrViewEntity):
		err = unwrap(err)
		w.WriteHeader(http.StatusBadRequest)

	case errors.Contains(err, svcerr.ErrCreateEntity),
		errors.Contains(err, svcerr.ErrUpdateEntity),
		errors.Contains(err, svcerr.ErrRemoveEntity):
		err = unwrap(err)
		w.WriteHeader(http.StatusUnprocessableEntity)

	case errors.Contains(err, svcerr.ErrNotFound):
		err = unwrap(err)
		w.WriteHeader(http.StatusNotFound)

	case errors.Contains(err, svcerr.ErrConflict):
		err = unwrap(err)
		w.WriteHeader(http.StatusConflict)

	case errors.Contains(err, apiutil.ErrUnsupportedContentType):
		err = unwrap(err)
		w.WriteHeader(http.StatusUnsupportedMediaType)

	default:
		w.WriteHeader(http.StatusInternalServerError)
	}

	if wrapper != nil {
		err = errors.Wrap(wrapper, err)
	}

	if errorVal, ok := err.(errors.Error); ok {
		if err := json.NewEncoder(w).Encode(errorVal); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func unwrap(err error) error {
	wrapper, err := errors.Unwrap(err)
	if wrapper != nil {
		return wrapper
	}
	return err
}
