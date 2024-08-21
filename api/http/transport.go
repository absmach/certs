// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/absmach/certs"
	"github.com/absmach/certs/internal/api"
	"github.com/absmach/certs/pkg/apiutil"
	"github.com/absmach/certs/pkg/errors"
	"github.com/go-chi/chi"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"golang.org/x/crypto/ocsp"
)

const (
	offsetKey       = "offset"
	limitKey        = "limit"
	entityKey       = "entity_id"
	ocspStatusParam = "force_status"
	defOffset       = 0
	defLimit        = 10
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(r *chi.Mux, svc certs.Service, logger *slog.Logger, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, api.EncodeError)),
	}

	r.Route("/certs", func(r chi.Router) {
		r.Post("/issue/{entityType}/{entityID}", otelhttp.NewHandler(kithttp.NewServer(
			issueCertEndpoint(svc),
			decodeIssueCert,
			api.EncodeResponse,
			opts...,
		), "issue_cert").ServeHTTP)

		r.Patch("/{id}/renew", otelhttp.NewHandler(kithttp.NewServer(
			renewCertEndpoint(svc),
			decodeView,
			api.EncodeResponse,
			opts...,
		), "renew_cert").ServeHTTP)

		r.Patch("/{id}/revoke", otelhttp.NewHandler(kithttp.NewServer(
			revokeCertEndpoint(svc),
			decodeView,
			api.EncodeResponse,
			opts...,
		), "revoke_cert").ServeHTTP)

		r.Get("/{id}/download/token", otelhttp.NewHandler(kithttp.NewServer(
			requestCertDownloadTokenEndpoint(svc),
			decodeView,
			api.EncodeResponse,
			opts...,
		), "get_download_token").ServeHTTP)

		r.Get("/", otelhttp.NewHandler(kithttp.NewServer(
			listCertsEndpoint(svc),
			decodeListCerts,
			api.EncodeResponse,
			opts...,
		), "list_certs").ServeHTTP)
		r.Get("/{id}/download", otelhttp.NewHandler(kithttp.NewServer(
			downloadCertEndpoint(svc),
			decodeDownloadCerts,
			encodeFileDownloadResponse,
			opts...,
		), "download_cert").ServeHTTP)
		r.Post("/ocsp", otelhttp.NewHandler(kithttp.NewServer(
			ocspEndpoint(svc),
			decodeOCSPRequest,
			encodeOSCPResponse,
			opts...,
		), "ocsp").ServeHTTP)
	})

	r.Get("/health", certs.Health("certs", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewReq{
		id: chi.URLParam(r, "id"),
	}
	return req, nil
}

func decodeDownloadCerts(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := apiutil.ReadStringQuery(r, "token", "")
	if err != nil {
		return nil, err
	}
	req := downloadReq{
		token: token,
		id:    chi.URLParam(r, "id"),
	}

	return req, nil
}

func decodeOCSPRequest(_ context.Context, r *http.Request) (interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	req, err := ocsp.ParseRequest(body)
	if err != nil {
		return nil, err
	}
	request := ocspReq{
		req:         req,
		statusParam: strings.TrimSpace(r.URL.Query().Get(ocspStatusParam)),
	}
	return request, nil
}

func decodeIssueCert(_ context.Context, r *http.Request) (interface{}, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	req := issueCertReq{
		entityID:   chi.URLParam(r, "entityID"),
		entityType: chi.URLParam(r, "entityType"),
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, errors.Wrap(apiutil.ErrInvalidRequest, err)
	}

	return req, nil
}

func decodeListCerts(_ context.Context, r *http.Request) (interface{}, error) {
	o, err := apiutil.ReadNumQuery[uint64](r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	l, err := apiutil.ReadNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	entity, err := apiutil.ReadStringQuery(r, entityKey, "")
	if err != nil {
		return nil, err
	}

	req := listCertsReq{
		pm: certs.PageMetadata{
			Offset:   o,
			Limit:    l,
			EntityID: entity,
		},
	}
	return req, nil
}

func encodeOSCPResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	res := response.(ocspRes)

	ocspRes, err := ocsp.CreateResponse(res.issuerCert, res.template.Certificate, res.template, res.signer)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/ocsp-response")
	if _, err := w.Write(ocspRes); err != nil {
		return err
	}
	return err
}

func encodeFileDownloadResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	resp := response.(fileDownloadRes)
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)

	f, err := zw.Create("ca.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.CA); err != nil {
		return err
	}

	f, err = zw.Create("cert.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.Certificate); err != nil {
		return err
	}

	f, err = zw.Create("key.pem")
	if err != nil {
		return err
	}

	if _, err = f.Write(resp.PrivateKey); err != nil {
		return err
	}

	if err := zw.Close(); err != nil {
		return err
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", resp.Filename))
	w.Header().Set("Content-Type", resp.ContentType)

	_, err = w.Write(buffer.Bytes())

	return err
}
