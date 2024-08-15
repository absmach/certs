// Copyright (c) Ultraviolet
package http

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/absmach/certs"
	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/go-chi/chi"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/go-kit/kit/otelkit"
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
		r.Patch("/{id}/renew", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("renew_cert"))(renewCertEndpoint(svc)),
			decodeView,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Patch("/{id}/revoke", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("revoke_cert"))(revokeCertEndpoint(svc)),
			decodeView,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/{id}/download/token", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("retrieve_certs_download_token"))(requestCertDownloadTokenEndpoint(svc)),
			decodeView,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/{id}/download", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("download_certs"))(downloadCertEndpoint(svc)),
			decodeDownloadCerts,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/issue/{entityType}/{entityID}", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("issue_cert"))(issueCertEndpoint(svc)),
			decodeIssueCert,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("list_cert"))(listCertsEndpoint(svc)),
			decodeListCerts,
			api.EncodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/ocsp", kithttp.NewServer(
			otelkit.EndpointMiddleware(otelkit.WithOperation("ocsp"))(ocspEndpoint(svc)),
			decodeOCSPRequest,
			encodeOSCPResponse,
			opts...,
		).ServeHTTP)
	})

	r.Get("/health", magistrala.Health("computations", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewReq{
		token: apiutil.ExtractBearerToken(r),
		id:    chi.URLParam(r, "id"),
	}
	return req, nil
}

func decodeDownloadCerts(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := apiutil.ReadStringQuery(r, "token", "")
	if err != nil {
		return nil, err
	}
	req := viewReq{
		token: token,
		id:    chi.URLParam(r, "id"),
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
		token:      apiutil.ExtractBearerToken(r),
		entityID:   chi.URLParam(r, "entityID"),
		entityType: chi.URLParam(r, "entityType"),
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeListCerts(_ context.Context, r *http.Request) (interface{}, error) {
	o, err := apiutil.ReadUintQuery(r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	l, err := apiutil.ReadUintQuery(r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	entity, err := apiutil.ReadStringQuery(r, entityKey, "")
	if err != nil {
		return nil, err
	}

	req := listCertsReq{
		token: apiutil.ExtractBearerToken(r),
		pm: certs.PageMetadata{
			Offset:   o,
			Limit:    l,
			EntityID: entity,
		},
	}
	return req, nil
}
